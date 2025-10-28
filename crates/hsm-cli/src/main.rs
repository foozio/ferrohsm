use std::{
    fs,
    io::{self, BufRead},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, Subcommand, ValueEnum};
use comfy_table::{presets::UTF8_FULL, Table};
use hsm_core::{
    compute_event_hash, crypto::sign_audit_record, AuditEvent, KeyAlgorithm, KeyPurpose, KeyUsage,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::{
    header::{HeaderMap, AUTHORIZATION},
    Client, Identity, StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "FerroHSM secure CLI",
    propagate_version = true
)]
struct Cli {
    /// API endpoint base URL (https).
    #[arg(long, default_value = "https://localhost:8443")]
    endpoint: String,

    /// Client certificate (PEM) for mutual TLS.
    #[arg(long)]
    client_cert: Option<PathBuf>,

    /// Client private key (PEM) for mutual TLS.
    #[arg(long)]
    client_key: Option<PathBuf>,

    /// Custom CA bundle (PEM).
    #[arg(long)]
    ca_bundle: Option<PathBuf>,

    /// Actor identifier propagated to the server.
    #[arg(long, default_value = "cli-operator")]
    actor: String,

    /// Comma-separated roles for the session.
    #[arg(long, default_value = "operator")]
    roles: String,

    /// Pre-generated bearer token (env: FERROHSM_AUTH_TOKEN).
    #[arg(long, env = "FERROHSM_AUTH_TOKEN", conflicts_with = "jwt_secret")]
    auth_token: Option<String>,

    /// Shared secret for signing JWTs locally (env: FERROHSM_JWT_SECRET).
    #[arg(long, env = "FERROHSM_JWT_SECRET", conflicts_with = "auth_token")]
    jwt_secret: Option<String>,

    /// Token time-to-live in seconds when signing locally.
    #[arg(long, default_value_t = 300)]
    token_ttl: u64,

    /// JWT signing algorithm to use when minting local tokens.
    #[arg(long, value_enum, default_value_t = JwtAlgorithmArg::Hs256)]
    jwt_algorithm: JwtAlgorithmArg,

    /// PEM-encoded private key for asymmetric JWT algorithms (RS256/ES256).
    #[arg(long)]
    jwt_private_key: Option<PathBuf>,

    /// JWT issuer claim to embed in locally minted tokens.
    #[arg(long)]
    jwt_issuer: Option<String>,

    /// JWT key identifier (kid) to embed in the token header.
    #[arg(long)]
    jwt_kid: Option<String>,

    /// Audit log file used by audit commands.
    #[arg(long, default_value = "data/audit.log")]
    audit_log: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List managed keys.
    List {
        #[arg(long)]
        page: Option<u32>,
        #[arg(long, value_name = "COUNT")]
        per_page: Option<u32>,
        #[arg(long)]
        algorithm: Option<String>,
        #[arg(long)]
        state: Option<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// Create a new key.
    Create {
        #[arg(value_enum)]
        algorithm: AlgorithmArg,
        #[arg(long)]
        description: Option<String>,
        #[arg(long, value_delimiter = ',', default_value = "Encrypt,Decrypt")]
        usage: Vec<UsageArg>,
        #[arg(long, value_delimiter = ',', default_value = "default")]
        tags: Vec<String>,
    },
    /// Request a signature operation.
    Sign {
        key_id: String,
        /// Raw data to sign (UTF-8). Use --base64 for binary payloads.
        payload: String,
        #[arg(long)]
        base64: bool,
    },
    /// Encrypt plaintext using a symmetric key.
    Encrypt {
        key_id: String,
        plaintext: String,
        #[arg(long)]
        base64: bool,
    },
    /// Decrypt ciphertext previously returned by the encrypt command.
    Decrypt {
        key_id: String,
        ciphertext_b64: String,
        nonce_b64: String,
    },
    /// Rotate a key to the next version.
    Rotate { key_id: String },
    /// Show the version history for a key.
    Versions { key_id: String },
    /// Roll back to a prior key version (creates a new generation from historical material).
    Rollback {
        key_id: String,
        #[arg(long)]
        version: u32,
    },
    /// Manage dual-control approvals.
    Approvals {
        #[command(subcommand)]
        action: ApprovalCommands,
    },
    /// Audit log inspection utilities.
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },
}

#[derive(Subcommand, Debug)]
enum ApprovalCommands {
    /// List pending or recently approved dual-control actions.
    List,
    /// Approve a pending dual-control action by identifier.
    Approve { approval_id: String },
    /// Deny a pending dual-control action by identifier.
    Deny { approval_id: String },
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    /// Verify audit log integrity and optional HMAC signatures.
    Verify {
        #[arg(long)]
        audit_path: Option<PathBuf>,
        #[arg(long)]
        hmac_key: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AlgorithmArg {
    Aes256Gcm,
    Rsa2048,
    Rsa4096,
    P256,
    P384,
}

impl From<AlgorithmArg> for KeyAlgorithm {
    fn from(value: AlgorithmArg) -> KeyAlgorithm {
        match value {
            AlgorithmArg::Aes256Gcm => KeyAlgorithm::Aes256Gcm,
            AlgorithmArg::Rsa2048 => KeyAlgorithm::Rsa2048,
            AlgorithmArg::Rsa4096 => KeyAlgorithm::Rsa4096,
            AlgorithmArg::P256 => KeyAlgorithm::P256,
            AlgorithmArg::P384 => KeyAlgorithm::P384,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum UsageArg {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Wrap,
    Unwrap,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum JwtAlgorithmArg {
    Hs256,
    Rs256,
    Es256,
}

impl Default for JwtAlgorithmArg {
    fn default() -> Self {
        JwtAlgorithmArg::Hs256
    }
}

impl From<UsageArg> for KeyPurpose {
    fn from(value: UsageArg) -> KeyPurpose {
        match value {
            UsageArg::Encrypt => KeyPurpose::Encrypt,
            UsageArg::Decrypt => KeyPurpose::Decrypt,
            UsageArg::Sign => KeyPurpose::Sign,
            UsageArg::Verify => KeyPurpose::Verify,
            UsageArg::Wrap => KeyPurpose::Wrap,
            UsageArg::Unwrap => KeyPurpose::Unwrap,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = build_client(&cli)?;
    let auth_token = prepare_auth_token(&cli)?;
    match &cli.command {
        Commands::List {
            page,
            per_page,
            algorithm,
            state,
            tags,
        } => {
            list_keys(
                &client,
                &cli,
                &auth_token,
                *page,
                *per_page,
                algorithm.clone(),
                state.clone(),
                tags.clone(),
            )
            .await?
        }
        Commands::Create {
            algorithm,
            description,
            usage,
            tags,
        } => {
            create_key(
                &client,
                &cli,
                &auth_token,
                *algorithm,
                description.clone(),
                usage.clone(),
                tags.clone(),
            )
            .await?
        }
        Commands::Sign {
            key_id,
            payload,
            base64,
        } => sign_payload(&client, &cli, &auth_token, key_id, payload, *base64).await?,
        Commands::Encrypt {
            key_id,
            plaintext,
            base64,
        } => encrypt_payload(&client, &cli, &auth_token, key_id, plaintext, *base64).await?,
        Commands::Decrypt {
            key_id,
            ciphertext_b64,
            nonce_b64,
        } => {
            decrypt_payload(
                &client,
                &cli,
                &auth_token,
                key_id,
                ciphertext_b64,
                nonce_b64,
            )
            .await?
        }
        Commands::Rotate { key_id } => rotate_key_cli(&client, &cli, &auth_token, key_id).await?,
        Commands::Versions { key_id } => {
            list_versions_cli(&client, &cli, &auth_token, key_id).await?
        }
        Commands::Rollback { key_id, version } => {
            rollback_key_cli(&client, &cli, &auth_token, key_id, *version).await?
        }
        Commands::Approvals { action } => match action {
            ApprovalCommands::List => list_approvals_cli(&client, &cli, &auth_token).await?,
            ApprovalCommands::Approve { approval_id } => {
                approve_pending_cli(&client, &cli, &auth_token, approval_id).await?
            }
            ApprovalCommands::Deny { approval_id } => {
                deny_pending_cli(&client, &cli, &auth_token, approval_id).await?
            }
        },
        Commands::Audit { action } => match action {
            AuditCommands::Verify {
                audit_path,
                hmac_key,
            } => verify_audit_log_cli(
                audit_path.as_ref().unwrap_or(&cli.audit_log),
                hmac_key.as_deref(),
            )?,
        },
    }
    Ok(())
}

fn build_client(cli: &Cli) -> anyhow::Result<Client> {
    let mut builder = Client::builder().timeout(Duration::from_secs(10));
    if let (Some(cert_path), Some(key_path)) = (&cli.client_cert, &cli.client_key) {
        let cert = fs::read(cert_path)
            .with_context(|| format!("reading client cert {}", cert_path.display()))?;
        let key = fs::read(key_path)
            .with_context(|| format!("reading client key {}", key_path.display()))?;
        let mut identity_pem = cert;
        identity_pem.extend_from_slice(&key);
        let identity = Identity::from_pem(&identity_pem)?;
        builder = builder.identity(identity);
    }
    if let Some(ca_path) = &cli.ca_bundle {
        let cert = fs::read(ca_path)
            .with_context(|| format!("reading ca bundle {}", ca_path.display()))?;
        let ca = reqwest::Certificate::from_pem(&cert)?;
        builder = builder.add_root_certificate(ca);
    }
    Ok(builder.build()?)
}

fn auth_headers(token: &str) -> anyhow::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, format!("Bearer {token}").parse()?);
    Ok(headers)
}

async fn list_keys(
    client: &Client,
    cli: &Cli,
    token: &str,
    page: Option<u32>,
    per_page: Option<u32>,
    algorithm: Option<String>,
    state: Option<String>,
    tags: Vec<String>,
) -> anyhow::Result<()> {
    let headers = auth_headers(token)?;
    let mut request = client
        .get(format!("{}/api/v1/keys", cli.endpoint))
        .headers(headers);

    let mut query: Vec<(&str, String)> = Vec::new();
    if let Some(page) = page {
        query.push(("page", page.to_string()));
    }
    if let Some(per_page) = per_page {
        query.push(("per_page", per_page.to_string()));
    }
    if let Some(alg) = algorithm {
        query.push(("algorithm", alg));
    }
    if let Some(state) = state {
        query.push(("state", state));
    }
    if !tags.is_empty() {
        query.push(("tags", tags.join(",")));
    }
    if !query.is_empty() {
        request = request.query(&query);
    }

    let response = request.send().await?.error_for_status()?;
    let KeyListResponse {
        items,
        total,
        page,
        per_page,
        has_more,
    } = response.json().await?;
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "ID",
        "Algorithm",
        "State",
        "Usage",
        "Version",
        "Created",
    ]);
    for key in items {
        let created = key
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| key.created_at.to_string());
        let usage = key
            .usage
            .iter()
            .map(|u| format!("{:?}", u))
            .collect::<Vec<_>>()
            .join(",");
        table.add_row(vec![
            key.id.clone(),
            format!("{:?}", key.algorithm),
            format!("{:?}", key.state),
            usage,
            key.version.to_string(),
            created,
        ]);
    }
    println!("{table}");
    println!(
        "Showing page {} ({} items per page) - total {}{}",
        page,
        per_page,
        total,
        if has_more {
            ", more results available"
        } else {
            ""
        }
    );
    Ok(())
}

async fn create_key(
    client: &Client,
    cli: &Cli,
    token: &str,
    algorithm: AlgorithmArg,
    description: Option<String>,
    usage: Vec<UsageArg>,
    tags: Vec<String>,
) -> anyhow::Result<()> {
    let headers = auth_headers(token)?;
    let payload = CreateKeyPayload {
        algorithm: algorithm.into(),
        description,
        usage: usage.into_iter().map(Into::into).collect(),
        policy_tags: tags,
    };
    let response = client
        .post(format!("{}/api/v1/keys", cli.endpoint))
        .headers(headers)
        .json(&payload)
        .send()
        .await?;
    if response.status() == StatusCode::ACCEPTED {
        let body: Value = response.json().await.unwrap_or_default();
        if let Some(msg) = body.get("error").and_then(|v| v.as_str()) {
            println!("{msg}");
        } else {
            println!("dual-control approval required");
        }
        return Ok(());
    }
    let response = response.error_for_status()?;
    let key: KeySummary = response.json().await?;
    println!("Created key {}", key.id);
    Ok(())
}

async fn sign_payload(
    client: &Client,
    cli: &Cli,
    token: &str,
    key_id: &str,
    payload: &str,
    base64_input: bool,
) -> anyhow::Result<()> {
    let headers = auth_headers(token)?;
    let payload_b64 = if base64_input {
        payload.to_string()
    } else {
        B64.encode(payload.as_bytes())
    };
    let response = client
        .post(format!("{}/api/v1/keys/{key_id}/sign", cli.endpoint))
        .headers(headers)
        .json(&SignRequestPayload { payload_b64 })
        .send()
        .await?;
    if response.status() == StatusCode::ACCEPTED {
        let body: Value = response.json().await.unwrap_or_default();
        if let Some(msg) = body.get("error").and_then(|v| v.as_str()) {
            println!("{msg}");
        } else {
            println!("dual-control approval required");
        }
        return Ok(());
    }
    let response = response.error_for_status()?;
    let result: SignResponsePayload = response.json().await?;
    println!("{}", result.signature_b64);
    Ok(())
}

async fn encrypt_payload(
    client: &Client,
    cli: &Cli,
    token: &str,
    key_id: &str,
    plaintext: &str,
    base64_input: bool,
) -> anyhow::Result<()> {
    let headers = auth_headers(token)?;
    let plaintext_b64 = if base64_input {
        plaintext.to_string()
    } else {
        B64.encode(plaintext.as_bytes())
    };
    let response = client
        .post(format!("{}/api/v1/keys/{key_id}/encrypt", cli.endpoint))
        .headers(headers)
        .json(&EncryptRequestPayload {
            plaintext_b64,
            associated_data_b64: None,
        })
        .send()
        .await?;
    if response.status() == StatusCode::ACCEPTED {
        let body: Value = response.json().await.unwrap_or_default();
        if let Some(msg) = body.get("error").and_then(|v| v.as_str()) {
            println!("{msg}");
        } else {
            println!("dual-control approval required");
        }
        return Ok(());
    }
    let response = response.error_for_status()?;
    let body: EncryptResponsePayload = response.json().await?;
    println!("ciphertext: {}", body.ciphertext_b64);
    println!("nonce: {}", body.nonce_b64);
    Ok(())
}

async fn decrypt_payload(
    client: &Client,
    cli: &Cli,
    token: &str,
    key_id: &str,
    ciphertext_b64: &str,
    nonce_b64: &str,
) -> anyhow::Result<()> {
    let headers = auth_headers(token)?;
    let response = client
        .post(format!("{}/api/v1/keys/{key_id}/decrypt", cli.endpoint))
        .headers(headers)
        .json(&DecryptRequestPayload {
            ciphertext_b64: ciphertext_b64.to_string(),
            nonce_b64: nonce_b64.to_string(),
            associated_data_b64: None,
        })
        .send()
        .await?;
    if response.status() == StatusCode::ACCEPTED {
        let body: Value = response.json().await.unwrap_or_default();
        if let Some(msg) = body.get("error").and_then(|v| v.as_str()) {
            println!("{msg}");
        } else {
            println!("dual-control approval required");
        }
        return Ok(());
    }
    let response = response.error_for_status()?;
    let body: DecryptResponsePayload = response.json().await?;
    let decoded = B64.decode(body.plaintext_b64)?;
    let plaintext = String::from_utf8_lossy(&decoded);
    println!("{}", plaintext);
    Ok(())
}

async fn rotate_key_cli(
    client: &Client,
    cli: &Cli,
    token: &str,
    key_id: &str,
) -> anyhow::Result<()> {
    let headers = auth_headers(token)?;
    let response = client
        .post(format!("{}/api/v1/keys/{key_id}/rotate", cli.endpoint))
        .headers(headers)
        .send()
        .await?;
    if response.status() == StatusCode::ACCEPTED {
        let body: Value = response.json().await.unwrap_or_default();
        if let Some(msg) = body.get("error").and_then(|v| v.as_str()) {
            println!("{msg}");
        } else {
            println!("dual-control approval recorded for rotation");
        }
        return Ok(());
    }
    let response = response.error_for_status()?;
    let key: KeySummary = response.json().await?;
    println!("Key {} rotated to version {}", key.id, key.version);
    Ok(())
}

async fn list_versions_cli(
    client: &Client,
    cli: &Cli,
    token: &str,
    key_id: &str,
) -> anyhow::Result<()> {
    let headers = auth_headers(token)?;
    let response = client
        .get(format!("{}/api/v1/keys/{key_id}/versions", cli.endpoint))
        .headers(headers)
        .send()
        .await?
        .error_for_status()?;
    let versions: Vec<KeySummary> = response.json().await?;
    if versions.is_empty() {
        println!("No versions found for {key_id}");
        return Ok(());
    }
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Version", "State", "Created", "Tamper", "Description"]);
    for version in versions {
        let created = version
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| version.created_at.to_string());
        table.add_row(vec![
            version.version.to_string(),
            format!("{:?}", version.state),
            created,
            format!("{:?}", version.tamper_status),
            version.description.unwrap_or_else(|| "-".into()),
        ]);
    }
    println!("{table}");
    Ok(())
}

async fn rollback_key_cli(
    client: &Client,
    cli: &Cli,
    token: &str,
    key_id: &str,
    version: u32,
) -> anyhow::Result<()> {
    let headers = auth_headers(token)?;
    let payload = RollbackRequestPayload { version };
    let response = client
        .post(format!("{}/api/v1/keys/{key_id}/rollback", cli.endpoint))
        .headers(headers)
        .json(&payload)
        .send()
        .await?;
    if response.status() == StatusCode::ACCEPTED {
        let body: Value = response.json().await.unwrap_or_default();
        if let Some(msg) = body.get("error").and_then(|v| v.as_str()) {
            println!("{msg}");
        } else {
            println!("dual-control approval recorded for rollback");
        }
        return Ok(());
    }
    let response = response.error_for_status()?;
    let key: KeySummary = response.json().await?;
    println!(
        "Key {} rolled back; new active version is {}",
        key.id, key.version
    );
    Ok(())
}

async fn list_approvals_cli(client: &Client, cli: &Cli, token: &str) -> anyhow::Result<()> {
    let headers = auth_headers(token)?;
    let response = client
        .get(format!("{}/api/v1/approvals", cli.endpoint))
        .headers(headers)
        .send()
        .await?
        .error_for_status()?;
    let approvals: Vec<ApprovalListItem> = response.json().await?;
    if approvals.is_empty() {
        println!("No pending approvals.");
        return Ok(());
    }
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "ID",
        "Action",
        "Subject",
        "Requester",
        "Approved By",
        "Approved At",
        "Created",
    ]);
    for approval in approvals {
        table.add_row(vec![
            approval.id,
            approval.action,
            approval.subject,
            approval.requester,
            approval.approved_by.unwrap_or_else(|| "-".into()),
            approval.approved_at.unwrap_or_else(|| "-".into()),
            approval.created_at,
        ]);
    }
    println!("{table}");
    Ok(())
}

async fn approve_pending_cli(
    client: &Client,
    cli: &Cli,
    token: &str,
    approval_id: &str,
) -> anyhow::Result<()> {
    let headers = auth_headers(token)?;
    let response = client
        .post(format!(
            "{}/api/v1/approvals/{approval_id}/approve",
            cli.endpoint
        ))
        .headers(headers)
        .send()
        .await?;
    if response.status() == StatusCode::ACCEPTED {
        let body: Value = response.json().await.unwrap_or_default();
        if let Some(msg) = body.get("error").and_then(|v| v.as_str()) {
            println!("{msg}");
        } else {
            println!("dual-control approval still pending");
        }
        return Ok(());
    }
    response.error_for_status()?;
    println!("Approved {approval_id}");
    Ok(())
}

async fn deny_pending_cli(
    client: &Client,
    cli: &Cli,
    token: &str,
    approval_id: &str,
) -> anyhow::Result<()> {
    let headers = auth_headers(token)?;
    let response = client
        .post(format!(
            "{}/api/v1/approvals/{approval_id}/deny",
            cli.endpoint
        ))
        .headers(headers)
        .send()
        .await?;
    if response.status() == StatusCode::ACCEPTED {
        let body: Value = response.json().await.unwrap_or_default();
        if let Some(msg) = body.get("error").and_then(|v| v.as_str()) {
            println!("{msg}");
        } else {
            println!("dual-control approval still pending");
        }
        return Ok(());
    }
    response.error_for_status()?;
    println!("Denied {approval_id}");
    Ok(())
}

fn prepare_auth_token(cli: &Cli) -> anyhow::Result<String> {
    if let Some(token) = &cli.auth_token {
        return Ok(token.clone());
    }
    let (encoding_key, algorithm) = match cli.jwt_algorithm {
        JwtAlgorithmArg::Hs256 => {
            let secret = cli
                .jwt_secret
                .as_ref()
                .ok_or_else(|| anyhow!("provide --auth-token or --jwt-secret"))?;
            let secret_bytes = decode_secret(secret)?;
            (EncodingKey::from_secret(&secret_bytes), Algorithm::HS256)
        }
        JwtAlgorithmArg::Rs256 => {
            let path = cli
                .jwt_private_key
                .as_ref()
                .ok_or_else(|| anyhow!("--jwt-private-key is required for RS256"))?;
            let pem = fs::read(path)
                .with_context(|| format!("reading JWT private key {}", path.display()))?;
            (EncodingKey::from_rsa_pem(&pem)?, Algorithm::RS256)
        }
        JwtAlgorithmArg::Es256 => {
            let path = cli
                .jwt_private_key
                .as_ref()
                .ok_or_else(|| anyhow!("--jwt-private-key is required for ES256"))?;
            let pem = fs::read(path)
                .with_context(|| format!("reading JWT private key {}", path.display()))?;
            (EncodingKey::from_ec_pem(&pem)?, Algorithm::ES256)
        }
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if now < 0 {
        return Err(anyhow!("system clock is behind epoch"));
    }
    let issued_at = now as usize;
    let expiry = issued_at + cli.token_ttl as usize;
    let roles = cli
        .roles
        .split(',')
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect::<Vec<_>>();
    if roles.is_empty() {
        return Err(anyhow!("at least one role must be specified"));
    }
    let claims = TokenClaims {
        sub: cli.actor.clone(),
        roles,
        exp: expiry,
        iat: issued_at,
        sid: uuid::Uuid::new_v4().to_string(),
        iss: cli.jwt_issuer.clone(),
        fp: None,
        rip: None,
    };
    let mut header = Header::new(algorithm);
    if let Some(kid) = &cli.jwt_kid {
        header.kid = Some(kid.clone());
    }
    let token = encode(&header, &claims, &encoding_key)?;
    Ok(token)
}

fn decode_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
    if secret.trim().is_empty() {
        return Err(anyhow!("jwt secret cannot be empty"));
    }
    match B64.decode(secret) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Ok(secret.as_bytes().to_vec()),
    }
}

fn verify_audit_log_cli(path: &Path, hmac_key: Option<&str>) -> anyhow::Result<()> {
    let file =
        fs::File::open(path).with_context(|| format!("opening audit log {}", path.display()))?;
    let reader = io::BufReader::new(file);
    let hmac_bytes = match hmac_key {
        Some(key) => Some(decode_secret(key)?),
        None => None,
    };

    let mut previous_hash: Option<String> = None;
    let mut lines_processed = 0usize;

    for (idx, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("reading line {}", idx + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let event: AuditEvent = serde_json::from_str(&line)
            .with_context(|| format!("parsing audit event at line {}", idx + 1))?;

        if event.prev_hash.as_deref() != previous_hash.as_deref() {
            bail!(
                "hash chain broken at line {}: expected previous hash {:?}, found {:?}",
                idx + 1,
                previous_hash,
                event.prev_hash
            );
        }

        let expected_hash = compute_event_hash(
            &event.record,
            event.signature.as_deref(),
            event.prev_hash.as_deref(),
        )
        .map_err(|err| anyhow!(err.to_string()))?;
        if event.hash != expected_hash {
            bail!(
                "hash mismatch at line {}: expected {}, found {}",
                idx + 1,
                expected_hash,
                event.hash
            );
        }

        if let (Some(sig), Some(key_bytes)) = (event.signature.as_ref(), hmac_bytes.as_ref()) {
            let expected_sig = sign_audit_record(key_bytes, &event.record);
            if &expected_sig != sig {
                bail!(
                    "HMAC verification failed at line {}: expected {}, found {}",
                    idx + 1,
                    expected_sig,
                    sig
                );
            }
        }

        previous_hash = Some(event.hash.clone());
        lines_processed += 1;
    }

    println!(
        "Audit log verification succeeded for {} entries at {}",
        lines_processed,
        path.display()
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct TokenClaims {
    sub: String,
    roles: Vec<String>,
    exp: usize,
    iat: usize,
    sid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rip: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KeySummary {
    id: String,
    algorithm: KeyAlgorithm,
    state: hsm_core::KeyState,
    usage: KeyUsage,
    version: u32,
    description: Option<String>,
    policy_tags: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    tamper_status: hsm_core::TamperStatus,
}

#[derive(Debug, Deserialize)]
struct KeyListResponse {
    items: Vec<KeySummary>,
    total: usize,
    page: u32,
    per_page: u32,
    has_more: bool,
}

#[derive(Debug, Serialize)]
struct CreateKeyPayload {
    algorithm: KeyAlgorithm,
    usage: KeyUsage,
    policy_tags: Vec<String>,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct SignRequestPayload {
    payload_b64: String,
}

#[derive(Debug, Deserialize)]
struct SignResponsePayload {
    signature_b64: String,
}

#[derive(Debug, Serialize)]
struct EncryptRequestPayload {
    plaintext_b64: String,
    associated_data_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EncryptResponsePayload {
    ciphertext_b64: String,
    nonce_b64: String,
}

#[derive(Debug, Serialize)]
struct DecryptRequestPayload {
    ciphertext_b64: String,
    nonce_b64: String,
    associated_data_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DecryptResponsePayload {
    plaintext_b64: String,
}

#[derive(Debug, Serialize)]
struct RollbackRequestPayload {
    version: u32,
}

#[derive(Debug, Deserialize)]
struct ApprovalListItem {
    id: String,
    action: String,
    subject: String,
    requester: String,
    created_at: String,
    approved_by: Option<String>,
    approved_at: Option<String>,
}
