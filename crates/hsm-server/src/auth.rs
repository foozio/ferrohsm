use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hsm_core::{AuthContext, Role};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use parking_lot::{Mutex, RwLock};
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{error, warn};
use uuid::Uuid;

use crate::AppError;

const MIN_HS256_KEY_LEN: usize = 32;

#[derive(Clone)]
pub struct AuthVerifier {
    inner: Arc<AuthState>,
}

pub struct AuthenticatedClient {
    context: AuthContext,
    throttle_key: String,
}

impl AuthenticatedClient {
    pub fn throttle_key(&self) -> &str {
        &self.throttle_key
    }

    pub fn into_context(self) -> AuthContext {
        self.context
    }
}

impl AuthVerifier {
    pub fn from_secret(secret: &str, issuer: Option<String>) -> anyhow::Result<Self> {
        let runtime = RuntimeConfig::from_shared_secret(secret, issuer)?;
        Ok(Self {
            inner: Arc::new(AuthState {
                source: ConfigSource::Static,
                runtime: RwLock::new(runtime),
            }),
        })
    }

    pub fn from_config_file(path: PathBuf, reload: Duration) -> anyhow::Result<Self> {
        let config = load_config(&path)?;
        let runtime = RuntimeConfig::try_from(&config)?;
        let metadata = fs::metadata(&path).ok().and_then(|m| m.modified().ok());
        Ok(Self {
            inner: Arc::new(AuthState {
                source: ConfigSource::File(Mutex::new(FileSource {
                    path,
                    reload_interval: reload,
                    last_checked: Instant::now(),
                    last_modified: metadata,
                })),
                runtime: RwLock::new(runtime),
            }),
        })
    }

    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        remote_addr: Option<IpAddr>,
    ) -> Result<AuthenticatedClient, AppError> {
        self.inner.refresh_if_needed();

        let auth_header = headers
            .get(axum::http::header::AUTHORIZATION)
            .ok_or_else(|| auth_failure("missing Authorization header"))?;
        let value = auth_header
            .to_str()
            .map_err(|_| auth_failure("invalid Authorization header"))?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or_else(|| auth_failure("unsupported authorization scheme"))?
            .trim()
            .to_owned();

        if token.is_empty() {
            return Err(auth_failure("empty bearer token"));
        }

        let header = decode_header(&token).map_err(|_| {
            // Log detailed error internally but return generic message to client
            error!("JWT header decode failed");
            auth_failure("invalid token header")
        })?;

        let config = self.inner.runtime.read();
        let mut validation = config.validation.clone();
        validation.algorithms = vec![header.alg];

        let candidates = config.select_keys(header.alg, header.kid.as_deref());
        if candidates.is_empty() {
            return Err(auth_failure("no verification key available"));
        }

        let mut last_err = None;
        for key in candidates {
            match decode::<Claims>(&token, &key, &validation) {
                Ok(token_data) => {
                    let context = build_auth_context(token_data.claims, remote_addr)?;
                    let throttle_key =
                        derive_throttle_key(header.alg, &context.actor_id, remote_addr, &token);
                    return Ok(AuthenticatedClient {
                        context,
                        throttle_key,
                    });
                }
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }

        if last_err.is_some() {
            // Log generic failure without exposing details
            error!("token validation failed");
        }
        Err(auth_failure("invalid token"))
    }

    pub fn jwks(&self) -> Result<serde_json::Value, AppError> {
        let config = self.inner.runtime.read();
        let mut keys = Vec::new();

        for (alg, public_keys) in &config.public_keys {
            let kids = config.kids.get(alg).unwrap();
            for (i, pem) in public_keys.iter().enumerate() {
                if *alg == Algorithm::HS256 {
                    continue;
                }

                if let Some(pem) = pem {
                    let kid = kids[i].clone();
                    let jwk = match alg {
                        Algorithm::RS256 => {
                            let pk = rsa::RsaPublicKey::from_public_key_pem(pem)
                                .map_err(|_| auth_failure("invalid RSA key"))?;
                            let n = pk.n().to_bytes_be();
                            let e = pk.e().to_bytes_be();
                            serde_json::json!({
                                "kty": "RSA",
                                "use": "sig",
                                "alg": "RS256",
                                "kid": kid,
                                "n": URL_SAFE_NO_PAD.encode(&n),
                                "e": URL_SAFE_NO_PAD.encode(&e),
                            })
                        }
                        Algorithm::ES256 => {
                            let pk = p256::PublicKey::from_public_key_pem(pem)
                                .map_err(|_| auth_failure("invalid EC key"))?;
                            let point = pk.to_encoded_point(false);
                            let x = point.x().unwrap();
                            let y = point.y().unwrap();
                            serde_json::json!({
                                "kty": "EC",
                                "use": "sig",
                                "alg": "ES256",
                                "kid": kid,
                                "crv": "P-256",
                                "x": URL_SAFE_NO_PAD.encode(x),
                                "y": URL_SAFE_NO_PAD.encode(y),
                            })
                        }
                        Algorithm::EdDSA => {
                            let pk = ed25519_dalek::VerifyingKey::from_public_key_pem(pem)
                                .map_err(|_| auth_failure("invalid EdDSA key"))?;
                            serde_json::json!({
                                "kty": "OKP",
                                "use": "sig",
                                "alg": "EdDSA",
                                "kid": kid,
                                "crv": "Ed25519",
                                "x": URL_SAFE_NO_PAD.encode(pk.to_bytes()),
                            })
                        }
                        _ => continue,
                    };
                    keys.push(jwk);
                }
            }
        }

        Ok(serde_json::json!({
            "keys": keys
        }))
    }
}

fn build_auth_context(
    claims: Claims,
    remote_addr: Option<IpAddr>,
) -> Result<AuthContext, AppError> {
    let roles = claims
        .roles
        .into_iter()
        .map(|role| Role::from_str(&role).map_err(|_| auth_failure("unrecognized role")))
        .collect::<Result<Vec<_>, _>>()?;

    if roles.is_empty() {
        return Err(auth_failure("no roles available"));
    }

    let session_id = if let Some(sid) = claims.sid {
        Uuid::parse_str(&sid).map_err(|_| auth_failure("invalid session id"))?
    } else {
        Uuid::new_v4()
    };

    let source_ip = claims.rip.or_else(|| remote_addr.map(|ip| ip.to_string()));

    Ok(AuthContext {
        actor_id: claims.sub,
        session_id,
        roles,
        client_fingerprint: claims.fp,
        source_ip,
    })
}

fn auth_failure(message: impl Into<String>) -> AppError {
    metrics::counter!("ferrohsm_auth_jwt_failure_total").increment(1);
    AppError::unauthorized(message)
}

struct AuthState {
    source: ConfigSource,
    runtime: RwLock<RuntimeConfig>,
}

impl AuthState {
    fn refresh_if_needed(&self) {
        let ConfigSource::File(handle) = &self.source else {
            return;
        };

        let mut source = handle.lock();
        if source.last_checked.elapsed() < source.reload_interval {
            return;
        }
        source.last_checked = Instant::now();

        match fs::metadata(&source.path) {
            Ok(meta) => {
                let modified = meta.modified().ok();
                let should_reload = match (source.last_modified, modified) {
                    (None, Some(_)) => true,
                    (Some(old), Some(newer)) if newer > old => true,
                    _ => false,
                };

                if should_reload {
                    match load_config(&source.path).and_then(|cfg| RuntimeConfig::try_from(&cfg)) {
                        Ok(runtime) => {
                            *self.runtime.write() = runtime;
                            source.last_modified = modified;
                        }
                        Err(err) => warn!("failed to reload JWT config: {err}"),
                    }
                }
            }
            Err(err) => warn!("failed to stat JWT config: {err}"),
        }
    }
}

enum ConfigSource {
    Static,
    File(parking_lot::Mutex<FileSource>),
}

struct FileSource {
    path: PathBuf,
    reload_interval: Duration,
    last_checked: Instant,
    last_modified: Option<SystemTime>,
}

struct RuntimeConfig {
    validation: Validation,
    keys: HashMap<Algorithm, Vec<Arc<DecodingKey>>>,
    kids: HashMap<Algorithm, Vec<Option<String>>>,
    public_keys: HashMap<Algorithm, Vec<Option<String>>>,
}

impl RuntimeConfig {
    fn from_shared_secret(secret: &str, issuer: Option<String>) -> anyhow::Result<Self> {
        let secret_bytes = STANDARD
            .decode(secret)
            .unwrap_or_else(|_| secret.as_bytes().to_vec());
        if secret_bytes.len() < MIN_HS256_KEY_LEN {
            anyhow::bail!("JWT secret must be at least {MIN_HS256_KEY_LEN} bytes after decoding");
        }
        let key = DecodingKey::from_secret(&secret_bytes);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        if let Some(iss) = issuer {
            validation.set_issuer(&[iss]);
        }
        let mut keys = HashMap::new();
        keys.insert(Algorithm::HS256, vec![Arc::new(key)]);
        let mut kids = HashMap::new();
        kids.insert(Algorithm::HS256, vec![None]);
        let mut public_keys = HashMap::new();
        public_keys.insert(Algorithm::HS256, vec![None]);

        Ok(Self {
            validation,
            keys,
            kids,
            public_keys,
        })
    }

    fn select_keys(&self, alg: Algorithm, kid: Option<&str>) -> Vec<Arc<DecodingKey>> {
        let keys = match self.keys.get(&alg) {
            Some(keys) => keys,
            None => return Vec::new(),
        };
        let kids = self.kids.get(&alg).unwrap();

        if let Some(kid) = kid {
            kids.iter()
                .zip(keys.iter())
                .filter_map(|(entry_kid, key)| {
                    if entry_kid.as_deref() == Some(kid) {
                        Some(Arc::clone(key))
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            keys.iter().map(Arc::clone).collect()
        }
    }
}

fn derive_throttle_key(
    algorithm: Algorithm,
    subject: &str,
    remote_addr: Option<IpAddr>,
    token: &str,
) -> String {
    match algorithm {
        Algorithm::HS256 => remote_addr
            .map(|ip| format!("addr:{ip}"))
            .unwrap_or_else(|| {
                let mut hasher = Sha256::new();
                hasher.update(token.as_bytes());
                format!("token:{}", hex::encode(hasher.finalize()))
            }),
        Algorithm::RS256 | Algorithm::ES256 | Algorithm::EdDSA => format!("sub:{subject}"),
        _ => {
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            format!("token:{}", hex::encode(hasher.finalize()))
        }
    }
}

impl TryFrom<&JwtConfig> for RuntimeConfig {
    type Error = anyhow::Error;

    fn try_from(value: &JwtConfig) -> Result<Self, Self::Error> {
        let mut all_keys = HashMap::new();
        let mut all_kids = HashMap::new();
        let mut all_public_keys = HashMap::new();

        for alg_config in &value.algorithms {
            let algorithm = alg_config.algorithm.into();
            let mut keys = Vec::new();
            let mut kids = Vec::new();
            let mut public_keys = Vec::new();

            for key_cfg in &alg_config.keys {
                let decoding = match algorithm {
                    Algorithm::HS256 => {
                        let secret = key_cfg
                            .secret
                            .as_deref()
                            .ok_or_else(|| anyhow::anyhow!("HS256 keys require 'secret' field"))?;
                        let bytes = STANDARD
                            .decode(secret)
                            .unwrap_or_else(|_| secret.as_bytes().to_vec());
                        if bytes.len() < MIN_HS256_KEY_LEN {
                            anyhow::bail!(
                                "JWT secret must be at least {MIN_HS256_KEY_LEN} bytes after decoding"
                            );
                        }
                        DecodingKey::from_secret(&bytes)
                    }
                    Algorithm::RS256 => {
                        let pem = key_cfg.public_key_pem.as_deref().ok_or_else(|| {
                            anyhow::anyhow!("RS256 keys require 'public_key_pem' field")
                        })?;
                        DecodingKey::from_rsa_pem(pem.as_bytes())?
                    }
                    Algorithm::ES256 => {
                        let pem = key_cfg.public_key_pem.as_deref().ok_or_else(|| {
                            anyhow::anyhow!("ES256 keys require 'public_key_pem' field")
                        })?;
                        DecodingKey::from_ec_pem(pem.as_bytes())?
                    }
                    Algorithm::EdDSA => {
                        let pem = key_cfg.public_key_pem.as_deref().ok_or_else(|| {
                            anyhow::anyhow!("EdDSA keys require 'public_key_pem' field")
                        })?;
                        DecodingKey::from_ed_pem(pem.as_bytes())?
                    }
                    other => anyhow::bail!("unsupported algorithm {other:?}"),
                };
                keys.push(Arc::new(decoding));
                kids.push(key_cfg.kid.clone());
                public_keys.push(key_cfg.public_key_pem.clone());
            }

            if keys.is_empty() {
                anyhow::bail!(
                    "JWT configuration for algorithm {:?} must include at least one key",
                    algorithm
                );
            }

            all_keys.insert(algorithm, keys);
            all_kids.insert(algorithm, kids);
            all_public_keys.insert(algorithm, public_keys);
        }

        if all_keys.is_empty() {
            anyhow::bail!("JWT configuration must include at least one algorithm");
        }

        let mut validation = Validation::default();
        validation.validate_exp = true;
        if let Some(issuer) = &value.issuer {
            validation.set_issuer(std::slice::from_ref(issuer));
        }
        validation.leeway = value.leeway_seconds;

        Ok(Self {
            validation,
            keys: all_keys,
            kids: all_kids,
            public_keys: all_public_keys,
        })
    }
}

#[derive(Debug, Deserialize)]
struct JwtConfig {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default = "default_leeway")]
    leeway_seconds: u64,
    algorithms: Vec<JwtAlgorithmConfig>,
}

#[derive(Debug, Deserialize)]
struct JwtAlgorithmConfig {
    algorithm: AlgorithmChoice,
    keys: Vec<JwtKey>,
}

#[derive(Debug, Deserialize)]
struct JwtKey {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    public_key_pem: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum AlgorithmChoice {
    HS256,
    RS256,
    ES256,
    EdDSA,
}

impl From<AlgorithmChoice> for Algorithm {
    fn from(value: AlgorithmChoice) -> Self {
        match value {
            AlgorithmChoice::HS256 => Algorithm::HS256,
            AlgorithmChoice::RS256 => Algorithm::RS256,
            AlgorithmChoice::ES256 => Algorithm::ES256,
            AlgorithmChoice::EdDSA => Algorithm::EdDSA,
        }
    }
}

fn default_leeway() -> u64 {
    60
}

fn load_config(path: &Path) -> anyhow::Result<JwtConfig> {
    let data = fs::read_to_string(path)?;
    let config: JwtConfig = serde_json::from_str(&data)
        .or_else(|_| serde_yaml::from_str(&data))
        .map_err(|err| anyhow::anyhow!("failed to parse JWT config: {err}"))?;
    Ok(config)
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    roles: Vec<String>,
    #[allow(dead_code)]
    exp: usize,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    iss: Option<String>,
    #[serde(default)]
    fp: Option<String>,
    #[serde(default)]
    rip: Option<String>,
}
