use crate::{Args, TlsMode};
use anyhow::{Context, Result, anyhow, bail};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures::StreamExt;
use hex::encode as hex_encode;
use num_bigint::BigUint;
use parking_lot::RwLock;
use reqwest::Client;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls_acme::AcmeConfig;
use rustls_acme::acme::ACME_TLS_ALPN_NAME;
use rustls_acme::acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY};
use rustls_acme::caches::DirCache;
use rustls_acme::is_tls_alpn_challenge;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use std::fs::File;
use std::io::{BufReader, Cursor, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::time::{self, MissedTickBehavior};
use tracing::{error, info, warn};
use x509_parser::extensions::GeneralName;
use x509_parser::extensions::{AccessDescription, ParsedExtension};
use x509_parser::parse_x509_certificate;
use yasna::models::ObjectIdentifier;

#[derive(Debug)]
pub enum TlsSetup {
    Manual(RustlsConfig),
    Acme {
        acceptor: axum_server::tls_rustls::RustlsAcceptor<rustls_acme::axum::AxumAcceptor>,
    },
}

#[derive(Clone)]
struct ManualTlsConfig {
    cert_path: PathBuf,
    key_path: PathBuf,
    client_ca: Option<PathBuf>,
    ocsp_path: Option<PathBuf>,
    cert_reload: Option<Duration>,
    ocsp_reload: Option<Duration>,
    http_client: Client,
}

#[derive(Clone)]
struct LoadedKey {
    certified: Arc<CertifiedKey>,
    fingerprint: Vec<u8>,
    ocsp: Option<Vec<u8>>,
}

#[derive(Debug)]
struct ManualCertResolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

impl ManualCertResolver {
    fn new(initial: Option<Arc<CertifiedKey>>) -> Self {
        Self {
            current: RwLock::new(initial),
        }
    }

    fn replace(&self, next: Arc<CertifiedKey>) {
        *self.current.write() = Some(next);
    }

    fn current(&self) -> Option<Arc<CertifiedKey>> {
        self.current.read().clone()
    }
}

impl ResolvesServerCert for ManualCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().clone()
    }
}

#[derive(Debug)]
struct HybridAcmeResolver {
    acme: Arc<dyn ResolvesServerCert + Send + Sync>,
    manual: Arc<ManualCertResolver>,
}

impl HybridAcmeResolver {
    fn new(
        acme: Arc<dyn ResolvesServerCert + Send + Sync>,
        manual: Arc<ManualCertResolver>,
    ) -> Self {
        Self { acme, manual }
    }
}

impl ResolvesServerCert for HybridAcmeResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if !is_tls_alpn_challenge(&client_hello)
            && let Some(cert) = self.manual.current()
        {
            return Some(cert);
        }
        self.acme.resolve(client_hello)
    }
}

pub async fn configure(args: &Args) -> Result<TlsSetup> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    match args.tls_mode {
        TlsMode::Manual => configure_manual(args).await,
        TlsMode::Acme => configure_acme(args).await,
    }
}

async fn configure_manual(args: &Args) -> Result<TlsSetup> {
    let cert_path = args
        .cert
        .clone()
        .ok_or_else(|| anyhow!("--cert is required when --tls-mode=manual"))?;
    let key_path = args
        .key
        .clone()
        .ok_or_else(|| anyhow!("--key is required when --tls-mode=manual"))?;

    let http_client = build_http_client()?;

    let manual = ManualTlsConfig {
        cert_path,
        key_path,
        client_ca: args.client_ca.clone(),
        ocsp_path: args.ocsp_response.clone(),
        cert_reload: interval_from_secs(args.cert_reload_interval_secs),
        ocsp_reload: interval_from_secs(args.ocsp_refresh_interval_secs),
        http_client,
    };

    let initial = load_certified_key(&manual).await?;
    let resolver = Arc::new(ManualCertResolver::new(Some(initial.certified.clone())));

    let builder = rustls::ServerConfig::builder();
    let builder = if let Some(ca_path) = &manual.client_ca {
        let roots = load_client_ca(ca_path)?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| anyhow!("failed to build client certificate verifier: {e}"))?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };

    let mut server_config = builder.with_cert_resolver(resolver.clone());
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let server_config = Arc::new(server_config);
    let rustls_config = RustlsConfig::from_config(server_config.clone());

    spawn_manual_reload(resolver, manual, initial);

    Ok(TlsSetup::Manual(rustls_config))
}

async fn configure_acme(args: &Args) -> Result<TlsSetup> {
    if args.acme_domains.is_empty() {
        return Err(anyhow!(
            "at least one --acme-domain must be provided when --tls-mode=acme"
        ));
    }

    std::fs::create_dir_all(&args.acme_cache_dir).with_context(|| {
        format!(
            "failed to create ACME cache directory: {}",
            args.acme_cache_dir.display()
        )
    })?;

    let directory_url = args.acme_directory_url.clone().unwrap_or_else(|| {
        if args.acme_use_production {
            LETS_ENCRYPT_PRODUCTION_DIRECTORY.to_string()
        } else {
            LETS_ENCRYPT_STAGING_DIRECTORY.to_string()
        }
    });

    let http_client = build_http_client()?;

    let contacts = args
        .acme_contacts
        .iter()
        .map(|c| ensure_mailto(c))
        .collect::<Vec<_>>();

    let mut config = AcmeConfig::new(args.acme_domains.iter().map(String::as_str))
        .directory(directory_url.as_str());

    if !contacts.is_empty() {
        config = config.contact(contacts.iter().map(|s| s.as_str()));
    }

    let config = config.cache(DirCache::new(args.acme_cache_dir.clone()));

    let cache_dir = Arc::new(args.acme_cache_dir.clone());
    let domains = Arc::new(args.acme_domains.clone());

    let state = config.state();
    let acme_resolver: Arc<dyn ResolvesServerCert + Send + Sync> = state.resolver();
    let manual_resolver = Arc::new(ManualCertResolver::new(None));
    let shared_loaded = Arc::new(RwLock::new(None::<LoadedKey>));

    if let Some(initial) = load_cached_acme_cert(
        cache_dir.as_ref(),
        domains.as_ref(),
        &directory_url,
        &http_client,
    )
    .await?
    {
        manual_resolver.replace(initial.certified.clone());
        info!(
            fingerprint = %hex_encode(&initial.fingerprint),
            "loaded cached ACME certificate"
        );
        *shared_loaded.write() = Some(initial);
    }

    let hybrid_resolver: Arc<dyn ResolvesServerCert + Send + Sync> = Arc::new(
        HybridAcmeResolver::new(acme_resolver.clone(), manual_resolver.clone()),
    );
    let builder = rustls::ServerConfig::builder();
    let mut server_config = builder
        .with_no_client_auth()
        .with_cert_resolver(hybrid_resolver);
    server_config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        ACME_TLS_ALPN_NAME.to_vec(),
    ];

    let server_config = Arc::new(server_config);
    let rustls_config = RustlsConfig::from_config(server_config.clone());
    let acme_acceptor = state.axum_acceptor(server_config);
    let acceptor =
        axum_server::tls_rustls::RustlsAcceptor::new(rustls_config.clone()).acceptor(acme_acceptor);

    {
        let cache_dir = cache_dir.clone();
        let domains = domains.clone();
        let directory_url = directory_url.clone();
        let http_client = http_client.clone();
        let manual_resolver = manual_resolver.clone();
        let shared_loaded = shared_loaded.clone();
        tokio::spawn(async move {
            let mut state_stream = state;
            while let Some(event) = state_stream.next().await {
                match event {
                    Ok(ok) => {
                        if matches!(
                            ok,
                            rustls_acme::EventOk::DeployedCachedCert
                                | rustls_acme::EventOk::DeployedNewCert
                        ) {
                            match load_cached_acme_cert(
                                cache_dir.as_ref(),
                                domains.as_ref(),
                                &directory_url,
                                &http_client,
                            )
                            .await
                            {
                                Ok(Some(next)) => {
                                    apply_loaded_key(
                                        &manual_resolver,
                                        &shared_loaded,
                                        next,
                                        "acme",
                                    );
                                }
                                Ok(None) => {}
                                Err(err) => warn!(?err, "failed to reload ACME certificate"),
                            }
                        }
                        info!(?ok, "ACME event");
                    }
                    Err(err) => warn!(?err, "ACME error"),
                }
            }
        });
    }

    if let Some(interval) = interval_from_secs(args.ocsp_refresh_interval_secs) {
        let cache_dir = cache_dir.clone();
        let domains = domains.clone();
        let directory_url = directory_url.clone();
        let http_client = http_client.clone();
        let manual_resolver = manual_resolver.clone();
        let shared_loaded = shared_loaded.clone();
        tokio::spawn(async move {
            let mut ticker = time::interval(interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                match load_cached_acme_cert(
                    cache_dir.as_ref(),
                    domains.as_ref(),
                    &directory_url,
                    &http_client,
                )
                .await
                {
                    Ok(Some(next)) => {
                        apply_loaded_key(&manual_resolver, &shared_loaded, next, "acme");
                    }
                    Ok(None) => {}
                    Err(err) => warn!(?err, "failed to refresh ACME OCSP staple"),
                }
            }
        });
    }

    Ok(TlsSetup::Acme { acceptor })
}

fn interval_from_secs(value: u64) -> Option<Duration> {
    if value == 0 {
        None
    } else {
        Some(Duration::from_secs(value))
    }
}

fn ensure_mailto(contact: &str) -> String {
    if contact.starts_with("mailto:") {
        contact.to_string()
    } else {
        format!("mailto:{contact}")
    }
}

fn load_client_ca(path: &Path) -> Result<rustls::RootCertStore> {
    let file = File::open(path)
        .with_context(|| format!("failed to open client CA bundle: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("failed to read client CA bundle: {e}"))?;
    if certs.is_empty() {
        return Err(anyhow!(
            "client CA bundle {} did not contain any certificates",
            path.display()
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!(
            "failed to parse any certificates from client CA bundle {}",
            path.display()
        ));
    }
    Ok(roots)
}

async fn load_certified_key(config: &ManualTlsConfig) -> Result<LoadedKey> {
    let cert_chain = read_cert_chain(&config.cert_path)?;
    let private_key = read_private_key(&config.key_path)?;

    let signing_key = any_supported_type(&private_key).map_err(|_| {
        anyhow!(
            "unsupported private key format in {}",
            config.key_path.display()
        )
    })?;
    let mut certified = CertifiedKey::new(cert_chain.clone(), signing_key);

    let ocsp = match &config.ocsp_path {
        Some(path) => match std::fs::read(path) {
            Ok(bytes) if bytes.is_empty() => None,
            Ok(bytes) => Some(bytes),
            Err(err) => {
                warn!(
                    ?err,
                    path = %path.display(),
                    "failed to read OCSP staple; continuing without"
                );
                maybe_fetch_ocsp("manual", &config.http_client, &cert_chain).await
            }
        },
        None => maybe_fetch_ocsp("manual", &config.http_client, &cert_chain).await,
    };
    certified.ocsp = ocsp.clone();

    let fingerprint = Sha256::digest(cert_chain[0].as_ref()).to_vec();
    info!(fingerprint = %hex_encode(&fingerprint), "loaded TLS certificate");

    Ok(LoadedKey {
        certified: Arc::new(certified),
        fingerprint,
        ocsp,
    })
}

fn read_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open certificate file: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("failed to parse certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err(anyhow!(
            "certificate file {} contained no certificates",
            path.display()
        ));
    }
    Ok(certs)
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open private key file: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    match rustls_pemfile::private_key(&mut reader)
        .map_err(|e| anyhow!("failed to parse private key PEM: {e}"))?
    {
        Some(key) => Ok(key),
        None => Err(anyhow!("no private key found in {}", path.display())),
    }
}

fn spawn_manual_reload(
    resolver: Arc<ManualCertResolver>,
    config: ManualTlsConfig,
    initial: LoadedKey,
) {
    if config.cert_reload.is_none() && config.ocsp_reload.is_none() {
        return;
    }

    let period = match (config.cert_reload, config.ocsp_reload) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return,
    };

    tokio::spawn(async move {
        let mut ticker = time::interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut last_fingerprint = initial.fingerprint;
        let mut last_ocsp = initial.ocsp;

        loop {
            ticker.tick().await;
            match load_certified_key(&config).await {
                Ok(next) => {
                    let LoadedKey {
                        certified,
                        fingerprint,
                        ocsp,
                    } = next;
                    let changed_cert = fingerprint.as_slice() != last_fingerprint.as_slice();
                    let changed_ocsp = ocsp.as_deref() != last_ocsp.as_deref();
                    if changed_cert || changed_ocsp {
                        resolver.replace(certified);
                        last_fingerprint = fingerprint;
                        last_ocsp = ocsp;
                        info!(
                            fingerprint = %hex_encode(&last_fingerprint),
                            changed_cert,
                            changed_ocsp,
                            "reloaded TLS certificate material"
                        );
                    }
                }
                Err(err) => error!(?err, "failed to reload TLS certificate"),
            }
        }
    });
}

fn build_http_client() -> Result<Client> {
    Client::builder()
        .user_agent("ferrohsm/ocsp")
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build HTTP client for OCSP operations")
}

fn apply_loaded_key(
    resolver: &Arc<ManualCertResolver>,
    store: &Arc<RwLock<Option<LoadedKey>>>,
    next: LoadedKey,
    label: &str,
) {
    let mut guard = store.write();
    let (changed_cert, changed_ocsp) = match guard.as_ref() {
        Some(current) => (
            current.fingerprint != next.fingerprint,
            current.ocsp.as_deref() != next.ocsp.as_deref(),
        ),
        None => (true, next.ocsp.is_some()),
    };

    if changed_cert || changed_ocsp {
        resolver.replace(next.certified.clone());
        info!(
            fingerprint = %hex_encode(&next.fingerprint),
            changed_cert,
            changed_ocsp,
            source = %label,
            "updated TLS certificate material"
        );
        *guard = Some(next);
    }
}

fn acme_cached_cert_path(cache_dir: &Path, domains: &[String], directory_url: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    for domain in domains {
        hasher.update(domain.as_bytes());
        hasher.update([0]);
    }
    hasher.update(directory_url.as_bytes());
    let hash = URL_SAFE_NO_PAD.encode(hasher.finalize());
    cache_dir.join(format!("cached_cert_{}", hash))
}

async fn load_cached_acme_cert(
    cache_dir: &Path,
    domains: &[String],
    directory_url: &str,
    client: &Client,
) -> Result<Option<LoadedKey>> {
    let path = acme_cached_cert_path(cache_dir, domains, directory_url);
    let pem_bytes = match fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow!(
                "failed to read cached ACME certificate {}: {err}",
                path.display()
            ));
        }
    };

    let mut cursor = Cursor::new(pem_bytes.as_slice());
    let items = rustls_pemfile::read_all(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("failed to parse cached ACME PEM data: {e}"))?;

    let mut private_key: Option<PrivateKeyDer<'static>> = None;
    let mut cert_chain: Vec<CertificateDer<'static>> = Vec::new();

    for item in items {
        match item {
            rustls_pemfile::Item::Pkcs1Key(key) => private_key = Some(key.into()),
            rustls_pemfile::Item::Pkcs8Key(key) => private_key = Some(key.into()),
            rustls_pemfile::Item::Sec1Key(key) => private_key = Some(key.into()),
            rustls_pemfile::Item::X509Certificate(cert) => cert_chain.push(cert),
            _ => {}
        }
    }

    let private_key = match private_key {
        Some(key) => key,
        None => {
            warn!(path = %path.display(), "cached ACME material did not include a private key");
            return Ok(None);
        }
    };

    if cert_chain.is_empty() {
        warn!(path = %path.display(), "cached ACME certificate missing leaf certificate");
        return Ok(None);
    }

    let signing_key = any_supported_type(&private_key)
        .map_err(|_| anyhow!("unsupported private key format in cached ACME material"))?;

    let ocsp = maybe_fetch_ocsp("acme", client, &cert_chain).await;

    let mut certified = CertifiedKey::new(cert_chain.clone(), signing_key);
    certified.ocsp = ocsp.clone();

    let fingerprint = Sha256::digest(cert_chain[0].as_ref()).to_vec();

    Ok(Some(LoadedKey {
        certified: Arc::new(certified),
        fingerprint,
        ocsp,
    }))
}

async fn maybe_fetch_ocsp(
    label: &str,
    client: &Client,
    cert_chain: &[CertificateDer<'static>],
) -> Option<Vec<u8>> {
    match fetch_ocsp_response(client, cert_chain).await {
        Ok(Some(bytes)) => Some(bytes),
        Ok(None) => None,
        Err(err) => {
            warn!(?err, source = %label, "failed to obtain OCSP response");
            None
        }
    }
}

async fn fetch_ocsp_response(
    client: &Client,
    cert_chain: &[CertificateDer<'static>],
) -> Result<Option<Vec<u8>>> {
    if cert_chain.len() < 2 {
        return Ok(None);
    }

    let leaf_der = cert_chain[0].as_ref();
    let issuer_der = cert_chain[1].as_ref();

    let (_, leaf) = parse_x509_certificate(leaf_der)
        .map_err(|err| anyhow!("failed to parse leaf certificate for OCSP: {err}"))?;
    let (_, issuer) = parse_x509_certificate(issuer_der)
        .map_err(|err| anyhow!("failed to parse issuer certificate for OCSP: {err}"))?;

    let ocsp_url = match extract_ocsp_url(&leaf) {
        Some(url) => url,
        None => return Ok(None),
    };

    let issuer_name = leaf.tbs_certificate.issuer.as_raw();
    let issuer_key = issuer
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref();
    let serial = leaf.tbs_certificate.serial.clone();

    let request_der = build_ocsp_request(issuer_name, issuer_key, &serial)?;

    let response = client
        .post(&ocsp_url)
        .header("Content-Type", "application/ocsp-request")
        .header("Accept", "application/ocsp-response")
        .body(request_der)
        .send()
        .await
        .with_context(|| format!("failed to contact OCSP responder {ocsp_url}"))?;

    if !response.status().is_success() {
        bail!(
            "OCSP responder {} returned status {}",
            ocsp_url,
            response.status()
        );
    }

    let body = response
        .bytes()
        .await
        .context("failed to read OCSP response body")?;

    if body.is_empty() {
        bail!("OCSP responder {} returned empty response", ocsp_url);
    }

    Ok(Some(body.to_vec()))
}

fn extract_ocsp_url(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<String> {
    const OCSP_METHOD_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    for ext in cert.tbs_certificate.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for AccessDescription {
                access_method,
                access_location,
            } in &aia.accessdescs
            {
                if access_method.as_bytes() == OCSP_METHOD_OID
                    && let GeneralName::URI(uri) = access_location
                {
                    return Some((*uri).to_string());
                }
            }
        }
    }
    None
}

fn build_ocsp_request(issuer_name: &[u8], issuer_key: &[u8], serial: &BigUint) -> Result<Vec<u8>> {
    let issuer_name_hash = Sha1::digest(issuer_name).to_vec();
    let issuer_key_hash = Sha1::digest(issuer_key).to_vec();
    let serial = serial.clone();
    let sha1_oid = ObjectIdentifier::from_slice(&[1, 3, 14, 3, 2, 26]);

    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer.next().write_sequence_of(|writer| {
                    writer.next().write_sequence(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&sha1_oid);
                            writer.next().write_null();
                        });
                        writer.next().write_bytes(&issuer_name_hash);
                        writer.next().write_bytes(&issuer_key_hash);
                        writer.next().write_biguint(&serial);
                    });
                });
            });
        });
    });

    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::tempdir;

    #[tokio::test]
    async fn manual_tls_requires_cert_and_key() {
        let args = Args::parse_from(["hsm-server", "--tls-mode", "manual"]);
        let err = configure(&args)
            .await
            .expect_err("expected missing cert error");
        assert!(err.to_string().contains("--cert"));
    }

    #[cfg_attr(
        target_os = "macos",
        ignore = "SystemConfiguration dynamic store unavailable in macOS test sandbox"
    )]
    #[tokio::test]
    async fn manual_tls_loads_self_signed_certificate() {
        let dir = tempdir().expect("Failed to create temp directory");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        let certified = rcgen::generate_simple_self_signed(["localhost".into()])
            .expect("Failed to generate self-signed certificate");
        std::fs::write(&cert_path, certified.cert.pem()).expect("Failed to write certificate file");
        std::fs::write(&key_path, certified.key_pair.serialize_pem())
            .expect("Failed to write private key file");

        let args = Args::parse_from([
            "hsm-server",
            "--tls-mode",
            "manual",
            "--cert",
            cert_path.to_str().expect("Invalid cert path"),
            "--key",
            key_path.to_str().expect("Invalid key path"),
            "--cert-reload-interval-secs",
            "0",
            "--ocsp-refresh-interval-secs",
            "0",
        ]);

        match configure(&args).await {
            Ok(TlsSetup::Manual(_)) => {}
            other => panic!("unexpected TLS setup: {other:?}"),
        }
    }

    #[tokio::test]
    async fn acme_mode_requires_domain() {
        let args = Args::parse_from(["hsm-server", "--tls-mode", "acme"]);
        let err = configure(&args)
            .await
            .expect_err("expected acme domain error");
        assert!(err.to_string().contains("--acme-domain"));
    }
}
