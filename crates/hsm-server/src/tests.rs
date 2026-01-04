#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use std::sync::Arc;
    use std::time::Instant;
    use crate::{AppState, create_router, AuditView, RateLimiter, KeyCache};
    use hsm_core::{
        KeyManager, storage::FileKeyStore, FileAuditLog, DefaultPolicyEngine,
        RbacAuthorizer, FileApprovalStore, KeyStore, AuditLog,
    };
    use crate::auth::AuthVerifier;
    use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
    use tempfile::{tempdir, TempDir};
    use std::sync::OnceLock;

    static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

    fn get_metrics_handle() -> PrometheusHandle {
        METRICS_HANDLE.get_or_init(|| {
            PrometheusBuilder::new().install_recorder().unwrap()
        }).clone()
    }

    async fn setup_test_app() -> (axum::Router, TempDir) {
        let tmp = tempdir().unwrap();
        let key_dir = tmp.path().join("keys");
        let audit_log_path = tmp.path().join("audit.log");
        let approval_dir = tmp.path().join("approvals");
        std::fs::create_dir_all(&key_dir).unwrap();
        std::fs::create_dir_all(&approval_dir).unwrap();

        let storage = Arc::new(FileKeyStore::new(&key_dir).unwrap());
        let audit_log = Arc::new(FileAuditLog::new(&audit_log_path).unwrap());
        let approval_store = Arc::new(FileApprovalStore::new(&approval_dir).unwrap());
        
        let policy = DefaultPolicyEngine::new(
            RbacAuthorizer::default(),
            std::collections::HashSet::new(),
            approval_store,
        );
        
        let master_key = [0u8; 32];
        let hmac_key = [0u8; 32];
        
        let manager: Arc<KeyManager<dyn KeyStore, dyn AuditLog, _>> = Arc::new(KeyManager::new(
            storage as Arc<dyn KeyStore>,
            audit_log.clone() as Arc<dyn AuditLog>,
            policy,
            master_key,
            hmac_key,
        ));
        
        let templates = Arc::new(tera::Tera::new("../../web/templates/**/*").unwrap());
        let auth = Arc::new(AuthVerifier::from_secret("test-secret-must-be-at-least-32-bytes-long-for-hmac", None).unwrap());
        let rate_limiter = Arc::new(RateLimiter::new(100, 200));
        let key_cache = Arc::new(KeyCache::new(std::time::Duration::from_secs(5)));
        let metrics_handle = get_metrics_handle();
        
        let state = AppState {
            manager,
            templates,
            auth,
            rate_limiter,
            key_cache,
            audit_view: AuditView::File(audit_log),
            metrics_handle,
            startup: Instant::now(),
        };
        
        (create_router(state, std::path::PathBuf::from("../../web/static")), tmp)
    }

    #[tokio::test]
    async fn test_static_file_serving() {
        let (app, _tmp) = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/static/styles.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/css"
        );
    }

    #[tokio::test]
    async fn test_dashboard_rendering() {
        let (app, _tmp) = setup_test_app().await;

        // Generate a token
        let secret = "test-secret-must-be-at-least-32-bytes-long-for-hmac";
        let claims = serde_json::json!({
            "sub": "test-user",
            "roles": ["Administrator"],
            "exp": 2000000000,
        });
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ui")
                    .header("Authorization", format!("Bearer {}", token))
                    .extension(axum::extract::connect_info::ConnectInfo(
                        "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        if status != StatusCode::OK {
            let body_bytes = axum::body::to_bytes(response.into_body(), 10000).await.unwrap();
            panic!("Request failed with status {} and body: {:?}", status, String::from_utf8_lossy(&body_bytes));
        }
    }
}