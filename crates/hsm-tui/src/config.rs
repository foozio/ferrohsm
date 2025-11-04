//! Configuration management for FerroHSM TUI
//!
//! Provides theme and key binding configuration with persistence.

use crate::ui::style::Theme;
use crate::ui::input::KeyBindings;
use anyhow::Result;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// UI theme
    pub theme: Theme,
    /// Key bindings
    pub key_bindings: KeyBindings,
    /// Default page size for lists
    pub default_page_size: usize,
    /// Auto-refresh interval in seconds (0 = disabled)
    pub auto_refresh_interval: u64,
    /// Enable vim key bindings
    pub vim_mode: bool,
    /// Authentication settings
    pub auth: AuthConfig,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// JWT authentication token
    pub token: Option<String>,
    /// Server endpoint URL
    pub server_endpoint: String,
    /// Path to client certificate for mTLS
    pub client_cert_path: Option<String>,
    /// Path to client private key for mTLS
    pub client_key_path: Option<String>,
    /// Path to CA bundle
    pub ca_bundle_path: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            theme: Theme::default(),
            key_bindings: KeyBindings::default(),
            default_page_size: 50,
            auto_refresh_interval: 30,
            vim_mode: false,
            auth: AuthConfig::default(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token: None,
            server_endpoint: "https://localhost:8443".to_string(),
            client_cert_path: None,
            client_key_path: None,
            ca_bundle_path: None,
        }
    }
}

impl AppConfig {
    /// Load configuration from disk
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path();
        if config_path.exists() {
            let content = fs::read_to_string(config_path)?;
            let config: AppConfig = toml::from_str(&content)?;
            Ok(config)
        } else {
            let config = Self::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Save configuration to disk
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path();
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        fs::write(config_path, content)?;
        Ok(())
    }

    /// Get the configuration file path
    fn config_path() -> PathBuf {
        ProjectDirs::from("com", "ferrohsm", "tui")
            .map(|dirs| dirs.config_dir().join("config.toml"))
            .unwrap_or_else(|| PathBuf::from("config.toml"))
    }
}