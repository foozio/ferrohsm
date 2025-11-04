mod api;
mod config;
mod error;
mod event;
mod ui;

use crate::api::{ApiClient, KeySummary, ApprovalResponse, PaginatedKeys, KeyListQuery, CreateKeyRequest, PaginatedAuditLogs, AuditLogQuery};
use crate::config::AppConfig;
use crate::error::{AppError, ErrorDisplay};
use crate::event::{EventLoop, EventResult};
use crate::ui::components::{Footer, Header, HelpPanel, MainMenu};
use crate::ui::input::KeyAction;
use crate::ui::layout::app_layout;
use crate::ui::widgets::{ErrorDialog, LoadingSpinner};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use axum::http::StatusCode;
use clap::Parser;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{prelude::*, widgets::{Block, Borders, Paragraph, Table, Row, Cell}};
use std::{io, panic};

/// FerroHSM TUI - Text-based User Interface for FerroHSM
#[derive(Parser)]
#[command(name = "hsm-tui", version)]
struct Cli {
    /// Server endpoint
    #[clap(long, default_value = "https://localhost:8443")]
    endpoint: String,

    /// Client certificate for mutual TLS
    #[clap(long)]
    client_cert: Option<String>,

    /// Client private key for mutual TLS
    #[clap(long)]
    client_key: Option<String>,

    /// Custom CA bundle
    #[clap(long)]
    ca_bundle: Option<String>,

    /// Configuration file path
    #[clap(long)]
    config: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum AppMode {
    MainMenu,
    KeysList,
    KeysListSearch,
    KeyDetails,
    KeyCreate,
    KeyCreateAlgorithm,
    KeyCreateUsage,
    KeyCreatePolicy,
    KeyCreateDescription,
    KeyCreateConfirm,
    KeyOperations,
    ApprovalsList,
    AuditViewer,
    Settings,
    SettingsAuth,
    Help,
    Loading,
    Error,
}

#[derive(Debug)]
struct AppState {
    mode: AppMode,
    quit: bool,
    main_menu: MainMenu,
    help_panel: HelpPanel,
    error: Option<AppError>,
    loading_message: Option<String>,
    config: AppConfig,
    keys_search: String,
    selected_key_index: usize,
    current_page: u32,
    api_client: ApiClient,
    // Cached data
    keys: Option<PaginatedKeys>,
    approvals: Option<Vec<ApprovalResponse>>,
    audit_logs: Option<PaginatedAuditLogs>,
    selected_key: Option<KeySummary>,
    user_info: Option<crate::api::UserInfo>,
    selected_approval_index: usize,
    selected_audit_index: usize,
    audit_page: u32,
    // Input fields
    auth_token_input: String,
    // Crypto operation fields
    crypto_operation: Option<String>,
    crypto_key_id: String,
    crypto_data: String,
    crypto_result: Option<String>,
    // Key creation form
    key_create_algorithm: Option<KeyAlgorithm>,
    key_create_usage: Vec<hsm_core::KeyPurpose>,
    key_create_policy_input: String,
    key_create_policy_tags: Vec<String>,
    key_create_description: String,
}

impl AppState {
    fn new(config: AppConfig, cli: &Cli) -> Result<AppState> {
        let menu_items = vec![
            "🔑 Key Management".to_string(),
            "➕ Create New Key".to_string(),
            "🔐 Cryptographic Operations".to_string(),
            "✅ Approvals Management".to_string(),
            "📝 Audit Log Viewer".to_string(),
            "⚙️  Settings".to_string(),
            "❓ Help".to_string(),
            "🚪 Quit".to_string(),
        ];

        let main_menu = MainMenu::new(menu_items, config.theme.clone());
        let help_panel = HelpPanel::new(config.theme.clone());

        // Use CLI args if provided, otherwise config
        let server_endpoint = cli.endpoint.clone();
        let client_cert = cli.client_cert.as_ref().or(config.auth.client_cert_path.as_ref()).cloned();
        let client_key = cli.client_key.as_ref().or(config.auth.client_key_path.as_ref()).cloned();
        let ca_bundle = cli.ca_bundle.as_ref().or(config.auth.ca_bundle_path.as_ref()).cloned();

        let mut api_client = ApiClient::new(
            server_endpoint,
            client_cert,
            client_key,
            ca_bundle,
        )?;

        // Set token from config if available
        let mut user_info = None;
        if let Some(token) = &config.auth.token {
            api_client.set_auth_token(token.clone());
            user_info = api_client.get_user_info();
        }

        Ok(AppState {
            mode: AppMode::MainMenu,
            quit: false,
            main_menu,
            help_panel,
            error: None,
            loading_message: None,
            config,
            keys_search: String::new(),
            selected_key_index: 0,
            current_page: 1,
            api_client,
            keys: None,
            approvals: None,
            audit_logs: None,
            selected_key: None,
            user_info,
            selected_approval_index: 0,
            selected_audit_index: 0,
            audit_page: 1,
            auth_token_input: String::new(),
            crypto_operation: None,
            crypto_key_id: String::new(),
            crypto_data: String::new(),
            crypto_result: None,
            key_create_algorithm: None,
            key_create_usage: Vec::new(),
            key_create_policy_input: String::new(),
            key_create_policy_tags: Vec::new(),
            key_create_description: String::new(),
        })
    }

    fn handle_char_input(&mut self, c: char) -> Result<()> {
        match self.mode {
            AppMode::KeysList => {
                if c == 'n' || c == 'N' {
                    if let Some(keys) = &self.keys {
                        if keys.has_more {
                            self.current_page += 1;
                            self.loading_message = Some("Loading keys...".to_string());
                            self.fetch_keys().await?;
                        }
                    }
                } else if c == 'p' || c == 'P' {
                    if self.current_page > 1 {
                        self.current_page -= 1;
                        self.loading_message = Some("Loading keys...".to_string());
                        self.fetch_keys().await?;
                    }
                } else if c == '/' {
                    self.mode = AppMode::KeysListSearch;
                }
            }
            AppMode::KeysListSearch => {
                if c == '\n' || c == '\r' {
                    self.mode = AppMode::KeysList;
                    self.loading_message = Some("Loading keys...".to_string());
                    self.fetch_keys().await?;
                } else if c == '\x08' || c == '\x7f' {
                    self.keys_search.pop();
                } else if !c.is_control() {
                    self.keys_search.push(c);
                }
            }
            AppMode::SettingsAuth => {
                if c == '\n' || c == '\r' {
                    // Save the token
                    self.api_client.set_auth_token(self.auth_token_input.clone());
                    self.mode = AppMode::Settings;
                    self.auth_token_input.clear();
                } else if c == '\x08' || c == '\x7f' {
                    // Backspace
                    self.auth_token_input.pop();
                } else if !c.is_control() {
                    self.auth_token_input.push(c);
                }
            }
            AppMode::KeyCreatePolicy => {
                if c == '\n' || c == '\r' {
                    // Parse comma-separated tags
                    self.key_create_policy_tags = self.key_create_description
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    self.key_create_description.clear(); // Reuse as input buffer
                } else if c == '\x08' || c == '\x7f' {
                    self.key_create_description.pop();
                } else if !c.is_control() {
                    self.key_create_description.push(c);
                }
            }
            AppMode::KeyCreateDescription => {
                if c == '\n' || c == '\r' {
                    // Description is already in key_create_description
                } else if c == '\x08' || c == '\x7f' {
                    self.key_create_description.pop();
                } else if !c.is_control() {
                    self.key_create_description.push(c);
                }
            }
            AppMode::KeyOperations => {
                if c == 'o' || c == 'O' {
                    // Cycle operations
                    self.crypto_operation = Some(match self.crypto_operation.as_deref() {
                        Some("sign") => "encrypt".to_string(),
                        Some("encrypt") => "decrypt".to_string(),
                        Some("decrypt") => "sign".to_string(),
                        _ => "sign".to_string(),
                    });
                } else if c == 'k' || c == 'K' {
                    // Enter key ID mode? For simplicity, assume typing key_id
                    // But to make it simple, perhaps use a sub-mode, but for now, ignore
                } else if c == 'i' || c == 'I' {
                    // Enter data
                } else if c == '\n' || c == '\r' {
                    // Execute
                    self.execute_crypto_operation().await?;
                }
            }
            _ => {} // Ignore char input in other modes
        }
        Ok(())
    }

    async fn approve_selected_approval(&mut self) -> Result<()> {
        if let Some(approvals) = &self.approvals {
            if self.selected_approval_index < approvals.len() {
                let approval_id = &approvals[self.selected_approval_index].id;
                match self.api_client.approve_approval(approval_id).await {
                    Ok(_) => {
                        // Refresh approvals
                        self.fetch_approvals().await?;
                    }
                    Err(e) => {
                        self.error = Some(AppError::new(
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to approve: {}", e),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    async fn deny_selected_approval(&mut self) -> Result<()> {
        if let Some(approvals) = &self.approvals {
            if self.selected_approval_index < approvals.len() {
                let approval_id = &approvals[self.selected_approval_index].id;
                match self.api_client.deny_approval(approval_id).await {
                    Ok(_) => {
                        // Refresh approvals
                        self.fetch_approvals().await?;
                    }
                    Err(e) => {
                        self.error = Some(AppError::new(
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to deny: {}", e),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    async fn fetch_audit_logs(&mut self) -> Result<()> {
        if !self.api_client.is_authenticated() {
            return Ok(());
        }

        let query = AuditLogQuery {
            page: Some(self.audit_page),
            per_page: Some(self.config.default_page_size as u32),
            user: None,
            action: None,
            from: None,
            to: None,
        };

        match self.api_client.list_audit_logs(&query).await {
            Ok(logs) => {
                self.audit_logs = Some(logs);
                self.selected_audit_index = 0;
            }
            Err(e) => {
                self.error = Some(AppError::new(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to load audit logs: {}", e),
                ));
            }
        }
        Ok(())
    }

    async fn fetch_approvals(&mut self) -> Result<()> {
        if !self.api_client.is_authenticated() {
            return Ok(());
        }

        match self.api_client.list_approvals().await {
            Ok(approvals) => {
                self.approvals = Some(approvals);
            }
            Err(e) => {
                self.error = Some(AppError::new(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to load approvals: {}", e),
                ));
            }
        }
        Ok(())
    }

    async fn execute_crypto_operation(&mut self) -> Result<()> {
        if self.crypto_key_id.is_empty() || self.crypto_data.is_empty() {
            self.crypto_result = Some("Key ID and data required".to_string());
            return Ok(());
        }

        let data_b64 = base64::encode(self.crypto_data.as_bytes());

        let result = match self.crypto_operation.as_deref() {
            Some("sign") => {
                match self.api_client.sign(&self.crypto_key_id, data_b64).await {
                    Ok(resp) => format!("Signature: {}", resp.signature_b64),
                    Err(e) => format!("Error: {}", e),
                }
            }
            Some("encrypt") => {
                match self.api_client.encrypt(&self.crypto_key_id, data_b64, None).await {
                    Ok(resp) => format!("Ciphertext: {}, Nonce: {}", resp.ciphertext_b64, resp.nonce_b64),
                    Err(e) => format!("Error: {}", e),
                }
            }
            Some("decrypt") => {
                // Assume data is ciphertext:nonce
                if let Some((ciphertext, nonce)) = self.crypto_data.split_once(':') {
                    let ciphertext_b64 = base64::encode(ciphertext.as_bytes());
                    let nonce_b64 = base64::encode(nonce.as_bytes());
                    match self.api_client.decrypt(&self.crypto_key_id, ciphertext_b64, nonce_b64, None).await {
                        Ok(resp) => format!("Plaintext: {}", String::from_utf8(base64::decode(&resp.plaintext_b64).unwrap_or_default()).unwrap_or_default()),
                        Err(e) => format!("Error: {}", e),
                    }
                } else {
                    "Invalid decrypt data format (ciphertext:nonce)".to_string()
                }
            }
            _ => "No operation selected".to_string(),
        };

        self.crypto_result = Some(result);
        Ok(())
    }

    async fn handle_wizard_action(&mut self, action: KeyAction) -> Result<()> {
        match (self.mode, action) {
            (AppMode::KeyCreateAlgorithm, KeyAction::Select) => {
                // For now, just select AES-256-GCM as default
                self.key_create_algorithm = Some(KeyAlgorithm::Aes256Gcm);
                self.mode = AppMode::KeyCreateUsage;
            }
            (AppMode::KeyCreateUsage, KeyAction::Select) => {
                // Set default usage for AES
                self.key_create_usage = vec![hsm_core::KeyPurpose::Encrypt, hsm_core::KeyPurpose::Decrypt];
                self.mode = AppMode::KeyCreatePolicy;
            }
            (AppMode::KeyCreatePolicy, KeyAction::Select) => {
                self.mode = AppMode::KeyCreateDescription;
            }
            (AppMode::KeyCreateDescription, KeyAction::Select) => {
                self.mode = AppMode::KeyCreateConfirm;
            }
            (AppMode::KeyCreateConfirm, KeyAction::Select) => {
                // Create the key
                if let Some(algorithm) = self.key_create_algorithm.clone() {
                    let request = crate::api::CreateKeyRequest {
                        algorithm,
                        usage: self.key_create_usage.clone(),
                        policy_tags: self.key_create_policy_tags.clone(),
                        description: if self.key_create_description.is_empty() { None } else { Some(self.key_create_description.clone()) },
                    };

                    match self.api_client.create_key(request).await {
                        Ok(key) => {
                            self.selected_key = Some(key);
                            self.mode = AppMode::KeysList;
                            // Refresh keys list
                            self.fetch_keys().await?;
                        }
                        Err(e) => {
                            self.error = Some(AppError::new(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("Failed to create key: {}", e),
                            ));
                            self.mode = AppMode::MainMenu;
                        }
                    }
                }
            }
            (_, KeyAction::Back) => {
                match self.mode {
                    AppMode::KeyCreateAlgorithm => self.mode = AppMode::MainMenu,
                    AppMode::KeyCreateUsage => self.mode = AppMode::KeyCreateAlgorithm,
                    AppMode::KeyCreatePolicy => self.mode = AppMode::KeyCreateUsage,
                    AppMode::KeyCreateDescription => self.mode = AppMode::KeyCreatePolicy,
                    AppMode::KeyCreateConfirm => self.mode = AppMode::KeyCreateDescription,
                    _ => {}
                }
            }
            _ => {} // Ignore other actions
        }
        Ok(())
    }

    async fn fetch_keys(&mut self) -> Result<()> {
        if !self.api_client.is_authenticated() {
            self.loading_message = None;
            return Ok(());
        }

        let query = KeyListQuery {
            page: Some(self.current_page),
            per_page: Some(self.config.default_page_size as u32),
            algorithm: None,
            state: None,
            tags: if self.keys_search.is_empty() { None } else { Some(self.keys_search.clone()) },
        };

        match self.api_client.list_keys(&query).await {
            Ok(keys) => {
                self.keys = Some(keys);
                self.selected_key_index = 0;
                self.loading_message = None;
            }
            Err(e) => {
                self.error = Some(AppError::new(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to load keys: {}", e),
                ));
                self.loading_message = None;
            }
        }
        Ok(())
    }

    async fn handle_key_action(&mut self, action: KeyAction) -> Result<()> {
        // Handle wizard navigation
        if matches!(self.mode, AppMode::KeyCreateAlgorithm | AppMode::KeyCreateUsage | AppMode::KeyCreatePolicy | AppMode::KeyCreateDescription | AppMode::KeyCreateConfirm) {
            return self.handle_wizard_action(action).await;
        }
        match action {
            KeyAction::Quit => {
                self.quit = true;
            }
            KeyAction::NavigateUp => {
                match self.mode {
                    AppMode::MainMenu => self.main_menu.previous(),
                    AppMode::KeysList => {
                        if self.selected_key_index > 0 {
                            self.selected_key_index -= 1;
                        }
                    }
                    AppMode::ApprovalsList => {
                        if self.selected_approval_index > 0 {
                            self.selected_approval_index -= 1;
                        }
                    }
                    AppMode::AuditViewer => {
                        if self.selected_audit_index > 0 {
                            self.selected_audit_index -= 1;
                        }
                    }
                    _ => {}
                }
            }
            KeyAction::NavigateDown => {
                match self.mode {
                    AppMode::MainMenu => self.main_menu.next(),
                    AppMode::KeysList => {
                        if let Some(keys) = &self.keys {
                            if self.selected_key_index < keys.items.len().saturating_sub(1) {
                                self.selected_key_index += 1;
                            }
                        }
                    }
                    AppMode::ApprovalsList => {
                        if let Some(approvals) = &self.approvals {
                            if self.selected_approval_index < approvals.len().saturating_sub(1) {
                                self.selected_approval_index += 1;
                            }
                        }
                    }
                    AppMode::AuditViewer => {
                        if let Some(logs) = &self.audit_logs {
                            if self.selected_audit_index < logs.items.len().saturating_sub(1) {
                                self.selected_audit_index += 1;
                            }
                        }
                    }
                    _ => {}
                }
            }
            KeyAction::Select => {
                match self.mode {
                    AppMode::MainMenu => {
                        match self.main_menu.selected() {
                            0 => {
                                self.mode = AppMode::KeysList;
                                self.loading_message = Some("Loading keys...".to_string());
                                self.fetch_keys().await?;
                            }
                            1 => {
                                self.mode = AppMode::KeyCreateAlgorithm;
                                // Reset form data
                                self.key_create_algorithm = None;
                                self.key_create_usage = Vec::new();
                                self.key_create_policy_tags = Vec::new();
                                self.key_create_description = String::new();
                            }
                            2 => self.mode = AppMode::KeyOperations,
                        3 => {
                            self.mode = AppMode::ApprovalsList;
                            if self.approvals.is_none() {
                                self.loading_message = Some("Loading approvals...".to_string());
                                self.fetch_approvals().await?;
                            }
                        }
                            4 => {
                            self.mode = AppMode::AuditViewer;
                            if self.audit_logs.is_none() {
                                self.loading_message = Some("Loading audit logs...".to_string());
                                self.fetch_audit_logs().await?;
                            }
                        }
                            5 => self.mode = AppMode::Settings,
                            6 => self.mode = AppMode::Help,
                            7 => self.quit = true,
                            _ => {}
                        }
                    }
                    AppMode::KeysList => {
                        if let Some(keys) = &self.keys {
                            if self.selected_key_index < keys.items.len() {
                                self.selected_key = Some(keys.items[self.selected_key_index].clone());
                                self.mode = AppMode::KeyDetails;
                            }
                        }
                    }
                    _ => {}
                }
            }
            KeyAction::Back => {
                match self.mode {
                    AppMode::MainMenu => self.quit = true,
                    AppMode::KeysList => self.mode = AppMode::MainMenu,
                    AppMode::KeysListSearch => self.mode = AppMode::KeysList,
                    AppMode::AuditViewer => self.mode = AppMode::MainMenu,
                    AppMode::KeyDetails => self.mode = AppMode::KeysList,
                    AppMode::SettingsAuth => self.mode = AppMode::Settings,
                    _ => self.mode = AppMode::MainMenu,
                }
            }
            KeyAction::Edit => {
                if let AppMode::Settings = self.mode {
                    self.mode = AppMode::SettingsAuth;
                    self.auth_token_input.clear();
                }
            }
            KeyAction::Select => {
                if let AppMode::SettingsAuth = self.mode {
                    // Save the token
                    let token = self.auth_token_input.clone();
                    self.api_client.set_auth_token(token.clone());
                    self.config.auth.token = Some(token.clone());
                    self.user_info = self.api_client.get_user_info();
                    if let Err(e) = self.config.save() {
                        self.error = Some(AppError::new(
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to save config: {}", e),
                        ));
                    }
                    self.mode = AppMode::Settings;
                    self.auth_token_input.clear();
                }
            }
            KeyAction::Help => {
                self.mode = AppMode::Help;
            }
            _ => {}
        }
        Ok(())
    }

    fn update_help_panel(&mut self) {
        self.help_panel.clear();
        match self.mode {
            AppMode::MainMenu => {
                self.help_panel.add_shortcut("↑↓".to_string(), "Navigate menu".to_string());
                self.help_panel.add_shortcut("Enter".to_string(), "Select option".to_string());
                self.help_panel.add_shortcut("q".to_string(), "Quit application".to_string());
                self.help_panel.add_shortcut("?".to_string(), "Show help".to_string());
            }
            AppMode::KeysList => {
                self.help_panel.add_shortcut("↑↓".to_string(), "Navigate keys".to_string());
                self.help_panel.add_shortcut("Enter".to_string(), "View key details".to_string());
                self.help_panel.add_shortcut("/".to_string(), "Search/filter".to_string());
                self.help_panel.add_shortcut("n".to_string(), "Next page".to_string());
                self.help_panel.add_shortcut("p".to_string(), "Previous page".to_string());
                self.help_panel.add_shortcut("c".to_string(), "Create new key".to_string());
                self.help_panel.add_shortcut("Esc".to_string(), "Back to menu".to_string());
            }
            AppMode::KeysListSearch => {
                self.help_panel.add_shortcut("Enter".to_string(), "Apply search".to_string());
                self.help_panel.add_shortcut("Esc".to_string(), "Cancel search".to_string());
            }
            AppMode::KeyDetails => {
                self.help_panel.add_shortcut("r".to_string(), "Rotate key".to_string());
                self.help_panel.add_shortcut("d".to_string(), "Destroy key".to_string());
                self.help_panel.add_shortcut("Esc".to_string(), "Back to keys list".to_string());
            }
            AppMode::ApprovalsList => {
                self.help_panel.add_shortcut("↑↓".to_string(), "Navigate approvals".to_string());
                self.help_panel.add_shortcut("a".to_string(), "Approve selected".to_string());
                self.help_panel.add_shortcut("d".to_string(), "Deny selected".to_string());
                self.help_panel.add_shortcut("Esc".to_string(), "Back to menu".to_string());
            }
            AppMode::AuditViewer => {
                self.help_panel.add_shortcut("↑↓".to_string(), "Navigate logs".to_string());
                self.help_panel.add_shortcut("n".to_string(), "Next page".to_string());
                self.help_panel.add_shortcut("p".to_string(), "Previous page".to_string());
                self.help_panel.add_shortcut("Enter".to_string(), "View log details".to_string());
                self.help_panel.add_shortcut("Esc".to_string(), "Back to menu".to_string());
            }
            AppMode::Settings => {
                self.help_panel.add_shortcut("e".to_string(), "Configure authentication".to_string());
                self.help_panel.add_shortcut("Esc".to_string(), "Back to menu".to_string());
            }
            AppMode::SettingsAuth => {
                self.help_panel.add_shortcut("Enter".to_string(), "Save token".to_string());
                self.help_panel.add_shortcut("Esc".to_string(), "Cancel".to_string());
            }
            _ => {
                self.help_panel.add_shortcut("Esc".to_string(), "Back to menu".to_string());
                self.help_panel.add_shortcut("?".to_string(), "Show help".to_string());
            }
        }
    }
}

#[derive(Debug)]
struct App {
    state: Arc<Mutex<AppState>>,
    event_loop: EventLoop,
}

impl App {
    fn new(cli: Cli) -> Result<App> {
        let config = AppConfig::load()?;
        let state = Arc::new(Mutex::new(AppState::new(config, &cli)?));
        let event_loop = EventLoop::new(Default::default()); // Use default key bindings

        Ok(App { state, event_loop })
    }

    async fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            // Handle events
            if let Some(event) = self.event_loop.next_event()? {
                let mut state = self.state.lock().await;
                match event {
                    EventResult::Action(action) => {
                        state.handle_key_action(action).await?;
                    }
                    EventResult::Char(c) => {
                        state.handle_char_input(c)?;
                    }
                }
                state.update_help_panel();

                if state.quit {
                    break;
                }
            }

            // Draw the UI
            let state = self.state.lock().await;
            self.draw(&state, terminal)?;
        }
        Ok(())
    }

    fn draw<B: Backend>(&self, state: &AppState, terminal: &mut Terminal<B>) -> Result<()> {
        terminal
            .draw(|f| {
                let chunks = app_layout(f.area());

                // Header
                let header = Header::new(
                    "FerroHSM - Hardware Security Module".to_string(),
                    state.config.theme.clone(),
                );
                header.render(f, chunks[0]);

                // Main content based on mode
                match state.mode {
                    AppMode::MainMenu => {
                        state.main_menu.render(f, chunks[1]);
                    }
                     AppMode::KeysList | AppMode::KeysListSearch => {
                         self.draw_keys_list(state, f, chunks[1]);
                     }
                     AppMode::KeyDetails => {
                         self.draw_key_details(state, f, chunks[1]);
                     }
                    AppMode::KeyCreate | AppMode::KeyCreateAlgorithm | AppMode::KeyCreateUsage | AppMode::KeyCreatePolicy | AppMode::KeyCreateDescription | AppMode::KeyCreateConfirm => {
                        self.draw_key_create_wizard(state, f, chunks[1]);
                    }
            AppMode::ApprovalsList => {
                if c == 'a' || c == 'A' {
                    self.approve_selected_approval().await?;
                } else if c == 'd' || c == 'D' {
                    self.deny_selected_approval().await?;
                }
            }
            AppMode::AuditViewer => {
                if c == 'n' || c == 'N' {
                    if let Some(logs) = &self.audit_logs {
                        if logs.has_more {
                            self.audit_page += 1;
                            self.loading_message = Some("Loading audit logs...".to_string());
                            self.fetch_audit_logs().await?;
                        }
                    }
                } else if c == 'p' || c == 'P' {
                    if self.audit_page > 1 {
                        self.audit_page -= 1;
                        self.loading_message = Some("Loading audit logs...".to_string());
                        self.fetch_audit_logs().await?;
                    }
                }
            }
            AppMode::KeyOperations => {
                        self.draw_key_operations(state, f, chunks[1]);
                    }
                    AppMode::ApprovalsList => {
                        self.draw_approvals_list(state, f, chunks[1]);
                    }
                    AppMode::AuditViewer => {
                        self.draw_audit_viewer(state, f, chunks[1]);
                    }
                    AppMode::Settings => {
                        self.draw_settings(state, f, chunks[1]);
                    }
                    AppMode::SettingsAuth => {
                        self.draw_settings_auth(state, f, chunks[1]);
                    }
                }

                // Footer with status information
                let footer_text = match state.mode {
                    AppMode::MainMenu => "↑↓: Navigate | Enter: Select | q: Quit | ?: Help",
                    AppMode::Settings => "e: Auth | Esc: Back | ?: Help",
                    AppMode::SettingsAuth => "Enter: Save | Esc: Cancel | Type to enter token",
                    _ => "Esc: Back to Menu | ?: Help",
                };
                let footer = Footer::new(footer_text.to_string(), state.config.theme.clone());
                footer.render(f, chunks[2]);
            })
            .map_err(|e| anyhow::anyhow!("Failed to draw terminal: {:?}", e))?;
        Ok(())
    }

    // Main menu is now handled by the MainMenu component in draw()

    fn draw_keys_list(&self, state: &AppState, f: &mut Frame, area: Rect) {
        let chunks = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([
                ratatui::layout::Constraint::Length(3),
                ratatui::layout::Constraint::Min(1),
            ])
            .split(area);

        // Search input
        let search_title = if let AppMode::KeysListSearch = state.mode { "Filter Keys (press Enter to search)" } else { "Filter Keys (press / to search)" };
        let search_input = Paragraph::new(format!("Search: {}", state.keys_search))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(search_title)
                    .border_style(state.config.theme.secondary_style()),
            )
            .style(state.config.theme.text_style());
        f.render_widget(search_input, chunks[0]);

        // Keys table
        let content = if !state.api_client.is_authenticated() {
            vec![Row::new(vec![Cell::from("Not authenticated. Please configure authentication in Settings.")])]
        } else if let Some(loading) = &state.loading_message {
            vec![Row::new(vec![Cell::from(loading.as_str())])]
        } else if let Some(keys) = &state.keys {
            if keys.items.is_empty() {
                vec![Row::new(vec![Cell::from("No keys found.")])]
            } else {
                let mut rows = Vec::new();
                for (i, key) in keys.items.iter().enumerate() {
                    let style = if i == state.selected_key_index {
                        state.config.theme.highlight_style()
                    } else {
                        state.config.theme.text_style()
                    };
                    rows.push(Row::new(vec![
                        Cell::from(key.id.clone()).style(style),
                        Cell::from(format!("{:?}", key.algorithm)).style(style),
                        Cell::from(format!("{:?}", key.state)).style(style),
                        Cell::from(key.description.clone().unwrap_or_default()).style(style),
                    ]));
                }
                rows
            }
        } else {
            vec![Row::new(vec![Cell::from("Loading keys...")])]
        };

        let table = Table::new(
            content,
            [
                ratatui::layout::Constraint::Percentage(30),
                ratatui::layout::Constraint::Percentage(20),
                ratatui::layout::Constraint::Percentage(20),
                ratatui::layout::Constraint::Percentage(30),
            ],
        )
        .header(
            Row::new(vec!["ID", "Algorithm", "State", "Description"])
                .style(state.config.theme.header_style())
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Keys (Page {})", state.current_page))
                .border_style(state.config.theme.secondary_style()),
        )
        .highlight_style(state.config.theme.highlight_style());
        f.render_widget(table, chunks[1]);
    }

    fn draw_key_create_wizard(&self, state: &AppState, f: &mut Frame, area: Rect) {
        let (title, content) = match state.mode {
            AppMode::KeyCreateAlgorithm => {
                let algorithms = vec![
                    "AES-256-GCM (Symmetric encryption)",
                    "RSA-2048 (Asymmetric encryption/signing)",
                    "RSA-4096 (Asymmetric encryption/signing)",
                    "EC P-256 (Elliptic curve)",
                    "EC P-384 (Elliptic curve)",
                    "ML-KEM-512 (Post-quantum KEM)",
                    "ML-KEM-768 (Post-quantum KEM)",
                    "ML-KEM-1024 (Post-quantum KEM)",
                    "ML-DSA-44 (Post-quantum signature)",
                    "ML-DSA-65 (Post-quantum signature)",
                    "ML-DSA-87 (Post-quantum signature)",
                ];

                let mut content = "Step 1: Select Algorithm\n\n".to_string();
                for (i, alg) in algorithms.iter().enumerate() {
                    let marker = if let Some(selected) = state.key_create_algorithm {
                        match i {
                            0 if matches!(selected, KeyAlgorithm::Aes256Gcm) => "▶ ",
                            1 if matches!(selected, KeyAlgorithm::Rsa2048) => "▶ ",
                            2 if matches!(selected, KeyAlgorithm::Rsa4096) => "▶ ",
                            3 if matches!(selected, KeyAlgorithm::P256) => "▶ ",
                            4 if matches!(selected, KeyAlgorithm::P384) => "▶ ",
                            5 if matches!(selected, KeyAlgorithm::MlKem512) => "▶ ",
                            6 if matches!(selected, KeyAlgorithm::MlKem768) => "▶ ",
                            7 if matches!(selected, KeyAlgorithm::MlKem1024) => "▶ ",
                            8 if matches!(selected, KeyAlgorithm::MlDsa44) => "▶ ",
                            9 if matches!(selected, KeyAlgorithm::MlDsa65) => "▶ ",
                            10 if matches!(selected, KeyAlgorithm::MlDsa87) => "▶ ",
                            _ => "  ",
                        }
                    } else {
                        "  "
                    };
                    content.push_str(&format!("{} {}. {}\n", marker, i + 1, alg));
                }
                content.push_str("\nUse ↑↓ to navigate, Enter to select, Esc to cancel.");
                ("Create New Key - Algorithm", content)
            }
            AppMode::KeyCreateUsage => {
                let purposes = vec![
                    "Encrypt - Use for encryption operations",
                    "Decrypt - Use for decryption operations",
                    "Sign - Use for digital signatures",
                    "Verify - Use for signature verification",
                    "Wrap - Use for key wrapping",
                    "Unwrap - Use for key unwrapping",
                ];

                let mut content = "Step 2: Select Key Usage\n\n".to_string();
                for (i, purpose) in purposes.iter().enumerate() {
                    let checked = match i {
                        0 => state.key_create_usage.contains(&hsm_core::KeyPurpose::Encrypt),
                        1 => state.key_create_usage.contains(&hsm_core::KeyPurpose::Decrypt),
                        2 => state.key_create_usage.contains(&hsm_core::KeyPurpose::Sign),
                        3 => state.key_create_usage.contains(&hsm_core::KeyPurpose::Verify),
                        4 => state.key_create_usage.contains(&hsm_core::KeyPurpose::Wrap),
                        5 => state.key_create_usage.contains(&hsm_core::KeyPurpose::Unwrap),
                        _ => false,
                    };
                    let marker = if checked { "[✓]" } else { "[ ]" };
                    content.push_str(&format!("{} {}. {}\n", marker, i + 1, purpose));
                }
                content.push_str("\nUse ↑↓ to navigate, Space to toggle, Enter to continue, Esc to go back.");
                ("Create New Key - Usage", content)
            }
            AppMode::KeyCreatePolicy => {
                let mut content = "Step 3: Policy Tags (optional)\n\n".to_string();
                content.push_str("Enter policy tags separated by commas:\n\n");
                content.push_str(&state.key_create_policy_tags.join(", "));
                content.push_str("\n\nPolicy tags control access to this key.\n");
                content.push_str("Examples: production, development, finance, audit\n\n");
                content.push_str("Enter to continue, Esc to go back.");
                ("Create New Key - Policy", content)
            }
            AppMode::KeyCreateDescription => {
                let mut content = "Step 4: Description (optional)\n\n".to_string();
                content.push_str("Enter a description for this key:\n\n");
                content.push_str(&state.key_create_description);
                content.push_str("\n\nEnter to continue, Esc to go back.");
                ("Create New Key - Description", content)
            }
            AppMode::KeyCreateConfirm => {
                let mut content = "Step 5: Confirm Key Creation\n\n".to_string();
                if let Some(alg) = state.key_create_algorithm {
                    content.push_str(&format!("Algorithm: {:?}\n", alg));
                }
                content.push_str(&format!("Usage: {:?}\n", state.key_create_usage));
                if !state.key_create_policy_tags.is_empty() {
                    content.push_str(&format!("Policy Tags: {}\n", state.key_create_policy_tags.join(", ")));
                }
                if !state.key_create_description.is_empty() {
                    content.push_str(&format!("Description: {}\n", state.key_create_description));
                }
                content.push_str("\nEnter to create key, Esc to go back.");
                ("Create New Key - Confirm", content)
            }
            _ => ("Create New Key", "Key Creation Wizard".to_string()),
        };

        let content_widget = Paragraph::new(content)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .border_style(state.config.theme.secondary_style()),
            )
            .style(state.config.theme.text_style());
        f.render_widget(content_widget, area);
    }

    fn draw_key_details(&self, state: &AppState, f: &mut Frame, area: Rect) {
        let content = if let Some(key) = &state.selected_key {
            format!(
                "Key Details\n\n\
                ID: {}\n\
                Algorithm: {:?}\n\
                Version: {}\n\
                State: {:?}\n\
                Usage: {:?}\n\
                Description: {}\n\
                Policy Tags: {}\n\
                Created: {}\n\
                Tamper Status: {}",
                key.id,
                key.algorithm,
                key.version,
                key.state,
                key.usage,
                key.description.as_deref().unwrap_or("None"),
                key.policy_tags.join(", "),
                key.created_at,
                key.tamper_status
            )
        } else {
            "No key selected".to_string()
        };

        let content_widget = Paragraph::new(content)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Key Details")
                    .border_style(state.config.theme.secondary_style()),
            )
            .style(state.config.theme.text_style());
        f.render_widget(content_widget, area);
    }

    fn draw_key_operations(&self, state: &AppState, f: &mut Frame, area: Rect) {
        let mut content = "Cryptographic Operations\n\n".to_string();

        content.push_str("Operation: ");
        if let Some(op) = &state.crypto_operation {
            content.push_str(op);
        } else {
            content.push_str("(select operation)");
        }
        content.push_str("\n\n");

        content.push_str(&format!("Key ID: {}\n\n", state.crypto_key_id));
        content.push_str(&format!("Data: {}\n\n", state.crypto_data));

        if let Some(result) = &state.crypto_result {
            content.push_str(&format!("Result: {}\n", result));
        }

        content.push_str("\nControls:\n");
        content.push_str("• 'o': Select operation (s=sign, e=encrypt, d=decrypt)\n");
        content.push_str("• 'k': Enter key ID\n");
        content.push_str("• 'i': Enter data\n");
        content.push_str("• Enter: Execute operation\n");
        content.push_str("• Esc: Back to menu\n");

        let content_widget = Paragraph::new(content)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Cryptographic Operations")
                    .border_style(state.config.theme.secondary_style()),
            )
            .style(state.config.theme.text_style());
        f.render_widget(content_widget, area);
    }

    fn draw_approvals_list(&self, state: &AppState, f: &mut Frame, area: Rect) {
        let content = if !state.api_client.is_authenticated() {
            vec![Row::new(vec![Cell::from("Not authenticated. Please configure authentication in Settings.")])]
        } else if let Some(loading) = &state.loading_message {
            vec![Row::new(vec![Cell::from(loading.as_str())])]
        } else if let Some(approvals) = &state.approvals {
            if approvals.is_empty() {
                vec![Row::new(vec![Cell::from("No pending approvals.")])]
            } else {
                let mut rows = Vec::new();
                for (i, approval) in approvals.iter().enumerate() {
                    let style = if i == state.selected_approval_index {
                        state.config.theme.highlight_style()
                    } else {
                        state.config.theme.text_style()
                    };
                    rows.push(Row::new(vec![
                        Cell::from(approval.id.clone()).style(style),
                        Cell::from(approval.action.clone()).style(style),
                        Cell::from(approval.requester.clone()).style(style),
                        Cell::from(approval.subject.clone()).style(style),
                    ]));
                }
                rows
            }
        } else {
            vec![Row::new(vec![Cell::from("Loading approvals...")])]
        };

        let table = Table::new(
            content,
            [
                ratatui::layout::Constraint::Percentage(20),
                ratatui::layout::Constraint::Percentage(20),
                ratatui::layout::Constraint::Percentage(20),
                ratatui::layout::Constraint::Percentage(40),
            ],
        )
        .header(
            Row::new(vec!["ID", "Action", "Requester", "Subject"])
                .style(state.config.theme.header_style())
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Approvals Management")
                .border_style(state.config.theme.secondary_style()),
        )
        .highlight_style(state.config.theme.highlight_style());
        f.render_widget(table, area);
    }

    fn draw_audit_viewer(&self, state: &AppState, f: &mut Frame, area: Rect) {
        let content = if !state.api_client.is_authenticated() {
            vec![Row::new(vec![Cell::from("Not authenticated. Please configure authentication in Settings.")])]
        } else if let Some(loading) = &state.loading_message {
            vec![Row::new(vec![Cell::from(loading.as_str())])]
        } else if let Some(logs) = &state.audit_logs {
            if logs.items.is_empty() {
                vec![Row::new(vec![Cell::from("No audit logs found.")])]
            } else {
                let mut rows = Vec::new();
                for (i, log) in logs.items.iter().enumerate() {
                    let style = if i == state.selected_audit_index {
                        state.config.theme.highlight_style()
                    } else {
                        state.config.theme.text_style()
                    };
                    rows.push(Row::new(vec![
                        Cell::from(log.timestamp.clone()).style(style),
                        Cell::from(log.user.clone()).style(style),
                        Cell::from(log.action.clone()).style(style),
                        Cell::from(log.resource.clone()).style(style),
                    ]));
                }
                rows
            }
        } else {
            vec![Row::new(vec![Cell::from("Loading audit logs...")])]
        };

        let table = Table::new(
            content,
            [
                ratatui::layout::Constraint::Percentage(25),
                ratatui::layout::Constraint::Percentage(20),
                ratatui::layout::Constraint::Percentage(20),
                ratatui::layout::Constraint::Percentage(35),
            ],
        )
        .header(
            Row::new(vec!["Timestamp", "User", "Action", "Resource"])
                .style(state.config.theme.header_style())
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Audit Logs (Page {})", state.audit_page))
                .border_style(state.config.theme.secondary_style()),
        )
        .highlight_style(state.config.theme.highlight_style());
        f.render_widget(table, area);
    }

    fn draw_settings(&self, state: &AppState, f: &mut Frame, area: Rect) {
        let mut content = "Settings\n\n".to_string();

        content.push_str(&format!("Server Endpoint: {}\n", state.api_client.base_url));
        content.push_str(&format!("Authenticated: {}\n", if state.api_client.is_authenticated() { "Yes" } else { "No" }));

        if let Some(user_info) = &state.user_info {
            content.push_str(&format!("User: {}\n", user_info.sub));
            if !user_info.roles.is_empty() {
                content.push_str(&format!("Roles: {}\n", user_info.roles.join(", ")));
            }
            if let Some(exp) = user_info.exp {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                if exp > now {
                    let remaining = exp - now;
                    content.push_str(&format!("Token expires in: {} seconds\n", remaining));
                } else {
                    content.push_str("Token expired\n");
                }
            }
        }

        content.push_str("\nAvailable Settings:\n");
        content.push_str("• Configure JWT authentication token\n");
        content.push_str("• Update server endpoint\n");
        content.push_str("• Configure TLS certificates\n");
        content.push_str("• Theme selection\n");

        content.push_str("\nNavigation:\n");
        content.push_str("• 'e': Configure authentication\n");
        content.push_str("• 's': Edit server endpoint\n");
        content.push_str("• 't': Change theme\n");

        let content_widget = Paragraph::new(content)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Settings")
                    .border_style(state.config.theme.secondary_style()),
            )
            .style(state.config.theme.text_style());
        f.render_widget(content_widget, area);
    }

    fn draw_settings_auth(&self, state: &AppState, f: &mut Frame, area: Rect) {
        let content = format!(
            "Authentication Setup\n\n\
            Enter your JWT authentication token:\n\n\
            {}\n\n\
            Press Enter to save, Esc to cancel.\n\
            Note: Token will be stored in memory only.",
            state.auth_token_input
        );

        let content_widget = Paragraph::new(content)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Authentication")
                    .border_style(state.config.theme.secondary_style()),
            )
            .style(state.config.theme.text_style());
        f.render_widget(content_widget, area);
    }

    // Help is now handled by HelpPanel component
}

fn init_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;
    Ok(terminal)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup panic hook to restore terminal
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        original_hook(panic_info);
    }));

    let mut terminal = init_terminal()?;

    let app_result = {
        let mut app = App::new(cli)?;
        app.run(&mut terminal).await
    };

    restore_terminal(&mut terminal)?;

    app_result
}
