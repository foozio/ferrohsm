mod config;
mod error;
mod event;
mod ui;

use crate::config::AppConfig;
use crate::error::{AppError, ErrorDisplay};
use crate::event::EventLoop;
use crate::ui::components::{Footer, Header, HelpPanel, MainMenu};
use crate::ui::input::KeyAction;
use crate::ui::layout::app_layout;
use crate::ui::widgets::{ErrorDialog, LoadingSpinner};
use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};
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
    KeyCreate,
    KeyOperations,
    ApprovalsList,
    AuditViewer,
    Settings,
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
}

impl AppState {
    fn new(config: AppConfig) -> Result<AppState> {
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

        Ok(AppState {
            mode: AppMode::MainMenu,
            quit: false,
            main_menu,
            help_panel,
            error: None,
            loading_message: None,
            config,
        })
    }

    fn handle_key_action(&mut self, action: KeyAction) -> Result<()> {
        match action {
            KeyAction::Quit => {
                self.quit = true;
            }
            KeyAction::NavigateUp => {
                if let AppMode::MainMenu = self.mode {
                    self.main_menu.previous();
                }
            }
            KeyAction::NavigateDown => {
                if let AppMode::MainMenu = self.mode {
                    self.main_menu.next();
                }
            }
            KeyAction::Select => {
                if let AppMode::MainMenu = self.mode {
                    match self.main_menu.selected() {
                        0 => self.mode = AppMode::KeysList,
                        1 => self.mode = AppMode::KeyCreate,
                        2 => self.mode = AppMode::KeyOperations,
                        3 => self.mode = AppMode::ApprovalsList,
                        4 => self.mode = AppMode::AuditViewer,
                        5 => self.mode = AppMode::Settings,
                        6 => self.mode = AppMode::Help,
                        7 => self.quit = true,
                        _ => {}
                    }
                }
            }
            KeyAction::Back => {
                if let AppMode::MainMenu = self.mode {
                    self.quit = true;
                } else {
                    self.mode = AppMode::MainMenu;
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
                self.help_panel
                    .add_shortcut("↑↓".to_string(), "Navigate menu".to_string());
                self.help_panel
                    .add_shortcut("Enter".to_string(), "Select option".to_string());
                self.help_panel
                    .add_shortcut("q".to_string(), "Quit application".to_string());
                self.help_panel
                    .add_shortcut("?".to_string(), "Show help".to_string());
            }
            AppMode::KeysList => {
                self.help_panel
                    .add_shortcut("↑↓".to_string(), "Navigate keys".to_string());
                self.help_panel
                    .add_shortcut("Enter".to_string(), "View key details".to_string());
                self.help_panel
                    .add_shortcut("c".to_string(), "Create new key".to_string());
                self.help_panel
                    .add_shortcut("Esc".to_string(), "Back to menu".to_string());
            }
            _ => {
                self.help_panel
                    .add_shortcut("Esc".to_string(), "Back to menu".to_string());
                self.help_panel
                    .add_shortcut("?".to_string(), "Show help".to_string());
            }
        }
    }
}

#[derive(Debug)]
struct App {
    state: AppState,
    event_loop: EventLoop,
}

impl App {
    fn new(_cli: Cli) -> Result<App> {
        let config = AppConfig::load()?;
        let state = AppState::new(config)?;
        let event_loop = EventLoop::new(state.config.key_bindings.clone());

        Ok(App { state, event_loop })
    }

    fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            // Handle events
            if let Some(action) = self.event_loop.next_event()? {
                self.state.handle_key_action(action)?;
                self.state.update_help_panel();

                if self.state.quit {
                    break;
                }
            }

            // Draw the UI
            self.draw(terminal)?;
        }
        Ok(())
    }

    fn draw<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        terminal
            .draw(|f| {
                let chunks = app_layout(f.area());

                // Header
                let header = Header::new(
                    "FerroHSM - Hardware Security Module".to_string(),
                    self.state.config.theme.clone(),
                );
                header.render(f, chunks[0]);

                // Main content based on mode
                match self.state.mode {
                    AppMode::MainMenu => {
                        self.state.main_menu.render(f, chunks[1]);
                    }
                    AppMode::KeysList => {
                        self.draw_keys_list(f, chunks[1]);
                    }
                    AppMode::KeyCreate => {
                        self.draw_key_create(f, chunks[1]);
                    }
                    AppMode::KeyOperations => {
                        self.draw_key_operations(f, chunks[1]);
                    }
                    AppMode::ApprovalsList => {
                        self.draw_approvals_list(f, chunks[1]);
                    }
                    AppMode::AuditViewer => {
                        self.draw_audit_viewer(f, chunks[1]);
                    }
                    AppMode::Settings => {
                        self.draw_settings(f, chunks[1]);
                    }
                    AppMode::Help => {
                        self.state.help_panel.render(f, chunks[1]);
                    }
                    AppMode::Loading => {
                        if let Some(ref message) = self.state.loading_message {
                            let spinner = LoadingSpinner::new(message.clone());
                            f.render_widget(spinner, chunks[1]);
                        }
                    }
                    AppMode::Error => {
                        if let Some(ref error) = self.state.error {
                            let display = ErrorDisplay::new(error.clone());
                            let dialog =
                                ErrorDialog::new(display.title().to_string(), display.message());
                            f.render_widget(dialog, chunks[1]);
                        }
                    }
                }

                // Footer with status information
                let footer_text = match self.state.mode {
                    AppMode::MainMenu => "↑↓: Navigate | Enter: Select | q: Quit | ?: Help",
                    _ => "Esc: Back to Menu | ?: Help",
                };
                let footer = Footer::new(footer_text.to_string(), self.state.config.theme.clone());
                footer.render(f, chunks[2]);
            })
            .map_err(|e| anyhow::anyhow!("Failed to draw terminal: {:?}", e))?;
        Ok(())
    }

    // Main menu is now handled by the MainMenu component in draw()

    fn draw_keys_list(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new("Keys List View\n\nList and manage cryptographic keys.")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Keys Management")
                    .border_style(self.state.config.theme.secondary_style()),
            )
            .style(self.state.config.theme.text_style());
        f.render_widget(content, area);
    }

    fn draw_key_create(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new(
            "Key Creation Wizard\n\nCreate new cryptographic keys with various algorithms.",
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Create New Key")
                .border_style(self.state.config.theme.secondary_style()),
        )
        .style(self.state.config.theme.text_style());
        f.render_widget(content, area);
    }

    fn draw_key_operations(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new(
            "Cryptographic Operations\n\nPerform sign, encrypt, and decrypt operations.",
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Cryptographic Operations")
                .border_style(self.state.config.theme.secondary_style()),
        )
        .style(self.state.config.theme.text_style());
        f.render_widget(content, area);
    }

    fn draw_approvals_list(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new("Approvals Management\n\nManage dual-control approvals.")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Approvals Management")
                    .border_style(self.state.config.theme.secondary_style()),
            )
            .style(self.state.config.theme.text_style());
        f.render_widget(content, area);
    }

    fn draw_audit_viewer(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new("Audit Log Viewer\n\nView and verify audit logs.")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Audit Log Viewer")
                    .border_style(self.state.config.theme.secondary_style()),
            )
            .style(self.state.config.theme.text_style());
        f.render_widget(content, area);
    }

    fn draw_settings(&self, f: &mut Frame, area: Rect) {
        let content =
            Paragraph::new("Settings\n\nConfigure connection and authentication settings.")
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Settings")
                        .border_style(self.state.config.theme.secondary_style()),
                )
                .style(self.state.config.theme.text_style());
        f.render_widget(content, area);
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

fn main() -> Result<()> {
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
        app.run(&mut terminal)
    };

    restore_terminal(&mut terminal)?;

    app_result
}
