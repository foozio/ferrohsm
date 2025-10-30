use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{block::Title, Block, Borders, List, ListItem, ListState, Paragraph},
};
use std::{io, panic};

/// FerroHSM TUI - Text-based User Interface for FerroHSM
#[derive(Parser)]
#[clap(name = "hsm-tui", version = "0.2.1")]
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
}

#[derive(Debug, Clone)]
enum AppMode {
    MainMenu,
    KeysList,
    KeyDetails,
    KeyCreate,
    KeyOperations,
    ApprovalsList,
    AuditViewer,
    Settings,
    Help,
}

#[derive(Debug)]
struct AppState {
    mode: AppMode,
    quit: bool,
    main_menu_state: ListState,
    endpoint: String,
    connection_status: String,
}

impl AppState {
    fn new(endpoint: String) -> AppState {
        let mut state = AppState {
            mode: AppMode::MainMenu,
            quit: false,
            main_menu_state: ListState::default(),
            endpoint,
            connection_status: "Disconnected".to_string(),
        };
        state.main_menu_state.select(Some(0));
        state
    }

    fn next_menu_item(&mut self) {
        if let AppMode::MainMenu = self.mode {
            let i = match self.main_menu_state.selected() {
                Some(i) => {
                    if i >= 8 {
                        0
                    } else {
                        i + 1
                    }
                }
                None => 0,
            };
            self.main_menu_state.select(Some(i));
        }
    }

    fn previous_menu_item(&mut self) {
        if let AppMode::MainMenu = self.mode {
            let i = match self.main_menu_state.selected() {
                Some(i) => {
                    if i == 0 {
                        8
                    } else {
                        i - 1
                    }
                }
                None => 0,
            };
            self.main_menu_state.select(Some(i));
        }
    }
}

#[derive(Debug)]
struct App {
    state: AppState,
}

impl App {
    fn new(cli: Cli) -> App {
        App {
            state: AppState::new(cli.endpoint),
        }
    }

    fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            self.draw(terminal)?;
            
            if let Event::Key(key) = event::read()? {
                match self.state.mode {
                    AppMode::MainMenu => {
                        self.handle_main_menu_key(key.code)?;
                    }
                    _ => {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                if let AppMode::MainMenu = self.state.mode {
                                    self.state.quit = true;
                                } else {
                                    self.state.mode = AppMode::MainMenu;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            
            if self.state.quit {
                break;
            }
        }
        Ok(())
    }

    fn handle_main_menu_key(&mut self, key: KeyCode) -> Result<()> {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.state.quit = true;
            }
            KeyCode::Down => {
                self.state.next_menu_item();
            }
            KeyCode::Up => {
                self.state.previous_menu_item();
            }
            KeyCode::Enter => {
                match self.state.main_menu_state.selected() {
                    Some(0) => self.state.mode = AppMode::KeysList,
                    Some(1) => self.state.mode = AppMode::KeyCreate,
                    Some(2) => self.state.mode = AppMode::KeyOperations,
                    Some(3) => self.state.mode = AppMode::ApprovalsList,
                    Some(4) => self.state.mode = AppMode::AuditViewer,
                    Some(5) => self.state.mode = AppMode::Settings,
                    Some(6) => self.state.mode = AppMode::Help,
                    Some(7) => self.state.quit = true,
                    _ => {}
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn draw<B: Backend>(&self, terminal: &mut Terminal<B>) -> Result<()> {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),  // Header
                    Constraint::Min(0),     // Main content
                    Constraint::Length(1),  // Footer
                ])
                .split(f.area());

            // Header
            let header = Paragraph::new("FerroHSM - Hardware Security Module")
                .style(Style::default().fg(Color::White).bg(Color::Blue))
                .alignment(Alignment::Center);
            f.render_widget(header, chunks[0]);

            // Main content based on mode
            match self.state.mode {
                AppMode::MainMenu => {
                    self.draw_main_menu(f, chunks[1]);
                }
                AppMode::KeysList => {
                    self.draw_keys_list(f, chunks[1]);
                }
                AppMode::KeyDetails => {
                    self.draw_key_details(f, chunks[1]);
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
                    self.draw_help(f, chunks[1]);
                }
            }

            // Footer
            let footer_text = match self.state.mode {
                AppMode::MainMenu => "↑↓: Navigate | Enter: Select | q/Esc: Quit",
                _ => "q/Esc: Back to Menu",
            };
            let footer = Paragraph::new(footer_text)
                .style(Style::default().fg(Color::White).bg(Color::DarkGray))
                .alignment(Alignment::Center);
            f.render_widget(footer, chunks[2]);
        })?;
        Ok(())
    }

    fn draw_main_menu(&self, f: &mut Frame, area: Rect) {
        let items = vec![
            ListItem::new("🔑 Key Management"),
            ListItem::new("➕ Create New Key"),
            ListItem::new("🔐 Cryptographic Operations"),
            ListItem::new("✅ Approvals Management"),
            ListItem::new("📝 Audit Log Viewer"),
            ListItem::new("⚙️  Settings"),
            ListItem::new("❓ Help"),
            ListItem::new("🚪 Quit"),
        ];

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Title::from("Main Menu".to_string())),
            )
            .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
            .highlight_symbol(">> ");

        f.render_stateful_widget(list, area, &mut self.state.main_menu_state.clone());
    }

    fn draw_keys_list(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new("Keys List View\n\nList and manage cryptographic keys.")
            .block(Block::default().borders(Borders::ALL).title("Keys Management"));
        f.render_widget(content, area);
    }

    fn draw_key_details(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new("Key Details View\n\nView detailed information about a specific key.")
            .block(Block::default().borders(Borders::ALL).title("Key Details"));
        f.render_widget(content, area);
    }

    fn draw_key_create(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new("Key Creation Wizard\n\nCreate new cryptographic keys with various algorithms.")
            .block(Block::default().borders(Borders::ALL).title("Create New Key"));
        f.render_widget(content, area);
    }

    fn draw_key_operations(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new("Cryptographic Operations\n\nPerform sign, encrypt, and decrypt operations.")
            .block(Block::default().borders(Borders::ALL).title("Cryptographic Operations"));
        f.render_widget(content, area);
    }

    fn draw_approvals_list(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new("Approvals Management\n\nManage dual-control approvals.")
            .block(Block::default().borders(Borders::ALL).title("Approvals Management"));
        f.render_widget(content, area);
    }

    fn draw_audit_viewer(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new("Audit Log Viewer\n\nView and verify audit logs.")
            .block(Block::default().borders(Borders::ALL).title("Audit Log Viewer"));
        f.render_widget(content, area);
    }

    fn draw_settings(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new("Settings\n\nConfigure connection and authentication settings.")
            .block(Block::default().borders(Borders::ALL).title("Settings"));
        f.render_widget(content, area);
    }

    fn draw_help(&self, f: &mut Frame, area: Rect) {
        let content = Paragraph::new("Help\n\nDocumentation and keyboard shortcuts.")
            .block(Block::default().borders(Borders::ALL).title("Help"));
        f.render_widget(content, area);
    }
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
        let mut app = App::new(cli);
        app.run(&mut terminal)
    };

    restore_terminal(&mut terminal)?;
    
    app_result
}