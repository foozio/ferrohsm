use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
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

#[derive(Debug, Clone, Copy)]
enum AppMode {
    Dashboard,
    Keys,
    Audit,
    Approvals,
}

#[derive(Debug)]
struct App {
    mode: AppMode,
    quit: bool,
}

impl App {
    fn new() -> App {
        App {
            mode: AppMode::Dashboard,
            quit: false,
        }
    }

    fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            self.draw(terminal)?;
            
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        self.quit = true;
                    }
                    KeyCode::Char('d') => {
                        self.mode = AppMode::Dashboard;
                    }
                    KeyCode::Char('k') => {
                        self.mode = AppMode::Keys;
                    }
                    KeyCode::Char('a') => {
                        self.mode = AppMode::Audit;
                    }
                    KeyCode::Char('p') => {
                        self.mode = AppMode::Approvals;
                    }
                    _ => {}
                }
            }
            
            if self.quit {
                break;
            }
        }
        Ok(())
    }

    fn draw<B: Backend>(&self, terminal: &mut Terminal<B>) -> Result<()> {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(0),
                    Constraint::Length(1),
                ])
                .split(f.area());

            // Header
            let header = Paragraph::new("FerroHSM - Hardware Security Module")
                .style(Style::default().fg(Color::White).bg(Color::Blue))
                .alignment(Alignment::Center);
            f.render_widget(header, chunks[0]);

            // Main content based on mode
            match self.mode {
                AppMode::Dashboard => {
                    let content = Paragraph::new("Dashboard View\n\nWelcome to FerroHSM TUI!\n\nPress keys to navigate:\n- d: Dashboard\n- k: Keys\n- a: Audit\n- p: Approvals\n- q/Esc: Quit")
                        .block(Block::default().borders(Borders::ALL).title("Dashboard"));
                    f.render_widget(content, chunks[1]);
                }
                AppMode::Keys => {
                    let content = Paragraph::new("Keys Management View\n\nManage your cryptographic keys here.")
                        .block(Block::default().borders(Borders::ALL).title("Keys"));
                    f.render_widget(content, chunks[1]);
                }
                AppMode::Audit => {
                    let content = Paragraph::new("Audit Logs View\n\nView and verify audit logs here.")
                        .block(Block::default().borders(Borders::ALL).title("Audit"));
                    f.render_widget(content, chunks[1]);
                }
                AppMode::Approvals => {
                    let content = Paragraph::new("Approvals View\n\nManage dual-control approvals here.")
                        .block(Block::default().borders(Borders::ALL).title("Approvals"));
                    f.render_widget(content, chunks[1]);
                }
            }

            // Footer
            let footer = Paragraph::new("Press 'q' or 'Esc' to quit | Use 'd', 'k', 'a', 'p' to navigate")
                .style(Style::default().fg(Color::White).bg(Color::DarkGray))
                .alignment(Alignment::Center);
            f.render_widget(footer, chunks[2]);
        })?;
        Ok(())
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
        let mut app = App::new();
        app.run(&mut terminal)
    };

    restore_terminal(&mut terminal)?;
    
    app_result
}