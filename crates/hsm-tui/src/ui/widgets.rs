//! Specialized widgets for FerroHSM TUI
//!
//! Provides enhanced widgets like syntax highlighting, text areas, and loading indicators.

#![allow(dead_code)]
#![allow(mismatched_lifetime_syntaxes)]

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};
use syntect::{highlighting::ThemeSet, parsing::SyntaxSet, util::LinesWithEndings};

/// Syntax highlighter for JSON and other formats
pub struct SyntaxHighlighter {
    syntax_set: SyntaxSet,
    theme_set: ThemeSet,
}

impl SyntaxHighlighter {
    /// Create a new syntax highlighter
    pub fn new() -> Self {
        Self {
            syntax_set: SyntaxSet::load_defaults_newlines(),
            theme_set: ThemeSet::load_defaults(),
        }
    }

    /// Highlight JSON text
    pub fn highlight_json(&self, json: &str) -> Vec<Line> {
        self.highlight_text(json, "json")
    }

    /// Highlight text with specified syntax
    pub fn highlight_text(&self, text: &str, syntax_name: &str) -> Vec<Line> {
        let syntax = self
            .syntax_set
            .find_syntax_by_name(syntax_name)
            .unwrap_or_else(|| self.syntax_set.find_syntax_plain_text());

        let theme = &self.theme_set.themes["base16-ocean.dark"];

        let mut lines = Vec::new();

        for line in LinesWithEndings::from(text) {
            let mut spans = Vec::new();
            let mut parsed = syntect::easy::HighlightLines::new(syntax, theme);
            let ranges = parsed
                .highlight_line(line, &self.syntax_set)
                .unwrap_or_default();

            for (style, text) in ranges {
                let color = Self::syntect_to_ratatui_color(style.foreground);
                spans.push(Span::styled(text.to_string(), Style::default().fg(color)));
            }

            lines.push(Line::from(spans));
        }

        lines
    }

    /// Convert syntect color to ratatui color
    fn syntect_to_ratatui_color(color: syntect::highlighting::Color) -> Color {
        Color::Rgb(color.r, color.g, color.b)
    }
}

impl Default for SyntaxHighlighter {
    fn default() -> Self {
        Self::new()
    }
}

/// Loading spinner widget
pub struct LoadingSpinner {
    message: String,
}

impl LoadingSpinner {
    /// Create a new loading spinner
    pub fn new(message: String) -> Self {
        Self { message }
    }

    /// Update the spinner state
    pub fn tick(&mut self) {
        // Throbber handles its own animation
    }
}

impl Widget for LoadingSpinner {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let block = Block::default().borders(Borders::ALL).title("Loading");

        let inner_area = block.inner(area);
        block.render(area, buf);

        // Render throbber (simple spinner character for now)
        let spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let spinner_idx = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            / 100) as usize
            % spinner_chars.len();
        let spinner = spinner_chars[spinner_idx];

        let throbber_area = Rect {
            x: inner_area.x + 2,
            y: inner_area.y + 1,
            width: 1,
            height: 1,
        };
        let spinner_widget = Paragraph::new(spinner.to_string());
        spinner_widget.render(throbber_area, buf);

        // Render message
        if inner_area.width > 6 {
            let message_area = Rect {
                x: inner_area.x + 6,
                y: inner_area.y + 1,
                width: inner_area.width.saturating_sub(6),
                height: 1,
            };
            let message = Paragraph::new(self.message);
            message.render(message_area, buf);
        }
    }
}

/// Error dialog widget
pub struct ErrorDialog {
    title: String,
    message: String,
}

impl ErrorDialog {
    /// Create a new error dialog
    pub fn new(title: String, message: String) -> Self {
        Self { title, message }
    }
}

impl Widget for ErrorDialog {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red));

        let paragraph = Paragraph::new(self.message)
            .block(block)
            .wrap(ratatui::widgets::Wrap { trim: true });

        paragraph.render(area, buf);
    }
}

/// Success dialog widget
pub struct SuccessDialog {
    title: String,
    message: String,
}

impl SuccessDialog {
    /// Create a new success dialog
    pub fn new(title: String, message: String) -> Self {
        Self { title, message }
    }
}

impl Widget for SuccessDialog {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green));

        let paragraph = Paragraph::new(self.message)
            .block(block)
            .wrap(ratatui::widgets::Wrap { trim: true });

        paragraph.render(area, buf);
    }
}

/// Status indicator widget
pub struct StatusIndicator {
    status: Status,
    label: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Status {
    Success,
    Warning,
    Error,
    Info,
}

impl StatusIndicator {
    /// Create a new status indicator
    pub fn new(status: Status, label: String) -> Self {
        Self { status, label }
    }
}

impl Widget for StatusIndicator {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 4 {
            return;
        }

        let (symbol, color) = match self.status {
            Status::Success => ("✓", Color::Green),
            Status::Warning => ("⚠", Color::Yellow),
            Status::Error => ("✗", Color::Red),
            Status::Info => ("ℹ", Color::Blue),
        };

        // Render symbol
        buf.set_string(area.x, area.y, symbol, Style::default().fg(color));

        // Render label if space allows
        if area.width > 4 {
            let label_width = area.width.saturating_sub(4);
            let label = if self.label.len() > label_width as usize {
                format!(
                    "{}...",
                    &self.label[..label_width.saturating_sub(3) as usize]
                )
            } else {
                self.label
            };
            buf.set_string(area.x + 2, area.y, label, Style::default().fg(Color::White));
        }
    }
}
