//! Reusable UI components for FerroHSM TUI
//!
//! Provides common UI patterns like headers, footers, menus, and forms.

#![allow(dead_code)]

use crate::ui::style::Theme;
use crate::ui::widgets::{ErrorDialog, LoadingSpinner, StatusIndicator, SuccessDialog};
use ratatui::{
    layout::{Alignment, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
    Frame,
};
use std::collections::HashMap;

/// Application header component
pub struct Header {
    title: String,
    theme: Theme,
}

impl Header {
    pub fn new(title: String, theme: Theme) -> Self {
        Self { title, theme }
    }

    pub fn render(&self, f: &mut Frame, area: Rect) {
        let header = Paragraph::new(&*self.title)
            .style(self.theme.header_style())
            .alignment(Alignment::Center);
        f.render_widget(header, area);
    }
}

/// Application footer component
pub struct Footer {
    text: String,
    theme: Theme,
}

impl Footer {
    pub fn new(text: String, theme: Theme) -> Self {
        Self { text, theme }
    }

    pub fn render(&self, f: &mut Frame, area: Rect) {
        let footer = Paragraph::new(&*self.text)
            .style(self.theme.footer_style())
            .alignment(Alignment::Center);
        f.render_widget(footer, area);
    }
}

/// Main menu component
#[derive(Debug)]
pub struct MainMenu {
    items: Vec<String>,
    selected: usize,
    theme: Theme,
}

impl MainMenu {
    pub fn new(items: Vec<String>, theme: Theme) -> Self {
        Self {
            items,
            selected: 0,
            theme,
        }
    }

    pub fn select(&mut self, index: usize) {
        if index < self.items.len() {
            self.selected = index;
        }
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn next(&mut self) {
        self.selected = (self.selected + 1) % self.items.len();
    }

    pub fn previous(&mut self) {
        if self.selected == 0 {
            self.selected = self.items.len() - 1;
        } else {
            self.selected -= 1;
        }
    }

    pub fn render(&self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let style = if i == self.selected {
                    self.theme.accent_style()
                } else {
                    self.theme.text_style()
                };
                ListItem::new(item.clone()).style(style)
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Main Menu")
                    .border_style(self.theme.secondary_style()),
            )
            .highlight_style(self.theme.primary_style())
            .highlight_symbol(">> ");

        f.render_widget(list, area);
    }
}

/// Help panel component
#[derive(Debug)]
pub struct HelpPanel {
    shortcuts: HashMap<String, String>,
    theme: Theme,
}

impl HelpPanel {
    pub fn new(theme: Theme) -> Self {
        Self {
            shortcuts: HashMap::new(),
            theme,
        }
    }

    pub fn add_shortcut(&mut self, key: String, description: String) {
        self.shortcuts.insert(key, description);
    }

    pub fn clear(&mut self) {
        self.shortcuts.clear();
    }

    pub fn render(&self, f: &mut Frame, area: Rect) {
        let mut lines = Vec::new();

        lines.push(Line::from(Span::styled(
            "Keyboard Shortcuts",
            self.theme.primary_style(),
        )));
        lines.push(Line::from(""));

        for (key, desc) in &self.shortcuts {
            lines.push(Line::from(vec![
                Span::styled(format!("{:<12}", key), self.theme.accent_style()),
                Span::styled(desc, self.theme.text_style()),
            ]));
        }

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Help")
                    .border_style(self.theme.secondary_style()),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });

        f.render_widget(paragraph, area);
    }
}

/// Status bar component
pub struct StatusBar {
    left_text: String,
    right_text: String,
    theme: Theme,
}

impl StatusBar {
    pub fn new(left_text: String, right_text: String, theme: Theme) -> Self {
        Self {
            left_text,
            right_text,
            theme,
        }
    }

    pub fn render(&self, f: &mut Frame, area: Rect) {
        let left_span = Span::styled(&self.left_text, self.theme.text_style());
        let right_span = Span::styled(&self.right_text, self.theme.muted_style());

        let line = Line::from(vec![left_span, Span::raw(" | "), right_span]);

        let paragraph = Paragraph::new(line)
            .style(self.theme.footer_style())
            .alignment(Alignment::Left);

        f.render_widget(paragraph, area);
    }
}

/// Modal dialog base component
#[allow(clippy::type_complexity)]
pub struct Modal {
    title: String,
    content: Box<dyn Fn(&mut Frame, Rect)>,
    theme: Theme,
}

impl Modal {
    pub fn new<F>(title: String, content_fn: F, theme: Theme) -> Self
    where
        F: Fn(&mut Frame, Rect) + 'static,
    {
        Self {
            title,
            content: Box::new(content_fn),
            theme,
        }
    }

    pub fn render(&self, f: &mut Frame, area: Rect) {
        // Clear the background
        f.render_widget(Clear, area);

        // Render the modal content
        let block = Block::default()
            .title(&*self.title)
            .borders(Borders::ALL)
            .border_style(self.theme.primary_style());

        let inner_area = block.inner(area);
        f.render_widget(block, area);

        // Render the content
        (self.content)(f, inner_area);
    }
}

/// Quick access functions for common components
pub fn render_error_dialog(f: &mut Frame, area: Rect, title: &str, message: &str) {
    let dialog = ErrorDialog::new(title.to_string(), message.to_string());
    f.render_widget(dialog, area);
}

pub fn render_success_dialog(f: &mut Frame, area: Rect, title: &str, message: &str) {
    let dialog = SuccessDialog::new(title.to_string(), message.to_string());
    f.render_widget(dialog, area);
}

pub fn render_loading_spinner(f: &mut Frame, area: Rect, message: &str) {
    let spinner = LoadingSpinner::new(message.to_string());
    f.render_widget(spinner, area);
}

pub fn render_status_indicator(f: &mut Frame, area: Rect, status: crate::ui::widgets::Status, label: &str) {
    let indicator = StatusIndicator::new(status, label.to_string());
    f.render_widget(indicator, area);
}