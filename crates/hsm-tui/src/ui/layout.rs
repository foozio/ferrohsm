//! Layout utilities for FerroHSM TUI
//!
//! Provides reusable layout patterns and constraints.

use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Standard application layout with header, content, and footer
pub fn app_layout(area: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Main content
            Constraint::Length(1), // Footer
        ])
        .split(area)
        .to_vec()
}

/// Two-column layout for side-by-side content
pub fn two_column_layout(area: Rect, left_ratio: u32, right_ratio: u32) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(left_ratio, left_ratio + right_ratio),
            Constraint::Ratio(right_ratio, left_ratio + right_ratio),
        ])
        .split(area)
        .to_vec()
}

/// Three-column layout
pub fn three_column_layout(area: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
        ])
        .split(area)
        .to_vec()
}

/// Centered content layout with margins
pub fn centered_layout(area: Rect, width: u16, height: u16) -> Rect {
    let horizontal_margin = (area.width.saturating_sub(width)) / 2;
    let vertical_margin = (area.height.saturating_sub(height)) / 2;

    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(vertical_margin),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area)[1];

    let centered = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(horizontal_margin),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(area)[1];

    centered
}

/// Dialog layout with title area and content
pub fn dialog_layout(area: Rect) -> [Rect; 2] {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(0),    // Content
        ])
        .split(area)
        .as_ref()
        .try_into()
        .unwrap()
}

/// Form layout with label and input areas
pub fn form_row_layout(area: Rect) -> [Rect; 2] {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(20), // Label width
            Constraint::Min(0),     // Input area
        ])
        .split(area)
        .as_ref()
        .try_into()
        .unwrap()
}

/// List layout with optional search bar
pub fn list_with_search_layout(area: Rect, has_search: bool) -> Vec<Rect> {
    let mut constraints = vec![];

    if has_search {
        constraints.push(Constraint::Length(3)); // Search bar
    }

    constraints.push(Constraint::Min(0)); // List area

    Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area)
        .to_vec()
}

/// Tab layout for multiple views
pub fn tab_layout(area: Rect) -> [Rect; 2] {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Tab bar
            Constraint::Min(0),    // Tab content
        ])
        .split(area)
        .as_ref()
        .try_into()
        .unwrap()
}