//! Input handling and key bindings for FerroHSM TUI
//!
//! Provides advanced key binding support using crokey.

#![allow(dead_code)]

use crokey::KeyCombination;
use serde::{Deserialize, Serialize};

/// Key bindings configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBindings {
    /// Quit application
    pub quit: KeyCombination,
    /// Navigate up
    pub navigate_up: KeyCombination,
    /// Navigate down
    pub navigate_down: KeyCombination,
    /// Navigate left
    pub navigate_left: KeyCombination,
    /// Navigate right
    pub navigate_right: KeyCombination,
    /// Select/confirm
    pub select: KeyCombination,
    /// Go back/cancel
    pub back: KeyCombination,
    /// Next page
    pub next_page: KeyCombination,
    /// Previous page
    pub prev_page: KeyCombination,
    /// Help
    pub help: KeyCombination,
    /// Search
    pub search: KeyCombination,
    /// Create new item
    pub create: KeyCombination,
    /// Edit current item
    pub edit: KeyCombination,
    /// Delete current item
    pub delete: KeyCombination,
    /// Refresh data
    pub refresh: KeyCombination,
}

impl Default for KeyBindings {
    fn default() -> Self {
        Self {
            quit: "q".parse().unwrap(),
            navigate_up: "k".parse().unwrap(), // vim-style by default
            navigate_down: "j".parse().unwrap(),
            navigate_left: "h".parse().unwrap(),
            navigate_right: "l".parse().unwrap(),
            select: "enter".parse().unwrap(),
            back: "esc".parse().unwrap(),
            next_page: "n".parse().unwrap(),
            prev_page: "p".parse().unwrap(),
            help: "?".parse().unwrap(),
            search: "/".parse().unwrap(),
            create: "c".parse().unwrap(),
            edit: "e".parse().unwrap(),
            delete: "d".parse().unwrap(),
            refresh: "r".parse().unwrap(),
        }
    }
}

impl KeyBindings {
    /// Create arrow-key based bindings (alternative to vim)
    pub fn arrow_keys() -> Self {
        Self {
            navigate_up: "up".parse().unwrap(),
            navigate_down: "down".parse().unwrap(),
            navigate_left: "left".parse().unwrap(),
            navigate_right: "right".parse().unwrap(),
            ..Self::default()
        }
    }

    /// Check if a key combination matches any binding
    pub fn matches(&self, key: &KeyCombination) -> Option<KeyAction> {
        if *key == self.quit {
            Some(KeyAction::Quit)
        } else if *key == self.navigate_up {
            Some(KeyAction::NavigateUp)
        } else if *key == self.navigate_down {
            Some(KeyAction::NavigateDown)
        } else if *key == self.navigate_left {
            Some(KeyAction::NavigateLeft)
        } else if *key == self.navigate_right {
            Some(KeyAction::NavigateRight)
        } else if *key == self.select {
            Some(KeyAction::Select)
        } else if *key == self.back {
            Some(KeyAction::Back)
        } else if *key == self.next_page {
            Some(KeyAction::NextPage)
        } else if *key == self.prev_page {
            Some(KeyAction::PrevPage)
        } else if *key == self.help {
            Some(KeyAction::Help)
        } else if *key == self.search {
            Some(KeyAction::Search)
        } else if *key == self.create {
            Some(KeyAction::Create)
        } else if *key == self.edit {
            Some(KeyAction::Edit)
        } else if *key == self.delete {
            Some(KeyAction::Delete)
        } else if *key == self.refresh {
            Some(KeyAction::Refresh)
        } else {
            None
        }
    }
}

/// Actions that can be triggered by key bindings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Quit,
    NavigateUp,
    NavigateDown,
    NavigateLeft,
    NavigateRight,
    Select,
    Back,
    NextPage,
    PrevPage,
    Help,
    Search,
    Create,
    Edit,
    Delete,
    Refresh,
}