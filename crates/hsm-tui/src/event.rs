//! Event handling for FerroHSM TUI
//!
//! Provides event processing with crokey key binding support.

#![allow(dead_code)]

use crate::ui::input::{KeyAction, KeyBindings};
use anyhow::Result;
use crokey::{crossterm::event::{self, Event, KeyEvent, KeyCode}, KeyCombination};

/// Event result from the event loop
#[derive(Debug, Clone)]
pub enum EventResult {
    Action(KeyAction),
    Char(char),
}

/// Event handler for the application
#[derive(Debug)]
pub struct EventHandler {
    key_bindings: KeyBindings,
}

impl EventHandler {
    /// Create a new event handler
    pub fn new(key_bindings: KeyBindings) -> Self {
        Self { key_bindings }
    }

    /// Wait for and process the next event
    pub fn next_event(&self) -> Result<Option<KeyAction>> {
        loop {
            match event::read()? {
                Event::Key(key_event) => {
                    if let Some(action) = self.handle_key_event(key_event) {
                        return Ok(Some(action));
                    }
                }
                Event::Resize(_, _) => {
                    // Handle resize events if needed
                    continue;
                }
                _ => continue,
            }
        }
    }

    /// Handle a key event
    fn handle_key_event(&self, key_event: KeyEvent) -> Option<KeyAction> {
        let key_combination = KeyCombination::from(key_event);
        self.key_bindings.matches(&key_combination)
    }
}

/// Event loop helper
#[derive(Debug)]
pub struct EventLoop {
    handler: EventHandler,
}

impl EventLoop {
    /// Create a new event loop
    pub fn new(key_bindings: KeyBindings) -> Self {
        Self {
            handler: EventHandler::new(key_bindings),
        }
    }

    /// Get the next event
    pub fn next_event(&self) -> Result<Option<EventResult>> {
        loop {
            match event::read()? {
                Event::Key(key_event) => {
                    if let Some(action) = self.handler.handle_key_event(key_event) {
                        return Ok(Some(EventResult::Action(action)));
                    } else if let KeyCode::Char(c) = key_event.code {
                        return Ok(Some(EventResult::Char(c)));
                    }
                }
                Event::Resize(_, _) => {
                    // Handle resize events if needed
                    continue;
                }
                _ => continue,
            }
        }
    }

    /// Run the event loop
    pub fn run<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(KeyAction) -> Result<bool>, // Returns true to continue, false to exit
    {
        loop {
            match event::read()? {
                Event::Key(key_event) => {
                    if let Some(action) = self.handler.handle_key_event(key_event)
                        && !callback(action)?
                    {
                        break;
                    }
                }
                Event::Resize(_, _) => {
                    // Handle resize events if needed
                    continue;
                }
                _ => continue,
            }
        }
        Ok(())
    }
}
