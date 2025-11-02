//! UI module for FerroHSM TUI
//!
//! This module provides a modular UI architecture inspired by ATAC,
//! with separate concerns for components, input handling, layout, styling, and widgets.

pub mod components;
pub mod input;
pub mod layout;
pub mod style;
pub mod widgets;

// Re-export commonly used items
pub use components::*;
pub use input::*;
pub use layout::*;
pub use style::*;
pub use widgets::*;