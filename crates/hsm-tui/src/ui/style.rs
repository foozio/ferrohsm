//! Styling and theming for FerroHSM TUI
//!
//! Provides color schemes and styling utilities.

#![allow(dead_code)]

use ratatui::style::{Color as RatatuiColor, Style};
use serde::{Deserialize, Serialize};

/// Serializable color wrapper for ratatui colors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Color {
    #[serde(flatten)]
    inner: ColorRepr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
enum ColorRepr {
    Reset,
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    Gray,
    DarkGray,
    LightRed,
    LightGreen,
    LightYellow,
    LightBlue,
    LightMagenta,
    LightCyan,
    White,
    Rgb(u8, u8, u8),
    Indexed(u8),
}

impl From<Color> for RatatuiColor {
    fn from(color: Color) -> Self {
        match color.inner {
            ColorRepr::Reset => RatatuiColor::Reset,
            ColorRepr::Black => RatatuiColor::Black,
            ColorRepr::Red => RatatuiColor::Red,
            ColorRepr::Green => RatatuiColor::Green,
            ColorRepr::Yellow => RatatuiColor::Yellow,
            ColorRepr::Blue => RatatuiColor::Blue,
            ColorRepr::Magenta => RatatuiColor::Magenta,
            ColorRepr::Cyan => RatatuiColor::Cyan,
            ColorRepr::Gray => RatatuiColor::Gray,
            ColorRepr::DarkGray => RatatuiColor::DarkGray,
            ColorRepr::LightRed => RatatuiColor::LightRed,
            ColorRepr::LightGreen => RatatuiColor::LightGreen,
            ColorRepr::LightYellow => RatatuiColor::LightYellow,
            ColorRepr::LightBlue => RatatuiColor::LightBlue,
            ColorRepr::LightMagenta => RatatuiColor::LightMagenta,
            ColorRepr::LightCyan => RatatuiColor::LightCyan,
            ColorRepr::White => RatatuiColor::White,
            ColorRepr::Rgb(r, g, b) => RatatuiColor::Rgb(r, g, b),
            ColorRepr::Indexed(i) => RatatuiColor::Indexed(i),
        }
    }
}

impl From<RatatuiColor> for Color {
    fn from(color: RatatuiColor) -> Self {
        let inner = match color {
            RatatuiColor::Reset => ColorRepr::Reset,
            RatatuiColor::Black => ColorRepr::Black,
            RatatuiColor::Red => ColorRepr::Red,
            RatatuiColor::Green => ColorRepr::Green,
            RatatuiColor::Yellow => ColorRepr::Yellow,
            RatatuiColor::Blue => ColorRepr::Blue,
            RatatuiColor::Magenta => ColorRepr::Magenta,
            RatatuiColor::Cyan => ColorRepr::Cyan,
            RatatuiColor::Gray => ColorRepr::Gray,
            RatatuiColor::DarkGray => ColorRepr::DarkGray,
            RatatuiColor::LightRed => ColorRepr::LightRed,
            RatatuiColor::LightGreen => ColorRepr::LightGreen,
            RatatuiColor::LightYellow => ColorRepr::LightYellow,
            RatatuiColor::LightBlue => ColorRepr::LightBlue,
            RatatuiColor::LightMagenta => ColorRepr::LightMagenta,
            RatatuiColor::LightCyan => ColorRepr::LightCyan,
            RatatuiColor::White => ColorRepr::White,
            RatatuiColor::Rgb(r, g, b) => ColorRepr::Rgb(r, g, b),
            RatatuiColor::Indexed(i) => ColorRepr::Indexed(i),
        };
        Self { inner }
    }
}

/// UI theme with customizable colors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Theme {
    /// Primary color for headers and highlights
    pub primary: Color,
    /// Secondary color for borders and accents
    pub secondary: Color,
    /// Accent color for buttons and links
    pub accent: Color,
    /// Error color for warnings and errors
    pub error: Color,
    /// Success color for confirmations
    pub success: Color,
    /// Text color for normal text
    pub text: Color,
    /// Background color
    pub background: Color,
    /// Muted text color
    pub muted: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            primary: RatatuiColor::Blue.into(),
            secondary: RatatuiColor::Gray.into(),
            accent: RatatuiColor::Green.into(),
            error: RatatuiColor::Red.into(),
            success: RatatuiColor::Green.into(),
            text: RatatuiColor::White.into(),
            background: RatatuiColor::Black.into(),
            muted: RatatuiColor::DarkGray.into(),
        }
    }
}

impl Theme {
    /// Get style for primary elements
    pub fn primary_style(&self) -> Style {
        Style::default().fg(self.primary.clone().into())
    }

    /// Get style for secondary elements
    pub fn secondary_style(&self) -> Style {
        Style::default().fg(self.secondary.clone().into())
    }

    /// Get style for accent elements
    pub fn accent_style(&self) -> Style {
        Style::default().fg(self.accent.clone().into())
    }

    /// Get style for error elements
    pub fn error_style(&self) -> Style {
        Style::default().fg(self.error.clone().into())
    }

    /// Get style for success elements
    pub fn success_style(&self) -> Style {
        Style::default().fg(self.success.clone().into())
    }

    /// Get style for normal text
    pub fn text_style(&self) -> Style {
        Style::default().fg(self.text.clone().into())
    }

    /// Get style for muted text
    pub fn muted_style(&self) -> Style {
        Style::default().fg(self.muted.clone().into())
    }

    /// Get style for headers
    pub fn header_style(&self) -> Style {
        Style::default()
            .fg(self.text.clone().into())
            .bg(self.primary.clone().into())
    }

    /// Get style for footers
    pub fn footer_style(&self) -> Style {
        Style::default()
            .fg(self.text.clone().into())
            .bg(self.secondary.clone().into())
    }

    /// Get style for highlighted elements (e.g. selected list items)
    pub fn highlight_style(&self) -> Style {
        Style::default()
            .fg(self.background.clone().into())
            .bg(self.primary.clone().into())
    }
}

/// Dark theme preset
pub fn dark_theme() -> Theme {
    Theme::default()
}

/// Light theme preset
pub fn light_theme() -> Theme {
    Theme {
        primary: RatatuiColor::Blue.into(),
        secondary: RatatuiColor::Gray.into(),
        accent: RatatuiColor::Green.into(),
        error: RatatuiColor::Red.into(),
        success: RatatuiColor::Green.into(),
        text: RatatuiColor::Black.into(),
        background: RatatuiColor::White.into(),
        muted: RatatuiColor::Gray.into(),
    }
}

/// Monokai-inspired theme
pub fn monokai_theme() -> Theme {
    Theme {
        primary: RatatuiColor::Rgb(249, 38, 114).into(), // Pink
        secondary: RatatuiColor::Rgb(102, 217, 239).into(), // Cyan
        accent: RatatuiColor::Rgb(166, 226, 46).into(),  // Green
        error: RatatuiColor::Rgb(249, 38, 114).into(),   // Pink
        success: RatatuiColor::Rgb(166, 226, 46).into(), // Green
        text: RatatuiColor::Rgb(248, 248, 242).into(),   // Light gray
        background: RatatuiColor::Rgb(39, 40, 34).into(), // Dark gray
        muted: RatatuiColor::Rgb(117, 113, 94).into(),   // Gray
    }
}
