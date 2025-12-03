//! Error handling for FerroHSM TUI
//!
//! Provides structured error types and user-friendly error display.

#![allow(dead_code)]

use std::fmt;

/// Application error type
#[derive(Debug, Clone)]
pub enum AppError {
    /// Network or API errors
    Network(String),
    /// Configuration errors
    Config(String),
    /// Input validation errors
    Validation(String),
    /// Authentication errors
    Auth(String),
    /// Internal application errors
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Network(msg) => write!(f, "Network error: {}", msg),
            AppError::Config(msg) => write!(f, "Configuration error: {}", msg),
            AppError::Validation(msg) => write!(f, "Validation error: {}", msg),
            AppError::Auth(msg) => write!(f, "Authentication error: {}", msg),
            AppError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        AppError::Network(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Internal(format!("JSON parsing error: {}", err))
    }
}

/// Error display helper
pub struct ErrorDisplay {
    error: AppError,
}

impl ErrorDisplay {
    /// Create a new error display
    pub fn new(error: AppError) -> Self {
        Self { error }
    }

    /// Get user-friendly title
    pub fn title(&self) -> &str {
        match self.error {
            AppError::Network(_) => "Connection Error",
            AppError::Config(_) => "Configuration Error",
            AppError::Validation(_) => "Input Error",
            AppError::Auth(_) => "Authentication Error",
            AppError::Internal(_) => "Application Error",
        }
    }

    /// Get detailed error message
    pub fn message(&self) -> String {
        match &self.error {
            AppError::Network(msg) => format!("Failed to connect to FerroHSM server:\n\n{}", msg),
            AppError::Config(msg) => format!("Invalid configuration:\n\n{}", msg),
            AppError::Validation(msg) => format!("Invalid input:\n\n{}", msg),
            AppError::Auth(msg) => format!("Authentication failed:\n\n{}", msg),
            AppError::Internal(msg) => format!("An unexpected error occurred:\n\n{}", msg),
        }
    }

    /// Get suggested action
    pub fn suggestion(&self) -> &str {
        match self.error {
            AppError::Network(_) => "Check your network connection and server configuration.",
            AppError::Config(_) => {
                "Review your configuration file and ensure all required fields are set."
            }
            AppError::Validation(_) => "Check your input and try again.",
            AppError::Auth(_) => "Verify your credentials and try again.",
            AppError::Internal(_) => "Please report this issue to the developers.",
        }
    }
}
