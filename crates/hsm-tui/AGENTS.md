# HSM TUI Agent Guidelines

## Overview
Advanced text-based user interface with ATAC-inspired modular design, syntax highlighting, customizable themes, and comprehensive key management capabilities. Now includes full HSM server integration with authentication, real-time key management, cryptographic operations, approval workflows, and audit log viewing.

## Key Responsibilities
- JWT-based authentication with token persistence and RBAC display
- Interactive key management with table views, search, pagination, and details
- Key creation wizard with algorithm selection and policy configuration
- Cryptographic operation execution (sign/encrypt/decrypt)
- Approval workflow management with real-time updates
- Audit log viewing with filtering and pagination
- Settings and configuration management with TLS support

## Development Commands
- `cargo run -p hsm-tui` - Start TUI application
- `cargo test --package hsm-tui` - Run TUI tests
- `cargo test --package hsm-tui -- --nocapture` - Run tests with output
- `cargo run -p hsm-tui -- --help` - Show TUI options

## UI Architecture
- **Components**: Modular widget system in `ui/` directory
- **Events**: Async event handling with `crossterm`
- **Styling**: Theme-based styling with `ratatui`
- **Layout**: Responsive layout management
- **Navigation**: Keyboard-driven navigation patterns

## Code Organization
- `ui/components.rs` - Reusable UI components
- `ui/widgets.rs` - Custom widget implementations
- `ui/style.rs` - Theme and styling definitions
- `ui/input.rs` - Input handling and validation
- `event.rs` - Event loop and message passing
- `config.rs` - Configuration management

## Testing
- Unit tests for UI components
- Integration tests for user workflows
- E2E tests in `tests/e2e.rs`
- Event handling tests
- Layout and rendering tests

## Dependencies
- `ratatui` for terminal UI framework
- `crossterm` for terminal event handling
- `tokio` for async operations
- `serde` for configuration serialization
- Keep dependencies minimal for fast compilation</content>
<parameter name="filePath">/home/ubuntu/codes/ferrohsm/crates/hsm-tui/AGENTS.md