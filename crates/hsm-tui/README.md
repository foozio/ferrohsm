# FerroHSM TUI

A Text-based User Interface for FerroHSM, providing an interactive terminal experience for managing your Hardware Security Module.

## Features

- Interactive dashboard with menu-based navigation
- Key management interface with full CRUD operations
- Cryptographic operations (sign, encrypt, decrypt)
- Audit log viewing and verification
- Approval workflow management
- Settings configuration
- Comprehensive help system

## Installation

The TUI application can be built and run using Cargo:

```bash
cargo build -p hsm-tui
cargo run -p hsm-tui
```

## Usage

After starting the application, you can navigate using these keys:

### Main Menu Navigation
- `↑`/`↓` - Navigate between menu items
- `Enter` - Select the current menu item
- `q` or `Esc` - Quit the application

### Within Views
- `q` or `Esc` - Return to the main menu

## Available Views

1. **Key Management** - List and manage cryptographic keys
2. **Create New Key** - Wizard for creating new keys
3. **Cryptographic Operations** - Sign, encrypt, and decrypt operations
4. **Approvals Management** - Manage dual-control approvals
5. **Audit Log Viewer** - View and verify audit logs
6. **Settings** - Configure connection and authentication settings
7. **Help** - Documentation and keyboard shortcuts

## Future Development

This enhanced implementation provides a foundation for a full-featured TUI that will eventually include:

- Integration with the HSM server API
- Real-time data display
- Interactive key creation and management
- Detailed audit log inspection
- Approval workflow controls
- Enhanced UI components and widgets