# FerroHSM TUI

A Text-based User Interface for FerroHSM, providing an interactive terminal experience for managing your Hardware Security Module.

## Features

- Interactive dashboard for monitoring HSM status
- Key management interface
- Audit log viewing
- Approval workflow management
- Keyboard navigation

## Installation

The TUI application can be built and run using Cargo:

```bash
cargo build -p hsm-tui
cargo run -p hsm-tui
```

## Usage

After starting the application, you can navigate using these keys:

- `d` - Dashboard view
- `k` - Keys management view
- `a` - Audit logs view
- `p` - Approvals view
- `q` or `Esc` - Quit the application

## Future Development

This is a basic implementation that demonstrates the TUI concept. Future enhancements could include:

- Integration with the HSM server API
- Real-time data display
- Interactive key creation and management
- Detailed audit log inspection
- Approval workflow controls