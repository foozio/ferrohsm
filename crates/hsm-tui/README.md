# FerroHSM TUI

A comprehensive Text-based User Interface for FerroHSM, providing an interactive terminal experience for managing your Hardware Security Module with full access to all HSM features.

## Features

- **Interactive Dashboard**: Menu-based navigation with real-time status
- **Complete Key Lifecycle Management**: Generate, list, view, rotate, rollback, revoke, and destroy keys
- **Cryptographic Operations**: Sign, verify, encrypt, decrypt with algorithm support including post-quantum
- **Approval Workflows**: Manage dual-control approvals with real-time updates
- **Audit Log Management**: View, search, filter, and verify audit logs
- **Advanced Settings**: Connection configuration, authentication, themes
- **Comprehensive Help**: Context-sensitive help and keyboard shortcuts
- **Multi-algorithm Support**: Classical, post-quantum, and hybrid cryptographic algorithms

## Installation

The TUI application can be built and run using Cargo:

```bash
cargo build -p hsm-tui
cargo run -p hsm-tui
```

For release builds:
```bash
cargo build -p hsm-tui --release
./target/release/hsm-tui
```

## Command Line Options

```bash
cargo run -p hsm-tui -- --help
```

Available options:
- `--endpoint <URL>`: HSM server endpoint (default: https://localhost:8443)
- `--client-cert <PATH>`: Client certificate for mutual TLS
- `--client-key <PATH>`: Client private key for mutual TLS
- `--ca-bundle <PATH>`: Custom CA bundle path
- `--config <PATH>`: Configuration file path

## Authentication

Upon startup, the TUI will prompt for authentication credentials. Supported methods:
- Username/password authentication
- Certificate-based authentication (when client cert provided)
- Session-based authentication with automatic renewal

## Main Interface

### Navigation
- `↑`/`↓` or `j`/`k`: Navigate menu items
- `Enter` or `l`: Select current item
- `q` or `Esc`: Quit or return to previous screen
- `?`: Show context-sensitive help
- `Ctrl+C`: Force quit

### Main Menu Options

1. **🔑 Key Management**
2. **➕ Create New Key**
3. **🔐 Cryptographic Operations**
4. **✅ Approvals Management**
5. **📝 Audit Log Viewer**
6. **⚙️ Settings**
7. **❓ Help**
8. **🚪 Quit**

## Detailed Usage Guide

### Key Management

**Purpose**: View, search, and manage all cryptographic keys in the HSM.

**Navigation**:
- `↑`/`↓`: Navigate key list
- `Enter`: View key details
- `c`: Create new key
- `r`: Rotate selected key
- `v`: View key versions
- `d`: Destroy selected key
- `/`: Search/filter keys
- `Esc`: Return to main menu

**Features**:
- **Search & Filter**: Filter by algorithm, state, policy tags
- **Pagination**: Navigate through large key lists
- **Key Details**: View metadata, usage, creation time, state
- **Version History**: View all versions of a key
- **Bulk Operations**: Select multiple keys for batch operations

**Key States**:
- 🟢 **Active**: Key is operational
- 🟡 **Staged**: Key pending activation
- 🔴 **Revoked**: Key deactivated but retained
- ⚫ **Destroyed**: Key permanently removed

### Create New Key

**Purpose**: Generate new cryptographic keys with full configuration options.

**Wizard Steps**:
1. **Algorithm Selection**: Choose from supported algorithms:
   - Classical: AES-256-GCM, RSA-2048/4096, EC P-256/P-384
   - Post-Quantum: ML-KEM, ML-DSA, SLH-DSA variants
   - Hybrid: Combined classical + post-quantum

2. **Usage Configuration**: Select key purposes:
   - Encrypt/Decrypt
   - Sign/Verify
   - Wrap/Unwrap

3. **Policy Tags**: Assign policy tags for access control

4. **Description**: Optional human-readable description

5. **Confirmation**: Review and generate

**Navigation**:
- `Tab`: Move between form fields
- `↑`/`↓`: Navigate within lists/dropdowns
- `Enter`: Select/confirm
- `Esc`: Cancel wizard

### Cryptographic Operations

**Purpose**: Perform cryptographic operations using HSM keys.

**Supported Operations**:
- **Sign**: Generate digital signatures
- **Verify**: Verify digital signatures
- **Encrypt**: Encrypt data with authenticated encryption
- **Decrypt**: Decrypt data

**Workflow**:
1. Select operation type
2. Choose key (filtered by compatible algorithms)
3. Input data (text, file, hex)
4. Configure operation parameters (AAD, etc.)
5. Execute operation
6. View results

**Navigation**:
- `Tab`: Switch between input fields
- `Ctrl+V`: Paste from clipboard
- `Ctrl+O`: Load from file
- `Enter`: Execute operation

### Approvals Management

**Purpose**: Manage dual-control approval workflows.

**Features**:
- View pending approvals requiring your action
- Approve or deny approval requests
- View approval history
- Real-time updates for new approvals

**Approval Types**:
- Key generation approvals
- Key destruction approvals
- Policy changes
- Administrative operations

**Navigation**:
- `↑`/`↓`: Navigate approval list
- `a`: Approve selected
- `d`: Deny selected
- `Enter`: View approval details
- `r`: Refresh list

### Audit Log Viewer

**Purpose**: View and analyze HSM audit logs.

**Features**:
- Chronological log viewing
- Search by actor, action, key ID
- Filter by date range, event type
- Log verification and integrity checking
- Export capabilities

**Navigation**:
- `↑`/`↓`: Scroll through logs
- `/`: Search logs
- `f`: Apply filters
- `v`: Verify log integrity
- `e`: Export logs

### Settings

**Purpose**: Configure TUI behavior and HSM connection.

**Configuration Options**:
- **Connection**: Server endpoint, TLS settings
- **Authentication**: Credentials, certificates
- **Display**: Theme selection, layout preferences
- **Behavior**: Auto-refresh intervals, confirmation prompts

**Navigation**:
- `↑`/`↓`: Navigate settings
- `Enter`: Edit setting
- `s`: Save configuration
- `r`: Reset to defaults

### Help System

**Purpose**: Access comprehensive documentation and shortcuts.

**Features**:
- Context-sensitive help
- Keyboard shortcut reference
- Feature documentation
- Troubleshooting guides

## Advanced Features

### Post-Quantum Cryptography

The TUI fully supports post-quantum algorithms:
- **ML-KEM**: Key encapsulation mechanisms
- **ML-DSA**: Digital signature algorithms
- **SLH-DSA**: Stateless hash-based signatures
- **Hybrid**: Classical + post-quantum combinations

### Real-Time Updates

- Automatic refresh of dynamic data
- Live approval notifications
- Key state change monitoring
- Connection status indicators

### Error Handling

- Comprehensive error dialogs with recovery options
- Network error recovery
- Authentication renewal prompts
- Data validation feedback

### Keyboard Shortcuts

**Global**:
- `Ctrl+C`: Force quit
- `F1`: Help
- `F5`: Refresh current view

**Navigation**:
- `h`/`j`/`k`/`l`: Vim-style navigation
- `gg`: Go to top
- `G`: Go to bottom
- `Ctrl+U`/`Ctrl+D`: Page up/down

**Actions**:
- `n`: New/Create
- `e`: Edit
- `d`: Delete/Destroy
- `y`: Confirm/Yes
- `N`: Cancel/No

## Troubleshooting

### Connection Issues
- Verify HSM server is running and accessible
- Check TLS certificate configuration
- Review network connectivity

### Authentication Problems
- Ensure valid credentials
- Check certificate validity
- Verify user permissions

### Performance Issues
- Use pagination for large datasets
- Adjust refresh intervals in settings
- Check network latency

## Development

The TUI is built with:
- **Ratatui**: Terminal UI framework
- **Crossterm**: Cross-platform terminal manipulation
- **Tokio**: Async runtime for API calls
- **Serde**: Data serialization

For development:
```bash
cargo build -p hsm-tui
cargo test -p hsm-tui
cargo clippy -p hsm-tui
```