# FerroHSM TUI Enhancement Plan

## Current State Analysis

The current TUI implementation is basic with only four views:
1. Dashboard - Welcome screen with navigation instructions
2. Keys - Placeholder for key management
3. Audit - Placeholder for audit logs
4. Approvals - Placeholder for approvals

The navigation is simple but limited to single-key shortcuts.

## Required Features

Based on the CLI capabilities, the TUI needs to support:

### Core Operations
1. **Key Management**
   - List keys with filtering (page, per-page, algorithm, state, tags)
   - Create new keys (algorithm selection, description, usage, tags)
   - View key details
   - Rotate keys
   - View key versions
   - Rollback to previous versions

2. **Cryptographic Operations**
   - Sign operations (key selection, payload input)
   - Encrypt operations (key selection, plaintext input)
   - Decrypt operations (key selection, ciphertext input)

3. **Approvals**
   - List pending approvals
   - Approve/deny approvals
   - View approval details

4. **Audit**
   - View audit logs
   - Verify audit log integrity

### Enhanced Navigation
- Menu-based navigation instead of single-key shortcuts
- Contextual help
- Status bar with connection information
- Error handling and user feedback

## Proposed Architecture

### New App Modes
1. **Main Menu** - Central navigation hub
2. **Keys List** - List and filter keys
3. **Key Details** - View key information and operations
4. **Key Creation** - Wizard for creating new keys
5. **Key Operations** - Sign/encrypt/decrypt operations
6. **Approvals List** - List and manage approvals
7. **Audit Viewer** - View and verify audit logs
8. **Settings** - Connection and authentication settings
9. **Help** - Documentation and keyboard shortcuts

### UI Components
1. **Navigation Bar** - Persistent menu at top/bottom
2. **Status Bar** - Connection status, current user, etc.
3. **Dialog Windows** - Modal dialogs for confirmation and input
4. **Forms** - Input forms for operations
5. **Tables** - For displaying lists of keys, approvals, etc.
6. **Text Areas** - For displaying large text content

### Data Management
1. **Connection Manager** - Handle API connections
2. **Key Cache** - Cache key information for performance
3. **State Management** - Track application state
4. **Error Handling** - Graceful error handling with user feedback

## Implementation Roadmap

### Phase 1: Foundation (1-2 weeks)
1. Redesign navigation system with menu-based approach
2. Implement connection management
3. Create basic key listing functionality
4. Add status bar with connection information

### Phase 2: Key Management (2-3 weeks)
1. Implement key listing with filtering
2. Add key details view
3. Implement key creation wizard
4. Add key rotation/version management

### Phase 3: Cryptographic Operations (2-3 weeks)
1. Implement sign operation interface
2. Implement encrypt/decrypt interfaces
3. Add input validation and error handling
4. Create result display components

### Phase 4: Approvals & Audit (1-2 weeks)
1. Implement approvals listing and management
2. Add audit log viewing
3. Implement audit verification

### Phase 5: Polish & Enhancements (1 week)
1. Add help system
2. Implement contextual help
3. Add keyboard shortcut reference
4. Polish UI and user experience

## Technical Considerations

### Dependencies
- Continue using Ratatui and Crossterm
- Add HTTP client for API communication (reqwest)
- Add JSON parsing (serde)
- Add form handling utilities

### State Management
- Use a central AppState struct
- Implement proper error handling
- Add loading states for async operations
- Cache data to improve responsiveness

### User Experience
- Provide clear feedback for all operations
- Implement undo/redo where appropriate
- Add confirmation dialogs for destructive operations
- Provide keyboard shortcuts for power users

## Success Metrics

1. **Feature Completeness** - All CLI features available in TUI
2. **Usability** - Intuitive navigation and clear feedback
3. **Performance** - Responsive interface with caching
4. **Reliability** - Proper error handling and recovery
5. **Accessibility** - Clear visual hierarchy and keyboard navigation

## Risks & Mitigations

1. **Complexity** - Break implementation into small, manageable pieces
2. **API Changes** - Design flexible architecture that can adapt to API changes
3. **Performance** - Implement caching and lazy loading
4. **User Adoption** - Provide clear documentation and tutorials