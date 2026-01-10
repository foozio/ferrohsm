# Spec: Web UI Dashboard

## Overview
Implement a browser-based management dashboard for FerroHSM to provide real-time visibility into the system's state, cryptographic keys, and security audits.

## Goals
- Provide an intuitive overview of the HSM status (online, sealed/unsealed, version).
- List active cryptographic keys with their metadata (algorithm, creation date, status).
- Display a feed of the most recent audit logs for security monitoring.
- Leverage the existing Axum server and static template structure.

## Requirements

### Backend (Rust/Axum)
- **Status API:** Endpoint to return system health and initialization status.
- **Keys API:** Endpoint to retrieve a list of active keys from the storage backend.
- **Audit API:** Endpoint to fetch the latest N audit entries from the tamper-evident log.
- **Static Asset Serving:** Configure Axum to serve the dashboard HTML, CSS, and JS.

### Frontend (HTML/JS/CSS)
- **Dashboard Layout:** A clean, professional layout consistent with FerroHSM's visual identity.
- **Status Widget:** Visual indicator of system health.
- **Keys Table:** Searchable/sortable list of keys.
- **Audit Feed:** Scrollable list of recent events with timestamps and severity.
- **Responsive Design:** Ensure the dashboard is usable on various screen sizes.

## Security Considerations
- **Authentication:** The dashboard must be protected by the existing JWT-based authentication.
- **Data Minimization:** Only expose necessary metadata; do not expose raw key material or sensitive secrets in the UI.
- **CSRF/XSS Protection:** Use standard web security best practices for the frontend implementation.
