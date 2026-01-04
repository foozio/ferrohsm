# Plan: Web UI Dashboard

## Phase 1: Foundation and Backend API [checkpoint: eae586b]

- [x] **Task: Setup basic Axum routes and static file serving** e8d233d
  - Write tests for static file serving in `hsm-server`.
  - Implement Axum routes to serve `web/templates/dashboard.html` and `web/static/styles.css`.
- [x] **Task: Implement HSM Status API endpoint** d7e3e71
  - Write tests for the status endpoint.
  - Implement `/api/v1/status` in `hsm-server` returning system health and version.
- [x] **Task: Implement Active Keys API endpoint** 95627d7
  - Write tests for the keys listing endpoint.
  - Implement `/api/v1/keys` in `hsm-server` to return metadata for active keys.
- [x] **Task: Implement Recent Audit Logs API endpoint** c3e94e3
  - Write tests for the audit log endpoint.
  - Implement `/api/v1/audit/recent` in `hsm-server` to return the last 50 audit entries.
- [x] **Task: Conductor - User Manual Verification 'Foundation and Backend API' (Protocol in workflow.md)**

## Phase 2: Frontend Dashboard Implementation

- [x] **Task: Create dashboard HTML structure** bd10c86
  - Implement the basic HTML layout in `web/templates/dashboard.html` using the existing `layout.html`.
- [~] **Task: Implement Status visualization**
  - Write JS to fetch `/api/v1/status` and update the UI with system health.
- [ ] **Task: Implement Keys table**
  - Write JS to fetch `/api/v1/keys` and render the list of keys in a table.
- [ ] **Task: Implement Audit log feed**
  - Write JS to fetch `/api/v1/audit/recent` and display the audit trail.
- [ ] **Task: Conductor - User Manual Verification 'Frontend Dashboard Implementation' (Protocol in workflow.md)**

## Phase 3: Integration and Refinement

- [ ] **Task: Apply consistent styling and responsiveness**
  - Update `web/static/styles.css` to ensure a professional look and mobile responsiveness.
- [ ] **Task: Final security review and UX polish**
  - Verify JWT authentication is enforced for all dashboard routes and APIs.
  - Add loading states and error handling to the frontend.
- [ ] **Task: Conductor - User Manual Verification 'Integration and Refinement' (Protocol in workflow.md)**
