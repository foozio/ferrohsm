document.addEventListener('DOMContentLoaded', () => {
    // Initial loading indicators
    document.getElementById('keys-table-body').innerHTML = '<tr><td colspan="5" class="empty">Loading keys...</td></tr>';
    const auditBody = document.getElementById('audit-table-body');
    if (auditBody) auditBody.innerHTML = '<tr><td colspan="6" class="empty">Loading audit logs...</td></tr>';

    fetchSystemStatus();
    fetchKeys();
    fetchAuditLogs();
    // Refresh status and keys periodically
    setInterval(fetchSystemStatus, 30000);
    setInterval(fetchKeys, 60000);
    setInterval(fetchAuditLogs, 60000);
});

async function fetchAuditLogs() {
    const tableBody = document.getElementById('audit-table-body');
    if (!tableBody) return;

    try {
        const response = await fetch('/api/v1/audit/recent');
        if (!response.ok) {
            if (response.status === 403) {
                tableBody.innerHTML = '<tr><td colspan="6" class="empty">Access denied to audit logs</td></tr>';
                return;
            }
            throw new Error('Audit API unreachable');
        }
        
        const events = await response.json();
        
        if (events.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="6" class="empty">No recent audit events</td></tr>';
            return;
        }

        tableBody.innerHTML = events.map(event => `
            <tr>
                <td>${escapeHtml(formatDate(event.timestamp))}</td>
                <td>${escapeHtml(event.actor_id)}</td>
                <td>${escapeHtml(event.action)}</td>
                <td>${escapeHtml(event.key_id || '-')}</td>
                <td>${escapeHtml(event.message)}</td>
                <td><span class="audit-hash" title="${escapeHtml(event.hash)}">${escapeHtml(event.hash.substring(0, 12))}...</span></td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Failed to fetch audit logs:', error);
        tableBody.innerHTML = '<tr><td colspan="6" class="empty error-text">Failed to load audit logs</td></tr>';
    }
}

async function fetchKeys() {
    const tableBody = document.getElementById('keys-table-body');
    if (!tableBody) return;

    try {
        const response = await fetch('/api/v1/keys');
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                tableBody.innerHTML = '<tr><td colspan="5" class="empty">Authentication required</td></tr>';
                return;
            }
            throw new Error('Keys API unreachable');
        }
        
        const data = await response.json();
        const keys = data.items || [];
        
        if (keys.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="5" class="empty">No keys managed yet</td></tr>';
            return;
        }

        tableBody.innerHTML = keys.map(key => `
            <tr>
                <td>${escapeHtml(key.id)}</td>
                <td>${escapeHtml(key.algorithm)}</td>
                <td><span class="state-tag state-${key.state.toLowerCase()}">${escapeHtml(key.state)}</span></td>
                <td>
                    ${key.usage.map(use => `<span class="tag">${escapeHtml(use)}</span>`).join(' ')}
                </td>
                <td>${key.version}</td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Failed to fetch keys:', error);
        tableBody.innerHTML = '<tr><td colspan="5" class="empty error-text">Failed to load key inventory</td></tr>';
    }
}

function formatDate(isoString) {
    try {
        const date = new Date(isoString);
        return date.toLocaleString();
    } catch (e) {
        return isoString;
    }
}

function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return unsafe;
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

async function fetchSystemStatus() {
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    const versionInfo = document.getElementById('version-info');

    try {
        const response = await fetch('/api/v1/status');
        if (!response.ok) throw new Error('Status API unreachable');
        
        const data = await response.json();
        
        statusDot.className = 'status-dot ' + (data.status === 'ok' ? 'status-online' : 'status-degraded');
        statusText.textContent = 'System Status: ' + data.status.toUpperCase();
        versionInfo.textContent = 'v' + data.version;
    } catch (error) {
        console.error('Failed to fetch system status:', error);
        statusDot.className = 'status-dot status-offline';
        statusText.textContent = 'System Status: OFFLINE';
    }
}
