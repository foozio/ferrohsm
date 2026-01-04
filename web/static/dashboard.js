document.addEventListener('DOMContentLoaded', () => {
    fetchSystemStatus();
    fetchKeys();
    // Refresh status and keys periodically
    setInterval(fetchSystemStatus, 30000);
    setInterval(fetchKeys, 60000);
});

async function fetchKeys() {
    const tableBody = document.getElementById('keys-table-body');
    if (!tableBody) return;

    try {
        const response = await fetch('/api/v1/keys');
        if (!response.ok) throw new Error('Keys API unreachable');
        
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
                <td>${escapeHtml(key.state)}</td>
                <td>
                    ${key.usage.map(use => `<span class="tag">${escapeHtml(use)}</span>`).join(' ')}
                </td>
                <td>${key.version}</td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Failed to fetch keys:', error);
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
