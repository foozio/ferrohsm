document.addEventListener('DOMContentLoaded', () => {
    fetchSystemStatus();
    // Refresh status every 30 seconds
    setInterval(fetchSystemStatus, 30000);
});

async fn fetchSystemStatus() {
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
