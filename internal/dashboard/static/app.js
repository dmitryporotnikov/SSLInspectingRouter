const api = {
    async getTraffic(limit) {
        try {
            const res = await fetch(`/api/traffic?limit=${limit}`);
            if (res.ok) return await res.json();
            throw new Error('Network response was not ok');
        } catch (e) {
            console.error(e);
            return null;
        }
    },
    async getDetail(id) {
        try {
            const res = await fetch(`/api/traffic?id=${id}`);
            if (res.ok) return await res.json();
        } catch (e) {
            console.error(e);
        }
        return null;
    },
    async getStatus() {
        try {
            const res = await fetch('/api/status');
            if (res.ok) return await res.json();
        } catch (e) { console.error(e); }
        return null;
    },
    async setInspection(enabled) {
        try {
            await fetch('/api/status', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ inspection_enabled: enabled })
            });
        } catch (e) { console.error(e); }
    },
    async getRewrites() {
        try {
            const res = await fetch('/api/rewrites');
            if (res.ok) return await res.json();
        } catch (e) { console.error(e); }
        return [];
    }
};

let isConnected = false;
let limit = 50;

const ledEl = document.getElementById('status-led');
const statusTextEl = document.getElementById('status-text');
const dbSizeEl = document.getElementById('db-size');
const limitSelect = document.getElementById('limit-select');
const inspectionToggle = document.getElementById('inspection-toggle');

function updateStatus(connected) {
    if (connected === isConnected) return;
    isConnected = connected;
    if (connected) {
        ledEl.classList.add('connected');
        statusTextEl.textContent = 'Live';
    } else {
        ledEl.classList.remove('connected');
        statusTextEl.textContent = 'Disconnected';
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

window.updateLimit = () => {
    limit = parseInt(limitSelect.value);
    loop(); // Refresh immediately
};

window.toggleInspection = async () => {
    const enabled = inspectionToggle.checked;
    await api.setInspection(enabled);
};

window.openRules = async () => {
    document.getElementById('modal-title').textContent = "Rewrite Rules";
    modalContent.innerHTML = '<div style="text-align:center; padding:20px;">Loading rules...</div>';
    modalOverlay.classList.remove('hidden');

    const rules = await api.getRewrites();
    if (!rules || rules.length === 0) {
        modalContent.innerHTML = '<div style="padding:20px; text-align:center; color: var(--text-secondary)">No rewrite rules loaded</div>';
        return;
    }

    modalContent.innerHTML = rules.map(r => `
        <div class="rule-item">
            <div class="rule-header">
                <span>${escapeHtml(r.name || 'Unnamed Rule')}</span>
                <span style="color: ${r.enabled !== false ? 'var(--success)' : 'var(--text-secondary)'}">
                    ${r.enabled !== false ? 'Enabled' : 'Disabled'}
                </span>
            </div>
            <div class="rule-match">
                Match: ${escapeHtml(JSON.stringify(r.match, null, 2))}
            </div>
            <div class="rule-actions">
                Actions: ${escapeHtml(JSON.stringify(r.actions))}
            </div>
        </div>
    `).join('');
};

function renderTraffic(entries) {
    const tbody = document.getElementById('traffic-body');
    if (!entries.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--text-secondary)">No traffic captured yet</td></tr>';
        return;
    }

    tbody.innerHTML = entries.map(e => `
        <tr onclick="openDetail(${e.id})">
            <td style="color: var(--text-secondary); font-size: 0.85em;">
                ${new Date(e.timestamp).toLocaleTimeString()}
            </td>
            <td><span class="method ${e.method}">${e.method || '?'}</span></td>
            <td>${e.host}</td>
            <td style="max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                ${e.url || '-'}
            </td>
            <td>${e.source_ip}</td>
            <td>${e.status || '-'}</td>
        </tr>
    `).join('');
}

// Modal Logic
const modalOverlay = document.getElementById('modal-overlay');
const modalClose = document.getElementById('modal-close');
const modalContent = document.getElementById('modal-content');

modalClose.onclick = () => {
    modalOverlay.classList.add('hidden');
};

modalOverlay.onclick = (e) => {
    if (e.target === modalOverlay) modalOverlay.classList.add('hidden');
};

window.openDetail = async (id) => {
    document.getElementById('modal-title').textContent = "Traffic Details";
    modalContent.innerHTML = '<div style="text-align:center; padding:20px;">Loading details...</div>';
    modalOverlay.classList.remove('hidden');

    const data = await api.getDetail(id);
    if (!data) {
        modalContent.innerHTML = '<div style="color:var(--error); text-align:center;">Failed to load details</div>';
        return;
    }

    modalContent.innerHTML = `
        <div class="detail-section">
            <h3>Request</h3>
            <pre>${escapeHtml(data.request_full)}\n\n${escapeHtml(data.request_body)}</pre>
        </div>
        <div class="detail-section">
            <h3>Response</h3>
            <pre>${escapeHtml(data.response_full)}\n\n${escapeHtml(data.response_body)}</pre>
        </div>
    `;
};

function escapeHtml(text) {
    if (text === undefined || text === null) return '';
    if (typeof text !== 'string') text = JSON.stringify(text, null, 2);
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

let lastPoll = 0;
async function loop() {
    const now = Date.now();

    // Poll status every 2s
    if (now - lastPoll > 2000) {
        const status = await api.getStatus();
        if (status) {
            dbSizeEl.textContent = formatBytes(status.db_size_bytes);
            // Only update toggle if not interacted recently? 
            // For simplicity, we sync unless user is dragging. 
            // But user might be toggling.
            // A better way is state tracking.
            // Let's just set it for now, it's fine for single user.
            if (document.activeElement !== inspectionToggle) {
                inspectionToggle.checked = status.inspection_enabled;
            }
        }
        lastPoll = now;
    }

    const data = await api.getTraffic(limit);
    updateStatus(!!data);
    if (data) renderTraffic(data);

    setTimeout(loop, 1000);
}

document.addEventListener('DOMContentLoaded', () => {
    limitSelect.value = limit;
    loop();
});
