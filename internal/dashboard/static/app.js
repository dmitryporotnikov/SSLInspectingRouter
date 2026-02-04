const api = {
    async getTraffic() {
        try {
            const res = await fetch('/api/traffic');
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
    }
};

let isConnected = false;
const ledEl = document.getElementById('status-led');
const statusTextEl = document.getElementById('status-text');

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
    if (!text) return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

async function loop() {
    const data = await api.getTraffic();
    updateStatus(!!data);
    if (data) renderTraffic(data);
    setTimeout(loop, 2000);
}

document.addEventListener('DOMContentLoaded', loop);
