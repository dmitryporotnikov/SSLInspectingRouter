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
const trafficBody = document.getElementById('traffic-body');
const modalTitle = document.getElementById('modal-title');
const modalOverlay = document.getElementById('modal-overlay');
const modalClose = document.getElementById('modal-close');
const modalContent = document.getElementById('modal-content');

function clearElement(element) {
    while (element.firstChild) {
        element.removeChild(element.firstChild);
    }
}

function appendMessage(element, text, className = '') {
    const container = document.createElement('div');
    if (className) {
        container.className = className;
    }
    container.style.padding = '20px';
    container.style.textAlign = 'center';
    container.textContent = text;
    element.appendChild(container);
}

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
    modalTitle.textContent = "Rewrite Rules";
    clearElement(modalContent);
    appendMessage(modalContent, 'Loading rules...');
    modalOverlay.classList.remove('hidden');

    const rules = await api.getRewrites();
    clearElement(modalContent);
    if (!rules || rules.length === 0) {
        appendMessage(modalContent, 'No rewrite rules loaded');
        return;
    }

    const fragment = document.createDocumentFragment();
    rules.forEach((rule) => {
        const card = document.createElement('div');
        card.className = 'rule-item';

        const header = document.createElement('div');
        header.className = 'rule-header';

        const name = document.createElement('span');
        name.textContent = rule && rule.name ? String(rule.name) : 'Unnamed Rule';
        header.appendChild(name);

        const enabled = document.createElement('span');
        const active = rule && rule.enabled !== false;
        enabled.style.color = active ? 'var(--success)' : 'var(--text-secondary)';
        enabled.textContent = active ? 'Enabled' : 'Disabled';
        header.appendChild(enabled);

        const match = document.createElement('div');
        match.className = 'rule-match';
        match.textContent = `Match: ${JSON.stringify(rule && rule.match ? rule.match : {}, null, 2)}`;

        const actions = document.createElement('div');
        actions.className = 'rule-actions';
        actions.textContent = `Actions: ${JSON.stringify(rule && rule.actions ? rule.actions : {})}`;

        card.appendChild(header);
        card.appendChild(match);
        card.appendChild(actions);
        fragment.appendChild(card);
    });
    modalContent.appendChild(fragment);
};

function renderTraffic(entries) {
    clearElement(trafficBody);
    if (!entries.length) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 6;
        cell.style.textAlign = 'center';
        cell.style.padding = '20px';
        cell.style.color = 'var(--text-secondary)';
        cell.textContent = 'No traffic captured yet';
        row.appendChild(cell);
        trafficBody.appendChild(row);
        return;
    }

    const fragment = document.createDocumentFragment();
    entries.forEach((entry) => {
        const row = document.createElement('tr');
        const id = Number.parseInt(String(entry && entry.id), 10);
        if (Number.isFinite(id) && id > 0) {
            row.addEventListener('click', () => {
                void window.openDetail(id);
            });
        }

        const timestampCell = document.createElement('td');
        timestampCell.style.color = 'var(--text-secondary)';
        timestampCell.style.fontSize = '0.85em';
        timestampCell.textContent = new Date(entry.timestamp).toLocaleTimeString();
        row.appendChild(timestampCell);

        const methodCell = document.createElement('td');
        const methodSpan = document.createElement('span');
        const method = String(entry && entry.method ? entry.method : '?');
        const methodClass = method.toUpperCase().replace(/[^A-Z0-9_-]/g, '');
        methodSpan.className = methodClass ? `method ${methodClass}` : 'method';
        methodSpan.textContent = method;
        methodCell.appendChild(methodSpan);
        row.appendChild(methodCell);

        const hostCell = document.createElement('td');
        hostCell.textContent = String(entry && entry.host ? entry.host : '-');
        row.appendChild(hostCell);

        const urlCell = document.createElement('td');
        urlCell.style.maxWidth = '300px';
        urlCell.style.whiteSpace = 'nowrap';
        urlCell.style.overflow = 'hidden';
        urlCell.style.textOverflow = 'ellipsis';
        urlCell.textContent = String(entry && entry.url ? entry.url : '-');
        row.appendChild(urlCell);

        const sourceCell = document.createElement('td');
        sourceCell.textContent = String(entry && entry.source_ip ? entry.source_ip : '-');
        row.appendChild(sourceCell);

        const statusCell = document.createElement('td');
        statusCell.textContent = String(entry && entry.status ? entry.status : '-');
        row.appendChild(statusCell);

        fragment.appendChild(row);
    });
    trafficBody.appendChild(fragment);
}

modalClose.onclick = () => {
    modalOverlay.classList.add('hidden');
};

modalOverlay.onclick = (e) => {
    if (e.target === modalOverlay) modalOverlay.classList.add('hidden');
};

window.openDetail = async (id) => {
    modalTitle.textContent = "Traffic Details";
    clearElement(modalContent);
    appendMessage(modalContent, 'Loading details...');
    modalOverlay.classList.remove('hidden');

    const data = await api.getDetail(id);
    clearElement(modalContent);
    if (!data) {
        const error = document.createElement('div');
        error.style.color = 'var(--error)';
        error.style.textAlign = 'center';
        error.textContent = 'Failed to load details';
        modalContent.appendChild(error);
        return;
    }

    const requestSection = document.createElement('div');
    requestSection.className = 'detail-section';
    const requestTitle = document.createElement('h3');
    requestTitle.textContent = 'Request';
    const requestBody = document.createElement('pre');
    requestBody.textContent = `${data.request_full || ''}\n\n${data.request_body || ''}`;
    requestSection.appendChild(requestTitle);
    requestSection.appendChild(requestBody);

    const responseSection = document.createElement('div');
    responseSection.className = 'detail-section';
    const responseTitle = document.createElement('h3');
    responseTitle.textContent = 'Response';
    const responseBody = document.createElement('pre');
    responseBody.textContent = `${data.response_full || ''}\n\n${data.response_body || ''}`;
    responseSection.appendChild(responseTitle);
    responseSection.appendChild(responseBody);

    modalContent.appendChild(requestSection);
    modalContent.appendChild(responseSection);
};

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
