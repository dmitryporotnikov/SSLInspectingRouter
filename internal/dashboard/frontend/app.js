const state = {
    user: null,
    authToken: null,
    theme: "dark",
    connection: {
        connected: true,
        consecutiveFailures: 0,
        lastSuccessAt: 0,
    },
    status: null,
    policy: {
        drop_list: [],
        bypass_list: [],
    },
    traffic: {
        items: [],
        total: 0,
        limit: 50,
        offset: 0,
        q: "",
        mode: "",
    },
    rewrites: {
        rules: [],
        items: [],
        managedFile: "",
        selectedKey: "new",
        dirty: false,
        lastSnapshot: "",
        lastWarning: "",
        transientEmptySkips: 0,
    },
    users: [],
    editingUserId: null,
    pollHandle: null,
    searchDebounce: null,
    section: "traffic",
};

const AUTH_TOKEN_KEY = "sir_auth_token";
const THEME_KEY = "sir_theme";
const CONNECTION_FAILURE_THRESHOLD = 3;
const CONNECTION_STALE_AFTER_MS = 10000;

const dom = {
    loginView: document.getElementById("login-view"),
    appView: document.getElementById("app-view"),
    loginForm: document.getElementById("login-form"),
    loginUsername: document.getElementById("login-username"),
    loginPassword: document.getElementById("login-password"),
    loginError: document.getElementById("login-error"),
    navButtons: Array.from(document.querySelectorAll(".nav-item")),
    usersNav: document.getElementById("users-nav"),
    trafficSection: document.getElementById("traffic-section"),
    rewritesSection: document.getElementById("rewrites-section"),
    usersSection: document.getElementById("users-section"),
    currentUser: document.getElementById("current-user"),
    currentRole: document.getElementById("current-role"),
    themeToggle: document.getElementById("theme-toggle"),
    themeToggleIcon: document.getElementById("theme-toggle-icon"),
    settingsPanel: document.getElementById("settings-panel"),
    inspectionControlWrap: document.getElementById("inspection-control-wrap"),
    inspectionToggle: document.getElementById("inspection-toggle"),
    truncateLogWrap: document.getElementById("truncate-log-wrap"),
    truncateLogToggle: document.getElementById("truncate-log-toggle"),
    bodyArtifactsWrap: document.getElementById("body-artifacts-wrap"),
    bodyArtifactsToggle: document.getElementById("body-artifacts-toggle"),
    bodyArtifactsPathWrap: document.getElementById("body-artifacts-path-wrap"),
    bodyArtifactsDirectoryInput: document.getElementById("body-artifacts-directory-input"),
    bodyArtifactsSave: document.getElementById("body-artifacts-save"),
    bodyArtifactsMeta: document.getElementById("body-artifacts-meta"),
    bodyArtifactsDir: document.getElementById("body-artifacts-dir"),
    dropListCount: document.getElementById("drop-list-count"),
    bypassListCount: document.getElementById("bypass-list-count"),
    policyControls: document.getElementById("policy-controls"),
    dropListInput: document.getElementById("drop-list-input"),
    bypassListInput: document.getElementById("bypass-list-input"),
    policySaveBtn: document.getElementById("policy-save-btn"),
    policySaveStatus: document.getElementById("policy-save-status"),
    allowQuicValue: document.getElementById("allow-quic-value"),
    tlsPortsValue: document.getElementById("tls-ports-value"),
    inspectOnlyValue: document.getElementById("inspect-only-value"),
    pcapPathValue: document.getElementById("pcap-path-value"),
    logoutBtn: document.getElementById("logout-btn"),
    metricConnection: document.getElementById("metric-connection"),
    metricDBSize: document.getElementById("metric-db-size"),
    metricRequests: document.getElementById("metric-requests"),
    rewriteCount: document.getElementById("rewrite-count"),
    viewRulesBtn: document.getElementById("view-rules-btn"),
    rewriteManagedFile: document.getElementById("rewrite-managed-file"),
    rewriteList: document.getElementById("rewrite-list"),
    rewriteNewBtn: document.getElementById("rewrite-new-btn"),
    rewriteReloadBtn: document.getElementById("rewrite-reload-btn"),
    rewriteForm: document.getElementById("rewrite-form"),
    rewriteFormTitle: document.getElementById("rewrite-form-title"),
    rewriteFormOrigin: document.getElementById("rewrite-form-origin"),
    rewriteFormError: document.getElementById("rewrite-form-error"),
    rewriteEnabled: document.getElementById("rewrite-enabled"),
    rewriteName: document.getElementById("rewrite-name"),
    rewriteHost: document.getElementById("rewrite-host"),
    rewriteHostRegex: document.getElementById("rewrite-host-regex"),
    rewritePathPrefix: document.getElementById("rewrite-path-prefix"),
    rewritePathRegex: document.getElementById("rewrite-path-regex"),
    rewriteMethod: document.getElementById("rewrite-method"),
    rewriteMethods: document.getElementById("rewrite-methods"),
    rewriteStatus: document.getElementById("rewrite-status"),
    rewriteStatuses: document.getElementById("rewrite-statuses"),
    rewriteContentTypeContains: document.getElementById("rewrite-content-type-contains"),
    rewriteContentTypeRegex: document.getElementById("rewrite-content-type-regex"),
    rewriteReqHeaders: document.getElementById("rewrite-req-headers"),
    rewriteRespHeaders: document.getElementById("rewrite-resp-headers"),
    rewriteSetHeaders: document.getElementById("rewrite-set-headers"),
    rewriteAddHeaders: document.getElementById("rewrite-add-headers"),
    rewriteDelHeaders: document.getElementById("rewrite-del-headers"),
    rewriteBodyReplace: document.getElementById("rewrite-body-replace"),
    rewriteBodyRegex: document.getElementById("rewrite-body-regex"),
    rewriteSaveBtn: document.getElementById("rewrite-save-btn"),
    rewriteDeleteBtn: document.getElementById("rewrite-delete-btn"),
    rewriteCloneBtn: document.getElementById("rewrite-clone-btn"),
    rewriteSaveStatus: document.getElementById("rewrite-save-status"),
    trafficSearch: document.getElementById("traffic-search"),
    trafficModeFilter: document.getElementById("traffic-mode-filter"),
    trafficLimit: document.getElementById("traffic-limit"),
    refreshBtn: document.getElementById("refresh-btn"),
    prevPageBtn: document.getElementById("prev-page"),
    nextPageBtn: document.getElementById("next-page"),
    trafficSummary: document.getElementById("traffic-summary"),
    trafficBody: document.getElementById("traffic-table-body"),
    reloadUsersBtn: document.getElementById("reload-users-btn"),
    usersBody: document.getElementById("users-table-body"),
    userForm: document.getElementById("user-form"),
    userFormTitle: document.getElementById("user-form-title"),
    userFormError: document.getElementById("user-form-error"),
    userSubmit: document.getElementById("user-submit"),
    cancelEditBtn: document.getElementById("cancel-edit"),
    userId: document.getElementById("user-id"),
    userUsername: document.getElementById("user-username"),
    userDisplayName: document.getElementById("user-display-name"),
    userRole: document.getElementById("user-role"),
    userPassword: document.getElementById("user-password"),
    userActive: document.getElementById("user-active"),
    modal: document.getElementById("modal"),
    modalTitle: document.getElementById("modal-title"),
    modalContent: document.getElementById("modal-content"),
    modalClose: document.getElementById("modal-close"),
};

function isAdmin() {
    return state.user && state.user.role === "admin";
}

function escapeHTML(value) {
    if (value === null || value === undefined) return "";
    const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function formatBytes(bytes) {
    const value = Number(bytes || 0);
    if (!Number.isFinite(value) || value <= 0) {
        return "0 B";
    }
    const units = ["B", "KB", "MB", "GB", "TB"];
    const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
    const scaled = value / Math.pow(1024, index);
    return `${scaled.toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

function formatTime(timestamp) {
    if (!timestamp) return "-";
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return timestamp;
    return date.toLocaleString();
}

function setConnectionState(connected) {
    state.connection.connected = connected;
    dom.metricConnection.textContent = connected ? "Connected" : "Disconnected";
    dom.metricConnection.style.color = connected ? "var(--ok)" : "var(--danger)";
}

function reportApiSuccess() {
    state.connection.consecutiveFailures = 0;
    state.connection.lastSuccessAt = Date.now();
    if (!state.connection.connected) {
        setConnectionState(true);
    }
}

function reportApiFailure() {
    state.connection.consecutiveFailures += 1;
    const now = Date.now();
    const stale = state.connection.lastSuccessAt === 0 || now - state.connection.lastSuccessAt > CONNECTION_STALE_AFTER_MS;
    if (stale && state.connection.consecutiveFailures >= CONNECTION_FAILURE_THRESHOLD) {
        setConnectionState(false);
    }
}

function normalizeTheme(raw) {
    const token = String(raw || "").trim().toLowerCase();
    if (token === "light") {
        return "light";
    }
    return "dark";
}

function loadStoredTheme() {
    try {
        return normalizeTheme(window.localStorage.getItem(THEME_KEY));
    } catch (_error) {
        return "dark";
    }
}

function persistTheme(theme) {
    try {
        window.localStorage.setItem(THEME_KEY, normalizeTheme(theme));
    } catch (_error) {
        // Ignore storage errors; theme still works in current session.
    }
}

function updateThemeToggle() {
    const theme = normalizeTheme(state.theme);
    const nextTheme = theme === "dark" ? "light" : "dark";
    dom.themeToggleIcon.textContent = theme === "dark" ? "☾" : "☀";
    dom.themeToggle.title = `Switch to ${nextTheme} theme`;
    dom.themeToggle.setAttribute("aria-label", `Switch to ${nextTheme} theme`);
}

function applyTheme(theme) {
    state.theme = normalizeTheme(theme);
    document.body.dataset.theme = state.theme;
    updateThemeToggle();
}

function initializeTheme() {
    applyTheme(loadStoredTheme());
}

function toggleTheme() {
    const next = state.theme === "dark" ? "light" : "dark";
    applyTheme(next);
    persistTheme(next);
}

function loadStoredAuthToken() {
    try {
        const token = window.localStorage.getItem(AUTH_TOKEN_KEY);
        if (typeof token === "string" && token.trim() !== "") {
            return token.trim();
        }
    } catch (_error) {
        // Ignore storage errors and fall back to cookie-only auth.
    }
    return null;
}

function persistAuthToken(token) {
    state.authToken = token && token.trim() !== "" ? token.trim() : null;
    try {
        if (state.authToken) {
            window.localStorage.setItem(AUTH_TOKEN_KEY, state.authToken);
        } else {
            window.localStorage.removeItem(AUTH_TOKEN_KEY);
        }
    } catch (_error) {
        // Ignore storage errors and keep token in-memory for current tab.
    }
}

async function apiRequest(path, options = {}) {
    const {
        method = "GET",
        body,
        allowUnauthorized = false,
        trackConnectivity = true,
    } = options;

    const headers = {
        Accept: "application/json",
    };
    if (state.authToken) {
        headers.Authorization = `Bearer ${state.authToken}`;
    }
    if (body !== undefined) {
        headers["Content-Type"] = "application/json";
    }

    let response;
    try {
        response = await fetch(path, {
            method,
            credentials: "include",
            headers,
            body: body !== undefined ? JSON.stringify(body) : undefined,
        });
    } catch (_error) {
        if (trackConnectivity) {
            reportApiFailure();
        }
        throw new Error("Network request failed");
    }

    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json") ? await response.json().catch(() => null) : null;

    if (!response.ok) {
        if (trackConnectivity && response.status >= 500) {
            reportApiFailure();
        }
        if (response.status === 401 && !allowUnauthorized) {
            handleSessionExpired();
        }
        const error = new Error((payload && payload.error) || `Request failed (${response.status})`);
        error.status = response.status;
        throw error;
    }

    if (trackConnectivity) {
        reportApiSuccess();
    }
    return payload || {};
}

function showLogin(message = "") {
    stopPolling();
    document.body.classList.add("login-mode");
    dom.appView.classList.add("hidden");
    dom.loginView.classList.remove("hidden");
    if (message) {
        dom.loginError.textContent = message;
        dom.loginError.classList.remove("hidden");
    }
}

function showApp() {
    document.body.classList.remove("login-mode");
    dom.loginView.classList.add("hidden");
    dom.appView.classList.remove("hidden");
    dom.loginError.classList.add("hidden");
}

function applyUserContext() {
    const user = state.user;
    dom.currentUser.textContent = user ? user.display_name || user.username : "-";
    dom.currentRole.textContent = user ? user.role : "-";

    const admin = isAdmin();
    dom.usersNav.classList.toggle("hidden", !admin);
    dom.settingsPanel.classList.toggle("hidden", !admin);
    dom.bodyArtifactsMeta.classList.toggle("hidden", !admin);
    if (!admin && state.section === "users") {
        switchSection("traffic");
    }
    renderRewriteEditor();
}

function switchSection(section) {
    state.section = section;
    dom.navButtons.forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.section === section);
    });

    dom.trafficSection.classList.toggle("hidden", section !== "traffic");
    dom.rewritesSection.classList.toggle("hidden", section !== "rewrites");
    dom.usersSection.classList.toggle("hidden", section !== "users");

    if (section === "rewrites") {
        renderRewriteEditor();
    }
}

async function bootstrap() {
    initializeTheme();
    bindEvents();
    persistAuthToken(loadStoredAuthToken());

    try {
        const me = await apiRequest("/api/v1/auth/me", { allowUnauthorized: true, trackConnectivity: false });
        if (!me.user) {
            throw new Error("not authenticated");
        }
        state.user = me.user;
    } catch (err) {
        showLogin();
        return;
    }

    showApp();
    applyUserContext();
    await refreshDashboard(true);
    startPolling();
}

function bindEvents() {
    dom.loginForm.addEventListener("submit", handleLogin);
    dom.themeToggle.addEventListener("click", toggleTheme);
    dom.logoutBtn.addEventListener("click", handleLogout);

    dom.navButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const section = btn.dataset.section;
            if (section === "users" && !isAdmin()) {
                return;
            }
            switchSection(section);
            if (section === "users") {
                void loadUsers();
            } else if (section === "rewrites") {
                void loadRewrites({ forceApply: true });
            }
        });
    });

    dom.trafficSearch.addEventListener("input", () => {
        clearTimeout(state.searchDebounce);
        state.searchDebounce = setTimeout(() => {
            state.traffic.q = dom.trafficSearch.value.trim();
            state.traffic.offset = 0;
            void loadTraffic();
        }, 260);
    });

    dom.trafficModeFilter.addEventListener("change", () => {
        state.traffic.mode = dom.trafficModeFilter.value;
        state.traffic.offset = 0;
        void loadTraffic();
    });

    dom.trafficLimit.addEventListener("change", () => {
        state.traffic.limit = Number(dom.trafficLimit.value) || 50;
        state.traffic.offset = 0;
        void loadTraffic();
    });

    dom.refreshBtn.addEventListener("click", () => {
        void refreshDashboard(true);
    });

    dom.prevPageBtn.addEventListener("click", () => {
        state.traffic.offset = Math.max(0, state.traffic.offset - state.traffic.limit);
        void loadTraffic();
    });

    dom.nextPageBtn.addEventListener("click", () => {
        if (state.traffic.offset + state.traffic.limit >= state.traffic.total) {
            return;
        }
        state.traffic.offset += state.traffic.limit;
        void loadTraffic();
    });

    dom.trafficBody.addEventListener("click", (event) => {
        const row = event.target.closest("tr[data-id]");
        if (!row) return;
        const id = Number(row.dataset.id);
        if (!id) return;
        void showTrafficDetail(id);
    });

    dom.inspectionToggle.addEventListener("change", () => {
        void updateInspection(dom.inspectionToggle.checked);
    });
    dom.truncateLogToggle.addEventListener("change", () => {
        void updateTruncateLog(dom.truncateLogToggle.checked);
    });
    dom.bodyArtifactsToggle.addEventListener("change", () => {
        void updateBodyArtifacts(dom.bodyArtifactsToggle.checked);
    });
    dom.bodyArtifactsSave.addEventListener("click", () => {
        void updateBodyArtifactsDirectory();
    });
    dom.bodyArtifactsDirectoryInput.addEventListener("keydown", (event) => {
        if (event.key !== "Enter") {
            return;
        }
        event.preventDefault();
        void updateBodyArtifactsDirectory();
    });
    dom.policySaveBtn.addEventListener("click", () => {
        void updateTrafficPolicy();
    });

    dom.viewRulesBtn.addEventListener("click", () => {
        switchSection("rewrites");
        void loadRewrites({ forceApply: true });
    });

    dom.rewriteNewBtn.addEventListener("click", () => {
        beginNewRewrite();
    });
    dom.rewriteReloadBtn.addEventListener("click", () => {
        void loadRewrites({ forceApply: true });
    });
    dom.rewriteForm.addEventListener("submit", handleRewriteSave);
    dom.rewriteDeleteBtn.addEventListener("click", () => {
        void handleRewriteDelete();
    });
    dom.rewriteCloneBtn.addEventListener("click", () => {
        void handleRewriteClone();
    });
    dom.rewriteList.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-rewrite-key]");
        if (!button) {
            return;
        }
        const key = button.dataset.rewriteKey || "";
        if (!key) {
            return;
        }
        selectRewriteKey(key);
    });
    dom.rewriteForm.addEventListener("input", () => {
        state.rewrites.dirty = true;
        dom.rewriteSaveStatus.textContent = "";
        dom.rewriteFormError.classList.add("hidden");
    });

    dom.reloadUsersBtn.addEventListener("click", () => {
        void loadUsers();
    });

    dom.userForm.addEventListener("submit", handleUserSubmit);
    dom.cancelEditBtn.addEventListener("click", resetUserForm);

    dom.usersBody.addEventListener("click", (event) => {
        const actionButton = event.target.closest("button[data-action]");
        if (!actionButton) return;
        const userID = Number(actionButton.dataset.id);
        if (!userID) return;

        const action = actionButton.dataset.action;
        if (action === "edit") {
            beginEditUser(userID);
        } else if (action === "delete") {
            void deleteUser(userID);
        }
    });

    dom.modalClose.addEventListener("click", closeModal);
    dom.modal.addEventListener("click", (event) => {
        if (event.target === dom.modal) {
            closeModal();
        }
    });
}

async function handleLogin(event) {
    event.preventDefault();
    dom.loginError.classList.add("hidden");

    const username = dom.loginUsername.value.trim();
    const password = dom.loginPassword.value;

    if (!username || !password) {
        dom.loginError.textContent = "Username and password are required.";
        dom.loginError.classList.remove("hidden");
        return;
    }

    try {
        const response = await apiRequest("/api/v1/auth/login", {
            method: "POST",
            body: { username, password },
            allowUnauthorized: true,
            trackConnectivity: false,
        });

        state.user = response.user;
        persistAuthToken(response.token || state.authToken);
        dom.loginPassword.value = "";

        showApp();
        applyUserContext();
        await refreshDashboard(true);
        startPolling();
    } catch (error) {
        dom.loginError.textContent = error.message;
        dom.loginError.classList.remove("hidden");
    }
}

async function handleLogout() {
    try {
        await apiRequest("/api/v1/auth/logout", { method: "POST", allowUnauthorized: true, trackConnectivity: false });
    } finally {
        handleSessionExpired();
    }
}

function handleSessionExpired() {
    state.user = null;
    persistAuthToken(null);
    state.users = [];
    state.traffic.items = [];
    state.traffic.total = 0;
    state.policy = {
        drop_list: [],
        bypass_list: [],
    };
    state.rewrites = {
        rules: [],
        items: [],
        managedFile: "",
        selectedKey: "new",
        dirty: false,
        lastSnapshot: "",
        lastWarning: "",
        transientEmptySkips: 0,
    };
    state.section = "traffic";
    dom.bodyArtifactsDir.textContent = "disabled";
    dom.bodyArtifactsDir.title = "disabled";
    dom.bodyArtifactsDirectoryInput.value = "";
    dom.dropListCount.textContent = "0";
    dom.bypassListCount.textContent = "0";
    dom.dropListInput.value = "";
    dom.bypassListInput.value = "";
    dom.policySaveStatus.textContent = "";
    dom.allowQuicValue.textContent = "-";
    dom.tlsPortsValue.textContent = "default";
    dom.inspectOnlyValue.textContent = "all sources";
    dom.pcapPathValue.textContent = "disabled";
    dom.truncateLogToggle.checked = false;
    dom.rewriteCount.textContent = "0";
    dom.rewriteManagedFile.textContent = "managed file: -";
    resetUserForm();
    resetRewriteForm();
    renderTraffic();
    renderRewriteEditor();
    renderUsers();
    showLogin("Session expired. Please sign in again.");
}

function startPolling() {
    stopPolling();
    state.pollHandle = setInterval(() => {
        void refreshDashboard(false);
    }, 3000);
}

function stopPolling() {
    if (state.pollHandle) {
        clearInterval(state.pollHandle);
        state.pollHandle = null;
    }
}

async function refreshDashboard(forceTrafficReload) {
    const statusTask = loadStatus();
    const policyTask = loadPolicy();
    const trafficTask = state.section === "traffic" || forceTrafficReload ? loadTraffic() : Promise.resolve();
    const rulesTask = loadRewrites({ preserveForm: state.section === "rewrites" && state.rewrites.dirty });

    if (isAdmin()) {
        await Promise.allSettled([statusTask, policyTask, trafficTask, rulesTask]);
        if (state.section === "users") {
            await loadUsers();
        }
        return;
    }

    await Promise.allSettled([statusTask, policyTask, trafficTask, rulesTask]);
}

async function loadStatus() {
    try {
        const status = await apiRequest("/api/v1/status");
        applyStatus(status);
    } catch (_error) {}
}

function applyStatus(status) {
    state.status = status;
    dom.metricDBSize.textContent = formatBytes(status.db_size_bytes || 0);
    const requestCount = Number(status.request_count);
    if (Number.isFinite(requestCount) && requestCount >= 0) {
        dom.metricRequests.textContent = requestCount.toLocaleString();
    }
    dom.inspectionToggle.checked = !!status.inspection_enabled;
    dom.truncateLogToggle.checked = !!status.truncate_log_enabled;
    dom.bodyArtifactsToggle.checked = !!status.body_artifacts_enabled;

    const artifactsDir = String(status.body_artifacts_directory || "").trim();
    if (document.activeElement !== dom.bodyArtifactsDirectoryInput) {
        dom.bodyArtifactsDirectoryInput.value = artifactsDir;
    }
    if (status.body_artifacts_enabled && artifactsDir !== "") {
        dom.bodyArtifactsDir.textContent = artifactsDir;
        dom.bodyArtifactsDir.title = artifactsDir;
    } else {
        dom.bodyArtifactsDir.textContent = "disabled";
        dom.bodyArtifactsDir.title = "disabled";
    }

    dom.allowQuicValue.textContent = status.allow_quic ? "enabled" : "blocked";

    const ports = Array.isArray(status.additional_tls_ports) ? status.additional_tls_ports : [];
    if (ports.length > 0) {
        const value = ports.join(", ");
        dom.tlsPortsValue.textContent = value;
        dom.tlsPortsValue.title = value;
    } else {
        dom.tlsPortsValue.textContent = "default";
        dom.tlsPortsValue.title = "default";
    }

    const inspectOnly = Array.isArray(status.inspect_only_sources) ? status.inspect_only_sources : [];
    if (inspectOnly.length > 0) {
        const value = inspectOnly.join(", ");
        dom.inspectOnlyValue.textContent = value;
        dom.inspectOnlyValue.title = value;
    } else {
        dom.inspectOnlyValue.textContent = "all sources";
        dom.inspectOnlyValue.title = "all sources";
    }

    const pcapPath = String(status.pcap_path || "").trim();
    if (pcapPath) {
        dom.pcapPathValue.textContent = pcapPath;
        dom.pcapPathValue.title = pcapPath;
    } else {
        dom.pcapPathValue.textContent = "disabled";
        dom.pcapPathValue.title = "disabled";
    }
}

function parsePolicyEntries(value) {
    if (!value) {
        return [];
    }
    const tokens = String(value)
        .split(/\n|,/g)
        .map((item) => item.trim().toLowerCase())
        .filter((item) => item !== "");
    return Array.from(new Set(tokens));
}

function formatPolicyEntries(entries) {
    if (!Array.isArray(entries) || entries.length === 0) {
        return "";
    }
    return entries.join("\n");
}

async function loadPolicy() {
    try {
        const policy = await apiRequest("/api/v1/policy");
        applyPolicy(policy);
    } catch (_error) {}
}

function applyPolicy(policy) {
    const dropList = Array.isArray(policy.drop_list) ? policy.drop_list : [];
    const bypassList = Array.isArray(policy.bypass_list) ? policy.bypass_list : [];

    state.policy = {
        drop_list: dropList.slice(),
        bypass_list: bypassList.slice(),
    };

    dom.dropListCount.textContent = String(dropList.length);
    dom.bypassListCount.textContent = String(bypassList.length);

    if (document.activeElement !== dom.dropListInput) {
        dom.dropListInput.value = formatPolicyEntries(dropList);
    }
    if (document.activeElement !== dom.bypassListInput) {
        dom.bypassListInput.value = formatPolicyEntries(bypassList);
    }
}

async function updateDashboardSettings(payload) {
    const status = await apiRequest("/api/v1/status", {
        method: "PUT",
        body: payload,
    });
    applyStatus(status);
}

async function updateInspection(enabled) {
    if (!isAdmin()) {
        return;
    }

    try {
        await updateDashboardSettings({ inspection_enabled: enabled });
    } catch (error) {
        dom.inspectionToggle.checked = !enabled;
        alert(error.message);
    }
}

async function updateTruncateLog(enabled) {
    if (!isAdmin()) {
        return;
    }

    try {
        await updateDashboardSettings({ truncate_log_enabled: enabled });
    } catch (error) {
        dom.truncateLogToggle.checked = !enabled;
        alert(error.message);
    }
}

async function updateBodyArtifacts(enabled) {
    if (!isAdmin()) {
        return;
    }

    try {
        await updateDashboardSettings({ body_artifacts_enabled: enabled });
    } catch (error) {
        dom.bodyArtifactsToggle.checked = !enabled;
        alert(error.message);
    }
}

async function updateBodyArtifactsDirectory() {
    if (!isAdmin()) {
        return;
    }

    const dir = dom.bodyArtifactsDirectoryInput.value.trim();
    if (!dir) {
        alert("Artifact directory cannot be empty.");
        dom.bodyArtifactsDirectoryInput.focus();
        return;
    }

    try {
        await updateDashboardSettings({ body_artifacts_directory: dir });
    } catch (error) {
        const previous = state.status ? String(state.status.body_artifacts_directory || "") : "";
        dom.bodyArtifactsDirectoryInput.value = previous;
        alert(error.message);
    }
}

async function updateTrafficPolicy() {
    if (!isAdmin()) {
        return;
    }

    const dropList = parsePolicyEntries(dom.dropListInput.value);
    const bypassList = parsePolicyEntries(dom.bypassListInput.value);

    dom.policySaveBtn.disabled = true;
    dom.policySaveStatus.textContent = "Saving...";

    try {
        const policy = await apiRequest("/api/v1/policy", {
            method: "PUT",
            body: {
                drop_list: dropList,
                bypass_list: bypassList,
            },
        });
        applyPolicy(policy);
        dom.policySaveStatus.textContent = "Saved.";
    } catch (error) {
        dom.policySaveStatus.textContent = "";
        alert(error.message);
    } finally {
        dom.policySaveBtn.disabled = false;
    }
}

function createEmptyRewriteRule() {
    return {
        name: "",
        enabled: true,
        match: {},
        actions: {},
    };
}

function rewriteKeyExists(key) {
    if (key === "new") {
        return true;
    }
    return state.rewrites.items.some((item) => item.key === key);
}

function currentRewriteItem() {
    return state.rewrites.items.find((item) => item.key === state.rewrites.selectedKey) || null;
}

function parseTokenList(value, options = {}) {
    const { upper = false } = options;
    if (!value) {
        return [];
    }
    const seen = new Set();
    const out = [];
    const tokens = String(value)
        .split(/\n|,/g)
        .map((item) => item.trim())
        .filter((item) => item !== "");
    for (const token of tokens) {
        const normalized = upper ? token.toUpperCase() : token;
        if (seen.has(normalized)) {
            continue;
        }
        seen.add(normalized);
        out.push(normalized);
    }
    return out;
}

function parseIntegerTokenList(value, label) {
    const tokens = parseTokenList(value);
    const values = [];
    for (const token of tokens) {
        const parsed = Number.parseInt(token, 10);
        if (!Number.isInteger(parsed) || parsed <= 0) {
            throw new Error(`${label} must be positive integers.`);
        }
        values.push(parsed);
    }
    return values;
}

function formatTokenList(values) {
    if (!Array.isArray(values) || values.length === 0) {
        return "";
    }
    return values.join(", ");
}

function parseHeaderMap(value, label) {
    const out = {};
    const lines = String(value || "")
        .split(/\n/g)
        .map((line) => line.trim())
        .filter((line) => line !== "");
    for (const line of lines) {
        const separator = line.indexOf(":");
        if (separator < 1) {
            throw new Error(`${label} lines must be in "Header: value" format.`);
        }
        const key = line.slice(0, separator).trim();
        const val = line.slice(separator + 1).trim();
        if (!key || !val) {
            throw new Error(`${label} lines must include both header name and value.`);
        }
        out[key] = val;
    }
    return out;
}

function formatHeaderMap(value) {
    if (!value || typeof value !== "object") {
        return "";
    }
    const keys = Object.keys(value).sort((a, b) => a.localeCompare(b));
    if (!keys.length) {
        return "";
    }
    return keys.map((key) => `${key}: ${String(value[key])}`).join("\n");
}

function parseReplacementLines(value, leftLabel, rightLabel) {
    const lines = String(value || "")
        .split(/\n/g)
        .map((line) => line.trim())
        .filter((line) => line !== "");
    const out = [];
    for (const line of lines) {
        const separator = line.indexOf("=>");
        if (separator < 1) {
            throw new Error(`Use "${leftLabel} => ${rightLabel}" format per line.`);
        }
        const left = line.slice(0, separator).trim();
        const right = line.slice(separator + 2).trim();
        if (!left) {
            throw new Error(`"${leftLabel}" value cannot be empty.`);
        }
        out.push({ left, right });
    }
    return out;
}

function formatReplacementLines(items, leftKey, rightKey) {
    if (!Array.isArray(items) || items.length === 0) {
        return "";
    }
    return items
        .map((item) => {
            const left = item && item[leftKey] !== undefined ? String(item[leftKey]) : "";
            const right = item && item[rightKey] !== undefined ? String(item[rightKey]) : "";
            return `${left} => ${right}`;
        })
        .join("\n");
}

function rewriteActionCount(rule) {
    const actions = rule && typeof rule.actions === "object" && rule.actions ? rule.actions : {};
    const setCount = actions.set_headers && typeof actions.set_headers === "object" ? Object.keys(actions.set_headers).length : 0;
    const addCount = actions.add_headers && typeof actions.add_headers === "object" ? Object.keys(actions.add_headers).length : 0;
    const delCount = Array.isArray(actions.del_headers) ? actions.del_headers.length : 0;
    const replaceCount = Array.isArray(actions.replace_body) ? actions.replace_body.length : 0;
    const regexCount = Array.isArray(actions.replace_body_regex) ? actions.replace_body_regex.length : 0;
    return setCount + addCount + delCount + replaceCount + regexCount;
}

function rewriteMatchSummary(rule) {
    const match = rule && typeof rule.match === "object" && rule.match ? rule.match : {};
    const parts = [];
    if (match.host) parts.push(`host=${match.host}`);
    if (match.host_regex) parts.push("host-regex");
    if (match.path_prefix) parts.push(`path^=${match.path_prefix}`);
    if (match.path_regex) parts.push("path-regex");
    if (match.method) parts.push(`method=${String(match.method).toUpperCase()}`);
    if (Array.isArray(match.methods) && match.methods.length) parts.push(`methods=${match.methods.length}`);
    if (match.status) parts.push(`status=${match.status}`);
    if (Array.isArray(match.statuses) && match.statuses.length) parts.push(`statuses=${match.statuses.length}`);
    if (match.content_type_contains) parts.push(`ct~=${match.content_type_contains}`);
    if (match.content_type_regex) parts.push("ct-regex");
    if (!parts.length) {
        return "matches all responses";
    }
    return parts.join(" • ");
}

function renderRewriteList() {
    if (!state.rewrites.items.length) {
        dom.rewriteList.innerHTML = `<p class="muted rewrite-empty">No rewrite rules loaded.</p>`;
        return;
    }

    dom.rewriteList.innerHTML = state.rewrites.items
        .map((item) => {
            const selected = item.key === state.rewrites.selectedKey ? " active" : "";
            const rule = item.rule || {};
            const enabled = rule.enabled === false ? "disabled" : "enabled";
            const scopeLabel = item.managed ? "Managed" : "External";
            const actionCount = rewriteActionCount(rule);
            const title = rule.name || `${item.file}#${item.index}`;
            return `
                <button type="button" class="rewrite-list-item${selected}" data-rewrite-key="${escapeHTML(item.key)}">
                    <div class="rewrite-list-top">
                        <strong title="${escapeHTML(title)}">${escapeHTML(title)}</strong>
                        <span class="rewrite-badge ${item.managed ? "managed" : "external"}">${escapeHTML(scopeLabel)}</span>
                    </div>
                    <div class="rewrite-list-meta">${escapeHTML(rewriteMatchSummary(rule))}</div>
                    <div class="rewrite-list-meta">${escapeHTML(enabled)} • ${actionCount} action${actionCount === 1 ? "" : "s"}</div>
                </button>
            `;
        })
        .join("");
}

function setRewriteFormLocked(locked) {
    const controls = Array.from(dom.rewriteForm.querySelectorAll("input, textarea, select"));
    controls.forEach((control) => {
        control.disabled = locked;
    });
    dom.rewriteSaveBtn.disabled = locked;
}

function resetRewriteForm() {
    const draft = createEmptyRewriteRule();
    dom.rewriteEnabled.checked = true;
    dom.rewriteName.value = draft.name;
    dom.rewriteHost.value = "";
    dom.rewriteHostRegex.value = "";
    dom.rewritePathPrefix.value = "";
    dom.rewritePathRegex.value = "";
    dom.rewriteMethod.value = "";
    dom.rewriteMethods.value = "";
    dom.rewriteStatus.value = "";
    dom.rewriteStatuses.value = "";
    dom.rewriteContentTypeContains.value = "";
    dom.rewriteContentTypeRegex.value = "";
    dom.rewriteReqHeaders.value = "";
    dom.rewriteRespHeaders.value = "";
    dom.rewriteSetHeaders.value = "";
    dom.rewriteAddHeaders.value = "";
    dom.rewriteDelHeaders.value = "";
    dom.rewriteBodyReplace.value = "";
    dom.rewriteBodyRegex.value = "";
    dom.rewriteSaveStatus.textContent = "";
    dom.rewriteFormError.classList.add("hidden");
}

function applyRewriteForm(rule) {
    const current = rule && typeof rule === "object" ? rule : createEmptyRewriteRule();
    const match = current.match && typeof current.match === "object" ? current.match : {};
    const actions = current.actions && typeof current.actions === "object" ? current.actions : {};

    dom.rewriteEnabled.checked = current.enabled !== false;
    dom.rewriteName.value = current.name ? String(current.name) : "";
    dom.rewriteHost.value = match.host ? String(match.host) : "";
    dom.rewriteHostRegex.value = match.host_regex ? String(match.host_regex) : "";
    dom.rewritePathPrefix.value = match.path_prefix ? String(match.path_prefix) : "";
    dom.rewritePathRegex.value = match.path_regex ? String(match.path_regex) : "";
    dom.rewriteMethod.value = match.method ? String(match.method).toUpperCase() : "";
    dom.rewriteMethods.value = formatTokenList(Array.isArray(match.methods) ? match.methods : []);
    dom.rewriteStatus.value = match.status ? String(match.status) : "";
    dom.rewriteStatuses.value = formatTokenList(Array.isArray(match.statuses) ? match.statuses : []);
    dom.rewriteContentTypeContains.value = match.content_type_contains ? String(match.content_type_contains) : "";
    dom.rewriteContentTypeRegex.value = match.content_type_regex ? String(match.content_type_regex) : "";
    dom.rewriteReqHeaders.value = formatHeaderMap(match.request_header_contains);
    dom.rewriteRespHeaders.value = formatHeaderMap(match.response_header_contains);
    dom.rewriteSetHeaders.value = formatHeaderMap(actions.set_headers);
    dom.rewriteAddHeaders.value = formatHeaderMap(actions.add_headers);
    dom.rewriteDelHeaders.value = formatTokenList(Array.isArray(actions.del_headers) ? actions.del_headers : []);
    dom.rewriteBodyReplace.value = formatReplacementLines(actions.replace_body, "from", "to");
    dom.rewriteBodyRegex.value = formatReplacementLines(actions.replace_body_regex, "pattern", "replace");
    dom.rewriteFormError.classList.add("hidden");
}

function renderRewriteEditor() {
    if (!rewriteKeyExists(state.rewrites.selectedKey)) {
        state.rewrites.selectedKey = state.rewrites.items.length ? state.rewrites.items[0].key : "new";
    }

    renderRewriteList();

    dom.rewriteManagedFile.textContent = state.rewrites.managedFile
        ? `managed file: ${state.rewrites.managedFile}`
        : "managed file: -";

    const selected = currentRewriteItem();
    const admin = isAdmin();

    if (!selected) {
        dom.rewriteFormTitle.textContent = "New Rewrite Rule";
        dom.rewriteFormOrigin.textContent = admin ? "Managed rule" : "Read-only mode";
        dom.rewriteDeleteBtn.disabled = true;
        dom.rewriteCloneBtn.classList.add("hidden");
        dom.rewriteCloneBtn.disabled = true;
        resetRewriteForm();
        setRewriteFormLocked(!admin);
        return;
    }

    const title = selected.rule && selected.rule.name ? String(selected.rule.name) : `${selected.file}#${selected.index}`;
    dom.rewriteFormTitle.textContent = title;
    dom.rewriteFormOrigin.textContent = selected.managed
        ? `Managed rule #${selected.managed_id}`
        : `External rule from ${selected.file}`;

    applyRewriteForm(selected.rule || createEmptyRewriteRule());

    const canEdit = admin && selected.managed;
    setRewriteFormLocked(!canEdit);
    dom.rewriteDeleteBtn.disabled = !canEdit;
    dom.rewriteCloneBtn.classList.toggle("hidden", !admin || selected.managed);
    dom.rewriteCloneBtn.disabled = !admin || selected.managed;
}

function beginNewRewrite() {
    if (!isAdmin()) {
        return;
    }
    state.rewrites.selectedKey = "new";
    state.rewrites.dirty = false;
    renderRewriteEditor();
}

function selectRewriteKey(key) {
    if (key === state.rewrites.selectedKey) {
        return;
    }
    if (state.rewrites.dirty && !window.confirm("Discard unsaved rewrite changes?")) {
        return;
    }
    state.rewrites.selectedKey = key;
    state.rewrites.dirty = false;
    dom.rewriteSaveStatus.textContent = "";
    renderRewriteEditor();
}

function buildRewriteRuleFromForm() {
    const name = dom.rewriteName.value.trim();
    if (!name) {
        throw new Error("Rule name is required.");
    }

    const match = {};
    const host = dom.rewriteHost.value.trim();
    if (host) match.host = host;
    const hostRegex = dom.rewriteHostRegex.value.trim();
    if (hostRegex) match.host_regex = hostRegex;
    const pathPrefix = dom.rewritePathPrefix.value.trim();
    if (pathPrefix) match.path_prefix = pathPrefix;
    const pathRegex = dom.rewritePathRegex.value.trim();
    if (pathRegex) match.path_regex = pathRegex;
    const method = dom.rewriteMethod.value.trim().toUpperCase();
    if (method) match.method = method;

    const methods = parseTokenList(dom.rewriteMethods.value, { upper: true });
    if (methods.length > 0) {
        match.methods = methods;
    }

    const statusRaw = dom.rewriteStatus.value.trim();
    if (statusRaw) {
        const statusValue = Number.parseInt(statusRaw, 10);
        if (!Number.isInteger(statusValue) || statusValue <= 0) {
            throw new Error("Status must be a positive integer.");
        }
        match.status = statusValue;
    }

    const statuses = parseIntegerTokenList(dom.rewriteStatuses.value, "Statuses");
    if (statuses.length > 0) {
        match.statuses = statuses;
    }

    const contentTypeContains = dom.rewriteContentTypeContains.value.trim();
    if (contentTypeContains) match.content_type_contains = contentTypeContains;
    const contentTypeRegex = dom.rewriteContentTypeRegex.value.trim();
    if (contentTypeRegex) match.content_type_regex = contentTypeRegex;

    const reqHeaders = parseHeaderMap(dom.rewriteReqHeaders.value, "Request Header Contains");
    if (Object.keys(reqHeaders).length > 0) {
        match.request_header_contains = reqHeaders;
    }
    const respHeaders = parseHeaderMap(dom.rewriteRespHeaders.value, "Response Header Contains");
    if (Object.keys(respHeaders).length > 0) {
        match.response_header_contains = respHeaders;
    }

    const actions = {};
    const setHeaders = parseHeaderMap(dom.rewriteSetHeaders.value, "Set Headers");
    if (Object.keys(setHeaders).length > 0) {
        actions.set_headers = setHeaders;
    }

    const addHeaders = parseHeaderMap(dom.rewriteAddHeaders.value, "Add Headers");
    if (Object.keys(addHeaders).length > 0) {
        actions.add_headers = addHeaders;
    }

    const delHeaders = parseTokenList(dom.rewriteDelHeaders.value);
    if (delHeaders.length > 0) {
        actions.del_headers = delHeaders;
    }

    const replaceBody = parseReplacementLines(dom.rewriteBodyReplace.value, "from", "to")
        .map((item) => ({ from: item.left, to: item.right }));
    if (replaceBody.length > 0) {
        actions.replace_body = replaceBody;
    }

    const replaceBodyRegex = parseReplacementLines(dom.rewriteBodyRegex.value, "pattern", "replace")
        .map((item) => ({ pattern: item.left, replace: item.right }));
    if (replaceBodyRegex.length > 0) {
        actions.replace_body_regex = replaceBodyRegex;
    }

    if (Object.keys(actions).length === 0) {
        throw new Error("At least one rewrite action is required.");
    }

    const rule = {
        name,
        enabled: dom.rewriteEnabled.checked,
        actions,
    };
    if (Object.keys(match).length > 0) {
        rule.match = match;
    }
    return rule;
}

async function handleRewriteSave(event) {
    event.preventDefault();
    if (!isAdmin()) {
        return;
    }

    dom.rewriteFormError.classList.add("hidden");
    dom.rewriteSaveStatus.textContent = "";

    let rule;
    try {
        rule = buildRewriteRuleFromForm();
    } catch (error) {
        dom.rewriteFormError.textContent = error.message;
        dom.rewriteFormError.classList.remove("hidden");
        return;
    }

    const selected = currentRewriteItem();
    const isManagedUpdate = selected && selected.managed;

    dom.rewriteSaveBtn.disabled = true;
    dom.rewriteDeleteBtn.disabled = true;
    dom.rewriteSaveStatus.textContent = "Saving...";

    try {
        let response;
        if (isManagedUpdate) {
            response = await apiRequest(`/api/v1/rewrites/${selected.managed_id}`, {
                method: "PUT",
                body: { rule },
            });
            state.rewrites.selectedKey = `managed:${selected.managed_id}`;
        } else {
            response = await apiRequest("/api/v1/rewrites", {
                method: "POST",
                body: { rule },
            });
            if (response.managed_id) {
                state.rewrites.selectedKey = `managed:${response.managed_id}`;
            }
        }
        state.rewrites.dirty = false;
        await loadRewrites({ preserveForm: false, forceApply: true });
        dom.rewriteSaveStatus.textContent = "Saved.";
    } catch (error) {
        dom.rewriteSaveStatus.textContent = "";
        dom.rewriteFormError.textContent = error.message;
        dom.rewriteFormError.classList.remove("hidden");
    } finally {
        if (state.rewrites.dirty) {
            dom.rewriteSaveBtn.disabled = false;
            const selectedNow = currentRewriteItem();
            dom.rewriteDeleteBtn.disabled = !(isAdmin() && selectedNow && selectedNow.managed);
        } else {
            renderRewriteEditor();
        }
    }
}

async function handleRewriteDelete() {
    if (!isAdmin()) {
        return;
    }
    const selected = currentRewriteItem();
    if (!selected || !selected.managed) {
        return;
    }
    if (!window.confirm(`Delete rewrite rule "${selected.rule && selected.rule.name ? selected.rule.name : selected.key}"?`)) {
        return;
    }

    dom.rewriteDeleteBtn.disabled = true;
    dom.rewriteSaveBtn.disabled = true;
    dom.rewriteSaveStatus.textContent = "Deleting...";
    dom.rewriteFormError.classList.add("hidden");

    try {
        await apiRequest(`/api/v1/rewrites/${selected.managed_id}`, {
            method: "DELETE",
        });
        state.rewrites.selectedKey = "new";
        state.rewrites.dirty = false;
        await loadRewrites({ preserveForm: false, forceApply: true });
        dom.rewriteSaveStatus.textContent = "Deleted.";
    } catch (error) {
        dom.rewriteSaveStatus.textContent = "";
        dom.rewriteFormError.textContent = error.message;
        dom.rewriteFormError.classList.remove("hidden");
    } finally {
        renderRewriteEditor();
    }
}

async function handleRewriteClone() {
    if (!isAdmin()) {
        return;
    }
    const selected = currentRewriteItem();
    if (!selected || selected.managed) {
        return;
    }

    dom.rewriteCloneBtn.disabled = true;
    dom.rewriteSaveStatus.textContent = "Cloning...";
    dom.rewriteFormError.classList.add("hidden");

    try {
        const response = await apiRequest("/api/v1/rewrites", {
            method: "POST",
            body: { rule: selected.rule || createEmptyRewriteRule() },
        });
        if (response.managed_id) {
            state.rewrites.selectedKey = `managed:${response.managed_id}`;
        } else {
            state.rewrites.selectedKey = "new";
        }
        state.rewrites.dirty = false;
        await loadRewrites({ preserveForm: false, forceApply: true });
        dom.rewriteSaveStatus.textContent = "Cloned.";
    } catch (error) {
        dom.rewriteSaveStatus.textContent = "";
        dom.rewriteFormError.textContent = error.message;
        dom.rewriteFormError.classList.remove("hidden");
    } finally {
        renderRewriteEditor();
    }
}

async function loadRewrites(options = {}) {
    const { preserveForm = false, forceApply = false } = options;
    try {
        const response = await apiRequest("/api/v1/rewrites");
        const rules = Array.isArray(response.rules) ? response.rules : [];
        const items = Array.isArray(response.items) ? response.items : [];
        const managedFile = String(response.managed_file || "");
        const warning = String(response.warning || "");
        const snapshot = JSON.stringify({
            managed_file: managedFile,
            items,
        });

        if (!forceApply && state.rewrites.items.length > 0 && items.length === 0 && warning === "") {
            state.rewrites.transientEmptySkips += 1;
            if (state.rewrites.transientEmptySkips < 2) {
                dom.rewriteSaveStatus.textContent = "Waiting for stable rewrite snapshot...";
                return state.rewrites.rules;
            }
        } else {
            state.rewrites.transientEmptySkips = 0;
        }

        const unchanged = snapshot === state.rewrites.lastSnapshot && warning === state.rewrites.lastWarning;

        state.rewrites.rules = rules;
        state.rewrites.items = items;
        state.rewrites.managedFile = managedFile;
        state.rewrites.lastSnapshot = snapshot;
        state.rewrites.lastWarning = warning;

        if (state.rewrites.selectedKey !== "new" && !rewriteKeyExists(state.rewrites.selectedKey)) {
            state.rewrites.selectedKey = items.length ? items[0].key : "new";
        }
        dom.rewriteCount.textContent = String(rules.length);

        if (!unchanged || forceApply) {
            renderRewriteList();
            dom.rewriteManagedFile.textContent = state.rewrites.managedFile
                ? `managed file: ${state.rewrites.managedFile}`
                : "managed file: -";

            if (!preserveForm) {
                renderRewriteEditor();
                state.rewrites.dirty = false;
            }
        }

        if (warning !== "") {
            dom.rewriteSaveStatus.textContent = `Warning: ${warning}`;
        } else if (!state.rewrites.dirty) {
            dom.rewriteSaveStatus.textContent = "";
        }
        return rules;
    } catch (_error) {
        dom.rewriteSaveStatus.textContent = "Rewrite list refresh failed. Showing last loaded snapshot.";
        return state.rewrites.rules;
    }
}

function trafficQueryString() {
    const params = new URLSearchParams();
    params.set("limit", String(state.traffic.limit));
    params.set("offset", String(state.traffic.offset));
    if (state.traffic.q) {
        params.set("q", state.traffic.q);
    }
    if (state.traffic.mode) {
        params.set("mode", state.traffic.mode);
    }
    return params.toString();
}

async function loadTraffic() {
    try {
        const response = await apiRequest(`/api/v1/traffic?${trafficQueryString()}`);
        state.traffic.items = Array.isArray(response.items) ? response.items : [];
        state.traffic.total = Number(response.total || 0);
        renderTraffic();
    } catch (_error) {}
}

function renderTraffic() {
    const items = state.traffic.items;
    if (!items.length) {
        dom.trafficBody.innerHTML = `<tr><td colspan="7" class="muted">No captured traffic for this query.</td></tr>`;
    } else {
        dom.trafficBody.innerHTML = items
            .map((entry) => {
                const mode = String(entry.mode || "inspected").toLowerCase();
                const modeClass = `mode-${mode}`;
                return `
                <tr class="row-clickable" data-id="${entry.id}">
                    <td>${escapeHTML(formatTime(entry.timestamp))}</td>
                    <td><span class="mode-pill ${escapeHTML(modeClass)}">${escapeHTML(mode)}</span></td>
                    <td>${escapeHTML(entry.method || "-")}</td>
                    <td class="host-cell" title="${escapeHTML(entry.host || "-")}">${escapeHTML(entry.host || "-")}</td>
                    <td class="url-cell" title="${escapeHTML(entry.url || "-")}">${escapeHTML(entry.url || "-")}</td>
                    <td>${escapeHTML(entry.source_ip || "-")}</td>
                    <td>${escapeHTML(entry.status || "-")}</td>
                </tr>
            `;
            })
            .join("");
    }

    const start = state.traffic.total === 0 ? 0 : state.traffic.offset + 1;
    const end = Math.min(state.traffic.offset + state.traffic.limit, state.traffic.total);
    dom.trafficSummary.textContent = `${start}-${end} of ${state.traffic.total.toLocaleString()} results`;

    dom.prevPageBtn.disabled = state.traffic.offset === 0;
    dom.nextPageBtn.disabled = state.traffic.offset + state.traffic.limit >= state.traffic.total;
}

async function showTrafficDetail(id) {
    try {
        const detail = await apiRequest(`/api/v1/traffic/${id}`);
        openModal(
            `Traffic #${id}`,
            `
            <h5>Request</h5>
            <pre>${escapeHTML(detail.request_full || "")}${detail.request_body ? "\n\n" + escapeHTML(detail.request_body) : ""}</pre>
            <h5>Response</h5>
            <pre>${escapeHTML(detail.response_full || "")}${detail.response_body ? "\n\n" + escapeHTML(detail.response_body) : ""}</pre>
        `
        );
    } catch (error) {
        openModal("Traffic Detail", `<p class="form-error">${escapeHTML(error.message)}</p>`);
    }
}

function openModal(title, html) {
    dom.modalTitle.textContent = title;
    dom.modalContent.innerHTML = html;
    dom.modal.classList.remove("hidden");
}

function closeModal() {
    dom.modal.classList.add("hidden");
}

async function loadUsers() {
    if (!isAdmin()) {
        return;
    }
    try {
        const response = await apiRequest("/api/v1/users");
        state.users = Array.isArray(response.users) ? response.users : [];
        renderUsers();
    } catch (error) {
        dom.userFormError.textContent = error.message;
        dom.userFormError.classList.remove("hidden");
    }
}

function renderUsers() {
    if (!state.users.length) {
        dom.usersBody.innerHTML = `<tr><td colspan="6" class="muted">No users available.</td></tr>`;
        return;
    }

    dom.usersBody.innerHTML = state.users
        .map((user) => {
            const stateLabel = user.is_active ? "Active" : "Disabled";
            return `
            <tr>
                <td>${escapeHTML(user.username)}</td>
                <td>${escapeHTML(user.display_name)}</td>
                <td>${escapeHTML(user.role)}</td>
                <td>${escapeHTML(stateLabel)}</td>
                <td>${escapeHTML(user.last_login_at ? formatTime(user.last_login_at) : "Never")}</td>
                <td>
                    <div class="user-actions">
                        <button type="button" class="btn btn-ghost" data-action="edit" data-id="${user.id}">Edit</button>
                        <button type="button" class="btn btn-ghost" data-action="delete" data-id="${user.id}">Delete</button>
                    </div>
                </td>
            </tr>
        `;
        })
        .join("");
}

function beginEditUser(userID) {
    const target = state.users.find((item) => item.id === userID);
    if (!target) {
        return;
    }

    state.editingUserId = userID;
    dom.userId.value = String(userID);
    dom.userUsername.value = target.username;
    dom.userDisplayName.value = target.display_name;
    dom.userRole.value = target.role;
    dom.userPassword.value = "";
    dom.userPassword.required = false;
    dom.userActive.checked = !!target.is_active;
    dom.userFormTitle.textContent = `Edit User: ${target.username}`;
    dom.userSubmit.textContent = "Update User";
    dom.cancelEditBtn.classList.remove("hidden");
    dom.userFormError.classList.add("hidden");
}

function resetUserForm() {
    state.editingUserId = null;
    dom.userId.value = "";
    dom.userUsername.value = "";
    dom.userDisplayName.value = "";
    dom.userRole.value = "viewer";
    dom.userPassword.value = "";
    dom.userPassword.required = true;
    dom.userActive.checked = true;
    dom.userFormTitle.textContent = "Create User";
    dom.userSubmit.textContent = "Create User";
    dom.cancelEditBtn.classList.add("hidden");
    dom.userFormError.classList.add("hidden");
}

async function handleUserSubmit(event) {
    event.preventDefault();
    if (!isAdmin()) {
        return;
    }

    dom.userFormError.classList.add("hidden");

    const payload = {
        username: dom.userUsername.value.trim(),
        display_name: dom.userDisplayName.value.trim(),
        role: dom.userRole.value,
        is_active: dom.userActive.checked,
    };

    const password = dom.userPassword.value;

    try {
        if (state.editingUserId) {
            const updatePayload = {
                username: payload.username,
                display_name: payload.display_name,
                role: payload.role,
                is_active: payload.is_active,
            };
            if (password.trim() !== "") {
                updatePayload.password = password;
            }

            await apiRequest(`/api/v1/users/${state.editingUserId}`, {
                method: "PUT",
                body: updatePayload,
            });
        } else {
            payload.password = password;
            await apiRequest("/api/v1/users", {
                method: "POST",
                body: payload,
            });
        }

        resetUserForm();
        await loadUsers();
    } catch (error) {
        dom.userFormError.textContent = error.message;
        dom.userFormError.classList.remove("hidden");
    }
}

async function deleteUser(userID) {
    if (!isAdmin()) {
        return;
    }

    const target = state.users.find((item) => item.id === userID);
    if (!target) {
        return;
    }

    if (!window.confirm(`Delete user ${target.username}?`)) {
        return;
    }

    try {
        await apiRequest(`/api/v1/users/${userID}`, { method: "DELETE" });
        if (state.editingUserId === userID) {
            resetUserForm();
        }
        await loadUsers();
    } catch (error) {
        alert(error.message);
    }
}

void bootstrap();
