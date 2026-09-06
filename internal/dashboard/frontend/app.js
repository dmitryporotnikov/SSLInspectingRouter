const state = {
    user: null,
    authToken: null,
    theme: "dark",
    locale: {
        code: "en",
        languages: [],
        strings: {},
        fallbackStrings: {},
        ready: false,
    },
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
    firewall: {
        enabled: false,
        rules: [],
        selectedRuleId: null,
        dirty: false,
        activeSubTab: "firewall-rules",
        outbound: {
            ports: [],
            dirty: false,
        },
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

const THEME_KEY = "sir_theme";
const LANGUAGE_KEY = "sir_language";
const DEFAULT_LOCALE_CODE = "en";
const CONNECTION_FAILURE_THRESHOLD = 3;
const CONNECTION_STALE_AFTER_MS = 10000;
let refreshInFlight = null;
let mutationRevision = 0;
let settingsSaving = false;
let trafficRequestId = 0;
let trafficSnapshot = "";
let lastRulesRefreshAt = 0;
let modalReturnFocus = null;

// A draft belongs to the user until it is successfully saved, even after blur.
const dirtyFields = new Set();

const dom = {
    languageSelects: Array.from(document.querySelectorAll("[data-language-select]")),
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
    firewallSection: document.getElementById("firewall-section"),
    firewallNav: document.getElementById("firewall-nav"),
    firewallModeToggle: document.getElementById("firewall-mode-toggle"),
    firewallModeWrap: document.getElementById("firewall-mode-wrap"),
    firewallAddRuleBtn: document.getElementById("firewall-add-rule-btn"),
    firewallRulesCount: document.getElementById("firewall-rules-count"),
    firewallRulesList: document.getElementById("firewall-rules-list"),
    firewallRuleForm: document.getElementById("firewall-rule-form"),
    firewallRuleFormTitle: document.getElementById("firewall-rule-form-title"),
    firewallRuleEnabled: document.getElementById("firewall-rule-enabled"),
    firewallRuleAction: document.getElementById("firewall-rule-action"),
    firewallBlockModeWrap: document.getElementById("firewall-block-mode-wrap"),
    firewallRuleBlockMode: document.getElementById("firewall-rule-block-mode"),
    firewallRulePriority: document.getElementById("firewall-rule-priority"),
    firewallRuleHost: document.getElementById("firewall-rule-host"),
    firewallRuleHostRegex: document.getElementById("firewall-rule-host-regex"),
    firewallRuleIP: document.getElementById("firewall-rule-ip"),
    firewallRuleCIDR: document.getElementById("firewall-rule-cidr"),
    firewallSaveBtn: document.getElementById("firewall-save-btn"),
    firewallDeleteBtn: document.getElementById("firewall-delete-btn"),
    firewallCancelBtn: document.getElementById("firewall-cancel-btn"),
    firewallSaveStatus: document.getElementById("firewall-save-status"),
    firewallFormError: document.getElementById("firewall-form-error"),
    firewallRulesPane: document.getElementById("firewall-rules-pane"),
    firewallOutboundPane: document.getElementById("firewall-outbound-pane"),
    firewallSubnavButtons: Array.from(document.querySelectorAll("#firewall-subnav .subnav-item")),
    firewallOutboundRows: document.getElementById("firewall-outbound-rows"),
    firewallOutboundEmpty: document.getElementById("firewall-outbound-empty"),
    firewallOutboundForm: document.getElementById("firewall-outbound-form"),
    firewallOutboundPort: document.getElementById("firewall-outbound-port"),
    firewallOutboundProtocol: document.getElementById("firewall-outbound-protocol"),
    firewallOutboundSaveBtn: document.getElementById("firewall-outbound-save-btn"),
    firewallOutboundSaveStatus: document.getElementById("firewall-outbound-save-status"),
    firewallOutboundFormError: document.getElementById("firewall-outbound-form-error"),
    currentUser: document.getElementById("current-user"),
    currentRole: document.getElementById("current-role"),
    themeToggle: document.getElementById("theme-toggle"),
    themeToggleIcon: document.getElementById("theme-toggle-icon"),
    settingsPanel: document.getElementById("settings-panel"),
    settingsNav: document.getElementById("settings-nav"),
    settingsFeedback: document.getElementById("settings-feedback"),
    inspectionControlWrap: document.getElementById("inspection-control-wrap"),
    inspectionToggle: document.getElementById("inspection-toggle"),
    truncateLogWrap: document.getElementById("truncate-log-wrap"),
    truncateLogToggle: document.getElementById("truncate-log-toggle"),
    logNothingWrap: document.getElementById("log-nothing-wrap"),
    logNothingToggle: document.getElementById("log-nothing-toggle"),
    sniOnlyWrap: document.getElementById("sni-only-wrap"),
    sniOnlyToggle: document.getElementById("sni-only-toggle"),
    wireguardWrap: document.getElementById("wireguard-wrap"),
    wireguardToggle: document.getElementById("wireguard-toggle"),
    torWrap: document.getElementById("tor-wrap"),
    torToggle: document.getElementById("tor-toggle"),
    wireguardConfigInput: document.getElementById("wireguard-config-input"),
    wireguardConfigSave: document.getElementById("wireguard-config-save"),
    wireguardConfigStatus: document.getElementById("wireguard-config-status"),
    wireguardMetaValue: document.getElementById("wireguard-meta-value"),
    torMetaValue: document.getElementById("tor-meta-value"),
    torStatus: document.getElementById("tor-status"),
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
    egressInterfaceValue: document.getElementById("egress-interface-value"),
    defaultEgressInterfaceValue: document.getElementById("default-egress-interface-value"),
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
    flushTrafficBtn: document.getElementById("flush-traffic-btn"),
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

function clearElement(element) {
    if (!element) return;
    while (element.firstChild) {
        element.removeChild(element.firstChild);
    }
}

function appendEmptyTableRow(tbody, colSpan, message) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = colSpan;
    cell.className = "muted";
    cell.textContent = message;
    row.appendChild(cell);
    tbody.appendChild(row);
}

function normalizeClassToken(value, fallback) {
    const normalized = String(value || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, "");
    if (normalized !== "") {
        return normalized;
    }
    return fallback;
}

function normalizeLocaleCode(raw) {
    return String(raw || "")
        .trim()
        .toLowerCase()
        .replace(/_/g, "-");
}

function currentLocaleCode() {
    return normalizeLocaleCode(state.locale.code) || DEFAULT_LOCALE_CODE;
}

function lookupTranslation(source, key) {
    if (!source || typeof source !== "object" || !key) {
        return undefined;
    }
    return String(key)
        .split(".")
        .reduce((value, token) => (value && typeof value === "object" ? value[token] : undefined), source);
}

function interpolate(template, params = {}) {
    return String(template).replace(/\{(\w+)\}/g, (match, token) => {
        if (Object.prototype.hasOwnProperty.call(params, token)) {
            return String(params[token]);
        }
        return match;
    });
}

function t(key, params = {}) {
    const direct = lookupTranslation(state.locale.strings, key);
    if (typeof direct === "string") {
        return interpolate(direct, params);
    }
    const fallback = lookupTranslation(state.locale.fallbackStrings, key);
    if (typeof fallback === "string") {
        return interpolate(fallback, params);
    }
    return key;
}

function tp(baseKey, count, params = {}) {
    const suffix = Number(count) === 1 ? "one" : "other";
    return t(`${baseKey}.${suffix}`, { count, ...params });
}

function loadStoredLanguage() {
    try {
        return normalizeLocaleCode(window.localStorage.getItem(LANGUAGE_KEY));
    } catch (_error) {
        return "";
    }
}

function persistLanguage(code) {
    try {
        window.localStorage.setItem(LANGUAGE_KEY, normalizeLocaleCode(code));
    } catch (_error) {
        // Ignore storage failures; language still applies for this load.
    }
}

function defaultLanguageCatalog() {
    return [
        {
            code: DEFAULT_LOCALE_CODE,
            name: "English",
            native_name: "English",
            url: "/locales/en.json",
        },
    ];
}

async function readJSON(url) {
    const response = await fetch(url, {
        headers: {
            Accept: "application/json",
        },
        credentials: "same-origin",
    });
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    return response.json();
}

async function loadLanguageCatalog() {
    try {
        const payload = await readJSON("/api/v1/localization/languages");
        const languages = Array.isArray(payload.languages) ? payload.languages : [];
        if (languages.length > 0) {
            return languages;
        }
    } catch (error) {
        console.error("language catalog load failed", error);
    }
    return defaultLanguageCatalog();
}

function findLanguageOption(code) {
    const normalized = normalizeLocaleCode(code);
    return state.locale.languages.find((language) => normalizeLocaleCode(language.code) === normalized) || null;
}

async function loadLocaleBundle(code, options = {}) {
    const { allowFallback = true } = options;
    const language = findLanguageOption(code);
    if (!language || !language.url) {
        if (allowFallback && normalizeLocaleCode(code) !== DEFAULT_LOCALE_CODE) {
            return loadLocaleBundle(DEFAULT_LOCALE_CODE, { allowFallback: false });
        }
        throw new Error(`missing locale bundle for ${code}`);
    }

    try {
        const payload = await readJSON(language.url);
        return {
            code: normalizeLocaleCode((payload.meta && payload.meta.code) || language.code || code),
            strings: payload && payload.strings && typeof payload.strings === "object" ? payload.strings : {},
        };
    } catch (error) {
        if (allowFallback && normalizeLocaleCode(code) !== DEFAULT_LOCALE_CODE) {
            return loadLocaleBundle(DEFAULT_LOCALE_CODE, { allowFallback: false });
        }
        throw error;
    }
}

function preferredLanguageCode() {
    const availableCodes = new Set(state.locale.languages.map((language) => normalizeLocaleCode(language.code)));
    const urlLanguage = normalizeLocaleCode(new URL(window.location.href).searchParams.get("lang"));
    if (urlLanguage && availableCodes.has(urlLanguage)) {
        return urlLanguage;
    }
    const storedLanguage = loadStoredLanguage();
    if (storedLanguage && availableCodes.has(storedLanguage)) {
        return storedLanguage;
    }
    if (availableCodes.has(DEFAULT_LOCALE_CODE)) {
        return DEFAULT_LOCALE_CODE;
    }
    const firstLanguage = state.locale.languages[0];
    return firstLanguage ? normalizeLocaleCode(firstLanguage.code) : DEFAULT_LOCALE_CODE;
}

function populateLanguageOptions() {
    dom.languageSelects.forEach((select) => {
        clearElement(select);
        state.locale.languages.forEach((language) => {
            const option = document.createElement("option");
            const code = normalizeLocaleCode(language.code);
            const displayName = String(language.native_name || language.name || code);
            const secondaryName = String(language.name || "");
            option.value = code;
            option.textContent = displayName !== secondaryName && secondaryName !== ""
                ? `${displayName} (${secondaryName})`
                : displayName;
            select.appendChild(option);
        });
        select.value = currentLocaleCode();
    });
}

function formatRole(role) {
    const normalized = normalizeClassToken(role, "");
    if (!normalized) {
        return "-";
    }
    const translated = lookupTranslation(state.locale.strings, `roles.${normalized}`) || lookupTranslation(state.locale.fallbackStrings, `roles.${normalized}`);
    return typeof translated === "string" ? translated : String(role);
}

function formatTrafficMode(mode) {
    const normalized = normalizeClassToken(mode, "inspected");
    const translated = lookupTranslation(state.locale.strings, `traffic.modes.${normalized}`) || lookupTranslation(state.locale.fallbackStrings, `traffic.modes.${normalized}`);
    return typeof translated === "string" ? translated : String(mode || normalized);
}

function formatManagedFileLabel(filePath) {
    if (filePath) {
        return t("rewrites.managedFileValue", { file: filePath });
    }
    return t("rewrites.managedFileEmpty");
}

function applyStaticTranslations() {
    document.documentElement.lang = currentLocaleCode();
    document.title = t("app.title");

    Array.from(document.querySelectorAll("[data-i18n]")).forEach((element) => {
        element.textContent = t(element.dataset.i18n);
    });
    Array.from(document.querySelectorAll("[data-i18n-html]")).forEach((element) => {
        element.innerHTML = t(element.dataset.i18nHtml);
    });
    Array.from(document.querySelectorAll("[data-i18n-placeholder]")).forEach((element) => {
        element.placeholder = t(element.dataset.i18nPlaceholder);
    });
    Array.from(document.querySelectorAll("[data-i18n-title]")).forEach((element) => {
        element.title = t(element.dataset.i18nTitle);
    });
    Array.from(document.querySelectorAll("[data-i18n-aria-label]")).forEach((element) => {
        element.setAttribute("aria-label", t(element.dataset.i18nAriaLabel));
    });

    updateThemeToggle();
    setConnectionState(state.connection.connected);
    resetUserForm();
    renderTraffic();
    renderRewriteEditor();
    if (state.status) {
        applyStatus(state.status);
    }
    if (state.user) {
        applyUserContext();
    }
    renderUsers();
}

async function initializeLocalization() {
    state.locale.languages = await loadLanguageCatalog();
    const preferredCode = preferredLanguageCode();
    persistLanguage(preferredCode);

    const primaryBundle = await loadLocaleBundle(preferredCode);
    let fallbackStrings = primaryBundle.strings;
    if (normalizeLocaleCode(primaryBundle.code) !== DEFAULT_LOCALE_CODE) {
        try {
            const fallbackBundle = await loadLocaleBundle(DEFAULT_LOCALE_CODE, { allowFallback: false });
            fallbackStrings = fallbackBundle.strings;
        } catch (error) {
            console.error("default locale load failed", error);
        }
    }

    state.locale.code = primaryBundle.code || preferredCode;
    state.locale.strings = primaryBundle.strings;
    state.locale.fallbackStrings = fallbackStrings;
    state.locale.ready = true;
    persistLanguage(state.locale.code);

    populateLanguageOptions();
    applyStaticTranslations();
    document.body.dataset.i18nState = "ready";
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
    return date.toLocaleString(currentLocaleCode());
}

function setConnectionState(connected) {
    state.connection.connected = connected;
    dom.metricConnection.textContent = connected ? t("status.connected") : t("status.disconnected");
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
    dom.themeToggle.title = t("theme.switchTo", { theme: t(`theme.${nextTheme}`) });
    dom.themeToggle.setAttribute("aria-label", t("theme.switchTo", { theme: t(`theme.${nextTheme}`) }));
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

function persistAuthToken(token) {
    // Keep bearer token in-memory only. Session persistence is handled by HttpOnly cookie auth.
    state.authToken = token && token.trim() !== "" ? token.trim() : null;
}

async function apiRequest(path, options = {}) {
    const {
        method = "GET",
        body,
        allowUnauthorized = false,
        trackConnectivity = true,
    } = options;
    const revision = mutationRevision;
    if (method !== "GET") mutationRevision++;
    const controller = new AbortController();
    const timeout = method === "GET" ? setTimeout(() => controller.abort(), 15000) : null;

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
    let payload;
    try {
        response = await fetch(path, {
            method,
            credentials: "include",
            headers,
            signal: controller.signal,
            body: body !== undefined ? JSON.stringify(body) : undefined,
        });
        const contentType = response.headers.get("content-type") || "";
        payload = contentType.includes("application/json") ? await response.json() : null;
    } catch (_error) {
        if (trackConnectivity) {
            reportApiFailure();
        }
        throw new Error(t("errors.networkRequestFailed"));
    } finally {
        clearTimeout(timeout);
        if (method !== "GET") mutationRevision++;
    }

    if (!response.ok) {
        if (trackConnectivity && response.status >= 500) {
            reportApiFailure();
        }
        if (response.status === 401 && !allowUnauthorized) {
            handleSessionExpired();
        }
        const error = new Error((payload && payload.error) || t("errors.requestFailed", { status: response.status }));
        error.status = response.status;
        throw error;
    }

    // A read started before a write must never roll the visible state back.
    if (method === "GET" && revision !== mutationRevision) {
        const error = new Error("Superseded dashboard response");
        error.name = "SupersededResponse";
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
    dom.currentRole.textContent = user ? formatRole(user.role) : "-";

    const admin = isAdmin();
    dom.usersNav.classList.toggle("hidden", !admin);
    dom.firewallNav.classList.toggle("hidden", !admin);
    dom.settingsNav.classList.toggle("hidden", !admin);
    dom.settingsPanel.classList.toggle("hidden", !admin || state.section !== "settings");
    dom.bodyArtifactsMeta.classList.toggle("hidden", !admin);
    dom.flushTrafficBtn.disabled = !admin;
    dom.flushTrafficBtn.title = admin ? t("traffic.flushTitle") : t("users.adminRequired");
    if (!admin && (state.section === "users" || state.section === "settings")) {
        switchSection("traffic");
    } else if (!admin && state.section === "firewall") {
        switchSection("traffic");
    }
    syncEgressToggleAvailability();
    renderRewriteEditor();
}

function switchSection(section) {
    if (!isAdmin() && ["settings", "users", "firewall"].includes(section)) section = "traffic";
    state.section = section;
    dom.navButtons.forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.section === section);
        if (btn.dataset.section === section) btn.setAttribute("aria-current", "page");
        else btn.removeAttribute("aria-current");
    });

    dom.trafficSection.classList.toggle("hidden", section !== "traffic");
    dom.rewritesSection.classList.toggle("hidden", section !== "rewrites");
    dom.firewallSection.classList.toggle("hidden", section !== "firewall");
    dom.usersSection.classList.toggle("hidden", section !== "users");
    dom.settingsPanel.classList.toggle("hidden", section !== "settings");

    if (section === "rewrites") {
        if (!state.rewrites.dirty) renderRewriteEditor();
    } else if (section === "firewall") {
        if (!state.firewall.dirty) renderFirewallTab();
        renderFirewallSubTab();
    }
}

function switchFirewallSubTab(name) {
    if (!name) name = "firewall-rules";
    state.firewall.activeSubTab = name;
    renderFirewallSubTab();
}

function renderFirewallSubTab() {
    const name = state.firewall.activeSubTab || "firewall-rules";
    dom.firewallSubnavButtons.forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.subtab === name);
    });
    dom.firewallRulesPane.classList.toggle("hidden", name !== "firewall-rules");
    dom.firewallOutboundPane.classList.toggle("hidden", name !== "firewall-outbound");
    dom.firewallAddRuleBtn.classList.toggle("hidden", name !== "firewall-rules");

    if (name === "firewall-outbound") {
        renderOutboundPortsPane();
    }
}

async function bootstrap() {
    try {
        await initializeLocalization();
    } catch (error) {
        console.error("localization bootstrap failed", error);
        document.body.dataset.i18nState = "ready";
    }
    initializeTheme();
    bindEvents();

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
    document.querySelectorAll('[id$="save-status"], #policy-save-status, #wireguard-config-status, #tor-status').forEach((element) => {
        element.setAttribute("role", "status");
    });
    [dom.dropListInput, dom.bypassListInput, dom.bodyArtifactsDirectoryInput].forEach((field) => {
        field.addEventListener("input", () => {
            dirtyFields.add(field);
            if (field !== dom.bodyArtifactsDirectoryInput) dom.policySaveStatus.textContent = t("settings.unsaved");
        });
    });
    document.addEventListener("visibilitychange", () => {
        if (document.hidden) stopPolling();
        else if (state.user) {
            void refreshDashboard(false);
            startPolling();
        }
    });
    dom.trafficBody.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") return;
        const row = event.target.closest("tr[data-id]");
        if (row) {
            event.preventDefault();
            void showTrafficDetail(Number(row.dataset.id));
        }
    });
    document.addEventListener("keydown", (event) => {
        if (dom.modal.classList.contains("hidden")) return;
        if (event.key === "Escape") closeModal();
        if (event.key === "Tab") {
            event.preventDefault();
            dom.modalClose.focus();
        }
    });
    dom.loginForm.addEventListener("submit", handleLogin);
    dom.languageSelects.forEach((select) => {
        select.addEventListener("change", () => {
            const nextCode = normalizeLocaleCode(select.value);
            if (!nextCode || nextCode === currentLocaleCode()) {
                return;
            }
            persistLanguage(nextCode);
            window.location.reload();
        });
    });
    dom.themeToggle.addEventListener("click", toggleTheme);
    dom.logoutBtn.addEventListener("click", handleLogout);

    dom.navButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const section = btn.dataset.section;
            if (!isAdmin() && (section === "users" || section === "firewall" || section === "settings")) {
                return;
            }
            switchSection(section);
            if (section === "users") {
                void loadUsers();
            } else if (section === "rewrites") {
                void loadRewrites({ preserveForm: state.rewrites.dirty });
            } else if (section === "firewall") {
                void loadFirewallStatus();
            } else if (section === "traffic") {
                void loadTraffic();
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
    dom.flushTrafficBtn.addEventListener("click", () => {
        void handleFlushTraffic();
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
    dom.logNothingToggle.addEventListener("change", () => {
        void updateLogNothing(dom.logNothingToggle.checked);
    });
    dom.sniOnlyToggle.addEventListener("change", () => {
        void updateSNIOnlyMode(dom.sniOnlyToggle.checked);
    });
    dom.wireguardToggle.addEventListener("change", () => {
        void updateWireGuard(dom.wireguardToggle.checked);
    });
    dom.torToggle.addEventListener("change", () => {
        void updateTor(dom.torToggle.checked);
    });
    dom.wireguardConfigSave.addEventListener("click", () => {
        void saveWireGuardConfig();
    });
    dom.wireguardConfigInput.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
            event.preventDefault();
            void saveWireGuardConfig();
        }
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

    dom.firewallModeToggle.addEventListener("change", () => {
        void updateFirewallMode(dom.firewallModeToggle.checked);
    });
    dom.firewallAddRuleBtn.addEventListener("click", () => {
        beginNewFirewallRule();
    });
    dom.firewallRuleForm.addEventListener("submit", handleFirewallRuleSave);
    dom.firewallDeleteBtn.addEventListener("click", () => {
        void handleFirewallRuleDelete();
    });
    dom.firewallCancelBtn.addEventListener("click", () => {
        resetFirewallRuleForm();
        renderFirewallTab();
    });
    dom.firewallSubnavButtons.forEach((btn) => {
        btn.addEventListener("click", () => switchFirewallSubTab(btn.dataset.subtab));
    });
    dom.firewallOutboundForm.addEventListener("submit", (event) => {
        event.preventDefault();
        const port = Number(dom.firewallOutboundPort.value);
        const protocol = dom.firewallOutboundProtocol.value;
        addOutboundPortRow(port, protocol);
        dom.firewallOutboundPort.value = "";
    });
    dom.firewallOutboundSaveBtn.addEventListener("click", () => {
        void saveOutboundPorts();
    });
    dom.firewallRuleAction.addEventListener("change", () => {
        const action = dom.firewallRuleAction.value;
        dom.firewallBlockModeWrap.classList.toggle("hidden", action !== "block");
    });
    dom.firewallRulesList.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-rule-id]");
        if (!button) return;
        const ruleId = Number(button.dataset.ruleId);
        if (!ruleId) return;
        selectFirewallRule(ruleId);
    });
    dom.firewallRuleForm.addEventListener("input", () => {
        state.firewall.dirty = true;
        dom.firewallSaveStatus.textContent = "";
        dom.firewallFormError.classList.add("hidden");
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
        dom.loginError.textContent = t("login.errors.required");
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
    dirtyFields.clear();
    trafficSnapshot = "";
    lastRulesRefreshAt = 0;
    trafficRequestId++;
    closeModal();
    state.user = null;
    state.status = null;
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
    state.firewall = {
        enabled: false,
        rules: [],
        selectedRuleId: null,
        dirty: false,
        activeSubTab: "firewall-rules",
        outbound: { ports: [], dirty: false },
    };
    state.section = "traffic";
    dom.bodyArtifactsDir.textContent = t("status.disabled");
    dom.bodyArtifactsDir.title = t("status.disabled");
    dom.bodyArtifactsDirectoryInput.value = "";
    dom.wireguardConfigInput.value = "";
    dom.dropListCount.textContent = "0";
    dom.bypassListCount.textContent = "0";
    dom.dropListInput.value = "";
    dom.bypassListInput.value = "";
    dom.policySaveStatus.textContent = "";
    dom.wireguardConfigStatus.textContent = "";
    dom.wireguardMetaValue.textContent = t("status.inactive");
    dom.wireguardMetaValue.title = t("status.inactive");
    dom.wireguardToggle.checked = false;
    dom.torMetaValue.textContent = t("status.inactive");
    dom.torMetaValue.title = t("status.inactive");
    dom.torToggle.checked = false;
    dom.torStatus.textContent = "";
    dom.allowQuicValue.textContent = "-";
    dom.tlsPortsValue.textContent = t("status.default");
    dom.inspectOnlyValue.textContent = t("status.allSources");
    dom.pcapPathValue.textContent = t("status.disabled");
    dom.egressInterfaceValue.textContent = "-";
    dom.defaultEgressInterfaceValue.textContent = "-";
    dom.truncateLogToggle.checked = false;
    dom.logNothingToggle.checked = false;
    dom.rewriteCount.textContent = "0";
    dom.rewriteManagedFile.textContent = formatManagedFileLabel("");
    syncEgressToggleAvailability();
    resetUserForm();
    resetRewriteForm();
    renderTraffic();
    renderRewriteEditor();
    renderUsers();
    showLogin(t("session.expired"));
}

function startPolling() {
    stopPolling();
    if (!state.user || document.hidden) return;
    state.pollHandle = setTimeout(async () => {
        state.pollHandle = null;
        await refreshDashboard(false);
        startPolling();
    }, 3000);
}

function stopPolling() {
    if (state.pollHandle) {
        clearTimeout(state.pollHandle);
        state.pollHandle = null;
    }
}

async function refreshDashboard(forceTrafficReload) {
    if (!state.user || document.hidden) return;
    if (refreshInFlight) {
        await refreshInFlight;
        if (forceTrafficReload) return refreshDashboard(true);
        return;
    }
    dom.refreshBtn.disabled = true;
    refreshInFlight = refreshDashboardData(forceTrafficReload);
    try {
        await refreshInFlight;
    } finally {
        refreshInFlight = null;
        dom.refreshBtn.disabled = false;
    }
}

async function refreshDashboardData(forceTrafficReload) {
    const statusTask = loadStatus();
    const policyTask = loadPolicy();
    const firewallTask = state.section === "firewall" ? loadFirewallStatus() : Promise.resolve();
    const trafficTask = state.section === "traffic" || forceTrafficReload ? loadTraffic() : Promise.resolve();
    const rulesTask = state.section === "rewrites" || forceTrafficReload || Date.now() - lastRulesRefreshAt >= 30000
        ? loadRewrites({ preserveForm: state.rewrites.dirty }) : Promise.resolve();

    if (isAdmin()) {
        await Promise.allSettled([statusTask, policyTask, firewallTask, trafficTask, rulesTask]);
        if (state.section === "users") {
            await loadUsers();
        }
        return;
    }

    await Promise.allSettled([statusTask, policyTask, firewallTask, trafficTask, rulesTask]);
}

async function loadStatus() {
    if (settingsSaving) return;
    try {
        const status = await apiRequest("/api/v1/status");
        if (!settingsSaving) applyStatus(status);
    } catch (_error) {}
}

function applyStatus(status) {
    state.status = status;
    dom.metricDBSize.textContent = formatBytes(status.db_size_bytes || 0);
    const requestCount = Number(status.request_count);
    if (Number.isFinite(requestCount) && requestCount >= 0) {
        dom.metricRequests.textContent = requestCount.toLocaleString(currentLocaleCode());
    }
    const wireguardEnabled = !!status.wireguard_enabled;
    const torEnabled = !!status.tor_enabled;
    dom.inspectionToggle.checked = !!status.inspection_enabled;
    dom.truncateLogToggle.checked = !!status.truncate_log_enabled;
    dom.logNothingToggle.checked = !!status.log_nothing_enabled;
    dom.sniOnlyToggle.checked = !!status.sni_only_mode;
    dom.wireguardToggle.checked = wireguardEnabled;
    dom.torToggle.checked = torEnabled;
    dom.bodyArtifactsToggle.checked = !!status.body_artifacts_enabled;
    syncEgressToggleAvailability();

    const artifactsDir = String(status.body_artifacts_directory || "").trim();
    if (!dirtyFields.has(dom.bodyArtifactsDirectoryInput) && document.activeElement !== dom.bodyArtifactsDirectoryInput) {
        dom.bodyArtifactsDirectoryInput.value = artifactsDir;
    }
    if (status.body_artifacts_enabled && artifactsDir !== "") {
        dom.bodyArtifactsDir.textContent = artifactsDir;
        dom.bodyArtifactsDir.title = artifactsDir;
    } else {
        dom.bodyArtifactsDir.textContent = t("status.disabled");
        dom.bodyArtifactsDir.title = t("status.disabled");
    }

    dom.allowQuicValue.textContent = status.allow_quic ? t("status.enabled") : t("status.blocked");

    const ports = Array.isArray(status.additional_tls_ports) ? status.additional_tls_ports : [];
    if (ports.length > 0) {
        const value = ports.join(", ");
        dom.tlsPortsValue.textContent = value;
        dom.tlsPortsValue.title = value;
    } else {
        dom.tlsPortsValue.textContent = t("status.default");
        dom.tlsPortsValue.title = t("status.default");
    }

    const inspectOnly = Array.isArray(status.inspect_only_sources) ? status.inspect_only_sources : [];
    if (inspectOnly.length > 0) {
        const value = inspectOnly.join(", ");
        dom.inspectOnlyValue.textContent = value;
        dom.inspectOnlyValue.title = value;
    } else {
        dom.inspectOnlyValue.textContent = t("status.allSources");
        dom.inspectOnlyValue.title = t("status.allSources");
    }

    const pcapPath = String(status.pcap_path || "").trim();
    if (pcapPath) {
        dom.pcapPathValue.textContent = pcapPath;
        dom.pcapPathValue.title = pcapPath;
    } else {
        dom.pcapPathValue.textContent = t("status.disabled");
        dom.pcapPathValue.title = t("status.disabled");
    }

    const wireguardInterface = String(status.wireguard_interface || "").trim();
    const wireguardConfigPresent = !!status.wireguard_config_present;
    const wireguardConfigPath = String(status.wireguard_config_path || "").trim();
    let wireguardMeta = wireguardEnabled ? t("status.active") : t("status.inactive");
    if (wireguardInterface) {
        wireguardMeta += ` (${wireguardInterface})`;
    }
    if (!wireguardConfigPresent) {
        wireguardMeta += ` | ${t("status.noConfig")}`;
    }
    dom.wireguardMetaValue.textContent = wireguardMeta;
    dom.wireguardMetaValue.title = wireguardConfigPath || wireguardMeta;

    const torSOCKSAddress = String(status.tor_socks_address || "").trim();
    const torReachable = !!status.tor_reachable;
    const torLastError = String(status.tor_last_error || "").trim();
    let torMeta = torEnabled ? t("status.active") : t("status.inactive");
    if (torSOCKSAddress) {
        torMeta += ` (${torSOCKSAddress})`;
    }
    if (torEnabled && !torReachable) {
        torMeta += ` | ${t("status.offline")}`;
    }
    dom.torMetaValue.textContent = torMeta;
    dom.torMetaValue.title = torMeta;
    dom.torStatus.textContent = torLastError;

    const egressInterface = String(status.egress_interface || "").trim();
    dom.egressInterfaceValue.textContent = egressInterface || "-";
    dom.egressInterfaceValue.title = egressInterface || "-";

    const defaultEgressInterface = String(status.default_egress_interface || "").trim();
    dom.defaultEgressInterfaceValue.textContent = defaultEgressInterface || "-";
    dom.defaultEgressInterfaceValue.title = defaultEgressInterface || "-";
}

function syncEgressToggleAvailability() {
    const wireguardEnabled = !!(state.status && state.status.wireguard_enabled);
    const torEnabled = !!(state.status && state.status.tor_enabled);
    const admin = isAdmin();

    dom.wireguardToggle.disabled = !admin || (torEnabled && !wireguardEnabled);
    dom.torToggle.disabled = !admin || (wireguardEnabled && !torEnabled);
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

    if (!dirtyFields.has(dom.dropListInput) && document.activeElement !== dom.dropListInput) {
        dom.dropListInput.value = formatPolicyEntries(dropList);
    }
    if (!dirtyFields.has(dom.bypassListInput) && document.activeElement !== dom.bypassListInput) {
        dom.bypassListInput.value = formatPolicyEntries(bypassList);
    }
}

async function updateDashboardSettings(payload) {
    if (settingsSaving) return;
    settingsSaving = true;
    const controls = Array.from(dom.settingsPanel.querySelectorAll("input, button, textarea"));
    const disabled = controls.map((control) => control.disabled);
    controls.forEach((control) => { control.disabled = true; });
    dom.settingsPanel.setAttribute("aria-busy", "true");
    dom.settingsFeedback.classList.remove("error");
    dom.settingsFeedback.textContent = t("settings.saving");
    try {
        const status = await apiRequest("/api/v1/status", { method: "PUT", body: payload });
        if (payload.body_artifacts_directory !== undefined) dirtyFields.delete(dom.bodyArtifactsDirectoryInput);
        applyStatus(status);
        dom.settingsFeedback.textContent = t("settings.saved");
    } catch (error) {
        dom.settingsFeedback.classList.add("error");
        dom.settingsFeedback.textContent = error.message;
        throw error;
    } finally {
        settingsSaving = false;
        controls.forEach((control, index) => { control.disabled = disabled[index]; });
        dom.settingsPanel.removeAttribute("aria-busy");
        syncEgressToggleAvailability();
    }
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

async function updateLogNothing(enabled) {
    if (!isAdmin()) {
        return;
    }

    try {
        await updateDashboardSettings({ log_nothing_enabled: enabled });
    } catch (error) {
        dom.logNothingToggle.checked = !enabled;
        alert(error.message);
    }
}

async function updateSNIOnlyMode(enabled) {
    if (!isAdmin()) {
        return;
    }

    try {
        await updateDashboardSettings({ sni_only_mode: enabled });
    } catch (error) {
        dom.sniOnlyToggle.checked = !enabled;
        alert(error.message);
    }
}

async function updateWireGuard(enabled) {
    if (!isAdmin()) {
        return;
    }
    if (enabled && state.status && state.status.tor_enabled) {
        dom.wireguardToggle.checked = false;
        dom.wireguardConfigStatus.textContent = t("wireguard.disableTorFirst");
        alert(t("wireguard.disableTorFirst"));
        syncEgressToggleAvailability();
        return;
    }

    dom.wireguardConfigStatus.textContent = enabled ? t("wireguard.enabling") : t("wireguard.disabling");
    dom.wireguardToggle.disabled = true;

    try {
        await updateDashboardSettings({ wireguard_enabled: enabled });
        dom.wireguardConfigStatus.textContent = enabled ? t("wireguard.enabled") : t("wireguard.disabled");
    } catch (error) {
        dom.wireguardToggle.checked = !enabled;
        dom.wireguardConfigStatus.textContent = "";
        alert(error.message);
    } finally {
        syncEgressToggleAvailability();
    }
}

async function updateTor(enabled) {
    if (!isAdmin()) {
        return;
    }
    if (enabled && state.status && state.status.wireguard_enabled) {
        dom.torToggle.checked = false;
        dom.torStatus.textContent = t("tor.disableWireGuardFirst");
        alert(t("tor.disableWireGuardFirst"));
        syncEgressToggleAvailability();
        return;
    }

    dom.torStatus.textContent = enabled ? t("tor.enabling") : t("tor.disabling");
    dom.torToggle.disabled = true;

    try {
        await updateDashboardSettings({ tor_enabled: enabled });
        dom.torStatus.textContent = enabled ? t("tor.enabled") : t("tor.disabled");
    } catch (error) {
        dom.torToggle.checked = !enabled;
        dom.torStatus.textContent = "";
        alert(error.message);
    } finally {
        syncEgressToggleAvailability();
    }
}

async function saveWireGuardConfig() {
    if (!isAdmin()) {
        return;
    }

    const config = dom.wireguardConfigInput.value;
    if (!config || !config.trim()) {
        alert(t("wireguard.errors.configEmpty"));
        dom.wireguardConfigInput.focus();
        return;
    }

    dom.wireguardConfigSave.disabled = true;
    dom.wireguardConfigStatus.textContent = t("wireguard.savingConfig");

    try {
        await updateDashboardSettings({ wireguard_config: config });
        const active = !!(state.status && state.status.wireguard_enabled);
        dom.wireguardConfigStatus.textContent = active
            ? t("wireguard.configSavedApply")
            : t("wireguard.configSaved");
    } catch (error) {
        dom.wireguardConfigStatus.textContent = "";
        alert(error.message);
    } finally {
        dom.wireguardConfigSave.disabled = false;
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
        alert(t("artifacts.errors.directoryEmpty"));
        dom.bodyArtifactsDirectoryInput.focus();
        return;
    }

    try {
        await updateDashboardSettings({ body_artifacts_directory: dir });
    } catch (error) {
        alert(error.message);
    }
}

async function updateTrafficPolicy() {
    if (!isAdmin()) {
        return;
    }

    const dropList = parsePolicyEntries(dom.dropListInput.value);
    const bypassList = parsePolicyEntries(dom.bypassListInput.value);
    const draftDrop = dom.dropListInput.value;
    const draftBypass = dom.bypassListInput.value;

    dom.policySaveBtn.disabled = true;
    dom.policySaveStatus.textContent = t("settings.saving");

    try {
        const policy = await apiRequest("/api/v1/policy", {
            method: "PUT",
            body: {
                drop_list: dropList,
                bypass_list: bypassList,
            },
        });
        if (dom.dropListInput.value === draftDrop) dirtyFields.delete(dom.dropListInput);
        if (dom.bypassListInput.value === draftBypass) dirtyFields.delete(dom.bypassListInput);
        applyPolicy(policy);
        dom.policySaveStatus.textContent = dirtyFields.has(dom.dropListInput) || dirtyFields.has(dom.bypassListInput)
            ? t("settings.unsaved") : t("settings.saved");
    } catch (error) {
        dom.policySaveStatus.textContent = "";
        alert(error.message);
    } finally {
        dom.policySaveBtn.disabled = false;
    }
}

async function handleFlushTraffic() {
    if (!isAdmin()) {
        return;
    }
    if (!window.confirm(t("traffic.flushConfirm"))) {
        return;
    }

    const previousLabel = dom.flushTrafficBtn.textContent;
    dom.flushTrafficBtn.disabled = true;
    dom.flushTrafficBtn.textContent = t("traffic.flushing");
    try {
        await apiRequest("/api/v1/traffic", { method: "DELETE" });
        state.traffic.offset = 0;
        await Promise.allSettled([loadTraffic(), loadStatus()]);
    } catch (error) {
        alert(error.message);
    } finally {
        dom.flushTrafficBtn.textContent = previousLabel;
        dom.flushTrafficBtn.disabled = false;
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
            throw new Error(t("rewrites.errors.positiveIntegers", { label }));
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
            throw new Error(t("rewrites.errors.headerFormat", { label }));
        }
        const key = line.slice(0, separator).trim();
        const val = line.slice(separator + 1).trim();
        if (!key || !val) {
            throw new Error(t("rewrites.errors.headerNameAndValue", { label }));
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
            throw new Error(t("rewrites.errors.replacementFormat", { left: leftLabel, right: rightLabel }));
        }
        const left = line.slice(0, separator).trim();
        const right = line.slice(separator + 2).trim();
        if (!left) {
            throw new Error(t("rewrites.errors.valueCannotBeEmpty", { label: leftLabel }));
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
    if (match.host) parts.push(t("rewrites.summary.host", { value: match.host }));
    if (match.host_regex) parts.push(t("rewrites.summary.hostRegex"));
    if (match.path_prefix) parts.push(t("rewrites.summary.pathPrefix", { value: match.path_prefix }));
    if (match.path_regex) parts.push(t("rewrites.summary.pathRegex"));
    if (match.method) parts.push(t("rewrites.summary.method", { value: String(match.method).toUpperCase() }));
    if (Array.isArray(match.methods) && match.methods.length) parts.push(t("rewrites.summary.methods", { count: match.methods.length }));
    if (match.status) parts.push(t("rewrites.summary.status", { value: match.status }));
    if (Array.isArray(match.statuses) && match.statuses.length) parts.push(t("rewrites.summary.statuses", { count: match.statuses.length }));
    if (match.content_type_contains) parts.push(t("rewrites.summary.contentTypeContains", { value: match.content_type_contains }));
    if (match.content_type_regex) parts.push(t("rewrites.summary.contentTypeRegex"));
    if (!parts.length) {
        return t("rewrites.summary.matchesAllResponses");
    }
    return parts.join(" • ");
}

function renderRewriteList() {
    clearElement(dom.rewriteList);
    if (!state.rewrites.items.length) {
        const empty = document.createElement("p");
        empty.className = "muted rewrite-empty";
        empty.textContent = t("rewrites.empty");
        dom.rewriteList.appendChild(empty);
        return;
    }

    const fragment = document.createDocumentFragment();
    state.rewrites.items.forEach((item) => {
        const selected = item.key === state.rewrites.selectedKey;
        const rule = item.rule || {};
        const enabledLabel = rule.enabled === false ? t("status.disabled") : t("status.enabled");
        const scopeLabel = item.managed ? t("rewrites.badges.managed") : t("rewrites.badges.external");
        const actionCount = rewriteActionCount(rule);
        const title = rule.name || `${item.file}#${item.index}`;

        const button = document.createElement("button");
        button.type = "button";
        button.className = selected ? "rewrite-list-item active" : "rewrite-list-item";
        button.dataset.rewriteKey = String(item.key || "");

        const top = document.createElement("div");
        top.className = "rewrite-list-top";

        const strong = document.createElement("strong");
        strong.title = title;
        strong.textContent = title;
        top.appendChild(strong);

        const badge = document.createElement("span");
        badge.className = item.managed ? "rewrite-badge managed" : "rewrite-badge external";
        badge.textContent = scopeLabel;
        top.appendChild(badge);

        const matchMeta = document.createElement("div");
        matchMeta.className = "rewrite-list-meta";
        matchMeta.textContent = rewriteMatchSummary(rule);

        const actionMeta = document.createElement("div");
        actionMeta.className = "rewrite-list-meta";
        actionMeta.textContent = tp("rewrites.actionCount", actionCount, { status: enabledLabel });

        button.appendChild(top);
        button.appendChild(matchMeta);
        button.appendChild(actionMeta);
        fragment.appendChild(button);
    });

    dom.rewriteList.appendChild(fragment);
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

    dom.rewriteManagedFile.textContent = formatManagedFileLabel(state.rewrites.managedFile);

    const selected = currentRewriteItem();
    const admin = isAdmin();

    if (!selected) {
        dom.rewriteFormTitle.textContent = t("rewrites.newRuleTitle");
        dom.rewriteFormOrigin.textContent = admin ? t("rewrites.managedRule") : t("rewrites.readOnlyMode");
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
        ? t("rewrites.managedRuleNumber", { id: selected.managed_id })
        : t("rewrites.externalRuleFrom", { file: selected.file });

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
    if (state.rewrites.dirty && !window.confirm(t("rewrites.discardUnsavedChanges"))) return;
    state.rewrites.selectedKey = "new";
    state.rewrites.dirty = false;
    renderRewriteEditor();
}

function selectRewriteKey(key) {
    if (key === state.rewrites.selectedKey) {
        return;
    }
    if (state.rewrites.dirty && !window.confirm(t("rewrites.discardUnsavedChanges"))) {
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
        throw new Error(t("rewrites.errors.ruleNameRequired"));
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
            throw new Error(t("rewrites.errors.statusPositiveInteger"));
        }
        match.status = statusValue;
    }

    const statuses = parseIntegerTokenList(dom.rewriteStatuses.value, t("rewrites.fields.statuses"));
    if (statuses.length > 0) {
        match.statuses = statuses;
    }

    const contentTypeContains = dom.rewriteContentTypeContains.value.trim();
    if (contentTypeContains) match.content_type_contains = contentTypeContains;
    const contentTypeRegex = dom.rewriteContentTypeRegex.value.trim();
    if (contentTypeRegex) match.content_type_regex = contentTypeRegex;

    const reqHeaders = parseHeaderMap(dom.rewriteReqHeaders.value, t("rewrites.fields.requestHeaderContains"));
    if (Object.keys(reqHeaders).length > 0) {
        match.request_header_contains = reqHeaders;
    }
    const respHeaders = parseHeaderMap(dom.rewriteRespHeaders.value, t("rewrites.fields.responseHeaderContains"));
    if (Object.keys(respHeaders).length > 0) {
        match.response_header_contains = respHeaders;
    }

    const actions = {};
    const setHeaders = parseHeaderMap(dom.rewriteSetHeaders.value, t("rewrites.fields.setHeaders"));
    if (Object.keys(setHeaders).length > 0) {
        actions.set_headers = setHeaders;
    }

    const addHeaders = parseHeaderMap(dom.rewriteAddHeaders.value, t("rewrites.fields.addHeaders"));
    if (Object.keys(addHeaders).length > 0) {
        actions.add_headers = addHeaders;
    }

    const delHeaders = parseTokenList(dom.rewriteDelHeaders.value);
    if (delHeaders.length > 0) {
        actions.del_headers = delHeaders;
    }

    const replaceBody = parseReplacementLines(dom.rewriteBodyReplace.value, t("rewrites.labels.from"), t("rewrites.labels.to"))
        .map((item) => ({ from: item.left, to: item.right }));
    if (replaceBody.length > 0) {
        actions.replace_body = replaceBody;
    }

    const replaceBodyRegex = parseReplacementLines(dom.rewriteBodyRegex.value, t("rewrites.labels.pattern"), t("rewrites.labels.replace"))
        .map((item) => ({ pattern: item.left, replace: item.right }));
    if (replaceBodyRegex.length > 0) {
        actions.replace_body_regex = replaceBodyRegex;
    }

    if (Object.keys(actions).length === 0) {
        throw new Error(t("rewrites.errors.actionRequired"));
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
    dom.rewriteSaveStatus.textContent = t("rewrites.status.saving");

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
        dom.rewriteSaveStatus.textContent = t("rewrites.status.saved");
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
    if (!window.confirm(t("rewrites.deleteConfirm", { name: selected.rule && selected.rule.name ? selected.rule.name : selected.key }))) {
        return;
    }

    dom.rewriteDeleteBtn.disabled = true;
    dom.rewriteSaveBtn.disabled = true;
    dom.rewriteSaveStatus.textContent = t("rewrites.status.deleting");
    dom.rewriteFormError.classList.add("hidden");

    try {
        await apiRequest(`/api/v1/rewrites/${selected.managed_id}`, {
            method: "DELETE",
        });
        state.rewrites.selectedKey = "new";
        state.rewrites.dirty = false;
        await loadRewrites({ preserveForm: false, forceApply: true });
        dom.rewriteSaveStatus.textContent = t("rewrites.status.deleted");
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
    dom.rewriteSaveStatus.textContent = t("rewrites.status.cloning");
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
        dom.rewriteSaveStatus.textContent = t("rewrites.status.cloned");
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
        lastRulesRefreshAt = Date.now();
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
                dom.rewriteSaveStatus.textContent = t("rewrites.status.waitingForStableSnapshot");
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
            dom.rewriteManagedFile.textContent = formatManagedFileLabel(state.rewrites.managedFile);

            if (!preserveForm && !state.rewrites.dirty) {
                renderRewriteEditor();
                state.rewrites.dirty = false;
            }
        }

        if (warning !== "") {
            dom.rewriteSaveStatus.textContent = t("rewrites.status.warning", { warning });
        } else if (!state.rewrites.dirty) {
            dom.rewriteSaveStatus.textContent = "";
        }
        return rules;
    } catch (_error) {
        if (_error.name === "SupersededResponse") return state.rewrites.rules;
        dom.rewriteSaveStatus.textContent = t("rewrites.status.refreshFailed");
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
    const requestId = ++trafficRequestId;
    const query = trafficQueryString();
    try {
        const response = await apiRequest(`/api/v1/traffic?${query}`);
        if (requestId !== trafficRequestId || query !== trafficQueryString() || !state.user) return;
        const snapshot = JSON.stringify([query, response.items, response.total, currentLocaleCode()]);
        if (snapshot === trafficSnapshot) return;
        trafficSnapshot = snapshot;
        state.traffic.items = Array.isArray(response.items) ? response.items : [];
        state.traffic.total = Number(response.total || 0);
        renderTraffic();
    } catch (_error) {}
}

function renderTraffic() {
    const items = state.traffic.items;
    clearElement(dom.trafficBody);
    if (!items.length) {
        appendEmptyTableRow(dom.trafficBody, 7, t("traffic.empty"));
    } else {
        const fragment = document.createDocumentFragment();
        items.forEach((entry) => {
            const row = document.createElement("tr");
            row.className = "row-clickable";
            row.dataset.id = String(Number.parseInt(String(entry.id), 10) || 0);
            row.tabIndex = 0;

            const timeCell = document.createElement("td");
            timeCell.textContent = formatTime(entry.timestamp);
            row.appendChild(timeCell);

            const modeCell = document.createElement("td");
            const mode = String(entry.mode || "inspected").toLowerCase();
            const modeToken = normalizeClassToken(mode, "inspected");
            const modePill = document.createElement("span");
            modePill.className = `mode-pill mode-${modeToken}`;
            modePill.textContent = formatTrafficMode(modeToken);
            modeCell.appendChild(modePill);
            row.appendChild(modeCell);

            const methodCell = document.createElement("td");
            methodCell.textContent = String(entry.method || "-");
            row.appendChild(methodCell);

            const hostCell = document.createElement("td");
            const host = String(entry.host || "-");
            hostCell.className = "host-cell";
            hostCell.title = host;
            hostCell.textContent = host;
            row.appendChild(hostCell);

            const urlCell = document.createElement("td");
            const url = String(entry.url || "-");
            urlCell.className = "url-cell";
            urlCell.title = url;
            urlCell.textContent = url;
            row.appendChild(urlCell);

            const sourceCell = document.createElement("td");
            sourceCell.textContent = String(entry.source_ip || "-");
            row.appendChild(sourceCell);

            const statusCell = document.createElement("td");
            statusCell.textContent = String(entry.status || "-");
            row.appendChild(statusCell);

            fragment.appendChild(row);
        });
        dom.trafficBody.appendChild(fragment);
    }

    const start = state.traffic.total === 0 ? 0 : state.traffic.offset + 1;
    const end = Math.min(state.traffic.offset + state.traffic.limit, state.traffic.total);
    dom.trafficSummary.textContent = state.traffic.total === 0
        ? t("traffic.summaryEmpty")
        : t("traffic.summaryRange", {
            start,
            end,
            total: state.traffic.total.toLocaleString(currentLocaleCode()),
        });

    dom.prevPageBtn.disabled = state.traffic.offset === 0;
    dom.nextPageBtn.disabled = state.traffic.offset + state.traffic.limit >= state.traffic.total;
}

async function showTrafficDetail(id) {
    try {
        const detail = await apiRequest(`/api/v1/traffic/${id}`);
        const content = document.createDocumentFragment();

        const requestTitle = document.createElement("h5");
        requestTitle.textContent = t("traffic.request");
        content.appendChild(requestTitle);

        const requestPre = document.createElement("pre");
        requestPre.textContent = `${detail.request_full || ""}${detail.request_body ? "\n\n" + detail.request_body : ""}`;
        content.appendChild(requestPre);

        const responseTitle = document.createElement("h5");
        responseTitle.textContent = t("traffic.response");
        content.appendChild(responseTitle);

        const responsePre = document.createElement("pre");
        responsePre.textContent = `${detail.response_full || ""}${detail.response_body ? "\n\n" + detail.response_body : ""}`;
        content.appendChild(responsePre);

        openModal(t("traffic.detailTitle", { id }), content);
    } catch (error) {
        const errorNode = document.createElement("p");
        errorNode.className = "form-error";
        errorNode.textContent = error.message;
        openModal(t("traffic.detailModalTitle"), errorNode);
    }
}

function openModal(title, content) {
    if (dom.modal.classList.contains("hidden")) modalReturnFocus = document.activeElement;
    dom.modalTitle.textContent = title;
    clearElement(dom.modalContent);
    if (content instanceof Node) {
        dom.modalContent.appendChild(content);
    } else if (content !== null && content !== undefined) {
        dom.modalContent.textContent = String(content);
    }
    dom.modal.classList.remove("hidden");
    dom.appView.inert = true;
    dom.modalClose.focus();
}

function closeModal() {
    dom.modal.classList.add("hidden");
    dom.appView.inert = false;
    if (modalReturnFocus && modalReturnFocus.isConnected) modalReturnFocus.focus();
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
    clearElement(dom.usersBody);
    if (!state.users.length) {
        appendEmptyTableRow(dom.usersBody, 6, t("users.empty"));
        return;
    }

    const fragment = document.createDocumentFragment();
    state.users.forEach((user) => {
        const row = document.createElement("tr");
        const stateLabel = user.is_active ? t("users.state.active") : t("users.state.disabled");

        const usernameCell = document.createElement("td");
        usernameCell.textContent = String(user.username || "");
        row.appendChild(usernameCell);

        const displayNameCell = document.createElement("td");
        displayNameCell.textContent = String(user.display_name || "");
        row.appendChild(displayNameCell);

        const roleCell = document.createElement("td");
        roleCell.textContent = formatRole(user.role);
        row.appendChild(roleCell);

        const stateCell = document.createElement("td");
        stateCell.textContent = stateLabel;
        row.appendChild(stateCell);

        const lastLoginCell = document.createElement("td");
        lastLoginCell.textContent = user.last_login_at ? formatTime(user.last_login_at) : t("users.lastLoginNever");
        row.appendChild(lastLoginCell);

        const actionsCell = document.createElement("td");
        const actionsWrap = document.createElement("div");
        actionsWrap.className = "user-actions";

        const userID = String(Number.parseInt(String(user.id), 10) || 0);

        const editButton = document.createElement("button");
        editButton.type = "button";
        editButton.className = "btn btn-ghost";
        editButton.dataset.action = "edit";
        editButton.dataset.id = userID;
        editButton.textContent = t("actions.edit");
        actionsWrap.appendChild(editButton);

        const deleteButton = document.createElement("button");
        deleteButton.type = "button";
        deleteButton.className = "btn btn-ghost";
        deleteButton.dataset.action = "delete";
        deleteButton.dataset.id = userID;
        deleteButton.textContent = t("actions.delete");
        actionsWrap.appendChild(deleteButton);

        actionsCell.appendChild(actionsWrap);
        row.appendChild(actionsCell);

        fragment.appendChild(row);
    });
    dom.usersBody.appendChild(fragment);
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
    dom.userFormTitle.textContent = t("users.form.editTitle", { username: target.username });
    dom.userSubmit.textContent = t("users.form.submitUpdate");
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
    dom.userFormTitle.textContent = t("users.form.createTitle");
    dom.userSubmit.textContent = t("users.form.submitCreate");
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

    if (!window.confirm(t("users.deleteConfirm", { username: target.username }))) {
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

async function loadFirewallStatus() {
    try {
        const response = await apiRequest("/api/v1/firewall/status");
        state.firewall.enabled = !!response.enabled;
        dom.firewallModeToggle.checked = state.firewall.enabled;
        await loadFirewallRules();
    } catch (_error) {}
    try {
        await loadOutboundPorts();
    } catch (_error) {}
}

async function loadFirewallRules() {
    try {
        const response = await apiRequest("/api/v1/firewall/rules");
        state.firewall.rules = Array.isArray(response.rules) ? response.rules : [];
        dom.firewallRulesCount.textContent = String(state.firewall.rules.length);
        renderFirewallRulesList();
    } catch (_error) {}
}

async function loadOutboundPorts() {
    if (state.firewall.outbound.dirty) return;
    try {
        const response = await apiRequest("/api/v1/firewall/outbound-ports");
        if (state.firewall.outbound.dirty) return;
        const ports = Array.isArray(response.ports) ? response.ports : [];
        state.firewall.outbound.ports = ports.map(normalizeOutboundPort).filter(Boolean);
        state.firewall.outbound.dirty = false;
        renderOutboundPortsPane();
    } catch (_error) {}
}

function normalizeOutboundPort(entry) {
    if (!entry || typeof entry.port !== "number") return null;
    const port = entry.port;
    const proto = String(entry.protocol || "").toLowerCase();
    if ((proto !== "tcp" && proto !== "udp") || port < 1 || port > 65535) return null;
    return { port, protocol: proto };
}

function renderOutboundPortsPane() {
    const ports = state.firewall.outbound.ports;
    clearElement(dom.firewallOutboundRows);

    if (!ports.length) {
        dom.firewallOutboundEmpty.classList.remove("hidden");
    } else {
        dom.firewallOutboundEmpty.classList.add("hidden");
    }

    const fragment = document.createDocumentFragment();
    ports.forEach((entry, index) => {
        const row = document.createElement("tr");

        const portCell = document.createElement("td");
        portCell.textContent = String(entry.port);
        row.appendChild(portCell);

        const protoCell = document.createElement("td");
        protoCell.textContent = entry.protocol.toUpperCase();
        row.appendChild(protoCell);

        const actionCell = document.createElement("td");
        const removeBtn = document.createElement("button");
        removeBtn.type = "button";
        removeBtn.className = "btn btn-ghost";
        removeBtn.textContent = t("actions.remove");
        removeBtn.addEventListener("click", () => removeOutboundPortRow(index));
        actionCell.appendChild(removeBtn);
        row.appendChild(actionCell);

        fragment.appendChild(row);
    });
    dom.firewallOutboundRows.appendChild(fragment);

    dom.firewallOutboundSaveBtn.disabled = !state.firewall.outbound.dirty;
}

function outboundPortsKey(entry) {
    return entry.protocol + "/" + entry.port;
}

function addOutboundPortRow(port, protocol) {
    const entry = normalizeOutboundPort({ port, protocol });
    if (!entry) {
        showOutboundFormError(t("firewall.outbound.errors.invalidEntry"));
        return;
    }
    const ports = state.firewall.outbound.ports;
    const exists = ports.some((p) => outboundPortsKey(p) === outboundPortsKey(entry));
    if (exists) {
        showOutboundFormError(t("firewall.outbound.errors.duplicate"));
        return;
    }
    ports.push(entry);
    state.firewall.outbound.dirty = true;
    hideOutboundFormError();
    renderOutboundPortsPane();
}

function removeOutboundPortRow(index) {
    const ports = state.firewall.outbound.ports;
    if (index < 0 || index >= ports.length) return;
    ports.splice(index, 1);
    state.firewall.outbound.dirty = true;
    renderOutboundPortsPane();
}

function showOutboundFormError(message) {
    dom.firewallOutboundFormError.textContent = message;
    dom.firewallOutboundFormError.classList.remove("hidden");
}

function hideOutboundFormError() {
    dom.firewallOutboundFormError.classList.add("hidden");
    dom.firewallOutboundFormError.textContent = "";
}

async function saveOutboundPorts() {
    if (!isAdmin()) return;
    hideOutboundFormError();
    dom.firewallOutboundSaveStatus.textContent = t("firewall.outbound.status.saving");
    dom.firewallOutboundSaveBtn.disabled = true;
    const savedPorts = JSON.stringify(state.firewall.outbound.ports);

    try {
        const response = await apiRequest("/api/v1/firewall/outbound-ports", {
            method: "PUT",
            body: { ports: state.firewall.outbound.ports },
        });
        if (JSON.stringify(state.firewall.outbound.ports) === savedPorts) {
            state.firewall.outbound.ports = (Array.isArray(response.ports) ? response.ports : [])
                .map(normalizeOutboundPort)
                .filter(Boolean);
            state.firewall.outbound.dirty = false;
        }
        renderOutboundPortsPane();
        dom.firewallOutboundSaveStatus.textContent = state.firewall.outbound.dirty
            ? t("settings.unsaved") : t("firewall.outbound.status.saved");
    } catch (error) {
        dom.firewallOutboundSaveStatus.textContent = "";
        showOutboundFormError(error.message);
        dom.firewallOutboundSaveBtn.disabled = false;
    }
}

function renderFirewallRulesList() {
    clearElement(dom.firewallRulesList);
    if (!state.firewall.rules.length) {
        const empty = document.createElement("p");
        empty.className = "muted firewall-empty";
        empty.textContent = t("firewall.empty");
        dom.firewallRulesList.appendChild(empty);
        return;
    }

    const fragment = document.createDocumentFragment();
    state.firewall.rules.forEach((rule) => {
        const selected = rule.id === state.firewall.selectedRuleId;
        const button = document.createElement("button");
        button.type = "button";
        button.className = selected ? "firewall-rule-item active" : "firewall-rule-item";
        button.dataset.ruleId = String(rule.id || "");

        const top = document.createElement("div");
        top.className = "firewall-rule-top";

        const priority = document.createElement("span");
        priority.className = "firewall-rule-priority";
        priority.textContent = `#${rule.priority}`;
        top.appendChild(priority);

        const action = document.createElement("span");
        action.className = `firewall-rule-action action-${rule.action}`;
        action.textContent = t(`firewall.actions.${rule.action}`);
        top.appendChild(action);

        const enabled = document.createElement("span");
        enabled.className = "firewall-rule-state";
        enabled.textContent = rule.enabled ? t("status.enabled") : t("status.disabled");
        top.appendChild(enabled);

        button.appendChild(top);

        const match = document.createElement("div");
        match.className = "firewall-rule-match";
        const matchParts = [];
        if (rule.match && rule.match.host) matchParts.push(rule.match.host);
        if (rule.match && rule.match.host_regex) matchParts.push(`Regex: ${rule.match.host_regex}`);
        if (rule.match && rule.match.ip) matchParts.push(`IP: ${rule.match.ip}`);
        if (rule.match && rule.match.cidr) matchParts.push(`CIDR: ${rule.match.cidr}`);
        match.textContent = matchParts.length ? matchParts.join(", ") : t("firewall.matchAll");
        button.appendChild(match);

        fragment.appendChild(button);
    });

    dom.firewallRulesList.appendChild(fragment);
}

function renderFirewallTab() {
    dom.firewallModeToggle.checked = state.firewall.enabled;
    dom.firewallRulesCount.textContent = String(state.firewall.rules.length);
    renderFirewallRulesList();

    if (state.firewall.selectedRuleId) {
        const rule = state.firewall.rules.find(r => r.id === state.firewall.selectedRuleId);
        if (rule) {
            applyFirewallRuleForm(rule);
            dom.firewallRuleFormTitle.textContent = rule.name || `Rule #${rule.id}`;
            dom.firewallSaveBtn.textContent = t("firewall.updateRule");
            dom.firewallDeleteBtn.classList.remove("hidden");
        } else {
            resetFirewallRuleForm();
        }
    } else {
        resetFirewallRuleForm();
    }
}

function applyFirewallRuleForm(rule) {
    dom.firewallRuleEnabled.checked = rule.enabled !== false;
    dom.firewallRuleAction.value = rule.action || "block";
    dom.firewallRuleBlockMode.value = rule.block_mode || "display_page";
    dom.firewallRulePriority.value = rule.priority || 0;
    dom.firewallBlockModeWrap.classList.toggle("hidden", rule.action !== "block");

    const match = rule.match || {};
    dom.firewallRuleHost.value = match.host || "";
    dom.firewallRuleHostRegex.value = match.host_regex || "";
    dom.firewallRuleIP.value = match.ip || "";
    dom.firewallRuleCIDR.value = match.cidr || "";

    dom.firewallFormError.classList.add("hidden");
}

function resetFirewallRuleForm() {
    state.firewall.selectedRuleId = null;
    state.firewall.dirty = false;
    dom.firewallRuleEnabled.checked = true;
    dom.firewallRuleAction.value = "block";
    dom.firewallRuleBlockMode.value = "display_page";
    dom.firewallRulePriority.value = 0;
    dom.firewallRuleHost.value = "";
    dom.firewallRuleHostRegex.value = "";
    dom.firewallRuleIP.value = "";
    dom.firewallRuleCIDR.value = "";
    dom.firewallBlockModeWrap.classList.add("hidden");
    dom.firewallRuleFormTitle.textContent = t("firewall.newRuleTitle");
    dom.firewallSaveBtn.textContent = t("firewall.saveRule");
    dom.firewallDeleteBtn.classList.add("hidden");
    dom.firewallSaveStatus.textContent = "";
    dom.firewallFormError.classList.add("hidden");
}

function beginNewFirewallRule() {
    if (!isAdmin()) return;
    if (state.firewall.dirty && !window.confirm(t("firewall.discardUnsavedChanges"))) return;
    state.firewall.selectedRuleId = null;
    state.firewall.dirty = false;
    resetFirewallRuleForm();
    renderFirewallRulesList();
}

function selectFirewallRule(ruleId) {
    if (state.firewall.dirty && !window.confirm(t("firewall.discardUnsavedChanges"))) {
        return;
    }
    state.firewall.selectedRuleId = ruleId;
    state.firewall.dirty = false;
    dom.firewallSaveStatus.textContent = "";
    renderFirewallTab();
}

function buildFirewallRuleFromForm() {
    const action = dom.firewallRuleAction.value;
    if (!action || (action !== "block" && action !== "bypass" && action !== "inspect")) {
        throw new Error(t("firewall.errors.invalidAction"));
    }

    const match = {};
    const host = dom.firewallRuleHost.value.trim();
    if (host) match.host = host;
    const hostRegex = dom.firewallRuleHostRegex.value.trim();
    if (hostRegex) match.host_regex = hostRegex;
    const ip = dom.firewallRuleIP.value.trim();
    if (ip) match.ip = ip;
    const cidr = dom.firewallRuleCIDR.value.trim();
    if (cidr) match.cidr = cidr;

    const rule = {
        enabled: dom.firewallRuleEnabled.checked,
        action: action,
        priority: Number(dom.firewallRulePriority.value) || 0,
        match: match,
    };

    if (action === "block") {
        rule.block_mode = dom.firewallRuleBlockMode.value || "display_page";
    }

    return rule;
}

async function updateFirewallMode(enabled) {
    if (!isAdmin()) return;
    try {
        await apiRequest("/api/v1/firewall/rules", {
            method: "PUT",
            body: { enabled },
        });
        state.firewall.enabled = enabled;
    } catch (error) {
        dom.firewallModeToggle.checked = !enabled;
        alert(error.message);
    }
}

async function handleFirewallRuleSave(event) {
    event.preventDefault();
    if (!isAdmin()) return;

    dom.firewallFormError.classList.add("hidden");
    dom.firewallSaveStatus.textContent = "";

    let rule;
    try {
        rule = buildFirewallRuleFromForm();
    } catch (error) {
        dom.firewallFormError.textContent = error.message;
        dom.firewallFormError.classList.remove("hidden");
        return;
    }

    dom.firewallSaveBtn.disabled = true;
    dom.firewallDeleteBtn.disabled = true;
    dom.firewallSaveStatus.textContent = t("firewall.saving");

    try {
        let response;
        if (state.firewall.selectedRuleId) {
            response = await apiRequest(`/api/v1/firewall/rules/${state.firewall.selectedRuleId}`, {
                method: "PUT",
                body: rule,
            });
        } else {
            response = await apiRequest("/api/v1/firewall/rules", {
                method: "POST",
                body: rule,
            });
        }
        state.firewall.dirty = false;
        if (response.rule && response.rule.id) {
            state.firewall.selectedRuleId = response.rule.id;
        }
        await loadFirewallRules();
        renderFirewallTab();
        dom.firewallSaveStatus.textContent = t("firewall.saved");
    } catch (error) {
        dom.firewallSaveStatus.textContent = "";
        dom.firewallFormError.textContent = error.message;
        dom.firewallFormError.classList.remove("hidden");
    } finally {
        dom.firewallSaveBtn.disabled = false;
        dom.firewallDeleteBtn.disabled = false;
    }
}

async function handleFirewallRuleDelete() {
    if (!isAdmin()) return;
    if (!state.firewall.selectedRuleId) return;
    if (!window.confirm(t("firewall.deleteConfirm"))) return;

    dom.firewallSaveBtn.disabled = true;
    dom.firewallDeleteBtn.disabled = true;
    dom.firewallSaveStatus.textContent = t("firewall.deleting");
    dom.firewallFormError.classList.add("hidden");

    try {
        await apiRequest(`/api/v1/firewall/rules/${state.firewall.selectedRuleId}`, {
            method: "DELETE",
        });
        state.firewall.selectedRuleId = null;
        state.firewall.dirty = false;
        await loadFirewallRules();
        resetFirewallRuleForm();
        renderFirewallTab();
        dom.firewallSaveStatus.textContent = t("firewall.deleted");
    } catch (error) {
        dom.firewallSaveStatus.textContent = "";
        dom.firewallFormError.textContent = error.message;
        dom.firewallFormError.classList.remove("hidden");
    } finally {
        dom.firewallSaveBtn.disabled = false;
    }
}

void bootstrap();
