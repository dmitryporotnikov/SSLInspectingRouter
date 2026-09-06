// Dependency-free regression coverage for dashboard request and draft handling.
// Run: node --test tests/dashboard_frontend.test.cjs
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../internal/dashboard/frontend/app.js"), "utf8")
    .replace("void bootstrap();", "");

function deferred() {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
}

function dashboard() {
    const elements = new Map();
    function element(id) {
        if (!elements.has(id)) {
            const classes = new Set();
            elements.set(id, {
                value: "", textContent: "", disabled: false, checked: false, dataset: {},
                listeners: {},
                addEventListener(name, callback) { this.listeners[name] = callback; },
                querySelectorAll() { return []; },
                setAttribute() {}, removeAttribute() {}, focus() {},
                classList: {
                    add(name) { classes.add(name); }, remove(name) { classes.delete(name); },
                    contains(name) { return classes.has(name); },
                    toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); },
                },
            });
        }
        return elements.get(id);
    }
    const document = {
        hidden: false, activeElement: null,
        getElementById: element, querySelectorAll() { return []; },
        addEventListener() {}, body: element("body"),
    };
    const context = vm.createContext({ document, console, URLSearchParams, AbortController,
        setTimeout, clearTimeout, setInterval, clearInterval,
        alert() {}, window: { confirm: () => true },
    });
    vm.runInContext(source, context);
    const run = (code) => vm.runInContext(code, context);
    run('state.user = {role: "admin"}; reportApiSuccess = () => {}; reportApiFailure = () => {};');
    return { context, run, element, document };
}

test("policy drafts survive blur and polling while untouched fields update", () => {
    const { run, element } = dashboard();
    run("bindEvents()");
    element("drop-list-input").value = "draft.example";
    element("drop-list-input").listeners.input();
    run('applyPolicy({drop_list: ["old.example"], bypass_list: ["new.example"]})');
    assert.equal(element("drop-list-input").value, "draft.example");
    assert.equal(element("bypass-list-input").value, "new.example");
});

test("Control Center is a separate admin page and preserves drafts across navigation", () => {
    const { run, element } = dashboard();
    element("drop-list-input").value = "draft.example";
    run('switchSection("settings")');
    assert.equal(element("settings-panel").classList.contains("hidden"), false);
    assert.equal(element("traffic-section").classList.contains("hidden"), true);
    run('switchSection("traffic")');
    assert.equal(element("settings-panel").classList.contains("hidden"), true);
    assert.equal(element("drop-list-input").value, "draft.example");
    run('state.user = {role: "viewer"}; switchSection("settings")');
    assert.equal(run("state.section"), "traffic");
    assert.equal(element("settings-panel").classList.contains("hidden"), true);
});

test("policy edits made during a save remain unsaved drafts", async () => {
    const { context, run, element } = dashboard();
    const pending = deferred();
    context.saveResponse = pending.promise;
    run("bindEvents(); apiRequest = () => saveResponse;");
    element("drop-list-input").value = "first.example";
    element("drop-list-input").listeners.input();
    const save = run("updateTrafficPolicy()");
    element("drop-list-input").value = "second.example";
    element("drop-list-input").listeners.input();
    pending.resolve({ drop_list: ["first.example"], bypass_list: [] });
    await save;
    run('applyPolicy({drop_list: ["first.example"], bypass_list: []})');
    assert.equal(element("drop-list-input").value, "second.example");
    assert.equal(run("dirtyFields.has(dom.dropListInput)"), true);
    assert.equal(element("policy-save-btn").disabled, false);
});

test("GET responses that predate a save cannot restore stale server state", async () => {
    const { context, run } = dashboard();
    const pending = deferred();
    const response = (payload) => ({ ok: true, headers: { get: () => "application/json" }, json: async () => payload });
    context.fetch = (_url, options) => options.method === "GET" ? pending.promise : Promise.resolve(response({ enabled: true }));
    const read = run('apiRequest("/api/v1/status")');
    await run('apiRequest("/api/v1/status", {method: "PUT", body: {enabled: true}})');
    pending.resolve(response({ enabled: false }));
    await assert.rejects(read, { name: "SupersededResponse" });
});

test("traffic ignores out-of-order results and does not redraw unchanged rows", async () => {
    const { context, run } = dashboard();
    const old = deferred(), latest = deferred();
    let calls = 0;
    context.request = () => (++calls === 1 ? old.promise : latest.promise);
    run("apiRequest = request; var renders = 0; renderTraffic = () => { renders++; };");
    const first = run("loadTraffic()");
    run('state.traffic.q = "latest"');
    const second = run("loadTraffic()");
    latest.resolve({ items: [{ id: 2 }], total: 1 });
    await second;
    old.resolve({ items: [{ id: 1 }], total: 1 });
    await first;
    await run("loadTraffic()");
    assert.equal(run("state.traffic.items[0].id"), 2);
    assert.equal(run("renders"), 1);
});

test("refreshes coalesce and hidden dashboards do not poll", async () => {
    const { context, run, document } = dashboard();
    const pending = deferred();
    context.pending = pending.promise;
    run("var refreshes = 0; refreshDashboardData = () => { refreshes++; return pending; };");
    const first = run("refreshDashboard(false)");
    const second = run("refreshDashboard(false)");
    assert.equal(run("refreshes"), 1);
    pending.resolve();
    await Promise.all([first, second]);
    document.hidden = true;
    await run("refreshDashboard(false)");
    run("startPolling()");
    assert.equal(run("refreshes"), 1);
    assert.equal(run("state.pollHandle"), null);
});

test("outbound edits made while a read is in flight are preserved", async () => {
    const { context, run } = dashboard();
    const pending = deferred();
    context.pending = pending.promise;
    run("apiRequest = () => pending; renderOutboundPortsPane = () => {};");
    const read = run("loadOutboundPorts()");
    run('state.firewall.outbound = {dirty: true, ports: [{port: 8443, protocol: "tcp"}]}');
    pending.resolve({ ports: [{ port: 443, protocol: "tcp" }] });
    await read;
    assert.equal(run("state.firewall.outbound.ports[0].port"), 8443);
    assert.equal(run("state.firewall.outbound.dirty"), true);
});

test("rewrite drafts started during a refresh are not overwritten", async () => {
    const { context, run } = dashboard();
    const pending = deferred();
    context.pending = pending.promise;
    run("apiRequest = () => pending; renderRewriteList = () => {}; var renders = 0; renderRewriteEditor = () => { renders++; };");
    const read = run("loadRewrites()");
    run("state.rewrites.dirty = true");
    pending.resolve({ rules: [], items: [] });
    await read;
    run('switchSection("rewrites")');
    assert.equal(run("renders"), 0);
    assert.equal(run("state.rewrites.dirty"), true);
});

test("failed runtime saves unlock controls and preserve the directory draft", async () => {
    const { context, run, element } = dashboard();
    const pending = deferred();
    context.pending = pending.promise;
    const input = element("body-artifacts-directory-input");
    element("settings-panel").querySelectorAll = () => [input];
    run("bindEvents(); apiRequest = () => pending;");
    input.value = "/new/path";
    input.listeners.input();
    const save = run('updateDashboardSettings({body_artifacts_directory: "/new/path"})');
    assert.equal(input.disabled, true);
    pending.reject(new Error("Save failed"));
    await assert.rejects(save, /Save failed/);
    assert.equal(input.disabled, false);
    assert.equal(input.value, "/new/path");
    assert.equal(run("dirtyFields.has(dom.bodyArtifactsDirectoryInput)"), true);
});

test("outbound edits made during a save remain drafts", async () => {
    const { context, run } = dashboard();
    const pending = deferred();
    context.pending = pending.promise;
    run('apiRequest = () => pending; renderOutboundPortsPane = () => {}; state.firewall.outbound = {dirty: true, ports: [{port: 443, protocol: "tcp"}]};');
    const save = run("saveOutboundPorts()");
    run('state.firewall.outbound.ports.push({port: 8443, protocol: "tcp"})');
    pending.resolve({ ports: [{ port: 443, protocol: "tcp" }] });
    await save;
    assert.equal(run("state.firewall.outbound.ports.length"), 2);
    assert.equal(run("state.firewall.outbound.dirty"), true);
});
