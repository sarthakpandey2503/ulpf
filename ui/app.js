const $ = (id) => document.getElementById(id);
let token = sessionStorage.getItem("ulpf_token") || "";
let role = "";
let demo = false;
let currentId = "";
let selectedUid = "";

function toast(msg) {
  let el = $("error");
  if (!el) {
    el = document.createElement("div");
    el.id = "error";
    document.body.appendChild(el);
  }
  el.textContent = msg;
  setTimeout(() => el.remove(), 5000);
}

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (token) headers.Authorization = "Bearer " + token;
  if (opts.body && typeof opts.body !== "string") {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, Object.assign({}, opts, {headers}));
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (_e) { data = {error: text.slice(0, 200)}; }
  if (res.status === 401) {
    role = "";
    $("who").textContent = "not connected";
    throw new Error((data && data.error) || "authentication required");
  }
  if (!res.ok) throw new Error((data && data.error) || ("HTTP " + res.status));
  return data;
}

function stat(label, value) {
  const d = document.createElement("div");
  d.className = "stat";
  const b = document.createElement("b");
  b.textContent = value;
  const s = document.createElement("span");
  s.textContent = label;
  d.append(b, s);
  return d;
}

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text == null || text === "" ? "—" : String(text);
  return td;
}

async function connect() {
  const who = await api("/v1/whoami");
  role = who.role;
  demo = !!who.demo;
  $("who").textContent = who.name + " · " + who.role;
  $("load-samples").hidden = role !== "admin";
  $("paste").hidden = role === "viewer";
  $("tamper-form").hidden = !(demo && role === "admin");
  $("approve-draft").hidden = role !== "admin";
  await refreshAll();
}

async function refreshAll() {
  const view = document.querySelector("nav button.active");
  const name = view ? view.dataset.view : "live";
  if (name === "live") await loadLive();
  if (name === "packs") await loadPacks();
  if (name === "onboard") await loadUnknown();
  if (name === "fidelity") await loadFidelity();
  if (name === "lineage") await loadLedger();
}

async function loadLive() {
  const [stats, ev] = await Promise.all([api("/v1/stats"), api("/v1/events?limit=40")]);
  const box = $("stats");
  box.replaceChildren();
  const store = stats.store || {};
  const pipe = stats.pipeline || {};
  box.append(
    stat("Stored", store.total ?? 0),
    stat("OCSF valid", store.valid_ratio != null ? Math.round(store.valid_ratio * 100) + "%" : "—"),
    stat("Avg EPS", pipe.avg_eps ?? 0),
    stat("Fallback", (pipe.counters || {}).fallback ?? 0),
    stat("Packs", stats.packs ?? 0),
    stat("Unknown clusters", stats.unknown_clusters ?? 0)
  );
  const body = $("rows");
  body.replaceChildren();
  for (const e of ev.events || []) {
    const tr = document.createElement("tr");
    tr.className = "click";
    const src = (e.src_endpoint && e.src_endpoint.ip) || "";
    const dst = (e.dst_endpoint && e.dst_endpoint.ip) || "";
    tr.append(
      cell(e.time ? new Date(e.time).toISOString().slice(0, 19) : ""),
      cell(e.class_name),
      cell((e.ulpf && e.ulpf.pack) || "fallback"),
      cell(src),
      cell(dst),
      cell(e.severity),
      cell(e.ulpf && e.ulpf.validation && e.ulpf.validation.valid ? "yes" : "no")
    );
    tr.addEventListener("click", () => openEvent(e.metadata.uid));
    body.append(tr);
  }
}

async function openEvent(uid) {
  selectedUid = uid;
  $("verify-uid").value = uid;
  const e = await api("/v1/events/" + encodeURIComponent(uid));
  show("event");
  $("event-meta").textContent = (e.metadata && e.metadata.uid) + "  ·  " + (e.ulpf && e.ulpf.pack || "fallback")
    + "  ·  confidence " + (e.ulpf && e.ulpf.confidence);
  $("raw").textContent = e.raw_data || "";
  const copy = Object.assign({}, e);
  delete copy.raw_data;
  $("norm").textContent = JSON.stringify(copy, null, 2);
  const body = $("lineage-rows");
  body.replaceChildren();
  const lineage = (e.ulpf && e.ulpf.field_lineage) || {};
  for (const key of Object.keys(lineage)) {
    const tr = document.createElement("tr");
    tr.append(cell(key), cell(typeof lineage[key] === "string" ? lineage[key] : JSON.stringify(lineage[key])));
    body.append(tr);
  }
}

async function loadPacks() {
  const data = await api("/v1/packs");
  const body = $("pack-rows");
  body.replaceChildren();
  for (const p of data.packs || []) {
    const tr = document.createElement("tr");
    tr.append(cell(p.ref), cell(p.vendor + " " + p.product), cell((p.formats || []).join(", ")),
      cell(p.signed ? "yes" : "no"), cell(p.trust));
    body.append(tr);
  }
}

async function loadUnknown() {
  const data = await api("/v1/unknown");
  const body = $("unknown-rows");
  body.replaceChildren();
  for (const c of data.clusters || []) {
    const tr = document.createElement("tr");
    tr.append(cell(c.label), cell(c.count), cell(c.preview));
    const td = document.createElement("td");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "Generate pack";
    btn.addEventListener("click", () => synthesizeCluster(c.id));
    td.append(btn);
    tr.append(td);
    body.append(tr);
  }
}

function showDraft(data) {
  currentId = data.id;
  $("draft-report").hidden = false;
  $("draft-yaml").hidden = false;
  $("draft-actions").hidden = false;
  const rep = data.report || {};
  $("draft-report").textContent = data.id + "  passed=" + data.passed
    + "\nparse " + rep.parse_rate + "  valid " + rep.ocsf_valid_rate
    + "  mapped " + rep.avg_mapped_attributes
    + "\n" + JSON.stringify(rep.checks || {}, null, 2);
  $("draft-yaml").value = data.yaml || "";
}

async function synthesizeCluster(id) {
  try {
    const data = await api("/v1/unknown/" + encodeURIComponent(id) + "/synthesize", {method: "POST"});
    showDraft(data);
  } catch (err) { toast(err.message); }
}

async function loadFidelity() {
  const data = await api("/v1/fidelity");
  const full = (data.modes && data.modes.full) || {};
  const box = $("fidelity");
  box.replaceChildren();
  box.append(
    stat("Schema fidelity", (data.schema_fidelity_score ?? "—") + "%"),
    stat("Native OCSF only", (data.native_ocsf_fidelity ?? "—") + "%"),
    stat("True-positive rate", (full.tp_detection_rate ?? "—") + "%"),
    stat("Benign silence", (full.benign_silence_rate ?? "—") + "%"),
    stat("Detections lost", full.detections_lost ?? "—"),
    stat("Datasets", data.datasets_found ?? "—")
  );
  $("fidelity-detail").textContent = "source: " + (data.source || "")
    + "\nrules evaluated: " + data.rules_evaluated
    + "\ncases: " + data.cases_evaluated
    + "\nby format: " + JSON.stringify(data.by_format || {}, null, 2);
}

async function loadLedger() {
  const [stats, chain] = await Promise.all([api("/v1/ledger"), api("/v1/ledger/verify")]);
  $("ledger-out").textContent = JSON.stringify({stats, chain}, null, 2);
}

function show(name) {
  for (const btn of document.querySelectorAll("nav button")) {
    btn.classList.toggle("active", btn.dataset.view === name);
  }
  for (const section of document.querySelectorAll("main section")) {
    section.hidden = section.id !== "view-" + name;
  }
}

document.querySelectorAll("nav button").forEach((btn) => {
  btn.addEventListener("click", () => {
    show(btn.dataset.view);
    if (token) refreshAll().catch((err) => toast(err.message));
  });
});

$("login").addEventListener("submit", (ev) => {
  ev.preventDefault();
  token = $("token").value.trim();
  sessionStorage.setItem("ulpf_token", token);
  connect().catch((err) => toast(err.message));
});

$("refresh").addEventListener("click", () => refreshAll().catch((err) => toast(err.message)));

$("paste").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const lines = $("paste-lines").value.split("\n").filter((l) => l.trim());
  if (!lines.length) return;
  try {
    const res = await api("/v1/ingest", {method: "POST", body: {lines}});
    $("paste-lines").value = "";
    toast("accepted " + res.accepted);
    await loadLive();
  } catch (err) { toast(err.message); }
});

$("load-samples").addEventListener("click", async () => {
  try {
    const res = await api("/v1/demo/load-samples", {method: "POST"});
    toast("loaded " + res.lines + " lines from " + res.files + " files");
    await loadLive();
  } catch (err) { toast(err.message); }
});

$("synth").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const lines = $("synth-lines").value.split("\n").filter((l) => l.trim());
  try {
    const data = await api("/v1/drafts/synthesize", {
      method: "POST",
      body: {lines, vendor: $("vendor").value || null, product: $("product").value || null}
    });
    showDraft(data);
  } catch (err) { toast(err.message); }
});

$("save-draft").addEventListener("click", async () => {
  if (!currentId) return;
  try {
    const data = await api("/v1/drafts/" + encodeURIComponent(currentId), {
      method: "PUT", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({yaml: $("draft-yaml").value})
    });
    $("draft-report").textContent = JSON.stringify(data, null, 2);
  } catch (err) { toast(err.message); }
});

$("approve-draft").addEventListener("click", async () => {
  if (!currentId) return;
  try {
    const data = await api("/v1/drafts/" + encodeURIComponent(currentId) + "/approve", {method: "POST"});
    toast("approved " + data.approved);
    currentId = "";
    $("draft-actions").hidden = true;
  } catch (err) { toast(err.message); }
});

$("reject-draft").addEventListener("click", async () => {
  if (!currentId) return;
  try {
    await api("/v1/drafts/" + encodeURIComponent(currentId) + "/reject", {method: "POST"});
    currentId = "";
    $("draft-actions").hidden = true;
    $("draft-yaml").value = "";
  } catch (err) { toast(err.message); }
});

$("verify-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const uid = $("verify-uid").value.trim();
  try {
    const data = await api("/v1/events/" + encodeURIComponent(uid) + "/verify");
    $("verify-out").textContent = JSON.stringify(data, null, 2);
    selectedUid = uid;
  } catch (err) { toast(err.message); }
});

$("tamper-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await api("/v1/demo/tamper", {method: "POST", body: {uid: selectedUid || $("verify-uid").value.trim(), raw: $("tamper-raw").value}});
    toast("stored raw overwritten; verify again");
  } catch (err) { toast(err.message); }
});

if (token) {
  $("token").value = token;
  connect().catch((err) => toast(err.message));
}
