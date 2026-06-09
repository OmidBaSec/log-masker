// Log Masker frontend. Talks to the local FastAPI backend.

const $ = (id) => document.getElementById(id);

function selectedCategories() {
  return [...document.querySelectorAll(".cats input:checked")].map((c) => c.value);
}

function customTerms() {
  return $("customTerms").value
    .split(/[\n,]/)
    .map((t) => t.trim())
    .filter(Boolean);
}

function setStatus(msg, kind = "") {
  const el = $("status");
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

// --- Minimal, safe Markdown-ish rendering -------------------------------
// Escapes HTML first, then highlights placeholders and applies light markdown
// (headings, bold, code, bullets). Keeps things readable without a heavy dep.
function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function renderMarkdown(text) {
  let html = escapeHtml(text);
  html = html.replace(/^### (.*)$/gm, "<h4>$1</h4>");
  html = html.replace(/^## (.*)$/gm, "<h3>$1</h3>");
  html = html.replace(/^# (.*)$/gm, "<h3>$1</h3>");
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/^\s*[-*] (.*)$/gm, "• $1");
  return html;
}

// Wrap restored real values so the user can see what was injected back.
function highlightRestored(text, mapping) {
  let html = renderMarkdown(text);
  const reals = [...new Set(Object.values(mapping))].sort((a, b) => b.length - a.length);
  for (const real of reals) {
    if (!real) continue;
    const esc = escapeHtml(real).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    html = html.replace(new RegExp(esc, "g"), `<mark>${escapeHtml(real)}</mark>`);
  }
  return html;
}

function fillMapping(mapping) {
  const body = $("mapBody");
  body.innerHTML = "";
  const keys = Object.keys(mapping);
  if (!keys.length) {
    body.innerHTML = `<tr><td colspan="2" class="hint">Nothing was masked.</td></tr>`;
    return;
  }
  for (const k of keys) {
    const tr = document.createElement("tr");
    const td1 = document.createElement("td");
    const td2 = document.createElement("td");
    td1.textContent = k;
    td2.textContent = mapping[k];
    tr.append(td1, td2);
    body.appendChild(tr);
  }
}

// --- Tabs ---------------------------------------------------------------
$("tabs").addEventListener("click", (e) => {
  const btn = e.target.closest(".tab");
  if (!btn) return;
  document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
  document.querySelectorAll(".tabpane").forEach((p) => p.classList.remove("active"));
  btn.classList.add("active");
  $("pane-" + btn.dataset.tab).classList.add("active");
});

function showTab(name) {
  document.querySelector(`.tab[data-tab="${name}"]`).click();
}

// --- Preview (mask only, no API call) -----------------------------------
// Runs locally on the server; only updates the "Sent to AI" + "Mapping" tabs.
async function runPreview() {
  const logs = $("logs").value.trim();
  if (!logs) {
    $("sent").textContent = "";
    fillMapping({});
    $("redBadge").textContent = "No analysis yet.";
    $("redBadge").className = "redaction-badge";
    setStatus("");
    return;
  }
  setStatus("Masking locally…");
  try {
    const r = await fetch("/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ logs, categories: selectedCategories(), custom_terms: customTerms() }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Preview failed");
    $("sent").textContent = d.masked;
    fillMapping(d.mapping);
    $("redBadge").textContent = `${d.count} value(s) masked. Nothing sent yet — review the "Sent to AI" and "Mapping" tabs.`;
    $("redBadge").className = "redaction-badge active";
    showTab("sent");
    setStatus(`Preview ready — ${d.count} value(s) would be masked.`, "ok");
  } catch (e) {
    setStatus(e.message, "err");
  }
}

// Manual button still works as an explicit refresh.
$("previewBtn").addEventListener("click", runPreview);

// Auto-preview: re-mask shortly after the user stops typing/pasting, or when
// the masking options change — no need to click "Preview masking".
let previewTimer = null;
function scheduleAutoPreview() {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(runPreview, 350);
}
$("logs").addEventListener("input", scheduleAutoPreview);
$("customTerms").addEventListener("input", scheduleAutoPreview);
document.querySelectorAll(".cats input").forEach((c) =>
  c.addEventListener("change", scheduleAutoPreview)
);

// --- Analyse (mask -> provider -> un-mask) ------------------------------
$("analyzeBtn").addEventListener("click", async () => {
  const logs = $("logs").value.trim();
  if (!logs) return setStatus("Paste some logs first.", "err");
  const btn = $("analyzeBtn");
  btn.disabled = true;
  setStatus("Masking locally and sending masked logs to the AI…");
  try {
    const r = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        logs,
        categories: selectedCategories(),
        custom_terms: customTerms(),
        instructions: $("instructions").value.trim() || null,
      }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Analysis failed");

    $("sent").textContent = d.masked_sent;
    fillMapping(d.mapping);
    $("restored").innerHTML = highlightRestored(d.ai_response_restored, d.mapping);
    $("redBadge").textContent =
      `${d.masked_count} value(s) masked before sending. Highlighted values below were restored locally.`;
    $("redBadge").className = "redaction-badge active";
    showTab("restored");
    setStatus(`Done — analysed with ${d.model}.`, "ok");
  } catch (e) {
    setStatus(e.message, "err");
  } finally {
    btn.disabled = false;
  }
});

// --- Setup / providers ---------------------------------------------------
const modal = $("settingsModal");
let REGISTRY = {};       // provider metadata from /config
let CONFIG = {};         // current saved settings
let CONFIGURED = {};     // provider -> bool (has a key)
let selectedProvider = "anthropic";

function setupMsg(msg, kind = "") {
  const el = $("setupMsg");
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

// Persist current settings, merging in `extra`, without wiping other fields.
async function persistConfig(extra) {
  const payload = {
    provider: CONFIG.provider,
    model: CONFIG.model || "",
    azure_endpoint: CONFIG.azure_endpoint || "",
    azure_deployment: CONFIG.azure_deployment || "",
    azure_api_version: CONFIG.azure_api_version || "2024-08-01-preview",
    m365_tenant_id: CONFIG.m365_tenant_id || "",
    m365_client_id: CONFIG.m365_client_id || "",
    ...extra,
  };
  const r = await fetch("/config", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const d = await r.json();
  if (r.ok) CONFIG = d.config;
  return r.ok;
}

// Populate the inline provider + model dropdowns (configured providers only).
function renderActiveProvider() {
  const pSel = $("activeProviderSelect");
  const mSel = $("activeModelSelect");

  // Providers you've set up (have a key / are signed in), plus the active one.
  const available = Object.keys(REGISTRY).filter(
    (pid) => CONFIGURED[pid] || pid === CONFIG.provider
  );

  pSel.innerHTML = "";
  if (!available.length) {
    const o = document.createElement("option");
    o.textContent = "No provider set up — open Setup";
    o.value = "";
    pSel.appendChild(o);
    pSel.disabled = true;
    mSel.style.display = "none";
    return;
  }
  pSel.disabled = false;
  for (const pid of available) {
    const o = document.createElement("option");
    o.value = pid;
    o.textContent = REGISTRY[pid].label + (CONFIGURED[pid] ? "" : " (no key)");
    pSel.appendChild(o);
  }
  pSel.value = CONFIG.provider;

  // Model dropdown: only for providers that expose a model list.
  const meta = REGISTRY[CONFIG.provider];
  if (meta && meta.models.length) {
    mSel.innerHTML = "";
    for (const m of meta.models) {
      const o = document.createElement("option");
      o.value = m; o.textContent = m;
      mSel.appendChild(o);
    }
    mSel.value = CONFIG.model || meta.default_model;
    mSel.style.display = "";
  } else {
    mSel.style.display = "none";   // Azure (deployment) / M365 (no model)
  }
}

// Inline provider change -> switch provider, pick a sensible model, persist.
$("activeProviderSelect").addEventListener("change", async (e) => {
  const pid = e.target.value;
  const meta = REGISTRY[pid];
  const newModel = meta.models.length ? (meta.default_model || meta.models[0]) : "";
  await persistConfig({ provider: pid, model: newModel });
  renderActiveProvider();
  setStatus(`Now analysing with ${meta.label}.`, "ok");
});

// Inline model change -> persist.
$("activeModelSelect").addEventListener("change", async (e) => {
  await persistConfig({ model: e.target.value });
  setStatus(`Model set to ${e.target.value}.`, "ok");
});

async function loadConfig() {
  const r = await fetch("/config");
  const d = await r.json();
  REGISTRY = d.providers;
  CONFIG = d.config;
  CONFIGURED = d.configured;
  selectedProvider = CONFIG.provider;
  renderActiveProvider();
}

// Render provider chooser cards inside the modal.
function renderProviderCards() {
  const wrap = $("providerCards");
  wrap.innerHTML = "";
  for (const [pid, meta] of Object.entries(REGISTRY)) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "provider-card" + (pid === selectedProvider ? " selected" : "");
    card.dataset.pid = pid;
    card.innerHTML =
      `<span class="pc-label">${meta.label}</span>` +
      `<span class="pc-state ${CONFIGURED[pid] ? "ok" : "warn"}">` +
      `${CONFIGURED[pid] ? "✓ key saved" : "no key"}</span>`;
    card.addEventListener("click", () => { selectedProvider = pid; renderModalForProvider(); });
    wrap.appendChild(card);
  }
}

// Render the model dropdown, extra fields, and key label for the selected provider.
function renderModalForProvider() {
  const meta = REGISTRY[selectedProvider];
  renderProviderCards();

  $("providerNote").textContent = meta.note || "";
  $("providerNote").style.display = meta.note ? "block" : "none";

  // Model dropdown (or free-text fallback when the provider lists none, e.g. Azure).
  const sel = $("modelSelect");
  sel.innerHTML = "";
  if (meta.models.length) {
    for (const m of meta.models) {
      const o = document.createElement("option");
      o.value = m; o.textContent = m;
      sel.appendChild(o);
    }
    sel.disabled = false;
    sel.value = (selectedProvider === CONFIG.provider && CONFIG.model) || meta.default_model;
  } else {
    const o = document.createElement("option");
    o.value = ""; o.textContent = "(set via deployment name below)";
    sel.appendChild(o);
    sel.disabled = true;
  }

  // Provider-specific extra fields (Azure endpoint/deployment/version).
  const ex = $("extraFields");
  ex.innerHTML = "";
  for (const f of meta.extra_fields) {
    const wrap = document.createElement("label");
    wrap.className = "field";
    wrap.textContent = f.label + (f.required ? " *" : "");
    const inp = document.createElement("input");
    inp.type = "text";
    inp.id = "ef_" + f.key;
    inp.placeholder = f.placeholder || "";
    inp.value = CONFIG[f.key] || "";
    wrap.appendChild(inp);
    ex.appendChild(wrap);
  }

  // Toggle API-key vs OAuth (Microsoft 365 Copilot) panels.
  const isOauth = meta.auth === "oauth";
  $("keySection").classList.toggle("hidden", isOauth);
  $("oauthSection").classList.toggle("hidden", !isOauth);
  $("deleteKeyBtn").style.display = isOauth ? "none" : "";
  // M365 Copilot has no model selection; hide the Model field for it.
  $("modelField").style.display = isOauth ? "none" : "";

  if (isOauth) {
    refreshM365();
  } else {
    $("keyLabel").textContent = meta.key_label;
    $("apiKey").placeholder = meta.key_url ? "paste key — get one at " + meta.key_url : "…";
    $("apiKey").value = "";
    $("keyState").textContent = CONFIGURED[selectedProvider]
      ? "✓ A key is saved for this provider."
      : "⚠ No key saved for this provider yet.";
  }
  setupMsg("");
}

// Show the exact redirect URI to register and the current sign-in status.
async function refreshM365() {
  try {
    const ru = await (await fetch("/m365/redirect-uri")).json();
    $("redirectUri").textContent = ru.redirect_uri;
    const st = await (await fetch("/m365/status")).json();
    $("signInState").textContent = st.signed_in
      ? `✓ Signed in as ${st.username}`
      : "⚠ Not signed in.";
    $("signInState").className = "key-state" + (st.signed_in ? " ok" : "");
    $("signOutBtn").style.display = st.signed_in ? "" : "none";
  } catch (e) { $("signInState").textContent = e.message; }
}

function collectExtra() {
  const meta = REGISTRY[selectedProvider];
  const out = {};
  for (const f of meta.extra_fields) {
    out[f.key] = (document.getElementById("ef_" + f.key) || {}).value || "";
  }
  return out;
}

function openSetup() {
  modal.classList.remove("hidden");
  renderModalForProvider();
}
$("settingsBtn").addEventListener("click", openSetup);
$("openSetupInline").addEventListener("click", openSetup);
$("closeSettings").addEventListener("click", () => modal.classList.add("hidden"));
modal.addEventListener("click", (e) => { if (e.target === modal) modal.classList.add("hidden"); });

// Save: persist key (if entered), then config (provider/model/extra fields).
$("saveSetupBtn").addEventListener("click", async () => {
  const extra = collectExtra();
  const key = $("apiKey").value.trim();
  try {
    if (key) {
      const rk = await fetch("/save-key", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: selectedProvider, api_key: key }),
      });
      if (!rk.ok) throw new Error((await rk.json()).detail || "Could not save key");
    }
    const rc = await fetch("/config", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: selectedProvider,
        model: $("modelSelect").value,
        ...extra,
      }),
    });
    if (!rc.ok) throw new Error((await rc.json()).detail || "Could not save settings");
    await loadConfig();
    selectedProvider = CONFIG.provider;
    renderModalForProvider();
    setupMsg("✓ Saved.", "ok");
  } catch (e) {
    setupMsg(e.message, "err");
  }
});

$("testBtn").addEventListener("click", async () => {
  const key = $("apiKey").value.trim();
  setupMsg("Testing connection…");
  try {
    // Save a freshly-typed key first so the test can use it.
    if (key) {
      await fetch("/save-key", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: selectedProvider, api_key: key }),
      });
      CONFIGURED[selectedProvider] = true;
    }
    const r = await fetch("/test", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: selectedProvider,
        model: $("modelSelect").value,
        ...collectExtra(),
      }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Test failed");
    setupMsg(`✓ Connection OK — model replied: "${d.reply}"`, "ok");
    renderProviderCards();
  } catch (e) {
    setupMsg("✗ " + e.message, "err");
  }
});

$("deleteKeyBtn").addEventListener("click", async () => {
  await fetch("/delete-key", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ provider: selectedProvider }),
  });
  CONFIGURED[selectedProvider] = false;
  renderModalForProvider();
  renderActiveProvider();
});

// --- Microsoft 365 Copilot sign-in ---------------------------------------
$("signInBtn").addEventListener("click", async () => {
  const tenant = (document.getElementById("ef_m365_tenant_id") || {}).value || "";
  const client = (document.getElementById("ef_m365_client_id") || {}).value || "";
  if (!tenant || !client) return setupMsg("Enter tenant & client IDs, then Save.", "err");
  // Persist tenant/client so the server-side login can read them.
  await fetch("/config", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ provider: "m365copilot", model: "",
      m365_tenant_id: tenant, m365_client_id: client }),
  });
  setupMsg("Opening Microsoft sign-in… complete it in the popup.");
  const popup = window.open("/m365/login", "m365login", "width=520,height=680");
  // Poll for completion, then refresh status.
  const timer = setInterval(async () => {
    if (popup && popup.closed) {
      clearInterval(timer);
      await loadConfig();
      await refreshM365();
      renderProviderCards();
      renderActiveProvider();
      setupMsg("");
    }
  }, 800);
});

$("signOutBtn").addEventListener("click", async () => {
  await fetch("/m365/logout", { method: "POST" });
  await loadConfig();
  await refreshM365();
  renderProviderCards();
  renderActiveProvider();
});

// Load provider config on startup.
loadConfig();
