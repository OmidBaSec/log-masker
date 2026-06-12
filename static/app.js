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

// Render masked text with the placeholders highlighted in red, so the
// masked fields stand out in the "Sent to AI" view.
function renderMasked(text) {
  return escapeHtml(text).replace(
    /\[([A-Z0-9]+_\d+)\]/g,
    '<span class="ph">[$1]</span>'
  );
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

// --- Structured verdict card ---------------------------------------------
const VERDICT_LABEL = {
  true_positive: "TRUE POSITIVE", false_positive: "FALSE POSITIVE",
  benign_true_positive: "BENIGN TRUE POSITIVE", inconclusive: "INCONCLUSIVE",
};
let lastVerdict = null;   // restored verdict object, for JSON export

function vList(title, items) {
  if (!items || !items.length) return "";
  const lis = items.map((x) => `<li>${escapeHtml(x)}</li>`).join("");
  return `<div class="v-section"><h5>${title}</h5><ul>${lis}</ul></div>`;
}

function verdictCardHtml(v) {
  if (!v) return "";
  const vClass = "v-" + (v.verdict || "inconclusive").replace(/_/g, "-");
  const conf = v.confidence
    ? `<span class="v-conf">confidence: <b>${escapeHtml(v.confidence)}</b></span>` : "";
  const sev = v.severity
    ? `<span class="v-sev sev-${escapeHtml(v.severity)}">${escapeHtml(v.severity)}</span>` : "";
  const mitre = (v.mitre || []).map((m) => {
    const id = m.technique_id ? `<span class="v-tid">${escapeHtml(m.technique_id)}</span> ` : "";
    const txt = [m.technique, m.tactic].filter(Boolean).map(escapeHtml).join(" · ");
    return `<span class="v-chip">${id}${txt}</span>`;
  }).join("");
  const iocs = (v.iocs || []).map((i) =>
    `<li><span class="v-ioc-type">${escapeHtml(i.type || "other")}</span> ` +
    `<code>${escapeHtml(i.value)}</code>` +
    (i.context ? ` <span class="hint">— ${escapeHtml(i.context)}</span>` : "") + `</li>`
  ).join("");

  return `<div class="verdict ${vClass}">` +
    `<div class="v-head">` +
      `<span class="v-badge">${escapeHtml(VERDICT_LABEL[v.verdict] || v.verdict)}</span>` +
      sev + conf +
      `<span class="v-spacer"></span>` +
      `<button class="v-json-btn" data-act="copy" type="button">⧉ Copy JSON</button>` +
      `<button class="v-json-btn" data-act="download" type="button">⬇ JSON</button>` +
    `</div>` +
    (v.summary ? `<div class="v-summary">${escapeHtml(v.summary)}</div>` : "") +
    (mitre ? `<div class="v-section"><h5>MITRE ATT&CK</h5><div class="v-chips">${mitre}</div></div>` : "") +
    (iocs ? `<div class="v-section"><h5>IOCs</h5><ul class="v-iocs">${iocs}</ul></div>` : "") +
    vList("Affected entities", v.affected_entities) +
    vList("Recommended actions", v.recommended_actions) +
    vList("Next steps", v.next_steps) +
    `</div>`;
}

// AI bubble = verdict card (if any) above the prose.
function aiAnswerHtml(d) {
  return verdictCardHtml(d.verdict) + highlightRestored(d.ai_response_restored, d.mapping);
}

// Wire the Copy/Download JSON buttons inside a freshly-rendered card.
function wireVerdictButtons(scope, v) {
  scope.querySelectorAll(".v-json-btn").forEach((b) => {
    b.addEventListener("click", () => {
      const text = JSON.stringify(v, null, 2);
      if (b.dataset.act === "copy") {
        navigator.clipboard.writeText(text).then(
          () => { b.textContent = "✓ Copied"; setTimeout(() => (b.textContent = "⧉ Copy JSON"), 1500); });
      } else {
        const blob = new Blob([text], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `verdict-${(v.verdict || "result")}-${Date.now()}.json`;
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(a.href);
      }
    });
  });
}

// Friendly names for the placeholder field types (custom labels fall through).
const FIELD_NAMES = {
  USER: "Username", DOMAIN: "Domain", EMAIL: "Email", HOST: "Hostname / device",
  IP: "IPv4 address", IPV6: "IPv6 address", MAC: "MAC address", DN: "AD DN",
  SID: "Windows SID", PHONE: "Phone number", SECRET: "Secret / password",
  APIKEY: "API key", UUID: "UUID / GUID", HASH: "Hash / hex blob",
  CC: "Card-like number", SERIAL: "Device serial", RESOURCE: "Azure resource",
  CUSTOM: "Custom term",
};

// Summary table under the "Sent to AI" text: field type, alias, real value.
function fillSentMapping(mapping) {
  const wrap = $("sentMapWrap");
  const body = $("sentMapBody");
  body.innerHTML = "";
  const entries = Object.keys(mapping).map((ph) => {
    const m = ph.match(/^\[([A-Z0-9]+)_(\d+)\]$/);
    return { ph, label: m ? m[1] : "", n: m ? +m[2] : 0, real: mapping[ph] };
  });
  if (!entries.length) {
    wrap.classList.add("hidden");
    return;
  }
  entries.sort((a, b) => a.label.localeCompare(b.label) || a.n - b.n);
  for (const e of entries) {
    const tr = document.createElement("tr");
    const tdField = document.createElement("td");
    const tdAlias = document.createElement("td");
    const tdReal = document.createElement("td");
    tdField.textContent = FIELD_NAMES[e.label] || e.label;
    tdField.className = "sent-map-field";
    tdAlias.textContent = e.ph;
    tdReal.textContent = e.real;
    tr.append(tdField, tdAlias, tdReal);
    body.appendChild(tr);
  }
  wrap.classList.remove("hidden");
}

// --- Tabs ---------------------------------------------------------------
$("tabs").addEventListener("click", (e) => {
  const btn = e.target.closest(".tab");
  if (!btn) return;
  document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
  document.querySelectorAll(".tabpane").forEach((p) => p.classList.remove("active"));
  btn.classList.add("active");
  $("pane-" + btn.dataset.tab).classList.add("active");
  if (btn.dataset.tab === "requests") loadRequests();
});

function showTab(name) {
  document.querySelector(`.tab[data-tab="${name}"]`).click();
}

// --- Preview (mask only, no API call) -----------------------------------
// Runs locally on the server; updates the "Sent to AI" tab + its field table.
async function runPreview() {
  const logs = $("logs").value.trim();
  if (!logs) {
    if (CONV.id) return;            // don't clobber an active conversation
    $("tplSuggest").classList.add("hidden");
    $("sent").textContent = "";
    setMaskedArtifact("");
    renderSentWarnings([]);
    fillSentMapping({});
    $("redBadge").textContent = "No analysis yet.";
    $("redBadge").className = "redaction-badge";
    setStatus("");
    return;
  }
  if (CONV.id) {
    setStatus("Conversation active — end it to analyse a new log. (Preview paused.)");
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
    setMaskedArtifact(d.masked);
    renderSentWarnings(d.warnings);
    fillSentMapping(d.mapping);
    if (uploadedFileName) {
      // File upload: keep the masked content out of the on-screen pane —
      // the analyst reviews it in the downloadable masked file instead.
      $("sent").innerHTML = fileMaskNotice(d.count);
      $("redBadge").textContent =
        `${d.count} value(s) masked in ${uploadedFileName}. Download the masked file (⬇) to review — masked fields are shown in red.`;
    } else {
      $("sent").innerHTML = renderMasked(d.masked);
      $("redBadge").textContent = `${d.count} value(s) masked. Nothing sent yet — review the "Sent to AI" tab (⬇ to download the masked file).`;
    }
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
  previewTimer = setTimeout(() => {
    runPreview();
    suggestTemplates();
  }, 350);
}
$("logs").addEventListener("input", scheduleAutoPreview);
$("customTerms").addEventListener("input", scheduleAutoPreview);
document.querySelectorAll(".cats input").forEach((c) =>
  c.addEventListener("change", scheduleAutoPreview)
);

// --- File upload (read locally in the browser; same masking pipeline) ----
// The file content goes into the raw-logs box and is auto-masked like a
// paste. Nothing is uploaded anywhere — masking happens on this machine.
let uploadedFileName = "";
const MAX_FILE_MB = 10;

function showFileChip(name, text) {
  const chip = $("fileChip");
  const lines = text ? text.split("\n").length : 0;
  chip.innerHTML =
    `📄 ${escapeHtml(name)} <span class="hint">(${lines.toLocaleString()} lines)</span> ` +
    `<button class="link-btn danger" id="fileClear" type="button" title="Remove file and clear the box">✕</button>`;
  chip.classList.remove("hidden");
  $("fileClear").addEventListener("click", () => {
    uploadedFileName = "";
    chip.classList.add("hidden");
    $("logs").value = "";
    scheduleAutoPreview();
  });
}

function loadLogFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_MB * 1024 * 1024) {
    return setStatus(`File too large — max ${MAX_FILE_MB} MB of text logs.`, "err");
  }
  const reader = new FileReader();
  reader.onload = () => {
    const text = String(reader.result || "");
    if (text.includes("\u0000")) {
      return setStatus("That looks like a binary file — only text logs are supported.", "err");
    }
    uploadedFileName = file.name;
    $("logs").value = text;
    showFileChip(file.name, text);
    setStatus(`Loaded ${file.name} — masking locally…`);
    scheduleAutoPreview();   // masks, fills "Sent to AI", suggests templates
  };
  reader.onerror = () => setStatus("Could not read the file.", "err");
  reader.readAsText(file);
}

$("uploadBtn").addEventListener("click", () => $("logFile").click());
$("logFile").addEventListener("change", (e) => {
  loadLogFile(e.target.files && e.target.files[0]);
  e.target.value = "";          // allow re-selecting the same file
});

// Drag & drop onto the raw-logs box.
const logsBox = $("logs");
["dragenter", "dragover"].forEach((ev) =>
  logsBox.addEventListener(ev, (e) => {
    e.preventDefault();
    logsBox.classList.add("dragover");
  }));
["dragleave", "drop"].forEach((ev) =>
  logsBox.addEventListener(ev, () => logsBox.classList.remove("dragover")));
logsBox.addEventListener("drop", (e) => {
  const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) {
    e.preventDefault();
    loadLogFile(f);
  }
});

// Hide the file chip when the box is emptied by hand.
logsBox.addEventListener("input", () => {
  if (!logsBox.value.trim() && uploadedFileName) {
    uploadedFileName = "";
    $("fileChip").classList.add("hidden");
  }
});

// In-pane notice shown instead of the full masked content for file uploads —
// the masked text lives only in the downloadable file the analyst reviews.
function fileMaskNotice(count) {
  return (
    `<div class="file-mask-notice">` +
    `<span class="fmn-icon">📄</span>` +
    `<div><strong>Masked file ready.</strong> ` +
    `The masked content of <code>${escapeHtml(uploadedFileName)}</code> is not shown here. ` +
    `<b>${count}</b> value(s) were masked. ` +
    `Click <b>⬇ Download masked</b> above to get the masked file in its ` +
    `original format, or <b>🔴 red review</b> for a coloured copy with masked ` +
    `fields in <span style="color:#ff6b6b">red</span>.</div>` +
    `</div>`
  );
}

// --- Download the masked log for offline review ---------------------------
let lastMaskedText = "";

function setMaskedArtifact(text) {
  lastMaskedText = text || "";
  const has = !!lastMaskedText;
  $("downloadMaskedBtn").classList.toggle("hidden", !has);
  // Red HTML review is only offered for uploaded files.
  $("downloadReviewBtn").classList.toggle("hidden", !(has && uploadedFileName));
}

// Trigger a browser download of `blob` as `name`.
function triggerDownload(blob, name) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

// Build a self-contained HTML document of the masked log with every
// [LABEL_n] placeholder shown in red, for offline review.
function buildMaskedHtmlDoc(text, fileName) {
  const body = escapeHtml(text).replace(
    /\[([A-Z0-9]+_\d+)\]/g,
    '<span class="ph">[$1]</span>'
  );
  return (
    "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">" +
    `<title>Masked — ${escapeHtml(fileName)}</title><style>` +
    "body{background:#0b0f16;color:#e6edf3;font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:0;padding:24px}" +
    "h1{font:600 15px system-ui,sans-serif;color:#9db4d0;margin:0 0 4px}" +
    ".meta{font:12px system-ui,sans-serif;color:#7d8da3;margin:0 0 18px}" +
    "pre{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;margin:0}" +
    ".ph{color:#ff6b6b;font-weight:600}" +
    "</style></head><body>" +
    `<h1>🛡️ Masked log — ${escapeHtml(fileName)}</h1>` +
    `<p class="meta">Sensitive values replaced by red placeholders. ` +
    `Generated locally by Log Masker — nothing was uploaded.</p>` +
    `<pre>${body}</pre></body></html>`
  );
}

const MIME_BY_EXT = {
  csv: "text/csv", json: "application/json", jsonl: "application/json",
  xml: "application/xml", log: "text/plain", txt: "text/plain",
  syslog: "text/plain", out: "text/plain",
};

// Main download: masked content in the ORIGINAL file format/extension.
// CSV stays .csv, JSON stays .json, etc. Pasted text downloads as .txt.
$("downloadMaskedBtn").addEventListener("click", () => {
  if (!lastMaskedText) return;
  let name, mime;
  if (uploadedFileName) {
    const m = uploadedFileName.match(/^(.*?)(\.[^.]+)?$/);
    const base = m[1] || "log";
    const ext = (m[2] || ".txt").slice(1).toLowerCase();
    name = `${base}.masked.${ext}`;
    mime = MIME_BY_EXT[ext] || "text/plain";
  } else {
    name = "logs.masked.txt";
    mime = "text/plain";
  }
  triggerDownload(new Blob([lastMaskedText], { type: `${mime};charset=utf-8` }), name);
});

// Secondary download: coloured HTML copy for visual review (uploads only).
$("downloadReviewBtn").addEventListener("click", () => {
  if (!lastMaskedText) return;
  const base = (uploadedFileName || "logs").replace(/\.[^.]+$/, "");
  triggerDownload(
    new Blob([buildMaskedHtmlDoc(lastMaskedText, uploadedFileName || "logs")],
      { type: "text/html;charset=utf-8" }),
    `${base}.masked-review.html`);
});

// --- Pre-send leak guard ---------------------------------------------------
// The server scans the MASKED text with independent detectors; blocking
// findings stop the send until the analyst explicitly acknowledges.
const leakModal = $("leakModal");
let leakPendingSend = null;     // resubmit callback after acknowledgement

const LEAK_TYPE_LABEL = {
  known_value: "masked value still visible",
  custom_term: "custom term not masked",
  ip_address: "IP address left unmasked",
  email: "email address left unmasked",
  secret_like: "secret-like token",
  host_like: "hostname-like token",
};

function leakFindingRow(f, allowQuickMask) {
  const row = document.createElement("div");
  row.className = "leak-row";
  row.innerHTML =
    `<span class="leak-sev ${f.severity}">${f.severity === "high" ? "HIGH" : "MED"}</span>` +
    `<div class="leak-body">` +
    `<div><code>${escapeHtml(f.value)}</code> <span class="hint">×${f.count}` +
    ` · ${escapeHtml(LEAK_TYPE_LABEL[f.type] || f.type)}</span></div>` +
    `<div class="hint">${escapeHtml(f.detail)}</div></div>`;
  if (allowQuickMask) {
    const b = document.createElement("button");
    b.className = "ghost-btn leak-mask-btn";
    b.type = "button";
    b.textContent = "➕ mask";
    b.title = "Add this value to custom terms and re-mask";
    b.addEventListener("click", () => {
      const ta = $("customTerms");
      ta.value = ta.value.trim() ? ta.value.trim() + "\n" + f.value : f.value;
      hideLeakModal();
      scheduleAutoPreview();
      setStatus(`"${f.value}" added to custom terms — re-masked. Analyse again when ready.`, "ok");
    });
    row.appendChild(b);
  }
  return row;
}

function showLeakModal(warnings, onSend, allowQuickMask) {
  const wrap = $("leakFindings");
  wrap.innerHTML = "";
  for (const f of warnings) wrap.appendChild(leakFindingRow(f, allowQuickMask));
  leakPendingSend = onSend;
  leakModal.classList.remove("hidden");
}

function hideLeakModal() {
  leakModal.classList.add("hidden");
  leakPendingSend = null;
}

$("closeLeak").addEventListener("click", hideLeakModal);
$("leakCancel").addEventListener("click", () => {
  hideLeakModal();
  setStatus("Cancelled — nothing was sent.", "ok");
});
$("leakSend").addEventListener("click", () => {
  const fn = leakPendingSend;
  hideLeakModal();
  if (fn) fn();
});
leakModal.addEventListener("click", (e) => {
  if (e.target === leakModal) hideLeakModal();
});

// Warnings strip shown above the masked text in the "Sent to AI" pane.
function renderSentWarnings(warnings) {
  const el = $("sentWarnings");
  if (!warnings || !warnings.length) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  const high = warnings.filter((w) => w.severity === "high").length;
  const med = warnings.length - high;
  const parts = [];
  if (high) parts.push(`<b>${high} blocking</b>`);
  if (med) parts.push(`${med} advisory`);
  el.innerHTML = `<div class="leak-strip-head">🚨 Leak guard: ${parts.join(" + ")} ` +
                 `finding(s) in the masked text</div>`;
  for (const f of warnings) el.appendChild(leakFindingRow(f, true));
  el.classList.remove("hidden");
}

// --- Custom always-mask terms (persisted locally) ------------------------
let savedTerms = [];

async function loadCustomTerms() {
  try {
    const d = await (await fetch("/custom_terms")).json();
    savedTerms = d.terms || [];
    $("customTerms").value = savedTerms.join("\n");
    renderSetupTerms();
  } catch { /* box stays as-is */ }
}

// Read-only list of saved custom terms, shown in Setup.
function renderSetupTerms() {
  const box = $("setupTermsList");
  if (!box) return;
  if (!savedTerms.length) {
    box.innerHTML = `<span class="hint">No custom terms saved yet.</span>`;
    return;
  }
  box.innerHTML = savedTerms
    .map((t) => `<span class="term-chip">${escapeHtml(t)}</span>`)
    .join("");
}

function termsMsg(msg, kind = "") {
  const el = $("termsMsg");
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

async function saveTerms() {
  const terms = customTerms();
  try {
    const r = await fetch("/custom_terms", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ terms }),
    });
    if (!r.ok) throw new Error("save failed");
    savedTerms = terms;                  // keep the Setup view in sync
    renderSetupTerms();
    termsMsg(`✓ Saved ${terms.length} term(s) — re-masking…`, "ok");
    await runPreview();                  // apply immediately to the current log
    termsMsg(`✓ Saved ${terms.length} term(s) and applied.`, "ok");
  } catch (e) {
    termsMsg("Could not save custom terms.", "err");
  }
}

// Explicit button — save + re-mask now, with confirmation (no autosave).
$("saveTermsBtn").addEventListener("click", saveTerms);

$("customTerms").addEventListener("input", () => {
  termsMsg("Unsaved changes — click 💾 Save & apply.");
});

loadCustomTerms();

// --- System prompt (editable, persisted in config) -----------------------
let defaultSystemPrompt = "";

function sysPromptMsg(msg, kind = "") {
  const el = $("sysPromptMsg");
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

function setSysPromptState(isCustom) {
  $("sysPromptState").textContent = isCustom ? "· customised" : "· default";
}

async function loadSystemPrompt() {
  try {
    const d = await (await fetch("/system_prompt")).json();
    defaultSystemPrompt = d.default || "";
    $("systemPrompt").value = d.prompt || "";
    setSysPromptState(d.is_custom);
  } catch { /* leave empty */ }
}

$("saveSysPromptBtn").addEventListener("click", async () => {
  const prompt = $("systemPrompt").value.trim();
  if (!prompt) return sysPromptMsg("The system prompt can't be empty.", "err");
  try {
    const r = await fetch("/system_prompt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Save failed");
    setSysPromptState(d.is_custom);
    sysPromptMsg("✓ System prompt saved.", "ok");
  } catch (e) {
    sysPromptMsg(e.message, "err");
  }
});

$("resetSysPromptBtn").addEventListener("click", async () => {
  try {
    const d = await (await fetch("/system_prompt/reset", { method: "POST" })).json();
    $("systemPrompt").value = d.prompt || defaultSystemPrompt;
    setSysPromptState(false);
    sysPromptMsg("Restored the built-in default.", "ok");
  } catch (e) {
    sysPromptMsg("Could not reset.", "err");
  }
});

$("systemPrompt").addEventListener("input", () => sysPromptMsg(""));

loadSystemPrompt();

// --- Saved regex patterns (persistent on the server) ---------------------
// Added once, applied automatically to every future mask/preview/analyse.
function patMsg(msg, kind = "") {
  const el = $("patMsg");
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

async function loadPatterns() {
  const body = $("patternBody");
  try {
    const d = await (await fetch("/patterns")).json();
    body.innerHTML = "";
    if (!d.patterns.length) {
      body.innerHTML = `<tr><td colspan="3" class="hint">No saved patterns yet.</td></tr>`;
      return;
    }
    d.patterns.forEach((p, i) => {
      const tr = document.createElement("tr");
      const td1 = document.createElement("td");
      const td2 = document.createElement("td");
      const td3 = document.createElement("td");
      td1.textContent = p.label;
      td2.textContent = p.regex;
      const del = document.createElement("button");
      del.className = "link-btn danger";
      del.type = "button";
      del.textContent = "✕";
      del.title = "Delete this pattern";
      del.addEventListener("click", async () => {
        await fetch("/patterns/delete", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ index: i }),
        });
        await loadPatterns();
        scheduleAutoPreview();
      });
      td3.appendChild(del);
      tr.append(td1, td2, td3);
      body.appendChild(tr);
    });
  } catch {
    body.innerHTML = `<tr><td colspan="3" class="hint">Could not load patterns.</td></tr>`;
  }
}

$("patAddBtn").addEventListener("click", async () => {
  const label = $("patLabel").value.trim();
  const regex = $("patRegex").value.trim();
  if (!label || !regex) return patMsg("Both label and regex are required.", "err");
  try {
    const r = await fetch("/patterns", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label, regex }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Could not save pattern");
    $("patLabel").value = "";
    $("patRegex").value = "";
    patMsg("Saved — it will be applied to every log from now on.", "ok");
    await loadPatterns();
    scheduleAutoPreview();
  } catch (e) {
    patMsg(e.message, "err");
  }
});

loadPatterns();

// --- SOC analysis template library ---------------------------------------
// Searchable dropdown of MITRE-mapped prompt templates, plus auto-suggestions
// from the pasted log. Selecting one fills the analysis instructions.
let TEMPLATES = [];
let selectedTemplateId = null;
let appliedTemplatePrompt = "";   // so "clear" only wipes an unedited prompt

async function loadTemplates() {
  try {
    const d = await (await fetch("/templates")).json();
    TEMPLATES = d.templates || [];
  } catch {
    TEMPLATES = [];
  }
}

function templateMatches(t, q) {
  const hay = `${t.name} ${t.category} ${t.tactic} ${t.tactic_id} ` +
              `${t.technique} ${t.technique_id} ${t.prompt}`.toLowerCase();
  return q.split(/\s+/).filter(Boolean).every((tok) => hay.includes(tok));
}

function renderTemplateDropdown(q = "") {
  const dd = $("templateDropdown");
  const items = q.trim()
    ? TEMPLATES.filter((t) => templateMatches(t, q.toLowerCase()))
    : TEMPLATES;
  dd.innerHTML = "";
  if (!items.length) {
    dd.innerHTML = `<div class="tpl-empty hint">No templates match “${escapeHtml(q)}”.</div>`;
    dd.classList.remove("hidden");
    return;
  }
  for (const t of items) {
    const row = document.createElement("div");
    row.className = "tpl-opt" + (t.id === selectedTemplateId ? " sel" : "");
    row.innerHTML =
      `<div class="tpl-opt-name">${escapeHtml(t.name)}</div>` +
      `<div class="tpl-opt-meta">` +
      `<span class="tpl-cat">${escapeHtml(t.category)}</span>` +
      `<span class="tpl-mitre">${escapeHtml(t.technique_id)} · ${escapeHtml(t.technique)}</span>` +
      `</div>`;
    // mousedown (not click) so it fires before the input's blur hides the list.
    row.addEventListener("mousedown", (e) => {
      e.preventDefault();
      selectTemplate(t.id);
    });
    dd.appendChild(row);
  }
  dd.classList.remove("hidden");
}

function selectTemplate(id) {
  const t = TEMPLATES.find((x) => x.id === id);
  if (!t) return;
  selectedTemplateId = id;
  $("templateSearch").value = t.name;
  $("templateDropdown").classList.add("hidden");
  // Fill instructions, preserving anything the analyst already typed.
  const cur = $("instructions").value.trim();
  $("instructions").value =
    cur && cur !== appliedTemplatePrompt.trim() ? cur + "\n\n" + t.prompt : t.prompt;
  appliedTemplatePrompt = $("instructions").value;
  const sel = $("tplSelected");
  sel.innerHTML =
    `<div class="tpl-sel-head"><strong>${escapeHtml(t.name)}</strong>` +
    `<button id="tplClear" class="link-btn danger" type="button">✕ clear</button></div>` +
    `<div class="tpl-sel-mitre">🎯 ${escapeHtml(t.mitre)}</div>` +
    `<div class="tpl-sel-prompt hint">${escapeHtml(t.prompt)}</div>`;
  sel.classList.remove("hidden");
  $("tplClear").addEventListener("click", clearTemplate);
}

function clearTemplate() {
  selectedTemplateId = null;
  $("templateSearch").value = "";
  $("tplSelected").classList.add("hidden");
  // Only wipe instructions if they still hold the unedited template prompt.
  if ($("instructions").value.trim() === appliedTemplatePrompt.trim()) {
    $("instructions").value = "";
  }
  appliedTemplatePrompt = "";
  renderTemplateDropdown("");
}

$("templateSearch").addEventListener("focus", (e) =>
  renderTemplateDropdown(e.target.value));
$("templateSearch").addEventListener("input", (e) =>
  renderTemplateDropdown(e.target.value));
$("templateSearch").addEventListener("keydown", (e) => {
  if (e.key === "Escape") $("templateDropdown").classList.add("hidden");
});
document.addEventListener("mousedown", (e) => {
  if (!e.target.closest(".tpl-combo")) $("templateDropdown").classList.add("hidden");
});

// Auto-suggest the most relevant templates from the pasted raw log.
async function suggestTemplates() {
  const logs = $("logs").value.trim();
  const wrap = $("tplSuggest");
  if (!logs || CONV.id) return wrap.classList.add("hidden");
  try {
    const r = await fetch("/templates/suggest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ logs, limit: 3 }),
    });
    const d = await r.json();
    const s = d.suggestions || [];
    if (!s.length) return wrap.classList.add("hidden");
    const chips = $("tplSuggestChips");
    chips.innerHTML = "";
    for (const t of s) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "tpl-chip" + (t.id === selectedTemplateId ? " sel" : "");
      b.innerHTML = `${escapeHtml(t.name)} ` +
        `<span class="tpl-chip-id">${escapeHtml(t.technique_id)}</span>`;
      b.title = `${t.mitre}\nmatch ${(t.score * 100).toFixed(0)}%\n\n${t.prompt}`;
      b.addEventListener("click", () => {
        selectTemplate(t.id);
        $("templateSection").open = true;
      });
      chips.appendChild(b);
    }
    wrap.classList.remove("hidden");
  } catch {
    wrap.classList.add("hidden");
  }
}

// --- Template editor (edit built-ins, create/delete custom) --------------
const templatesModal = $("templatesModal");

function tplEditMsg(msg, kind = "") {
  const el = $("tplEditMsg");
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

function tplField(label, key, value, mono = false) {
  return `<label class="tpl-f"><span>${label}</span>` +
    `<input data-k="${key}" type="text" value="${escapeHtml(value || "")}"` +
    (mono ? ` class="mono"` : "") + ` autocomplete="off" /></label>`;
}

// Build an editor card. `t` null => the "new template" form.
function templateEditorCard(t) {
  const isNew = !t;
  const isCustom = isNew || t.custom;
  const card = document.createElement("details");
  card.className = "tpl-card";
  if (isNew) card.open = true;
  card.dataset.id = isNew ? "" : t.id;

  const sum = document.createElement("summary");
  sum.innerHTML = isNew
    ? `<strong>＋ New template</strong>`
    : `<strong>${escapeHtml(t.name)}</strong>` +
      `<span class="tpl-mitre">${escapeHtml(t.technique_id || "—")}</span>` +
      (t.custom ? `<span class="tpl-tag custom">custom</span>`
                : (t.modified ? `<span class="tpl-tag mod">modified</span>` : ""));
  card.appendChild(sum);

  const body = document.createElement("div");
  body.className = "tpl-card-body";
  body.innerHTML =
    `<div class="tpl-grid">` +
      tplField("Name", "name", isNew ? "" : t.name) +
      tplField("Category", "category", isNew ? "" : t.category) +
      tplField("Tactic", "tactic", isNew ? "" : t.tactic) +
      tplField("Tactic ID", "tactic_id", isNew ? "" : t.tactic_id, true) +
      tplField("Technique", "technique", isNew ? "" : t.technique) +
      tplField("Technique ID", "technique_id", isNew ? "" : t.technique_id, true) +
    `</div>` +
    `<label class="tpl-f"><span>Prompt</span>` +
    `<textarea data-k="prompt" rows="5" spellcheck="false">` +
    `${escapeHtml(isNew ? "" : t.prompt)}</textarea></label>` +
    (isCustom
      ? `<label class="tpl-f"><span>Suggestion keywords (comma-separated)</span>` +
        `<input data-k="keywords" type="text" class="mono" autocomplete="off" ` +
        `value="${escapeHtml(isNew ? "" : (t.keywords || []).join(", "))}" ` +
        `placeholder="e.g. xmrig, stratum+tcp, minerd" /></label>`
      : "");

  const actions = document.createElement("div");
  actions.className = "tpl-card-actions";
  const get = (k) => {
    const el = body.querySelector(`[data-k="${k}"]`);
    return el ? el.value : "";
  };
  const collect = () => {
    const o = {
      name: get("name"), category: get("category"),
      tactic: get("tactic"), tactic_id: get("tactic_id"),
      technique: get("technique"), technique_id: get("technique_id"),
      prompt: get("prompt"),
    };
    if (isCustom) {
      o.keywords = get("keywords").split(",").map((s) => s.trim()).filter(Boolean);
    }
    return o;
  };

  const saveBtn = document.createElement("button");
  saveBtn.className = "primary-btn";
  saveBtn.type = "button";
  saveBtn.textContent = isNew ? "Create template" : "Save";
  saveBtn.addEventListener("click", async () => {
    const fields = collect();
    const url = isNew ? "/templates/create" : "/templates/save";
    const payload = isNew ? fields : { id: t.id, ...fields };
    try {
      const r = await fetch(url, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || "Save failed");
      tplEditMsg(isNew ? `✓ Created “${d.template.name}”.`
                       : `✓ Saved “${d.template.name}”.`, "ok");
      await refreshTemplatesEverywhere();
      loadTemplateEditors();
    } catch (e) {
      tplEditMsg("✗ " + e.message, "err");
    }
  });
  actions.appendChild(saveBtn);

  if (!isNew && t.custom) {
    const del = document.createElement("button");
    del.className = "ghost-btn danger";
    del.type = "button";
    del.textContent = "🗑 Delete";
    del.addEventListener("click", async () => {
      await fetch("/templates/delete", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: t.id }),
      });
      tplEditMsg(`Deleted “${t.name}”.`, "ok");
      if (selectedTemplateId === t.id) clearTemplate();
      await refreshTemplatesEverywhere();
      loadTemplateEditors();
    });
    actions.appendChild(del);
  }
  if (!isNew && !t.custom && t.modified) {
    const reset = document.createElement("button");
    reset.className = "ghost-btn";
    reset.type = "button";
    reset.textContent = "↺ default";
    reset.addEventListener("click", async () => {
      await fetch("/templates/reset", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: t.id }),
      });
      tplEditMsg(`“${t.name}” restored to default.`, "ok");
      await refreshTemplatesEverywhere();
      loadTemplateEditors();
    });
    actions.appendChild(reset);
  }

  body.appendChild(actions);
  card.appendChild(body);
  return card;
}

async function loadTemplateEditors() {
  const wrap = $("templateEditors");
  const openIds = new Set([...wrap.querySelectorAll("details[open]")]
    .map((d) => d.dataset.id).filter(Boolean));
  await loadTemplates();
  wrap.innerHTML = "";
  for (const t of TEMPLATES) {
    const card = templateEditorCard(t);
    if (openIds.has(t.id)) card.open = true;
    wrap.appendChild(card);
  }
}

// Refresh the main dropdown, selected card, and suggestions after edits.
async function refreshTemplatesEverywhere() {
  await loadTemplates();
  if (!$("templateDropdown").classList.contains("hidden")) {
    renderTemplateDropdown($("templateSearch").value);
  }
  if (selectedTemplateId) {
    const t = TEMPLATES.find((x) => x.id === selectedTemplateId);
    if (t) $("templateSearch").value = t.name;
  }
  suggestTemplates();
}

$("editTemplatesBtn").addEventListener("click", () => {
  templatesModal.classList.remove("hidden");
  tplEditMsg("");
  loadTemplateEditors();
});
$("closeTemplates").addEventListener("click", () =>
  templatesModal.classList.add("hidden"));
templatesModal.addEventListener("click", (e) => {
  if (e.target === templatesModal) templatesModal.classList.add("hidden");
});
$("newTemplateBtn").addEventListener("click", () => {
  const wrap = $("templateEditors");
  wrap.insertBefore(templateEditorCard(null), wrap.firstChild);
});

loadTemplates();

// --- Built-in masking patterns (per log source, editable) ----------------
const patternsModal = $("patternsModal");

function builtinMsg(msg, kind = "") {
  const el = $("builtinMsg");
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

function renderBuiltinRow(p) {
  const row = document.createElement("div");
  row.className = "pat-row";

  const head = document.createElement("div");
  head.className = "pat-row-head";
  const field = document.createElement("span");
  field.className = "pat-field";
  field.textContent = `[${p.label}]`;
  field.title = `Placeholder prefix — masked values appear as [${p.label}_1], [${p.label}_2]…`;
  head.appendChild(field);
  if (p.modified) {
    const badge = document.createElement("span");
    badge.className = "pat-modified";
    badge.textContent = "modified";
    badge.title = "Default:\n" + p.default_regex;
    head.appendChild(badge);
  }
  const note = document.createElement("span");
  note.className = "hint";
  note.textContent = p.note || "";
  head.appendChild(note);

  const line = document.createElement("div");
  line.className = "pat-edit";
  const inp = document.createElement("input");
  inp.type = "text";
  inp.value = p.regex;
  inp.spellcheck = false;
  inp.autocomplete = "off";
  const save = document.createElement("button");
  save.className = "ghost-btn";
  save.type = "button";
  save.textContent = "Save";
  save.disabled = true;
  inp.addEventListener("input", () => { save.disabled = inp.value === p.regex; });
  inp.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !save.disabled) save.click();
  });
  save.addEventListener("click", async () => {
    try {
      const r = await fetch("/builtin_patterns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: p.id, regex: inp.value }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || "Could not save");
      builtinMsg(`✓ Saved — "${p.source} · ${p.label}" now uses your regex.`, "ok");
      await loadBuiltinPatterns();
      scheduleAutoPreview();
    } catch (e) {
      builtinMsg("✗ " + e.message, "err");
    }
  });
  line.append(inp, save);

  if (p.modified) {
    const reset = document.createElement("button");
    reset.className = "ghost-btn";
    reset.type = "button";
    reset.textContent = "↺ default";
    reset.title = "Restore the built-in regex:\n" + p.default_regex;
    reset.addEventListener("click", async () => {
      await fetch("/builtin_patterns/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: p.id }),
      });
      builtinMsg(`✓ "${p.source} · ${p.label}" restored to the default regex.`, "ok");
      await loadBuiltinPatterns();
      scheduleAutoPreview();
    });
    line.appendChild(reset);
  }

  row.append(head, line);
  return row;
}

async function loadBuiltinPatterns() {
  const wrap = $("builtinGroups");
  // Remember which groups are expanded across reloads.
  const openSources = new Set(
    [...wrap.querySelectorAll("details[open]")].map((d) => d.dataset.source)
  );
  try {
    const d = await (await fetch("/builtin_patterns")).json();
    wrap.innerHTML = "";
    const groups = new Map();           // source -> patterns, first-seen order
    for (const p of d.patterns) {
      if (!groups.has(p.source)) groups.set(p.source, []);
      groups.get(p.source).push(p);
    }
    for (const [source, pats] of groups) {
      const det = document.createElement("details");
      det.className = "pat-group";
      det.dataset.source = source;
      if (openSources.has(source)) det.open = true;
      const sum = document.createElement("summary");
      sum.textContent = source;
      const count = document.createElement("span");
      count.className = "hint";
      count.textContent = ` (${pats.length} pattern${pats.length > 1 ? "s" : ""})`;
      sum.appendChild(count);
      if (pats.some((p) => p.modified)) {
        const badge = document.createElement("span");
        badge.className = "pat-modified";
        badge.textContent = "modified";
        sum.appendChild(badge);
      }
      det.appendChild(sum);
      for (const p of pats) det.appendChild(renderBuiltinRow(p));
      wrap.appendChild(det);
    }
  } catch {
    wrap.innerHTML = `<p class="hint">Could not load patterns.</p>`;
  }
}

$("openPatternsBtn").addEventListener("click", () => {
  patternsModal.classList.remove("hidden");
  builtinMsg("");
  loadBuiltinPatterns();
});
$("closePatterns").addEventListener("click", () => patternsModal.classList.add("hidden"));
patternsModal.addEventListener("click", (e) => {
  if (e.target === patternsModal) patternsModal.classList.add("hidden");
});

// --- Conversation (mask -> provider -> un-mask, with follow-ups) ----------
const CONV = { id: null, model: "" };

function chatClear() {
  $("chat").innerHTML = "";
}

// role: "user" | "ai" | "sys". `html` is already-safe HTML.
function addBubble(role, html, roleLabel) {
  const div = document.createElement("div");
  div.className = "msg " + role;
  if (roleLabel) {
    const r = document.createElement("div");
    r.className = "role";
    r.textContent = roleLabel;
    div.appendChild(r);
  }
  const body = document.createElement("div");
  body.className = "markdown";
  body.innerHTML = html;
  div.appendChild(body);
  $("chat").appendChild(div);
  $("chat").scrollTop = $("chat").scrollHeight;
  return div;
}

function setConvActive(active) {
  $("chatControls").classList.toggle("hidden", !active);
  const btn = $("analyzeBtn");
  btn.disabled = active;
  btn.title = active
    ? "A conversation is active — End conversation to analyse a new log"
    : "";
}

// "Sent to AI" tab: the full masked transcript that has left the machine.
function renderTranscript(transcript) {
  $("sent").innerHTML = transcript
    .map((m) =>
      `<span class="sent-role">── ${m.role === "user" ? "You → AI" : "AI reply"} (masked) ──</span>\n` +
      renderMasked(m.content))
    .join("\n\n");
}

async function doAnalyze(acknowledgeLeaks = false) {
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
        structured: $("structuredChk").checked,
        use_system: $("useSystemChk").checked,
        acknowledge_leaks: acknowledgeLeaks,
      }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Analysis failed");

    if (d.blocked) {
      // Leak guard stopped the send — nothing left the machine.
      renderSentWarnings(d.warnings);
      showLeakModal(d.warnings, () => doAnalyze(true), true);
      setStatus(`🚨 Blocked by leak guard — ${d.warnings.length} finding(s). Nothing was sent.`, "err");
      return;
    }

    CONV.id = d.conversation_id;
    CONV.model = d.model;
    chatClear();
    const instr = $("instructions").value.trim();
    addBubble("user",
      `📄 Raw log submitted — <strong>${d.masked_count}</strong> value(s) masked before sending.` +
      (instr ? `<br>📝 ${escapeHtml(instr)}` : ""),
      "You");
    const aiBubble = addBubble("ai", aiAnswerHtml(d), `AI · ${d.model}`);
    if (d.verdict) { lastVerdict = d.verdict; wireVerdictButtons(aiBubble, d.verdict); }
    setConvActive(true);
    renderTranscript(d.transcript);
    setMaskedArtifact(d.masked_sent);
    renderSentWarnings(d.warnings);
    fillSentMapping(d.mapping);
    $("redBadge").textContent =
      `Conversation active — ${d.masked_count} value(s) masked. ` +
      `Follow-up questions keep the AI's context; placeholders stay consistent.`;
    $("redBadge").className = "redaction-badge active";
    showTab("restored");
    setStatus(`Done — analysed with ${d.model}. Ask follow-ups below.`, "ok");
    $("followUp").focus();
  } catch (e) {
    setStatus(e.message, "err");
    if (!CONV.id) btn.disabled = false;
  } finally {
    if (!CONV.id) btn.disabled = false;
  }
}

$("analyzeBtn").addEventListener("click", () => doAnalyze());

async function sendFollowUp(forcedQ = null, acknowledgeLeaks = false) {
  const q = forcedQ !== null ? forcedQ : $("followUp").value.trim();
  if (!q || !CONV.id) return;
  $("followUp").value = "";
  $("sendFollowUp").disabled = true;
  const userBubble = addBubble("user", renderMarkdown(q), "You");
  const thinking = addBubble("ai", "<em>Thinking…</em>", `AI · ${CONV.model}`);
  try {
    const r = await fetch("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ conversation_id: CONV.id, question: q,
                             acknowledge_leaks: acknowledgeLeaks }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Follow-up failed");
    if (d.blocked) {
      // Leak guard stopped the question — roll the bubbles back and let the
      // analyst decide. (Quick-mask isn't offered here: the conversation's
      // custom terms are fixed at analysis time.)
      userBubble.remove();
      thinking.remove();
      $("followUp").value = q;
      showLeakModal(d.warnings, () => sendFollowUp(q, true), false);
      setStatus("🚨 Blocked by leak guard — the question was not sent.", "err");
      return;
    }
    thinking.querySelector(".markdown").innerHTML = aiAnswerHtml(d);
    if (d.verdict) { lastVerdict = d.verdict; wireVerdictButtons(thinking, d.verdict); }
    renderTranscript(d.transcript);
    fillSentMapping(d.mapping);
    $("redBadge").textContent =
      `Conversation active — ${d.masked_count} value(s) masked across all turns.`;
    setStatus("");
  } catch (e) {
    thinking.remove();
    setStatus(e.message, "err");
    if (/conversation has ended|start a new one/i.test(e.message)) {
      addBubble("sys", escapeHtml(e.message));
      CONV.id = null;
      setConvActive(false);
    }
  } finally {
    $("sendFollowUp").disabled = false;
    $("chat").scrollTop = $("chat").scrollHeight;
    $("followUp").focus();
  }
}

// --- "Add to follow-up" on text selection in the chat (Perplexity-style) --
const selPop = document.createElement("button");
selPop.type = "button";
selPop.className = "sel-pop hidden";
selPop.textContent = "➕ Add to follow-up";
document.body.appendChild(selPop);

function hideSelPop() {
  selPop.classList.add("hidden");
}

$("chat").addEventListener("mouseup", () => {
  // Let the browser finalise the selection first.
  setTimeout(() => {
    const sel = window.getSelection();
    const text = sel ? sel.toString().trim() : "";
    if (!text || sel.isCollapsed || !CONV.id) return hideSelPop();
    if (!sel.anchorNode || !$("chat").contains(sel.anchorNode)) return hideSelPop();
    const rect = sel.getRangeAt(0).getBoundingClientRect();
    selPop.style.top = `${window.scrollY + rect.top - 40}px`;
    selPop.style.left = `${window.scrollX + rect.left + rect.width / 2}px`;
    selPop.dataset.text = text;
    selPop.classList.remove("hidden");
  }, 0);
});

// mousedown would collapse the selection before click fires — prevent it.
selPop.addEventListener("mousedown", (e) => e.preventDefault());
selPop.addEventListener("click", () => {
  const t = (selPop.dataset.text || "").replace(/\s+/g, " ");
  const fu = $("followUp");
  const quoted = `Regarding "${t}": `;
  fu.value = fu.value.trim() ? fu.value.trimEnd() + "\n" + quoted : quoted;
  hideSelPop();
  if (window.getSelection) window.getSelection().removeAllRanges();
  fu.focus();
  fu.selectionStart = fu.selectionEnd = fu.value.length;
});

document.addEventListener("mousedown", (e) => {
  if (e.target !== selPop) hideSelPop();
});
document.addEventListener("scroll", hideSelPop, true);

$("sendFollowUp").addEventListener("click", () => sendFollowUp());
$("followUp").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendFollowUp();
  }
});

$("endConvBtn").addEventListener("click", async () => {
  if (CONV.id) {
    await fetch("/chat/end", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ conversation_id: CONV.id }),
    });
  }
  CONV.id = null;
  addBubble("sys",
    "Conversation ended — the AI-side history and the local mapping were discarded. " +
    "Paste a new raw log and Mask &amp; Analyse to start a new one.");
  setConvActive(false);
  $("redBadge").textContent = "Conversation ended. Ready for a new log.";
  $("redBadge").className = "redaction-badge";
  setStatus("Conversation ended.", "ok");
});

// --- Requests tab: audit log of everything sent to the AI ----------------
function reqBlock(title, html) {
  return `<div class="req-block"><div class="req-block-title">${title}</div>` +
         `<pre class="req-pre">${html}</pre></div>`;
}

async function loadRequests() {
  const wrap = $("requestList");
  try {
    const d = await (await fetch("/requests")).json();
    if (d.file) $("reqFile").textContent = d.file;
    if (!d.requests.length) {
      wrap.innerHTML =
        `<p class="hint">No AI requests in view. Run an analysis, a ` +
        `follow-up, or a connection test and it will appear here.</p>`;
      return;
    }
    wrap.innerHTML = "";
    for (const r of d.requests) {
      const det = document.createElement("details");
      det.className = "req-item " + (r.ok ? "ok" : "err");
      const sum = document.createElement("summary");
      sum.innerHTML =
        `<span class="req-status">${r.ok ? "✓" : "✗"}</span>` +
        `<span class="req-seq">#${r.seq}</span>` +
        `<span>${escapeHtml(r.time)}</span>` +
        `<span class="req-kind">${escapeHtml(r.kind)}</span>` +
        `<span class="req-model">${escapeHtml(r.provider)} · ${escapeHtml(r.model)}</span>` +
        (r.leakguard ? `<span class="pat-modified" title="Sent after the analyst acknowledged leak-guard findings">🚨 leak ack</span>` : "") +
        `<span class="hint">${(r.duration_ms / 1000).toFixed(1)}s` +
        (r.conversation_id ? ` · conv ${escapeHtml(r.conversation_id)}` : "") +
        `</span>`;
      det.appendChild(sum);

      const body = document.createElement("div");
      body.className = "req-body";
      let html = "";
      if (r.error) {
        html += `<div class="req-error">✗ ${escapeHtml(r.error)}</div>`;
      }
      html += `<details class="req-sys"><summary class="hint">System prompt ` +
              `(${r.system.length} chars)</summary>` +
              `<pre class="req-pre">${escapeHtml(r.system)}</pre></details>`;
      r.messages.forEach((m, i) => {
        const who = m.role === "user" ? `➤ Sent (user message ${i + 1})`
                                      : `↩ History (assistant message ${i + 1})`;
        html += reqBlock(who, renderMasked(m.content));
      });
      if (r.response) {
        html += reqBlock("✓ Response received (masked)", renderMasked(r.response));
      }
      body.innerHTML = html;
      det.appendChild(body);
      wrap.appendChild(det);
    }
  } catch (e) {
    wrap.innerHTML = `<p class="hint">Could not load the request log: ` +
                     `${escapeHtml(e.message)}</p>`;
  }
}

$("refreshReqBtn").addEventListener("click", loadRequests);
$("clearReqBtn").addEventListener("click", async () => {
  await fetch("/requests/clear", { method: "POST" });
  loadRequests();
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

// Persist settings without wiping other fields. `over` may include:
//   provider, make_default (promote to default provider),
//   provider_models {pid: model} (per-provider default model overrides),
//   azure_*/m365_* (global provider fields).
async function persistConfig(over = {}) {
  const payload = {
    provider: over.provider || CONFIG.provider,
    make_default: !!over.make_default,
    provider_models: { ...(CONFIG.provider_models || {}), ...(over.provider_models || {}) },
    azure_endpoint: over.azure_endpoint ?? CONFIG.azure_endpoint ?? "",
    azure_deployment: over.azure_deployment ?? CONFIG.azure_deployment ?? "",
    azure_api_version: over.azure_api_version ?? CONFIG.azure_api_version ?? "2024-08-01-preview",
    m365_tenant_id: over.m365_tenant_id ?? CONFIG.m365_tenant_id ?? "",
    m365_client_id: over.m365_client_id ?? CONFIG.m365_client_id ?? "",
  };
  const r = await fetch("/config", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const d = await r.json();
  if (r.ok) CONFIG = d.config;
  return r.ok;
}

// The saved default model for a provider (falls back to registry default).
function modelFor(pid) {
  return (CONFIG.provider_models || {})[pid] || (REGISTRY[pid] || {}).default_model || "";
}

// Live model lists fetched from each provider's API (provider -> [ids]).
const LIVE_MODELS = {};
const CUSTOM = "__custom__";

// Candidate models for a provider: live list if fetched, else the built-in
// list; always include the currently-saved model so it shows even if custom.
function modelOptionsFor(pid) {
  const live = LIVE_MODELS[pid];
  const base = (live && live.length) ? live.slice() : ((REGISTRY[pid] || {}).models || []).slice();
  const saved = modelFor(pid);
  if (saved && !base.includes(saved)) base.unshift(saved);
  return base;
}

// Pull the live model list from the provider's API and re-render dropdowns.
async function refreshModels(pid, { announce = false } = {}) {
  try {
    const d = await (await fetch("/models?provider=" + encodeURIComponent(pid))).json();
    if (d.models && d.models.length) {
      LIVE_MODELS[pid] = d.models;
      if (selectedProvider === pid) renderModalForProvider();
      if (CONFIG.provider === pid) renderActiveProvider();
      if (announce) setupMsg(`✓ Loaded ${d.models.length} live models from the provider.`, "ok");
    } else if (announce) {
      setupMsg(d.error || "No models returned.", "err");
    }
  } catch (e) {
    if (announce) setupMsg(e.message, "err");
  }
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

  // Model dropdown: only for providers that expose a model list. Shows this
  // provider's saved default model (built-in or live-fetched).
  const meta = REGISTRY[CONFIG.provider];
  const opts = modelOptionsFor(CONFIG.provider);
  if (meta && meta.auth !== "oauth" && CONFIG.provider !== "azure" && opts.length) {
    mSel.innerHTML = "";
    for (const m of opts) {
      const o = document.createElement("option");
      o.value = m; o.textContent = m;
      mSel.appendChild(o);
    }
    mSel.value = modelFor(CONFIG.provider);
    mSel.style.display = "";
  } else {
    mSel.style.display = "none";   // Azure (deployment) / M365 (no model)
  }
}

// Inline provider change -> make it the default provider (its saved model rides along).
$("activeProviderSelect").addEventListener("change", async (e) => {
  const pid = e.target.value;
  await persistConfig({ provider: pid, make_default: true });
  renderActiveProvider();
  setStatus(`Default provider is now ${REGISTRY[pid].label}.`, "ok");
});

// Inline model change -> update the default model for the current provider.
$("activeModelSelect").addEventListener("change", async (e) => {
  await persistConfig({ provider_models: { [CONFIG.provider]: e.target.value } });
  setStatus(`Default model for ${REGISTRY[CONFIG.provider].label} set to ${e.target.value}.`, "ok");
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
    const isDefault = pid === CONFIG.provider;
    card.innerHTML =
      `<span class="pc-label">${meta.label}` +
      (isDefault ? ` <span class="pc-default">★ default</span>` : "") + `</span>` +
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

  // Model dropdown: built-in or live-fetched options, plus a "Custom…" entry.
  const sel = $("modelSelect");
  const custom = $("modelCustom");
  custom.classList.add("hidden");
  sel.innerHTML = "";
  const hasModels = meta.models.length || (LIVE_MODELS[selectedProvider] || []).length;
  if (hasModels) {
    for (const m of modelOptionsFor(selectedProvider)) {
      const o = document.createElement("option");
      o.value = m; o.textContent = m;
      sel.appendChild(o);
    }
    const co = document.createElement("option");
    co.value = CUSTOM; co.textContent = "Custom…";
    sel.appendChild(co);
    sel.disabled = false;
    sel.value = modelFor(selectedProvider);
    // Auto-fetch the live list once per provider if a key is configured.
    if (CONFIGURED[selectedProvider] && !LIVE_MODELS[selectedProvider]) {
      refreshModels(selectedProvider);
    }
  } else {
    const o = document.createElement("option");
    o.value = ""; o.textContent = "(set via deployment name below)";
    sel.appendChild(o);
    sel.disabled = true;
  }

  // "Use as default" checkbox: checked+locked when already the default.
  const isDefault = selectedProvider === CONFIG.provider;
  const chk = $("makeDefaultChk");
  chk.checked = isDefault;
  chk.disabled = isDefault;
  $("defaultToggle").title = isDefault
    ? "This is already your default provider"
    : "Tick to make this your default provider when you Save";

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
  renderSetupTerms();
}
$("settingsBtn").addEventListener("click", openSetup);
$("openSetupInline").addEventListener("click", openSetup);
$("viewTermsBtn").addEventListener("click", () => {
  openSetup();
  $("setupTermsList").scrollIntoView({ behavior: "smooth", block: "center" });
});

// Per-provider default model — save immediately when changed (no Save needed).
// (renderModalForProvider sets .value programmatically, which doesn't fire change.)
$("modelSelect").addEventListener("change", async (e) => {
  const custom = $("modelCustom");
  if (e.target.value === CUSTOM) {
    custom.classList.remove("hidden");
    custom.value = "";
    custom.focus();
    return;
  }
  custom.classList.add("hidden");
  if (!e.target.value) return;
  await saveProviderModel(e.target.value);
});

// Free-text custom model id.
$("modelCustom").addEventListener("change", async (e) => {
  const v = e.target.value.trim();
  if (v) await saveProviderModel(v);
});

async function saveProviderModel(model) {
  await persistConfig({ provider_models: { [selectedProvider]: model } });
  renderProviderCards();
  renderActiveProvider();
  setupMsg(`✓ Default model for ${REGISTRY[selectedProvider].label}: ${model}`, "ok");
}

// Manual refresh of the live model list.
$("refreshModelsBtn").addEventListener("click", () => {
  setupMsg("Fetching live model list…");
  refreshModels(selectedProvider, { announce: true });
});

// Default provider — apply immediately when ticked.
$("makeDefaultChk").addEventListener("change", async (e) => {
  if (!e.target.checked) return;
  await persistConfig({ provider: selectedProvider, make_default: true });
  renderModalForProvider();
  renderActiveProvider();
  setupMsg(`✓ ${REGISTRY[selectedProvider].label} is now your default provider.`, "ok");
});
$("closeSettings").addEventListener("click", () => modal.classList.add("hidden"));
modal.addEventListener("click", (e) => { if (e.target === modal) modal.classList.add("hidden"); });

// Save: persist key (if entered), this provider's default model, its provider
// fields, and optionally promote it to the default provider.
$("saveSetupBtn").addEventListener("click", async () => {
  const extra = collectExtra();               // azure_*/m365_* for this provider
  const key = $("apiKey").value.trim();
  const makeDefault = $("makeDefaultChk").checked;
  const meta = REGISTRY[selectedProvider];
  try {
    if (key) {
      const rk = await fetch("/save-key", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: selectedProvider, api_key: key }),
      });
      if (!rk.ok) throw new Error((await rk.json()).detail || "Could not save key");
    }
    const over = { provider: selectedProvider, make_default: makeDefault, ...extra };
    if (meta.models.length) over.provider_models = { [selectedProvider]: $("modelSelect").value };
    const ok = await persistConfig(over);
    if (!ok) throw new Error("Could not save settings");
    await loadConfig();
    renderModalForProvider();
    setupMsg("✓ Saved." + (makeDefault ? " Set as default provider." : ""), "ok");
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
  await persistConfig({ provider: "m365copilot",
    m365_tenant_id: tenant, m365_client_id: client });
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
