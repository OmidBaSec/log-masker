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

// --- Analyse (mask -> Claude -> un-mask) --------------------------------
$("analyzeBtn").addEventListener("click", async () => {
  const logs = $("logs").value.trim();
  if (!logs) return setStatus("Paste some logs first.", "err");
  const btn = $("analyzeBtn");
  btn.disabled = true;
  setStatus("Masking locally and sending masked logs to Claude…");
  try {
    const r = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        logs,
        categories: selectedCategories(),
        custom_terms: customTerms(),
        model: $("model").value,
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
    setStatus(`Done — analysed with ${$("model").value}.`, "ok");
  } catch (e) {
    setStatus(e.message, "err");
  } finally {
    btn.disabled = false;
  }
});

// --- Settings / API key --------------------------------------------------
const modal = $("settingsModal");
async function refreshKeyState() {
  try {
    const r = await fetch("/key-status");
    const d = await r.json();
    $("keyState").textContent = d.has_key
      ? "✓ A key is configured (keychain or environment)."
      : "⚠ No key configured yet.";
  } catch { /* ignore */ }
}
$("settingsBtn").addEventListener("click", () => {
  modal.classList.remove("hidden");
  refreshKeyState();
});
$("closeSettings").addEventListener("click", () => modal.classList.add("hidden"));
modal.addEventListener("click", (e) => { if (e.target === modal) modal.classList.add("hidden"); });

$("saveKeyBtn").addEventListener("click", async () => {
  const key = $("apiKey").value.trim();
  if (!key) return ($("keyState").textContent = "Enter a key first.");
  const r = await fetch("/save-key", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: key }),
  });
  if (r.ok) { $("apiKey").value = ""; $("keyState").textContent = "✓ Saved to keychain."; }
  else { $("keyState").textContent = "Could not save key."; }
});

$("deleteKeyBtn").addEventListener("click", async () => {
  await fetch("/delete-key", { method: "POST" });
  refreshKeyState();
});

// Warn on load if no key.
refreshKeyState();
