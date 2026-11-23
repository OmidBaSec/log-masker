// HTML rendering helpers for the workspace views.
//
// These four functions build the markup for everything the analyst reads back:
// the masked payload, the AI's restored answer, and the hover cards that pair
// an alias with its real value. They are pure string -> string, with no DOM
// dependency, so they can be tested without a browser (see test_frontend.js).
//
// They are also the app's single trust boundary on the way *out*. Log content
// is attacker-influenced by definition — a username in a failed logon, a
// user-agent, a filename — and it arrives here unmasked, because restoring the
// real values is the whole point of the product. Everything interpolated into
// markup below must therefore be escaped, and escaped for the context it lands
// in: several of these values end up inside a quoted attribute, where escaping
// only < and > is not enough.

(function (root) {
  // Escapes for both text and quoted-attribute contexts. The quotes matter:
  // `data-real="${escapeHtml(real)}"` with a value like `a" onmouseover=…`
  // would otherwise close the attribute and inject a live event handler.
  function escapeHtml(s) {
    return String(s === undefined || s === null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Escapes HTML first, then applies light markdown (headings, bold, code,
  // bullets). Keeps things readable without a heavy dep.
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

  // Render masked text with placeholders highlighted in red. Each placeholder
  // is a hover card: when the mapping is known (alias -> real), hovering shows
  // the original local value; otherwise (e.g. the audit view, which only ever
  // holds masked content) it shows a neutral note. A known value also carries
  // data-keep, so a click can add it to the never-mask list.
  function renderMasked(text, mapping = {}) {
    return escapeHtml(text).replace(/\[([A-Z0-9]+_\d+)\]/g, (_m, p1) => {
      const alias = `[${p1}]`;
      const real = mapping[alias];
      const tip = real ? `Original: ${real}` : "Local masked value";
      const keep = real ? ` data-keep="${escapeHtml(real)}"` : "";
      return `<span class="masked-placeholder" data-alias="${escapeHtml(alias)}"` +
             `${keep} data-tip="${escapeHtml(tip)}"` +
             `${real ? ' title="Click if this should not be masked"' : ""}>` +
             `${escapeHtml(alias)}</span>`;
    });
  }

  // Wrap restored real values so the user can see what was injected back. Each
  // restored value is a hover card showing the redacted alias it maps to. Uses
  // token substitution so an already-wrapped value can't be re-matched by a
  // shorter value nested inside it.
  function highlightRestored(text, mapping = {}) {
    let html = renderMarkdown(text);
    const aliasFor = {};
    for (const [alias, real] of Object.entries(mapping)) {
      if (real && !(real in aliasFor)) aliasFor[real] = alias;
    }
    const reals = Object.keys(aliasFor).sort((a, b) => b.length - a.length);
    // Pass 1: replace each real value with a unique, HTML-safe token.
    reals.forEach((real, i) => {
      const esc = escapeHtml(real).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      html = html.replace(new RegExp(esc, "g"), `\uE000R${i}\uE000`);
    });
    // Pass 2: swap tokens for restored badges (no real text present in pass 1).
    reals.forEach((real, i) => {
      const badge = `<span class="restored-badge" data-real="${escapeHtml(real)}"` +
        ` data-tip="${escapeHtml(`Redacted alias: ${aliasFor[real]}`)}">` +
        `${escapeHtml(real)}</span>`;
      html = html.split(`\uE000R${i}\uE000`).join(badge);
    });
    return html;
  }

  const api = { escapeHtml, renderMarkdown, renderMasked, highlightRestored };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.LogRender = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
