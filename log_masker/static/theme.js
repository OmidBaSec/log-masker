// Apply the saved theme (or the OS appearance) and the sidebar state before
// first paint, so the page never flashes the wrong theme or layout.
//
// This lives in its own file rather than inline in the page so the Content
// Security Policy can be script-src 'self' with no 'unsafe-inline' — an
// injected <script> or event handler then cannot run at all. Loaded without
// defer/async on purpose: it must finish before the body renders.
(function () {
  var theme = "dark";
  try {
    var saved = localStorage.getItem("logmasker.theme");
    if (saved !== "light" && saved !== "dark") saved = null;  // null = follow the OS
    theme = saved || (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  } catch (e) { /* storage blocked — stay on the dark default */ }
  document.documentElement.setAttribute("data-theme", theme);
  try {
    if (localStorage.getItem("logmasker.sidebar") === "hidden") {
      document.documentElement.classList.add("sidebar-hidden");
    }
  } catch (e) { /* storage blocked — the sidebar stays visible */ }
})();
