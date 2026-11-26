// Applies the saved theme before first paint (external file: strict CSP forbids inline scripts).
(function () {
  var theme = "system";
  try {
    theme = localStorage.getItem("leazone-theme") || "system";
  } catch (e) {
    // storage unavailable
  }
  var dark =
    theme === "dark" ||
    (theme !== "light" && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  if (dark) document.documentElement.classList.add("dark");
})();
