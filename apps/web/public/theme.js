// Applies the saved theme before first paint. Kept as a file, not inline, so the site runs
// under a Content-Security-Policy without 'unsafe-inline' for scripts.
(function () {
  try {
    var s = JSON.parse(localStorage.getItem('revlens.settings') || '{}');
    var t = s.theme || 'black';
    if (t === 'system') t = matchMedia('(prefers-color-scheme: light)').matches ? 'sun' : 'black';
    var d = document.documentElement;
    d.dataset.theme = t;
    d.dataset.accent = s.accent || 'gold';
    d.classList.toggle('dark', t !== 'sun');
    if (s.motion === 'reduced') d.dataset.motion = 'reduced';
  } catch (e) {}
})();
