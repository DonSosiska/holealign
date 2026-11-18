// Holealign UI: tiny progressive enhancements. Everything works without JS except clipboard copy.
document.addEventListener('submit', function (e) {
  var msg = e.target && e.target.getAttribute && e.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) {
    e.preventDefault();
  }
});
document.addEventListener('click', function (e) {
  var btn = e.target.closest ? e.target.closest('[data-copy]') : null;
  if (!btn) return;
  var el = document.getElementById(btn.getAttribute('data-copy'));
  if (!el) return;
  var text = el.textContent;
  var done = function () {
    var old = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(function () { btn.textContent = old; }, 1500);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function () {});
  } else {
    var r = document.createRange();
    r.selectNodeContents(el);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(r);
    try { document.execCommand('copy'); done(); } catch (_) {}
  }
});
