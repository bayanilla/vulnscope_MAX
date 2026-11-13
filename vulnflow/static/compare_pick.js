// Compare page: tick reports, filter the list, and remember network names changed here (in this
// browser only; the reports themselves are never changed).
(function () {
  const KEY = "vulnscope-compare-networks";
  const rows = Array.from(document.querySelectorAll(".cmp-pick tbody tr[data-text]"));
  const boxes = () => rows.map(r => r.querySelector("input[type=checkbox]"));
  const go = document.getElementById("cmp-go"), count = document.getElementById("cmp-count");
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(KEY) || "{}") || {}; } catch (e) { saved = {}; }
  const store = () => { try { localStorage.setItem(KEY, JSON.stringify(saved)); } catch (e) {} };
  document.querySelectorAll("input.cmp-net").forEach(inp => {
    const id = inp.name.slice(4);
    // the server shows what it was sent after a refused compare; otherwise use the remembered name
    if (saved[id] && inp.value === inp.dataset.saved) inp.value = saved[id];
    inp.addEventListener("change", () => {
      const v = inp.value.replace(/\s+/g, " ").trim();
      if (!v || v === inp.dataset.saved) delete saved[id]; else saved[id] = v;
      store();
    });
  });
  function update() {
    const n = boxes().filter(b => b && b.checked).length;
    if (count) count.textContent = n ? n + " report" + (n === 1 ? "" : "s") + " ticked" : "Tick the reports to compare.";
    if (go) go.disabled = !n;
  }
  rows.forEach(r => r.addEventListener("change", e => { if (e.target.type === "checkbox") update(); }));
  const visible = () => rows.filter(r => !r.hidden);
  const all = document.getElementById("cmp-all"), none = document.getElementById("cmp-none");
  if (all) all.onclick = () => { visible().forEach(r => r.querySelector("input[type=checkbox]").checked = true); update(); };
  if (none) none.onclick = () => { boxes().forEach(b => b.checked = false); update(); };
  const filter = document.getElementById("cmp-filter");
  if (filter) filter.addEventListener("input", () => {
    const q = filter.value.trim().toLowerCase();
    rows.forEach(r => { r.hidden = !!q && !r.dataset.text.includes(q); });
  });
  window.addEventListener("pageshow", update);
  update();
})();
