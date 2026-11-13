// Upload page: send the report details with whichever form is submitted, and relabel the folder
// form's button "Open report" when the folder is a completed report's output folder.
(function () {
  const cfg = JSON.parse(document.getElementById("vs-page").textContent);
  const $ = id => document.getElementById(id);
  document.querySelectorAll('form[action="/analyze"],form[action="/analyze-folder"]').forEach(f => f.addEventListener("submit", () => {
    // the report details sit outside both forms
    ["report_name", "report_network", "report_description"].forEach(n => {
      let h = f.querySelector('input[type=hidden][name="' + n + '"]');
      if (!h) { h = document.createElement("input"); h.type = "hidden"; h.name = n; f.prepend(h); }
      h.value = $(n).value;
    });
  }));
  const path = $("path"), btn = $("analyze-folder"), form = path.form;
  const analyzing = {busy: form.dataset.busy, hint: form.dataset.busyHint};
  let kindSeq = 0, kindTimer = null;
  async function checkKind() {
    const p = path.value.trim(), seq = ++kindSeq;
    let report = false;
    if (p) {
      try {
        const r = await fetch("/folder-kind", {method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({csrf: cfg.csrf, path: p})});
        report = !!(await r.json()).report;
      } catch (e) {}
    }
    if (seq !== kindSeq) return;
    btn.textContent = report ? "Open report" : "Analyze folder";
    if (report) btn.dataset.report = "1"; else delete btn.dataset.report;
    form.dataset.busy = report ? "Opening report…" : analyzing.busy;
    form.dataset.busyHint = report ? "" : analyzing.hint;
  }
  path.addEventListener("input", () => { clearTimeout(kindTimer); kindTimer = setTimeout(checkKind, 300); });
  path.addEventListener("change", checkKind);
  checkKind();
})();
