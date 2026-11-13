// Browse… for a folder path field (#path). Three ways, depending on where the server runs:
// - in the container: the browser's own folder window; the page sends the folder's name plus a few
//   file names, sizes and times (no contents) and the server finds that folder among the folders
//   shared with the container (browsers never reveal where a chosen folder is);
// - on a Mac: the system's Choose Folder dialog, opened by the server;
// - otherwise: a small in-page folder list served by /browse.
// Setting the path fires "change" on #path, so the page can react (the upload page relabels its
// button for a report folder).
(function () {
  const cfg = JSON.parse(document.getElementById("vs-page").textContent);
  const csrf = cfg.csrf, native = cfg.native, dialog = cfg.dialog;
  const $ = id => document.getElementById(id), box = $("picker"), list = $("pk-list"), path = $("path");
  if (!path || !box) return;
  let cur = null, parent = null;
  async function call(url, body) {
    const r = await fetch(url, {method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(Object.assign({csrf}, body))});
    return r.json();
  }
  const submit = () => path.form.querySelector('button[type="submit"]');
  function set(p) {
    path.value = p; box.hidden = true;
    path.dispatchEvent(new Event("change", {bubbles: true}));
  }
  async function show(where) {
    const d = await call("/browse", {path: where});
    if (d.error) { $("pk-info").textContent = d.error; return; }
    cur = d.path; parent = d.parent; $("pk-where").textContent = d.path; $("pk-up").disabled = !d.parent;
    const roots = $("pk-roots"); roots.innerHTML = "";
    (d.roots || []).forEach(r => {
      const btn = document.createElement("button"); btn.type = "button"; btn.className = "secondary";
      btn.textContent = (r === d.roots[0] ? "Home folder" : r); btn.title = r; btn.disabled = r === d.path; btn.onclick = () => show(r);
      roots.appendChild(btn);
    });
    list.innerHTML = "";
    d.dirs.forEach(name => {
      const li = document.createElement("li"); li.textContent = name; li.tabIndex = 0;
      const go = () => show((d.path.endsWith(d.sep) ? d.path : d.path + d.sep) + name);
      li.onclick = go; li.onkeydown = e => { if (e.key === "Enter") { e.preventDefault(); go(); } };
      list.appendChild(li);
    });
    $("pk-info").textContent = d.files + " file" + (d.files === 1 ? "" : "s") + " here" +
      (d.dirs.length ? ", " + d.dirs.length + " subfolder" + (d.dirs.length === 1 ? "" : "s") : "");
    box.hidden = false;
  }
  const msg = (t, bad) => { const m = $("pick-msg"); m.textContent = t || "";
    m.style.color = bad ? "#c0392b" : ""; m.style.fontWeight = bad ? "600" : ""; };
  if (dialog) $("pick-dir").onchange = async () => {
    const files = Array.from($("pick-dir").files || []); $("pick-dir").value = "";
    if (!files.length) { msg("That folder looks empty, or the browser didn't list its files. Type the path instead.", true); return; }
    const name = files[0].webkitRelativePath.split("/")[0];
    const step = Math.max(1, Math.floor(files.length / 12));
    const samples = files.filter((f, i) => i % step === 0).slice(0, 12)
      .map(f => [f.webkitRelativePath.split("/").slice(1).join("/"), f.size, f.lastModified]);
    msg("Finding " + name + " ...");
    const d = await call("/locate-folder", {name, samples, count: files.length});
    if (d.error) { msg(d.error, true); return; }
    const ready = p => { set(p); msg("Folder set."); const b = submit(); if (b) b.focus(); };
    if (d.matches.length === 1) { ready(d.matches[0]); return; }
    msg("Found " + d.matches.length + " folders named " + name + ". Pick one:");
    cur = null; $("pk-where").textContent = name; $("pk-up").disabled = true; $("pk-roots").innerHTML = "";
    list.innerHTML = "";
    d.matches.forEach(p => {
      const li = document.createElement("li"); li.textContent = p; li.tabIndex = 0;
      const use = () => ready(p);
      li.onclick = use; li.onkeydown = e => { if (e.key === "Enter") { e.preventDefault(); use(); } };
      list.appendChild(li);
    });
    $("pk-info").textContent = ""; box.hidden = false;
  };
  $("browse").onclick = async () => {
    if (dialog) { msg(""); $("pick-dir").click(); return; }
    if (native) {
      $("browse").disabled = true;
      try {
        const d = await call("/pick-folder", {path: path.value});
        if (d.path) { set(d.path); return; }
        if (d.cancelled) return;
      } catch (e) {} finally { $("browse").disabled = false; }
    }
    show(path.value);
  };
  $("pk-up").onclick = () => parent && show(parent);
  path.form.addEventListener("submit", e => {
    if (!path.value.trim()) { e.preventDefault(); msg("Choose a folder first: click Browse… and pick one, or type its full path.", true); path.focus(); }
  });
  $("pk-use").onclick = () => { if (cur) set(cur); else box.hidden = true; path.focus(); };
  $("pk-cancel").onclick = () => { box.hidden = true; };
})();
