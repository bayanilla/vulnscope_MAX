// "Working" overlay for long form posts (analyze, open report, compare): the logo turns, a timer
// counts, and every button is disabled so the form can't be sent twice. A form opts in with
// data-busy="<title>" (and data-busy-hint="<one line>"). The listener sits on the document, so it
// runs after the form's own submit handlers and skips a submit one of them refused.
(function () {
  const busy = document.getElementById("busy");
  if (!busy) return;
  const clock = document.getElementById("busy-time"), title = document.getElementById("busy-title"),
        hint = document.getElementById("busy-hint");
  let timer = null;
  document.addEventListener("submit", e => {
    const f = e.target;
    if (!(f instanceof HTMLFormElement) || !f.dataset.busy) return;
    if (busy.dataset.running) { e.preventDefault(); return; }
    if (e.defaultPrevented) return;
    title.textContent = f.dataset.busy;
    hint.textContent = f.dataset.busyHint || "";
    hint.hidden = !f.dataset.busyHint;
    busy.dataset.running = "1";
    const start = Date.now(), tick = () => {
      const s = Math.floor((Date.now() - start) / 1000);
      clock.textContent = Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
    };
    tick(); timer = setInterval(tick, 1000);
    busy.hidden = false;
    // after this event: a disabled button is left out of the form data, and these carry none
    setTimeout(() => document.querySelectorAll("button").forEach(b => b.disabled = true), 0);
  });
  window.addEventListener("pageshow", e => {
    if (!e.persisted) return;          // back button from the result: clear the overlay
    clearInterval(timer); delete busy.dataset.running; busy.hidden = true;
    document.querySelectorAll("button").forEach(b => b.disabled = false);
  });
})();
