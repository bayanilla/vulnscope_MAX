(function () {
  'use strict';
  const root = document.querySelector('[data-ai-chat]');
  if (!root) return;

  const log = root.querySelector('.ai-chat-log');
  const form = root.querySelector('.ai-chat-form');
  const input = form.querySelector('textarea');
  const submit = form.querySelector('.ai-chat-submit');
  const busy = form.querySelector('.ai-chat-busy');
  const history = [];
  let csrfToken = null;
  async function csrf() {
    if (csrfToken) return csrfToken;
    const response = await fetch('ai-status', {cache: 'no-store'});
    if (!response.ok) throw new Error('The Security Assistant is not available for this page.');
    csrfToken = (await response.json()).csrf;
    return csrfToken;
  }
  const keyHint = document.createElement('span');
  keyHint.className = 'ai-chat-keyhint';
  keyHint.id = input.id + '-keyhint';
  keyHint.textContent = 'Enter to send · Shift+Enter for a new line';
  input.insertAdjacentElement('afterend', keyHint);
  input.setAttribute('aria-describedby', [input.getAttribute('aria-describedby'), keyHint.id].filter(Boolean).join(' '));

  let composing = false;
  input.addEventListener('compositionstart', () => { composing = true; });
  input.addEventListener('compositionend', () => { composing = false; });
  input.addEventListener('keydown', event => {
    if (event.key !== 'Enter' || event.shiftKey || event.ctrlKey || event.altKey || event.metaKey ||
        event.isComposing || composing || event.keyCode === 229) return;
    event.preventDefault();
    if (!submit.disabled && input.value.trim()) form.requestSubmit(submit);
  });

  function addMessage(kind, title, content, isHtml) {
    const message = document.createElement('div');
    message.className = 'ai-chat-msg ' + kind;
    const heading = document.createElement('strong');
    heading.textContent = title;
    const body = document.createElement('div');
    if (isHtml) body.innerHTML = content;
    else { const paragraph = document.createElement('p'); paragraph.textContent = content; body.appendChild(paragraph); }
    message.append(heading, body);
    log.appendChild(message);
    log.scrollTop = log.scrollHeight;
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (submit.disabled) return;
    const question = input.value.trim();
    if (!question) { input.focus(); return; }
    clearSuggestions();
    addMessage('you', 'You', question, false);
    input.value = '';
    submit.disabled = true;
    busy.textContent = 'Thinking…';
    try {
      const response = await fetch(root.dataset.askUrl, {
        method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': await csrf()},
        body: JSON.stringify({question, history})
      });
      const result = await response.json();
      if (!response.ok || result.error) throw new Error(result.error || `Request failed (${response.status})`);
      addMessage('ai', 'Security Assistant', result.answer_html, true);
      history.push({role: 'user', content: question}, {role: 'assistant', content: result.answer});
      if (history.length > 40) history.splice(0, history.length - 40);
    } catch (error) {
      addMessage('error', 'Error', String(error.message || error), false);
      if (!input.value) input.value = question;
    } finally {
      submit.disabled = false;
      busy.textContent = '';
      input.focus();
    }
  });

  // Built-in offline assistant: offer a few starting questions while the conversation is empty.
  const SUGGESTIONS = ['What should we fix first?', 'Show outbound callbacks', 'Any lateral movement?',
    'What is exposed to the internet?', 'Which IOCs matched?', 'What could this analysis be missing?'];
  function focusedHost() {
    const m = location.hash.match(/host=([^&]+)/);
    try { return m ? decodeURIComponent(m[1]) : ''; } catch (e) { return ''; }
  }
  function showSuggestions() {
    if (log.querySelector('.ai-chat-msg')) return;
    let box = log.querySelector('.ai-chat-suggest');
    if (!box) {
      box = document.createElement('div');
      box.className = 'ai-chat-suggest';
      log.appendChild(box);
    }
    box.replaceChildren();
    const intro = document.createElement('p');
    intro.textContent = 'Ask about a host, IP, CVE, plugin ID or IOC, or start with one of these:';
    box.appendChild(intro);
    const host = focusedHost();
    (host ? ['Explain ' + host].concat(SUGGESTIONS) : SUGGESTIONS).forEach(text => {
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.textContent = text;
      chip.addEventListener('click', () => {
        if (submit.disabled) return;
        input.value = text;
        form.requestSubmit(submit);
      });
      box.appendChild(chip);
    });
  }
  function clearSuggestions() { const box = log.querySelector('.ai-chat-suggest'); if (box) box.remove(); }
  window.addEventListener('hashchange', () => { if (root.dataset.offline) showSuggestions(); });

  const toggle = document.getElementById('btn-ai');
  if (!toggle) return;
  const match = location.pathname.match(/^\/runs\/([A-Za-z0-9][A-Za-z0-9_-]{0,120})\/(?:explorer\.html)?$/);
  if (!match) return; // Downloaded, standalone reports have no run-scoped AI endpoint.
  const runUrl = `/runs/${match[1]}/`;
  const close = root.querySelector('.ai-chat-close');
  const status = root.querySelector('.ai-chat-status');
  const settings = root.querySelector('.ai-chat-settings');
  settings.href = `/settings?next=${encodeURIComponent(runUrl)}`;

  function setOpen(open) {
    root.hidden = !open;
    document.body.classList.toggle('ai-chat-open', open);
    window.dispatchEvent(new Event('resize'));
    toggle.setAttribute('aria-expanded', String(open));
    if (open) form.hidden ? close.focus() : input.focus();
    else toggle.focus();
  }
  toggle.addEventListener('click', () => setOpen(root.hidden));
  close.addEventListener('click', () => setOpen(false));
  window.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !root.hidden) {
      event.preventDefault();
      event.stopImmediatePropagation();
      setOpen(false);
    }
  }, true);

  fetch(runUrl + 'ai-status', {cache: 'no-store'})
    .then(response => { if (!response.ok) throw new Error(); return response.json(); })
    .then(config => {
      if (config.csrf) csrfToken = config.csrf;
      if (!config.enabled) return;
      toggle.hidden = false;
      status.textContent = config.description + (config.ready && !config.offline ? ' Answers are AI-generated; verify before acting.' : '');
      form.hidden = !config.ready;
      log.hidden = !config.ready;
      settings.textContent = config.offline ? 'Use an AI model instead' : (config.ready ? 'Change provider' : 'Choose a provider');
      if (config.offline) { root.dataset.offline = '1'; showSuggestions(); }
    })
    .catch(() => {});
})();
