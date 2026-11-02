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
    addMessage('you', 'You', question, false);
    input.value = '';
    submit.disabled = true;
    busy.textContent = 'Thinking…';
    try {
      const response = await fetch(root.dataset.askUrl, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
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

  const toggle = document.getElementById('btn-ai');
  if (!toggle) return;
  const match = location.pathname.match(/^\/runs\/([a-f0-9]{16})\/(?:explorer\.html)?$/);
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
      if (!config.enabled) return;
      toggle.hidden = false;
      status.textContent = config.description + (config.ready ? ' Answers are AI-generated; verify before acting.' : '');
      form.hidden = !config.ready;
      log.hidden = !config.ready;
      settings.textContent = config.ready ? 'Change provider' : 'Choose a provider';
    })
    .catch(() => {});
})();
