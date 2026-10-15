function setValue(element, value) {
  element.focus(); element.value = value;
  element.dispatchEvent(new Event('input', {bubbles: true}));
  element.dispatchEvent(new Event('change', {bubbles: true}));
}
chrome.runtime.sendMessage({type: 'page', url: location.href, title: document.title, top: window === top});
// L3 masking (CONTRACTS.md 4.5, 5.4): report whether keyboard focus is on a secret field, so the gateway records the
// keys typed into it masked. Runs in every frame; the gateway keeps the state per tab and frame.
const SECRET_AUTOCOMPLETE = /(^|\s)(current-password|new-password|one-time-code)(\s|$)/;
function deepActiveElement() {
  let element = document.activeElement;
  while (element && element.shadowRoot && element.shadowRoot.activeElement) element = element.shadowRoot.activeElement;
  return element;
}
function isSecretField(element) {
  if (!element || element.tagName !== 'INPUT') return false;
  return element.type === 'password' || SECRET_AUTOCOMPLETE.test((element.getAttribute('autocomplete') || '').toLowerCase());
}
let secretFocus = false;
function sendFocus(sensitive) {
  secretFocus = sensitive;
  chrome.runtime.sendMessage({type: 'focus', sensitive}).catch(() => {});
}
function reportFocus(force) {
  const sensitive = isSecretField(deepActiveElement());
  if (sensitive === secretFocus && !force) return;
  sendFocus(sensitive);
}
document.addEventListener('focusin', () => reportFocus(false), true);
document.addEventListener('focusout', () => setTimeout(() => reportFocus(false), 0), true);
// Every key typed while sensitive re-asserts the state, and a key re-checks it: this catches focus moved by page script
// and a "show password" toggle that flips the field type, within the gateway's masking window.
document.addEventListener('keydown', () => reportFocus(secretFocus), true);
window.addEventListener('pagehide', () => { if (secretFocus) sendFocus(false); });
reportFocus(false);
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'login_check') {
    const check = message.successCheck || {};
    const ok = check.type === 'selector_present' && Boolean(document.querySelector(check.value));
    return chrome.runtime.sendMessage({type: 'login_result', requestId: message.requestId, ok, reason: ok ? 'success_check_passed' : 'success_check_failed', url: location.href});
  }
  if (message.type !== 'form_login') return;
  const recipe = message.recipe || {};
  if (recipe.loginUrl) {
    try {
      const target = new URL(recipe.loginUrl); const current = new URL(location.href);
      const path = target.pathname.endsWith('/') ? target.pathname : target.pathname + '/';
      if (target.origin !== current.origin || (current.pathname !== target.pathname && !current.pathname.startsWith(path)))
        return chrome.runtime.sendMessage({type: 'login_result', requestId: message.requestId, ok: false, reason: 'success_check_failed', url: location.href});
    } catch (_) {
      return chrome.runtime.sendMessage({type: 'login_result', requestId: message.requestId, ok: false, reason: 'success_check_failed', url: location.href});
    }
  }
  const user = document.querySelector(recipe.usernameSelector);
  const pass = document.querySelector(recipe.passwordSelector);
  const submit = document.querySelector(recipe.submitSelector);
  if (!user || !pass || !submit) return chrome.runtime.sendMessage({type: 'login_result', requestId: message.requestId, ok: false, reason: 'selector_not_found', url: location.href});
  setValue(user, message.username || ''); setValue(pass, message.password || '');
  chrome.runtime.sendMessage({type: 'credential_injected', requestId: message.requestId, fields: ['username', 'password'], url: location.href});
  submit.click();
  const timeout = Math.min(Math.max(Number(message.timeoutMs || 15000), 100), 30000);
  const check = recipe.successCheck || {};
  const deadline = Date.now() + timeout;
  const poll = () => {
    let ok = false;
    if (check.type === 'selector_present') ok = Boolean(document.querySelector(check.value));
    else if (check.type === 'url_prefix') ok = location.href.startsWith(check.value || '');
    if (ok) return chrome.runtime.sendMessage({type: 'login_result', requestId: message.requestId, ok: true, reason: 'success_check_passed', url: location.href});
    if (Date.now() >= deadline) return chrome.runtime.sendMessage({type: 'login_result', requestId: message.requestId, ok: false, reason: 'timeout', url: location.href});
    setTimeout(poll, 250);
  };
  setTimeout(poll, 250);
});
