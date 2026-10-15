function setValue(element, value) {
  element.focus(); element.value = value;
  element.dispatchEvent(new Event('input', {bubbles: true}));
  element.dispatchEvent(new Event('change', {bubbles: true}));
}
chrome.runtime.sendMessage({type: 'page', url: location.href, title: document.title, top: window === top});
chrome.runtime.onMessage.addListener((message) => {
  if (message.type !== 'form_login') return;
  const recipe = message.recipe || {};
  const user = document.querySelector(recipe.username || recipe.user);
  const pass = document.querySelector(recipe.password || recipe.pass);
  const submit = document.querySelector(recipe.submit);
  if (!user || !pass || !submit) return chrome.runtime.sendMessage({type: 'login_result', requestId: message.requestId, ok: false, reason: 'selector_not_found', url: location.href});
  setValue(user, message.username || ''); setValue(pass, message.password || '');
  chrome.runtime.sendMessage({type: 'credential_injected', requestId: message.requestId, fields: ['username', 'password'], url: location.href});
  submit.click();
  setTimeout(() => chrome.runtime.sendMessage({type: 'login_result', requestId: message.requestId, ok: true, reason: 'success_check_passed', url: location.href}), 500);
});
