let port;
const pending = new Map();
const send = (message) => { try { if (port) port.postMessage(message); } catch (_) {} };
function connect() {
  port = chrome.runtime.connectNative('com.infisical.rbi');
  port.onMessage.addListener((m) => {
    if (m.type === 'ping') return send({type: 'pong', requestId: m.requestId});
    if (m.type === 'form_login') {
      chrome.tabs.query({active: true, lastFocusedWindow: true}).then((tabs) => {
        const tab = tabs[0];
        if (tab) {
          pending.set(tab.id, {requestId: m.requestId, check: m.recipe && m.recipe.successCheck, deadline: Date.now() + Number(m.timeoutMs || 15000)});
          chrome.tabs.sendMessage(tab.id, m).catch(() => send({type: 'login_result', requestId: m.requestId, ok: false, reason: 'selector_not_found', url: tab.url || ''}));
          setTimeout(() => { const p = pending.get(tab.id); if (p && p.requestId === m.requestId) { pending.delete(tab.id); send({type: 'login_result', requestId: m.requestId, ok: false, reason: 'timeout', url: tab.url || ''}); } }, Number(m.timeoutMs || 15000));
        }
      });
    }
  });
  port.onDisconnect.addListener(() => { port = null; setTimeout(connect, 1000); });
  send({type: 'ext_hello', extVersion: chrome.runtime.getManifest().version, extensionId: chrome.runtime.id});
}
chrome.runtime.onMessage.addListener((m, sender) => send({...m, frameUrl: sender.url || '', tabId: sender.tab && sender.tab.id, frameId: sender.frameId}));
chrome.downloads.onChanged.addListener(async (change) => {
  if (change.state && change.state.current === 'complete') {
    const rows = await chrome.downloads.search({id: change.id});
    const item = rows[0];
    if (item) send({type: 'download-complete', filename: item.filename, url: item.url, bytes: item.fileSize || 0, mime: item.mime || ''});
  }
});
chrome.windows.onCreated.addListener(async (window) => {
  const all = await chrome.windows.getAll();
  if (all.length > 1) { await chrome.windows.remove(window.id); send({type: 'guard_closed', target: 'window', windowId: window.id, url: ''}); }
});
chrome.tabs.onCreated.addListener(async (tab) => {
  const tabs = await chrome.tabs.query({windowId: tab.windowId});
  if (tabs.length > 1) { await chrome.tabs.remove(tab.id); send({type: 'guard_closed', target: 'tab', tabId: tab.id, url: ''}); }
});
chrome.webNavigation.onErrorOccurred.addListener((d) => send({type: 'nav_blocked', url: d.url, error: d.error, tabId: d.tabId, frameId: d.frameId}));
chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  const p = pending.get(tabId);
  if (!p || change.status !== 'complete') return;
  if (p.check && p.check.type === 'url_prefix' && tab.url.startsWith(p.check.value || '')) {
    pending.delete(tabId); send({type: 'login_result', requestId: p.requestId, ok: true, reason: 'success_check_passed', url: tab.url});
  } else chrome.tabs.sendMessage(tabId, {type: 'login_check', requestId: p.requestId, successCheck: p.check}).catch(() => {});
});
connect();
