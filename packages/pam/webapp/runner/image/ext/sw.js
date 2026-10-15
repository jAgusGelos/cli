let port;
const send = (message) => { try { if (port) port.postMessage(message); } catch (_) {} };
function connect() {
  port = chrome.runtime.connectNative('com.infisical.rbi');
  port.onMessage.addListener((m) => {
    if (m.type === 'ping') return send({type: 'pong', requestId: m.requestId});
    if (m.type === 'form_login') {
      chrome.tabs.query({active: true, lastFocusedWindow: true}).then((tabs) => {
        const tab = tabs[0];
        if (tab) chrome.tabs.sendMessage(tab.id, m).catch(() => send({type: 'login_result', requestId: m.requestId, ok: false, reason: 'selector_not_found', url: tab.url || ''}));
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
connect();
