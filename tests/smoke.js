// Load-time smoke test: runs app.js against DOM/fetch stubs to catch
// startup errors without a browser. Exits non-zero on failure.
const els = {};
const mkEl = () => ({
  value: '', type: 'password', textContent: '', className: '', hidden: true,
  disabled: false, addEventListener() {}, dispatchEvent() {}, onclick: null,
});
['token-input', 'reveal-btn', 'provider-select', 'detect-note', 'status-section',
 'status-box', 'status-detail', 'revoke-btn', 'wipe-btn']
  .forEach((id) => { els[id] = mkEl(); });
global.document = {
  getElementById: (id) => els[id] || mkEl(),
  addEventListener() {},
};
global.window = { addEventListener() {} };
global.fetch = () => Promise.resolve({ type: 'opaque', status: 0 });

try {
  require('../app.js');
  console.log('smoke: app.js loads cleanly');
} catch (e) {
  console.error('smoke: FAILED —', e && e.message ? e.message : e);
  process.exit(1);
}
