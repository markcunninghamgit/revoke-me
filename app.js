'use strict';

// revoke.me — all logic: detection table, provider modules, state machine.
//
// SECURITY-RELEVANT NOTES — DO NOT MODIFY REQUEST SHAPES:
// Every content-type, header, and parameter placement below is dictated by CORS rules.
// - Slack/Google use application/x-www-form-urlencoded bodies with NO custom headers:
//   these are "simple requests", sent and executed by the server even without CORS
//   response headers. Converting them to JSON or adding Authorization headers would
//   trigger a preflight that the server rejects — the revoke would silently never happen.
// - GitHub's revoke endpoint is UNAUTHENTICATED ONLY; authenticated calls return 403.
// - GitLab uses the private_token query parameter to avoid custom-header preflights.
// - Google's revoke endpoint does not support CORS; we use mode:'no-cors' so the request
//   is sent (and executed) even though the response is opaque and unreadable.
//
// The token is held ONLY in the `currentToken` JS variable: no localStorage,
// no sessionStorage, no cookies, no console logging, never in the URL.

const TIMEOUT_MS = 15000;

let currentToken = null;
let preCheckInFlight = false;

const el = (id) => document.getElementById(id);
const tokenInput = el('token-input');
const revealBtn = el('reveal-btn');
const providerSelect = el('provider-select');
const detectNote = el('detect-note');
const statusSection = el('status-section');
const statusBox = el('status-box');
const statusDetail = el('status-detail');
const revokeBtn = el('revoke-btn');
const wipeBtn = el('wipe-btn');

function wipe() {
  currentToken = null;
  tokenInput.value = '';
  tokenInput.type = 'password';
  revealBtn.textContent = 'Show';
  detectNote.textContent = '';
  statusBox.textContent = '';
  statusBox.className = 'status';
  statusDetail.textContent = '';
  statusDetail.hidden = true;
  revokeBtn.hidden = true;
  statusSection.hidden = true;
}

window.addEventListener('beforeunload', wipe);
wipeBtn.addEventListener('click', wipe);

revealBtn.addEventListener('click', () => {
  if (tokenInput.type === 'password') {
    tokenInput.type = 'text';
    revealBtn.textContent = 'Hide';
  } else {
    tokenInput.type = 'password';
    revealBtn.textContent = 'Show';
  }
});

function setStatus(cls, text, detail) {
  statusSection.hidden = false;
  statusBox.className = 'status ' + cls;
  statusBox.textContent = text;
  if (detail) {
    statusDetail.textContent = detail;
    statusDetail.hidden = false;
  } else {
    statusDetail.textContent = '';
    statusDetail.hidden = true;
  }
}

function busy(text) { setStatus('busy', text); }

function reportState(status, detail) {
  setStatus(status, status.replace(/_/g, ' '), detail);
}

function safeErrorText(e) {
  const msg = e && e.message ? e.message : String(e);
  return msg.length > 200 ? msg.slice(0, 200) + '…' : msg;
}

// fetch wrapper: 15s timeout, error classification
// (network error vs HTTP 4xx/5xx vs opaque response — `response.type === 'opaque'`).
// An opaque response means the request WAS sent but cannot be read.
async function request(url, options) {
  const opts = Object.assign({ credentials: 'omit', referrerPolicy: 'no-referrer' }, options);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  opts.signal = controller.signal;
  let response;
  try {
    response = await fetch(url, opts);
  } catch (e) {
    clearTimeout(timer);
    if (e && e.name === 'AbortError') {
      throw { kind: 'network', message: 'request timed out after ' + TIMEOUT_MS / 1000 + 's' };
    }
    throw { kind: 'network', message: 'network error — request may have been blocked or offline' };
  }
  clearTimeout(timer);
  if (response.type === 'opaque') {
    return { opaque: true, status: 0 };
  }
  let body = null;
  try { body = await response.json(); } catch (e) { body = null; }
  return { opaque: false, status: response.status, headers: response.headers, body };
}

function httpDetail(res) {
  const parts = ['HTTP ' + res.status];
  if (res.body && typeof res.body === 'object') {
    try {
      const s = JSON.stringify(res.body);
      parts.push(s.length > 400 ? s.slice(0, 400) + '…' : s);
    } catch (e) { /* ignore */ }
  }
  return parts.join('\n');
}

// ---------------------------------------------------------------------------
// Provider modules. Shared interface:
//   { detect(token) → bool, preCheck(token), revoke(token), postCheck(token) }
// ---------------------------------------------------------------------------

const providers = {

  github: {
    name: 'GitHub',
    // DO NOT add an Authorization header to the revoke call — the credentials/revoke
    // endpoint is unauthenticated ONLY; authenticated calls return 403.
    detect: (t) => /^(ghp_|gho_|ghu_|ghr_|github_pat_)/.test(t),
    async preCheck(token) {
      const res = await request('https://api.github.com/user', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Accept': 'application/vnd.github+json',
        },
      });
      if (res.status === 200) {
        const scopes = res.headers.get('X-OAuth-Scopes'); // exposed to browsers via CORS
        const login = res.body && res.body.login ? res.body.login : '(unknown login)';
        const name = res.body && res.body.name ? res.body.name : '';
        return {
          live: true,
          identity: 'login: ' + login + (name ? ' (' + name + ')' : '') +
            (scopes !== null ? '\nscopes: ' + scopes : ''),
        };
      }
      if (res.status === 401) return { live: false };
      if (res.status === 403) {
        // 403: token likely fine but request blocked / rate-limited — surface it.
        throw {
          kind: 'http',
          message: 'GitHub returned 403 — the token may be fine but the request was blocked or rate-limited.',
          detail: httpDetail(res),
        };
      }
      throw { kind: 'http', message: 'GitHub pre-check failed', detail: httpDetail(res) };
    },
    async revoke(token) {
      const res = await request('https://api.github.com/credentials/revoke', {
        method: 'POST',
        headers: {
          'Accept': 'application/vnd.github+json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ credentials: [token] }),
      });
      if (res.status === 202) return { sent: true };
      if (res.status === 422 || res.status === 429) {
        // 60 unauthenticated requests/hour per IP.
        throw {
          kind: 'http',
          message: 'GitHub revoke rate limit (60 unauthenticated requests/hour per IP) or malformed credentials — HTTP ' + res.status + '.',
          detail: httpDetail(res),
        };
      }
      throw { kind: 'http', message: 'GitHub revoke failed with HTTP ' + res.status, detail: httpDetail(res) };
    },
    async postCheck(token) {
      // Repeat the pre-check GET /user; 401 confirms revoked.
      try {
        const res = await request('https://api.github.com/user', {
          method: 'GET',
          headers: {
            'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.github+json',
          },
        });
        return res.status === 401 ? 'CONFIRMED_REVOKED' : 'SENT_UNVERIFIED';
      } catch (e) {
        return 'SENT_UNVERIFIED';
      }
    },
  },

  slack: {
    name: 'Slack',
    // NEVER use an Authorization header (Slack's CORS preflight rejects it) and NEVER a
    // JSON body (these methods reject JSON). Token goes in the form body.
    detect: (t) => /^(xoxb-|xoxp-|xoxa-|xoxr-|xoxs-|xapps-)/.test(t),
    async preCheck(token) {
      const res = await request('https://slack.com/api/auth.test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'token=' + encodeURIComponent(token),
      });
      if (res.opaque) return { live: null };
      if (res.body && res.body.ok === true) {
        return {
          live: true,
          identity: 'team: ' + (res.body.team || '(unknown team)') +
            '\nuser: ' + (res.body.user || '(unknown user)'),
        };
      }
      if (res.body && res.body.ok === false &&
          (res.body.error === 'invalid_auth' || res.body.error === 'token_revoked')) {
        return { live: false };
      }
      throw {
        kind: 'http',
        message: 'Slack pre-check failed' + (res.body && res.body.error ? ': ' + res.body.error : ''),
        detail: httpDetail(res),
      };
    },
    async revoke(token) {
      let res;
      try {
        res = await request('https://slack.com/api/auth.revoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'token=' + encodeURIComponent(token),
        });
      } catch (e) {
        // Simple request: even on an unreadable response the revoke was sent.
        if (e && e.kind === 'network' && e.message.indexOf('timed out') === -1) {
          return { sent: true, unverified: true };
        }
        throw e;
      }
      if (res.opaque) return { sent: true, unverified: true };
      if (res.body && res.body.ok === true && res.body.revoked === true) return { sent: true };
      if (res.body && res.body.ok === true && res.body.revoked === false) {
        throw { kind: 'http', message: 'Slack reports the token was already revoked (revoked:false).', detail: httpDetail(res) };
      }
      throw {
        kind: 'http',
        message: 'Slack revoke failed' + (res.body && res.body.error ? ': ' + res.body.error : ''),
        detail: httpDetail(res),
      };
    },
    async postCheck(token) {
      const res = await request('https://slack.com/api/auth.test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'token=' + encodeURIComponent(token),
      });
      if (res.body && res.body.ok === false &&
          (res.body.error === 'invalid_auth' || res.body.error === 'token_revoked')) {
        return 'CONFIRMED_REVOKED';
      }
      return 'SENT_UNVERIFIED';
    },
  },

  gitlab: {
    name: 'GitLab',
    // gitlab.com only in v1; self-hosted instances are out of scope.
    // The token goes in the private_token QUERY PARAMETER (avoids custom-header preflight).
    detect: (t) => /^glpat-/.test(t),
    async preCheck(token) {
      const res = await request(
        'https://gitlab.com/api/v4/personal_access_tokens/self?private_token=' + encodeURIComponent(token),
        { method: 'GET' });
      if (res.status === 200) {
        const scopes = res.body && Array.isArray(res.body.scopes) ? res.body.scopes.join(', ') : '(unknown)';
        const expiry = res.body && res.body.expires_at ? res.body.expires_at : '(none)';
        return {
          live: true,
          identity: 'name: ' + (res.body && res.body.name ? res.body.name : '(unknown)') +
            '\nscopes: ' + scopes + '\nexpires: ' + expiry,
        };
      }
      if (res.status === 401) return { live: false };
      throw { kind: 'http', message: 'GitLab pre-check failed', detail: httpDetail(res) };
    },
    async revoke(token) {
      let res;
      try {
        // DELETE always triggers a CORS preflight; GitLab permits it in production.
        res = await request(
          'https://gitlab.com/api/v4/personal_access_tokens/self?private_token=' + encodeURIComponent(token),
          { method: 'DELETE' });
      } catch (e) {
        if (e && e.kind === 'network') {
          throw {
            kind: 'preflight',
            message: 'Browser blocked the GitLab revoke — try the GitLab UI: User Settings → Access Tokens.',
          };
        }
        throw e;
      }
      if (res.status === 204) return { sent: true };
      throw { kind: 'http', message: 'GitLab revoke failed with HTTP ' + res.status, detail: httpDetail(res) };
    },
    async postCheck(token) {
      try {
        const res = await request(
          'https://gitlab.com/api/v4/personal_access_tokens/self?private_token=' + encodeURIComponent(token),
          { method: 'GET' });
        return res.status === 401 ? 'CONFIRMED_REVOKED' : 'SENT_UNVERIFIED';
      } catch (e) {
        return 'SENT_UNVERIFIED';
      }
    },
  },

  dropbox: {
    name: 'Dropbox',
    // Dropbox OAuth tokens are not reliably pattern-matchable: auto-detect is best
    // effort only; rely on the manual dropdown.
    detect: () => false,
    async preCheck(token) {
      const res = await request('https://api.dropboxapi.com/2/users/get_current_account', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token },
      });
      if (res.status === 200 && res.body) {
        const name = res.body.name && res.body.name.display_name ? res.body.name.display_name : '(unknown)';
        const email = res.body.email || '(unknown email)';
        return { live: true, identity: 'account: ' + name + '\nemail: ' + email };
      }
      if (res.status === 401) return { live: false };
      throw { kind: 'http', message: 'Dropbox pre-check failed', detail: httpDetail(res) };
    },
    async revoke(token) {
      const res = await request('https://api.dropboxapi.com/2/auth/token/revoke', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token },
      });
      if (res.status === 200) return { sent: true };
      throw { kind: 'http', message: 'Dropbox revoke failed with HTTP ' + res.status, detail: httpDetail(res) };
    },
    async postCheck(token) {
      try {
        const res = await request('https://api.dropboxapi.com/2/users/get_current_account', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + token },
        });
        return res.status === 401 ? 'CONFIRMED_REVOKED' : 'SENT_UNVERIFIED';
      } catch (e) {
        return 'SENT_UNVERIFIED';
      }
    },
  },

  google: {
    name: 'Google',
    // Heuristics only (refresh tokens typically start 1//; older access tokens ya29.).
    // Prefer manual dropdown selection.
    detect: (t) => /^1\/\//.test(t) || /^ya29\./.test(t),
    async preCheck(token) {
      // Access tokens can be inspected via tokeninfo; refresh tokens cannot.
      if (/^ya29\./.test(token)) {
        const res = await request(
          'https://oauth2.googleapis.com/tokeninfo?access_token=' + encodeURIComponent(token),
          { method: 'GET' });
        if (res.status === 200 && res.body) {
          return {
            live: true,
            identity: 'scope: ' + (res.body.scope || '(unknown)') +
              '\nexpires_in: ' + (res.body.expires_in || '(unknown)'),
          };
        }
        if (res.status === 400 || res.status === 401) return { live: false };
        throw { kind: 'http', message: 'Google pre-check failed', detail: httpDetail(res) };
      }
      return { live: null };
    },
    async revoke(token) {
      // The token MUST go in the FORM BODY, not the query string. This endpoint does
      // NOT support CORS — sent via mode:'no-cors', the response is always opaque.
      const res = await request('https://oauth2.googleapis.com/revoke', {
        method: 'POST',
        mode: 'no-cors',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'token=' + encodeURIComponent(token),
      });
      if (res.opaque) return { sent: true, unverified: true };
      if (res.status === 200) return { sent: true, confirmed: true };
      if (res.status === 400) {
        throw {
          kind: 'http',
          message: 'Google returned 400 — the token is likely already invalid or malformed.',
          detail: httpDetail(res),
        };
      }
      throw { kind: 'http', message: 'Google revoke failed with HTTP ' + res.status, detail: httpDetail(res) };
    },
    async postCheck(token) {
      // Access tokens only. Refresh tokens cannot be verified from a browser.
      if (/^ya29\./.test(token)) {
        try {
          const res = await request(
            'https://oauth2.googleapis.com/tokeninfo?access_token=' + encodeURIComponent(token),
            { method: 'GET' });
          if (res.status === 400 || res.status === 401) return 'CONFIRMED_REVOKED';
          return 'SENT_UNVERIFIED';
        } catch (e) {
          return 'SENT_UNVERIFIED';
        }
      }
      return 'SENT_UNVERIFIED';
    },
    // Honest messaging for refresh tokens (cannot be verified from a browser):
    refreshTokenMessage:
      'Revocation request sent — Google does not allow browsers to confirm this. ' +
      'If revocation failed, revoke via https://myaccount.google.com/permissions.',
  },
};

// ---------------------------------------------------------------------------
// Detection + UI state machine
// ---------------------------------------------------------------------------

function detectProvider(token) {
  for (const id of Object.keys(providers)) {
    if (providers[id].detect(token)) return id;
  }
  return null;
}

tokenInput.addEventListener('input', () => {
  currentToken = tokenInput.value;
  statusSection.hidden = true;
  revokeBtn.hidden = true;
  const manual = providerSelect.value;
  const detected = detectProvider(tokenInput.value);
  if (manual !== 'auto') {
    detectNote.textContent = 'Provider set manually: ' + providers[manual].name;
  } else if (detected) {
    detectNote.textContent = 'Detected provider: ' + providers[detected].name;
  } else if (tokenInput.value.length > 0) {
    detectNote.textContent =
      'Could not auto-detect — pick a provider manually (Dropbox tokens are not pattern-matchable).';
  } else {
    detectNote.textContent = '';
  }
});

providerSelect.addEventListener('change', () => {
  tokenInput.dispatchEvent(new Event('input'));
  runFlow();
});

function chosenProvider() {
  if (providerSelect.value !== 'auto') return providerSelect.value;
  return detectProvider(tokenInput.value);
}

function reportError(p, e) {
  if (e && e.kind === 'preflight') {
    reportState('FAILED', p.name + ': ' + e.message);
    return;
  }
  if (e && e.kind === 'network') {
    reportState('FAILED', p.name + ': ' + e.message);
    return;
  }
  reportState('FAILED',
    (p ? p.name + ': ' : '') + (e && e.message ? e.message : safeErrorText(e)),
    e && e.detail ? e.detail : undefined);
}

async function runFlow() {
  if (preCheckInFlight) return;
  const token = tokenInput.value.trim();
  if (!token) return;
  currentToken = token;

  const providerId = chosenProvider();
  if (!providerId) {
    setStatus('FAILED', 'Unknown provider — pick one manually from the dropdown.');
    return;
  }
  const p = providers[providerId];

  try {
    preCheckInFlight = true;
    busy(p.name + ': pre-check…');
    const pre = await p.preCheck(token);
    preCheckInFlight = false;

    if (pre.live === false) {
      // Already dead — stop; no revoke call is sent.
      reportState('ALREADY_DEAD', p.name + ': token is already invalid — nothing to do.');
      return;
    }

    if (pre.live === null) {
      setStatus('busy', p.name + ' — confirm revocation',
        'No pre-check available for this token type; the token cannot be inspected before revocation.');
    } else {
      setStatus('busy', p.name + ' — confirm revocation',
        'This token belongs to:\n' + pre.identity);
    }
    revokeBtn.hidden = false;
    revokeBtn.disabled = false;
    revokeBtn.onclick = async () => {
      revokeBtn.disabled = true;
      revokeBtn.hidden = true;
      try {
        busy(p.name + ': revoking…');
        const rev = await p.revoke(token);
        if (rev.unverified) {
          reportState('SENT_UNVERIFIED',
            p.name + ': revoke request was sent, but the response is opaque (browser cannot read it).');
          return;
        }
        if (rev.confirmed) {
          reportState('CONFIRMED_REVOKED',
            p.name + ': revoke endpoint returned 200 — token revoked.');
          return;
        }
        busy(p.name + ': post-check…');
        let result = await p.postCheck(token);
        if (result !== 'CONFIRMED_REVOKED' && pre.live === true) {
          // Propagation delay: wait 1 second and retry once before reporting failure.
          await new Promise((r) => setTimeout(r, 1000));
          result = await p.postCheck(token);
        }
        if (result === 'CONFIRMED_REVOKED') {
          reportState('CONFIRMED_REVOKED',
            p.name + ': token was live before and is dead after revoke — confirmed revoked.');
        } else if (providerId === 'google' && /^1\/\//.test(token) && p.refreshTokenMessage) {
          reportState('SENT_UNVERIFIED', p.refreshTokenMessage);
        } else {
          reportState('SENT_UNVERIFIED',
            p.name + ': revoke was accepted, but the post-check could not confirm (opaque response or propagation delay).');
        }
      } catch (e) {
        reportError(p, e);
      }
    };
  } catch (e) {
    preCheckInFlight = false;
    reportError(p, e);
  }
}

tokenInput.addEventListener('paste', () => { setTimeout(runFlow, 0); });
tokenInput.addEventListener('change', runFlow);

// ---------------------------------------------------------------------------
// CLI command section: shell tabs (bash/zsh vs PowerShell) + copy buttons.
// The commands are static text; nothing here reads or stores a token.
// ---------------------------------------------------------------------------

document.querySelectorAll('.cli-block').forEach((block) => {
  const tabs = block.querySelectorAll('.cli-tab');
  const panes = block.querySelectorAll('.cli-pane');
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((t) => t.classList.toggle('active', t === tab));
      panes.forEach((p) => { p.hidden = p.dataset.shell !== tab.dataset.shell; });
    });
  });
  block.querySelector('.copy-btn').addEventListener('click', (ev) => {
    const visible = Array.from(panes).find((p) => !p.hidden);
    const text = visible.querySelector('code').textContent;
    const btn = ev.currentTarget;
    const done = () => { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = 'Copy'; }, 1500); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(() => { fallbackCopy(text); done(); });
    } else {
      fallbackCopy(text);
      done();
    }
  });
});

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch (e) { /* best effort */ }
  document.body.removeChild(ta);
}
