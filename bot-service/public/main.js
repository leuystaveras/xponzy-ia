const selectors = {
  tokenInput: document.getElementById('token'),
  saveToken: document.getElementById('saveToken'),
  authStatus: document.getElementById('authStatus'),
  panels: {
    status: document.getElementById('statusPanel'),
    analytics: document.getElementById('analyticsPanel'),
    aiMetrics: document.getElementById('aiMetricsPanel'),
    logs: document.getElementById('logsPanel')
  },
  configFields: {
    whitelist: document.getElementById('cfgWhitelist'),
    regexRules: document.getElementById('cfgRegexRules'),
    groupRulesText: document.getElementById('cfgGroupRulesText'),
    thresholds: document.getElementById('cfgThresholds'),
    adminRoles: document.getElementById('cfgAdminRoles'),
    groupContexts: document.getElementById('cfgGroupContexts')
  },
  configStatus: document.getElementById('configStatus'),
  feedback: {
    messageId: document.getElementById('feedbackMessageId'),
    verdict: document.getElementById('feedbackVerdict'),
    status: document.getElementById('feedbackStatus')
  },
  ban: {
    groupId: document.getElementById('banGroupId'),
    number: document.getElementById('banNumber'),
    status: document.getElementById('banStatus')
  }
};

const tokenStorageKey = 'bot-dashboard-token';

function getToken() {
  return localStorage.getItem(tokenStorageKey) || '';
}

function setToken(value) {
  localStorage.setItem(tokenStorageKey, value);
}

function updateAuthStatus(message, ok = true) {
  selectors.authStatus.textContent = message;
  selectors.authStatus.className = ok ? 'status ok' : 'status error';
}

function parseArrayField(rawValue, trimItems = false) {
  const value = (rawValue || '').trim();
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) {
      return trimItems ? parsed.map((item) => (typeof item === 'string' ? item.trim() : item)) : parsed;
    }
  } catch (error) {
    // Fallback to manual parsing below
  }
  return value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function parseObjectField(rawValue, fallback = {}) {
  const value = (rawValue || '').trim();
  if (!value) return { ...fallback };
  try {
    const parsed = JSON.parse(value);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed;
    }
  } catch (error) {
    // Fallback to key=value parsing below
  }
  const lines = value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const output = { ...fallback };
  for (const line of lines) {
    const [key, raw] = line.split('=');
    if (!key || raw === undefined) continue;
    const trimmedKey = key.trim();
    const trimmedValue = raw.trim();
    if (!trimmedKey) continue;
    const numeric = Number(trimmedValue);
    output[trimmedKey] = Number.isNaN(numeric) ? trimmedValue : numeric;
  }
  return output;
}

async function callApi(path, options = {}) {
  const token = getToken();
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${token}`);
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    throw new Error('Unauthorized: check BOT_INTERNAL_TOKEN');
  }
  return res;
}

function bindButton(action, handler) {
  document.querySelectorAll(`button[data-action="${action}"]`).forEach((button) => {
    button.addEventListener('click', handler);
  });
}

async function loadStatus() {
  try {
    const res = await callApi('/status');
    const data = await res.json();
    selectors.panels.status.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    selectors.panels.status.textContent = `Error: ${error.message}`;
  }
}

async function loadAnalytics() {
  try {
    const res = await callApi('/analytics');
    const data = await res.json();
    selectors.panels.analytics.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    selectors.panels.analytics.textContent = `Error: ${error.message}`;
  }
}

async function loadAIMetrics() {
  try {
    const res = await callApi('/ai/metrics');
    const data = await res.json();
    selectors.panels.aiMetrics.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    selectors.panels.aiMetrics.textContent = `Error: ${error.message}`;
  }
}

async function loadLogs() {
  try {
    const res = await callApi('/logs/recent?limit=120');
    const data = await res.json();
    selectors.panels.logs.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    selectors.panels.logs.textContent = `Error: ${error.message}`;
  }
}

async function loadConfig() {
  try {
    const res = await callApi('/config');
    const data = await res.json();
    const cfg = data.config || {};
    selectors.configFields.whitelist.value = JSON.stringify(cfg.whitelist || [], null, 2);
    selectors.configFields.regexRules.value = JSON.stringify(cfg.regexRules || [], null, 2);
    selectors.configFields.groupRulesText.value = cfg.groupRulesText || '';
    selectors.configFields.thresholds.value = JSON.stringify(cfg.thresholds || {}, null, 2);
    selectors.configFields.adminRoles.value = JSON.stringify(cfg.adminRoles || {}, null, 2);
    selectors.configFields.groupContexts.value = JSON.stringify(cfg.groupContexts || {}, null, 2);
    selectors.configStatus.textContent = 'Configuration loaded';
    selectors.configStatus.className = 'status ok';
  } catch (error) {
    selectors.configStatus.textContent = error.message;
    selectors.configStatus.className = 'status error';
  }
}

async function saveConfig() {
  try {
    const payload = {
      whitelist: parseArrayField(selectors.configFields.whitelist.value, true),
      regexRules: parseArrayField(selectors.configFields.regexRules.value, true),
      groupRulesText: selectors.configFields.groupRulesText.value,
      thresholds: parseObjectField(selectors.configFields.thresholds.value),
      adminRoles: parseObjectField(selectors.configFields.adminRoles.value),
      groupContexts: parseObjectField(selectors.configFields.groupContexts.value)
    };

    const res = await callApi('/config/update', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    selectors.configStatus.textContent = res.ok ? 'Configuration saved' : JSON.stringify(data);
    selectors.configStatus.className = res.ok ? 'status ok' : 'status error';
  } catch (error) {
    selectors.configStatus.textContent = error.message;
    selectors.configStatus.className = 'status error';
  }
}

async function sendFeedback() {
  const messageId = selectors.feedback.messageId.value.trim();
  const verdict = selectors.feedback.verdict.value;
  if (!messageId || !verdict) {
    selectors.feedback.status.textContent = 'Provide messageId and verdict.';
    selectors.feedback.status.className = 'status error';
    return;
  }

  try {
    const res = await callApi('/ai/feedback', {
      method: 'POST',
      body: JSON.stringify({ messageId, verdict })
    });
    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || res.statusText);
    }
    selectors.feedback.status.textContent = 'Feedback sent!';
    selectors.feedback.status.className = 'status ok';
  } catch (error) {
    selectors.feedback.status.textContent = error.message;
    selectors.feedback.status.className = 'status error';
  }
}

async function banNumber() {
  const groupId = selectors.ban.groupId.value.trim();
  const number = selectors.ban.number.value.trim();
  if (!groupId || !number) {
    selectors.ban.status.textContent = 'Group ID and number are required.';
    selectors.ban.status.className = 'status error';
    return;
  }
  try {
    const res = await callApi('/ban', {
      method: 'POST',
      body: JSON.stringify({ groupId, number })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Ban failed');
    }
    selectors.ban.status.textContent = 'Ban request sent';
    selectors.ban.status.className = 'status ok';
  } catch (error) {
    selectors.ban.status.textContent = error.message;
    selectors.ban.status.className = 'status error';
  }
}

function initToken() {
  selectors.tokenInput.value = getToken();
  selectors.saveToken.addEventListener('click', () => {
    setToken(selectors.tokenInput.value.trim());
    updateAuthStatus('Token saved', true);
  });
}

function initActions() {
  bindButton('status', loadStatus);
  bindButton('analytics', loadAnalytics);
  bindButton('aiMetrics', loadAIMetrics);
  bindButton('logs', loadLogs);
  bindButton('loadConfig', loadConfig);
  bindButton('saveConfig', saveConfig);
  bindButton('feedback', sendFeedback);
  bindButton('ban', banNumber);
}

function autoRefresh() {
  loadStatus();
  loadAnalytics();
  loadAIMetrics();
  loadLogs();
}

initToken();
initActions();
updateAuthStatus('Token stored locally', true);
autoRefresh();

// Espanol: El dashboard usa fetch con el token almacenado en el navegador. Manten el token seguro.
