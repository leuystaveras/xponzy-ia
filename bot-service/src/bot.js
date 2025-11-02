import 'dotenv/config';
import express from 'express';
import qrcode from 'qrcode-terminal';
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import whatsapp from 'whatsapp-web.js';
import translate from '@vitalets/google-translate-api';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../');
const storageDir = path.join(repoRoot, 'storage');
const logsDir = path.join(repoRoot, 'logs');
const publicDir = path.join(__dirname, '../public');

const configFile = path.join(storageDir, 'config.json');
const moderationLogFile = path.join(storageDir, 'moderation.log.jsonl');
const botLogFile = path.join(logsDir, 'bot-service.log');
const warningsFile = path.join(storageDir, 'warnings.json');

const DEFAULT_WARNING_POLICY = {
  maxWarnings: 5,
  cooldownHours: 24
};

const defaultConfig = {
  whitelist: ['1234567890'],
  regexRules: [
    '\\bforex signals?\\b',
    'free stock group',
    'grow your portfolio',
    'passive income guaranteed'
  ],
  groupRulesText:
    'Group rules:\n- Be respectful. No harassment or hate speech.\n- No sexual content.\n- No spam, no trading groups.\n- Keep it on-topic.',
  thresholds: {
    spamThreshold: 0.75,
    harassmentThreshold: 0.75,
    autoKickForSpam: true,
    autoKickForHarassment: false,
    inviteLinkBlocking: true
  },
  warningPolicy: {
    maxWarnings: DEFAULT_WARNING_POLICY.maxWarnings,
    cooldownHours: DEFAULT_WARNING_POLICY.cooldownHours
  },
  adminRoles: {
    '1234567890': 'superadmin'
  },
  groupContexts: {
    default: {
      domain: 'general',
      severityModifier: 1.0
    }
  }
};

const INVITE_KEYWORDS = [
  'chat.whatsapp.com',
  'whatsapp.com/invite',
  'wa.me/join',
  't.me/',
  'discord.gg/',
  'discord.com/invite'
];

const PORT = parseInt(process.env.PORT || '3562', 10);
const SESSION_ID = process.env.SESSION_ID || 'moderator-bot';
const LOG_LEVEL = (process.env.LOG_LEVEL || 'info').toLowerCase();
const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'http://127.0.0.1:8080';
const AI_SERVICE_TOKEN = process.env.AI_SERVICE_TOKEN || 'changeme-ai-token';
const BOT_INTERNAL_TOKEN = process.env.BOT_INTERNAL_TOKEN || 'changeme-internal-token';
const WWJS_WEB_VERSION = process.env.WWJS_WEB_VERSION || '2.2413.51';
const TRANSLATE_ENABLED = (process.env.TRANSLATE_ENABLED || 'false').toLowerCase() === 'true';
const TRANSLATE_TARGET_LANG = process.env.TRANSLATE_TARGET_LANG || 'en';
const OBS_WEBHOOK_URL = (process.env.OBS_WEBHOOK_URL || '').trim();
const OBS_WEBHOOK_TOKEN = process.env.OBS_WEBHOOK_TOKEN || '';
const OBS_WEBHOOK_TIMEOUT_MS = Number.parseInt(process.env.OBS_WEBHOOK_TIMEOUT_MS || '2000', 10);

const EMOJI = Object.freeze({
  statusOnline: '\u{1F7E2}',
  check: '\u2705',
  noEntry: '\u{1F6AB}',
  warning: '\u26A0',
  shield: '\u{1F6E1}',
  info: '\u2139',
  magnifier: '\u{1F50D}'
});
const RULES_REMINDER_TEXT =
  'Rules reminder: Be respectful. No harassment, hate speech, or discrimination.';
const BOT_VERSION = '1.1.0';

let isReady = false;
let compiledRegex = [];
let config = { ...defaultConfig };
let harassmentWarningsState = { groups: {} };

function ensureBootstrap() {
  [storageDir, logsDir].forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });

  if (!fs.existsSync(botLogFile)) {
    fs.writeFileSync(botLogFile, '', 'utf8');
  }

  if (!fs.existsSync(moderationLogFile)) {
    fs.writeFileSync(moderationLogFile, '', 'utf8');
  }

  if (!fs.existsSync(configFile)) {
    fs.writeFileSync(configFile, JSON.stringify(defaultConfig, null, 2), 'utf8');
  }

  if (!fs.existsSync(warningsFile)) {
    fs.writeFileSync(warningsFile, JSON.stringify({ groups: {} }, null, 2), 'utf8');
  }
}

ensureBootstrap();
loadWarningsState();

function writeBotLog(level, message) {
  if (!message) return;
  const levels = ['error', 'warn', 'info', 'debug'];
  const levelIdx = levels.indexOf(level);
  const currentIdx = levels.indexOf(LOG_LEVEL);
  if (levelIdx === -1 || (currentIdx !== -1 && levelIdx > currentIdx)) return;
  const line = `[${new Date().toISOString()}] [${level.toUpperCase()}] ${message}`;
  try {
    fs.appendFileSync(botLogFile, `${line}\n`, 'utf8');
  } catch {
    // Swallow disk errors to keep bot alive
  }
}

function readJSONFile(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    writeBotLog('error', `Failed to read ${file}: ${error.message}`);
    return fallback;
  }
}

function persistWarningState() {
  try {
    fs.writeFileSync(warningsFile, JSON.stringify(harassmentWarningsState, null, 2), 'utf8');
  } catch (error) {
    writeBotLog('error', `Failed to persist warning counters: ${error.message}`);
  }
}

function loadWarningsState() {
  try {
    const raw = fs.readFileSync(warningsFile, 'utf8');
    const parsed = JSON.parse(raw);
    const hydrated = { groups: {} };
    if (parsed && typeof parsed === 'object' && typeof parsed.groups === 'object') {
      for (const [groupId, groupEntries] of Object.entries(parsed.groups)) {
        if (!groupEntries || typeof groupEntries !== 'object') {
          continue;
        }
        const normalizedEntries = {};
        for (const [userKey, entryValue] of Object.entries(groupEntries)) {
          const normalized = normalizeWarningEntry(entryValue);
          if (normalized.count > 0) {
            normalizedEntries[userKey] = normalized;
          }
        }
        if (Object.keys(normalizedEntries).length > 0) {
          hydrated.groups[groupId] = normalizedEntries;
        }
      }
    }
    harassmentWarningsState = hydrated;
  } catch (error) {
    harassmentWarningsState = { groups: {} };
    persistWarningState();
    writeBotLog('warn', `Failed to load warning counters: ${error.message}`);
  }
}

function normalizeWarningEntry(entryValue) {
  if (entryValue && typeof entryValue === 'object') {
    const count = Number.isFinite(Number(entryValue.count)) ? Math.max(0, Math.round(Number(entryValue.count))) : 0;
    const lastWarningAt = typeof entryValue.lastWarningAt === 'string' ? entryValue.lastWarningAt : null;
    return { count, lastWarningAt };
  }
  if (Number.isFinite(Number(entryValue))) {
    return { count: Math.max(0, Math.round(Number(entryValue))), lastWarningAt: null };
  }
  return { count: 0, lastWarningAt: null };
}

function sanitizeWarningPolicy(policy) {
  const source = policy && typeof policy === 'object' ? policy : {};
  const maxWarningsRaw = Number(source.maxWarnings ?? DEFAULT_WARNING_POLICY.maxWarnings);
  const cooldownRaw = Number(source.cooldownHours ?? DEFAULT_WARNING_POLICY.cooldownHours);
  const maxWarnings = Math.min(Math.max(Number.isFinite(maxWarningsRaw) ? Math.round(maxWarningsRaw) : DEFAULT_WARNING_POLICY.maxWarnings, 1), 10);
  const cooldownHours = Math.min(Math.max(Number.isFinite(cooldownRaw) ? cooldownRaw : DEFAULT_WARNING_POLICY.cooldownHours, 0), 168);
  return { maxWarnings, cooldownHours };
}

function getWarningPolicy() {
  return sanitizeWarningPolicy(config.warningPolicy);
}

function sanitizeThresholds(rawThresholds) {
  const source = rawThresholds && typeof rawThresholds === 'object' ? rawThresholds : {};
  const clamp01 = (value, fallback) => {
    const num = Number(value);
    if (!Number.isFinite(num)) {
      return fallback;
    }
    return Math.min(Math.max(num, 0), 1);
  };
  return {
    spamThreshold: clamp01(source.spamThreshold, defaultConfig.thresholds.spamThreshold),
    harassmentThreshold: clamp01(source.harassmentThreshold, defaultConfig.thresholds.harassmentThreshold),
    autoKickForSpam: source.autoKickForSpam !== undefined ? Boolean(source.autoKickForSpam) : defaultConfig.thresholds.autoKickForSpam,
    autoKickForHarassment: source.autoKickForHarassment !== undefined ? Boolean(source.autoKickForHarassment) : defaultConfig.thresholds.autoKickForHarassment,
    inviteLinkBlocking: source.inviteLinkBlocking !== undefined ? Boolean(source.inviteLinkBlocking) : defaultConfig.thresholds.inviteLinkBlocking
  };
}

function validateConfigPayload(payload) {
  const errors = [];
  if (payload.whitelist !== undefined && !Array.isArray(payload.whitelist)) {
    errors.push('whitelist must be an array of numbers or strings');
  }
  if (Array.isArray(payload.whitelist)) {
    payload.whitelist.forEach((item, index) => {
      if (!normalizeNumber(item)) {
        errors.push(`whitelist[${index}] is not a valid phone number`);
      }
    });
  }

  if (payload.regexRules !== undefined && !Array.isArray(payload.regexRules)) {
    errors.push('regexRules must be an array of strings');
  }
  if (Array.isArray(payload.regexRules)) {
    payload.regexRules.forEach((pattern, index) => {
      if (typeof pattern !== 'string' || !pattern.trim()) {
        errors.push(`regexRules[${index}] must be a non-empty string`);
        return;
      }
      try {
        // eslint-disable-next-line no-new
        new RegExp(pattern);
      } catch (error) {
        errors.push(`regexRules[${index}] is not a valid regular expression: ${error.message}`);
      }
    });
  }

  if (payload.thresholds) {
    const { spamThreshold, harassmentThreshold } = payload.thresholds;
    if (spamThreshold !== undefined) {
      const num = Number(spamThreshold);
      if (!Number.isFinite(num) || num < 0 || num > 1) {
        errors.push('thresholds.spamThreshold must be between 0 and 1');
      }
    }
    if (harassmentThreshold !== undefined) {
      const num = Number(harassmentThreshold);
      if (!Number.isFinite(num) || num < 0 || num > 1) {
        errors.push('thresholds.harassmentThreshold must be between 0 and 1');
      }
    }
  }

  if (payload.warningPolicy) {
    const { maxWarnings, cooldownHours } = payload.warningPolicy;
    if (maxWarnings !== undefined) {
      const num = Number(maxWarnings);
      if (!Number.isFinite(num) || num < 1 || num > 10) {
        errors.push('warningPolicy.maxWarnings must be between 1 and 10');
      }
    }
    if (cooldownHours !== undefined) {
      const num = Number(cooldownHours);
      if (!Number.isFinite(num) || num < 0 || num > 168) {
        errors.push('warningPolicy.cooldownHours must be between 0 and 168');
      }
    }
  }

  if (payload.adminRoles && typeof payload.adminRoles !== 'object') {
    errors.push('adminRoles must be an object mapping numbers to roles');
  }

  if (payload.groupContexts && typeof payload.groupContexts !== 'object') {
    errors.push('groupContexts must be an object');
  }

  return errors;
}

function getWarningBucket(groupId) {
  if (!harassmentWarningsState.groups[groupId]) {
    harassmentWarningsState.groups[groupId] = {};
  }
  return harassmentWarningsState.groups[groupId];
}

function getWarningKey(senderNumber, senderJid) {
  const normalized = normalizeNumber(senderNumber);
  const fallback = (senderJid || '').trim();
  return normalized || fallback || 'unknown';
}

function describeWarnedMember(key) {
  if (!key) {
    return 'unknown';
  }
  if (/^\d+$/.test(key)) {
    return `+${key}`;
  }
  if (key.includes('@')) {
    return key.split('@')[0];
  }
  return key;
}

function getWarningSnapshot(groupId, key) {
  const bucket = harassmentWarningsState.groups[groupId];
  if (!bucket || !bucket[key]) {
    return null;
  }
  const entry = normalizeWarningEntry(bucket[key]);
  return {
    count: entry.count || 0,
    lastWarningAt: entry.lastWarningAt || null
  };
}

function renderWarningsSummary(groupId, limit = 10) {
  const bucket = harassmentWarningsState.groups[groupId];
  const policy = getWarningPolicy();
  if (!bucket || Object.keys(bucket).length === 0) {
    return 'No warnings recorded for this group.';
  }
  const sorted = Object.entries(bucket)
    .map(([key, value]) => {
      const entry = normalizeWarningEntry(value);
      return { key, count: entry.count || 0 };
    })
    .filter((entry) => entry.count > 0)
    .sort((a, b) => b.count - a.count);
  const limited = sorted.slice(0, limit);
  if (limited.length === 0) {
    return 'No warnings recorded for this group.';
  }
  const lines = limited.map((entry, index) => {
    const label = describeWarnedMember(entry.key);
    return `${index + 1}. ${label} - ${entry.count}/${policy.maxWarnings} warnings`;
  });
  const remainder = sorted.length - limited.length;
  if (remainder > 0) {
    lines.push(`...and ${remainder} more member${remainder === 1 ? '' : 's'} tracked.`);
  }
  lines.push('Use /warnings <number or @mention> to view a specific member.');
  lines.push('Use /warnings reset <number|@mention|all> to clear warnings.');
  return lines.join('\n');
}

function resolveWarningTarget(args, message) {
  const mentionedId = Array.isArray(message?.mentionedIds) && message.mentionedIds.length > 0 ? message.mentionedIds[0] : null;
  if (mentionedId) {
    const normalizedMention = normalizeNumber(mentionedId);
    const key = normalizedMention || mentionedId;
    return { key, label: describeWarnedMember(key) };
  }
  const combined = Array.isArray(args) ? args.join(' ').trim() : '';
  if (combined) {
    const withoutPlus = combined.startsWith('@') ? combined.slice(1) : combined;
    const normalized = normalizeNumber(withoutPlus);
    if (normalized) {
      return { key: normalized, label: `+${normalized}` };
    }
    if (combined.includes('@')) {
      const trimmed = combined.split(/\s+/)[0];
      return { key: trimmed, label: describeWarnedMember(trimmed) };
    }
  }
  return null;
}

function registerHarassmentWarning(groupId, senderNumber, senderJid, policyOverride) {
  const policy = policyOverride || getWarningPolicy();
  const bucket = getWarningBucket(groupId);
  const key = getWarningKey(senderNumber, senderJid);
  const now = new Date();
  const currentEntry = normalizeWarningEntry(bucket[key]);

  let count = currentEntry.count || 0;
  if (currentEntry.lastWarningAt && policy.cooldownHours > 0) {
    const last = Date.parse(currentEntry.lastWarningAt);
    if (!Number.isNaN(last)) {
      const hoursSince = (now.getTime() - last) / (1000 * 60 * 60);
      if (hoursSince >= policy.cooldownHours) {
        count = 0;
      }
    }
  }

  if (count < policy.maxWarnings) {
    count += 1;
  }

  const shouldKick = count >= policy.maxWarnings;
  const remaining = Math.max(policy.maxWarnings - count, 0);

  bucket[key] = {
    count,
    lastWarningAt: now.toISOString()
  };

  persistWarningState();
  return { count, remaining, shouldKick, key, groupId, policy };
}

function clearHarassmentWarning(groupId, key) {
  if (!key) {
    return;
  }
  const bucket = harassmentWarningsState.groups[groupId];
  if (bucket && Object.prototype.hasOwnProperty.call(bucket, key)) {
    delete bucket[key];
    if (Object.keys(bucket).length === 0) {
      delete harassmentWarningsState.groups[groupId];
    }
    persistWarningState();
  }
}

function saveConfig(newConfig) {
  config = { ...config, ...newConfig };
  if (!Array.isArray(config.whitelist)) config.whitelist = [];
  if (!Array.isArray(config.regexRules)) config.regexRules = [];
  if (typeof config.groupRulesText !== 'string') config.groupRulesText = defaultConfig.groupRulesText;
  config.thresholds = sanitizeThresholds(config.thresholds);
  config.warningPolicy = sanitizeWarningPolicy(config.warningPolicy);
  config.adminRoles = { ...(config.adminRoles || {}) };
  config.groupContexts = { ...(config.groupContexts || {}) };

  try {
    fs.writeFileSync(configFile, JSON.stringify(config, null, 2), 'utf8');
    compileRegexRules();
    writeBotLog('info', 'Configuration persisted');
  } catch (error) {
    writeBotLog('error', `Failed to persist configuration: ${error.message}`);
  }
}

function loadConfig() {
  const fileConfig = readJSONFile(configFile, defaultConfig);
  config = { ...defaultConfig, ...fileConfig };
  saveConfig(config);
}

function compileRegexRules() {
  compiledRegex = [];
  for (const rule of config.regexRules || []) {
    try {
      compiledRegex.push({ pattern: rule, regex: new RegExp(rule, 'i') });
    } catch (error) {
      writeBotLog('warn', `Invalid regex pattern skipped: ${rule} (${error.message})`);
    }
  }
}

loadConfig();

function normalizeNumber(value) {
  if (!value) return '';
  return `${value}`.replace(/[^0-9]/g, '');
}

function escapeRegexLiteral(value) {
  if (!value) return '';
  return value.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&');
}

function numberToJid(number) {
  const digits = normalizeNumber(number);
  return digits ? `${digits}@c.us` : '';
}

function isWhitelisted(number) {
  const digits = normalizeNumber(number);
  return (config.whitelist || []).includes(digits);
}

function getRole(number) {
  const digits = normalizeNumber(number);
  return (config.adminRoles || {})[digits] || null;
}

function hasPermission(role, action) {
  const matrix = {
    view: ['viewer', 'admin', 'superadmin'],
    whitelist: ['admin', 'superadmin'],
    regex: ['admin', 'superadmin'],
    ban: ['admin', 'superadmin'],
    config: ['superadmin']
  };
  if (!role) return false;
  if (role === 'superadmin') return true;
  const allowed = matrix[action] || [];
  return allowed.includes(role);
}

function containsInviteLink(text) {
  if (!text) return false;
  const lower = `${text}`.toLowerCase();
  return INVITE_KEYWORDS.some((keyword) => lower.includes(keyword));
}

function findRegexMatch(text) {
  if (!text) return null;
  for (const entry of compiledRegex) {
    try {
      if (entry.regex.test(text)) {
        return entry.pattern;
      }
    } catch {
      // ignore evaluation errors, patterns already validated during compilation
    }
  }
  return null;
}

const ACTION_SEVERITY = Object.freeze({
  allow: 0,
  flag_for_review: 1,
  delete_only: 2,
  kick: 3
});

function severityScore(action) {
  return ACTION_SEVERITY[action] ?? 0;
}

function pickDecision(current, candidate) {
  if (!candidate) return current;
  if (!current) return candidate;
  const candidateScore = severityScore(candidate.action);
  const currentScore = severityScore(current.action);
  if (candidateScore > currentScore) {
    return candidate;
  }
  if (candidateScore === currentScore) {
    const candidateConfidence = typeof candidate.confidence === 'number' ? candidate.confidence : 0;
    const currentConfidence = typeof current.confidence === 'number' ? current.confidence : 0;
    if (candidateConfidence >= currentConfidence) {
      return candidate;
    }
  }
  return current;
}

function appendModerationLog(entry) {
  try {
    fs.appendFileSync(moderationLogFile, `${JSON.stringify(entry)}\n`, 'utf8');
  } catch (error) {
    writeBotLog('error', `Failed to append moderation log: ${error.message}`);
  }
}

function readModerationLog(limit = 100) {
  try {
    if (!fs.existsSync(moderationLogFile)) return [];
    const lines = fs
      .readFileSync(moderationLogFile, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean);
    return lines.slice(-limit).map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return { raw: line };
      }
    });
  } catch (error) {
    writeBotLog('error', `Failed to read moderation log: ${error.message}`);
    return [];
  }
}

async function isAdminInGroup(chat, userJid) {
  try {
    const participants = chat?.participants || [];
    return participants.some((participant) => {
      const candidate = participant.id?._serialized;
      return (
        candidate === userJid && (participant.isAdmin || participant.isSuperAdmin)
      );
    });
  } catch (error) {
    writeBotLog('error', `Failed to evaluate admin status: ${error.message}`);
    return false;
  }
}

async function deleteMessageSafe(message) {
  try {
    await message.delete(true);
    return true;
  } catch (error) {
    writeBotLog('warn', `Failed to delete message ${message.id.id} (force): ${error.message}`);
    try {
      await message.delete();
      return true;
    } catch (fallbackError) {
      writeBotLog(
        'warn',
        `Fallback delete failed for message ${message.id.id}: ${fallbackError.message}`
      );
    }
    return false;
  }
}

async function kickParticipantSafe(chat, userJid, senderNumber = '') {
  const candidates = new Set();
  if (userJid) candidates.add(userJid);
  const digits = normalizeNumber(senderNumber);
  if (digits) {
    candidates.add(`${digits}@c.us`);
    candidates.add(`${digits}@s.whatsapp.net`);
  }
  if (candidates.size === 0) {
    writeBotLog('warn', 'No valid target JID available to kick');
    return false;
  }

  for (const target of candidates) {
    try {
      await chat.removeParticipants([target]);
      return true;
    } catch (error) {
      writeBotLog('warn', `chat.removeParticipants failed for ${target}: ${error.message}`);
      if (client) {
        try {
          await client.removeParticipant(chat.id._serialized, target);
          return true;
        } catch (innerError) {
          writeBotLog(
            'warn',
            `client.removeParticipant failed for ${target}: ${innerError.message}`
          );
        }
      }
    }
  }

  return false;
}

function extractJidsFromString(value) {
  if (!value || typeof value !== 'string') {
    return [];
  }
  const matches = value.match(/(\d+@c\.us|\d+@s\.whatsapp\.net)/g);
  return matches ? matches.map((item) => item.trim()) : [];
}

async function resolveMessageAuthor(message) {
  let contact = null;
  try {
    contact = await message.getContact();
  } catch (error) {
    writeBotLog('debug', `Unable to fetch contact for quoted message: ${error.message}`);
  }

  const candidateJids = new Set();
  if (contact?.id?._serialized) {
    candidateJids.add(contact.id._serialized);
  }
  if (message.author && message.author.includes('@')) {
    candidateJids.add(message.author);
  }
  if (message.id?.participant && message.id.participant.includes('@')) {
    candidateJids.add(message.id.participant);
  }
  for (const value of [
    message.id?._serialized,
    message.from,
    message._data?.id?._serialized,
    message._data?.author,
    message._data?.participant
  ]) {
    extractJidsFromString(value).forEach((jid) => candidateJids.add(jid));
  }

  const nonGroupJids = [...candidateJids].filter(
    (jid) => !jid.endsWith('@g.us') && !jid.endsWith('@broadcast')
  );

  const preferredJid = nonGroupJids.find(
    (jid) => jid.endsWith('@c.us') || jid.endsWith('@s.whatsapp.net')
  );

  let senderJid = preferredJid || nonGroupJids[0] || '';
  let senderNumber = normalizeNumber(
    contact?.number ||
      contact?.id?.user ||
      (senderJid ? senderJid.split('@')[0] : '') ||
      (message.author || '').split('@')[0] ||
      (message.id?.participant || '').split('@')[0]
  );

  if (!senderJid && senderNumber) {
    senderJid = numberToJid(senderNumber);
  } else if (!senderNumber && senderJid) {
    senderNumber = normalizeNumber(senderJid.split('@')[0]);
  }

  return {
    contact,
    senderNumber,
    senderJid
  };
}

function withTimeout(promise, ms, errorMessage = 'timeout') {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error(errorMessage)), ms);
    })
  ]);
}

async function translateTextForModeration(text) {
  if (!TRANSLATE_ENABLED) {
    return { processedText: text, translated: false, detectedLanguage: 'unknown', provider: null };
  }
  const trimmed = (text || '').trim();
  if (!trimmed) {
    return { processedText: text, translated: false, detectedLanguage: 'unknown', provider: null };
  }
  try {
    const translation = await translate(trimmed, { to: TRANSLATE_TARGET_LANG });
    const processed = typeof translation?.text === 'string' ? translation.text.trim() : trimmed;
    const detectedLanguage = translation?.from?.language?.iso || 'unknown';
    return {
      processedText: processed || trimmed,
      translated: processed && processed.toLowerCase() !== trimmed.toLowerCase(),
      detectedLanguage,
      provider: 'google-translate-api'
    };
  } catch (error) {
    writeBotLog('warn', `Translation failed: ${error.message}`);
    return { processedText: text, translated: false, detectedLanguage: 'unknown', provider: null };
  }
}

function buildModerationMetadata(translationInfo) {
  if (!translationInfo) {
    return undefined;
  }
  const metadata = {
    language: translationInfo.detectedLanguage,
    translated: translationInfo.translated
  };
  if (translationInfo.provider) {
    metadata.translationProvider = translationInfo.provider;
  }
  return metadata;
}

function forwardModerationEvent(entry) {
  if (!OBS_WEBHOOK_URL) {
    return;
  }
  try {
    const controller = new AbortController();
    const timeoutRef = setTimeout(() => controller.abort(), OBS_WEBHOOK_TIMEOUT_MS);
    const headers = { 'Content-Type': 'application/json' };
    if (OBS_WEBHOOK_TOKEN) {
      headers.Authorization = `Bearer ${OBS_WEBHOOK_TOKEN}`;
    }
    fetch(OBS_WEBHOOK_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify(entry),
      signal: controller.signal
    })
      .catch((error) => {
        writeBotLog('warn', `Webhook forward failed: ${error.message}`);
      })
      .finally(() => clearTimeout(timeoutRef));
  } catch (error) {
    writeBotLog('warn', `Webhook dispatch error: ${error.message}`);
  }
}

async function callAIService(text, context) {
  try {
    const response = await withTimeout(
      fetch(`${AI_SERVICE_URL}/classify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, context })
      }),
      2500
    );
    if (!response.ok) throw new Error(`status ${response.status}`);
    return await response.json();
  } catch (error) {
    writeBotLog('warn', `AI classify failed: ${error.message}`);
    return null;
  }
}

function getGroupContext(chat) {
  const groupId = chat?.id?._serialized;
  const contexts = config.groupContexts || {};
  const context = contexts[groupId] || contexts.default || { domain: 'general', severityModifier: 1 };
  return { groupId, ...context };
}

const LOCAL_FINANCIAL_KEYWORDS = [
  'crypto signals',
  'crypto signal',
  'investment signals',
  'copy trading',
  'trade alerts',
  'vip signals',
  'trading academy',
  'pump group',
  'pump signal',
  'grow your portfolio',
  'passive income',
  'double your income',
  'guaranteed return',
  'stock tips'
];

const LOCAL_FINANCIAL_KEYWORDS_SPANISH = [
  'grupo de senales',
  'senales vip',
  'senales crypto',
  'senales cripto',
  'senales forex',
  'senales binarias',
  'dobla tu dinero',
  'multiplica tu dinero',
  'ganancias garantizadas',
  'ingresos pasivos',
  'dinero facil',
  'retiro diario',
  'alertas de trading',
  'grupo de inversion',
  'canal de inversion',
  'invierte con nosotros'
];

const LOCAL_FINANCIAL_REGEXES = [
  /(grupo|canal|chat).{0,30}(signal|signals|senal|senales|alerta|alertas)/i,
  /(dobla|duplica|multiplica).{0,20}(dinero|ganancia|ingreso|capital)/i,
  /(ganancias?|rendimiento|rentabilidad).{0,20}(garantizado|seguro|asegurado)/i,
  /(crypto|cripto).{0,10}(signal|signals|senal|senales|alerta|alertas)/i,
  /(vip).{0,10}(signal|signals|senal|senales)/i
];

const LOCAL_HARASSMENT_KEYWORDS = [
  'idiot',
  'stupid',
  'moron',
  'loser',
  'trash',
  'bastard',
  'asshole',
  'coward',
  'pervert',
  'imbecil',
  'idiota',
  'estupido',
  'pendejo',
  'payaso',
  'basura',
  'asqueroso',
  'maldito',
  'maricon',
  'zorra',
  'perra',
  'rata'
];

const LOCAL_HATE_SPEECH_KEYWORDS = [
  'nazi',
  'kkk',
  'white power',
  'supremacy',
  'subhuman',
  'negro de mierda',
  'maldito negro',
  'monkey',
  'gorilla',
  'muerto de hambre',
  'india de mierda',
  'sudaca',
  'chink',
  'spic',
  'wetback',
  'beaner'
];

const LOCAL_HARASSMENT_REGEXES = [
  /(vete|vete a|muere|muerete).{0,10}(mierda|infierno|basura)/i,
  /(put(o|a)|pendejo|pendeja|cabron|cabrona)/i,
  /(eres|son).{0,5}(una|un).{0,5}(porqueria|escoria|asqueros[oa])/i
];

const LOCAL_HATE_SPEECH_REGEXES = [
  /(muerte|mueran).{0,10}(negros|judios|gitanos|moros)/i,
  /(odio|odiar).{0,10}(a los|a las).{0,10}(negros|judios|gitanos|moros)/i,
  /(fuera|largate).{0,10}(de aqui).{0,10}(negro|negros|indio|indios)/i
];

function classifyLocally(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) {
    return null;
  }
  const lower = trimmed.toLowerCase();
  const folded = lower.normalize('NFD').replace(/[\u0300-\u036f]/g, '');

  const hateMatch =
    LOCAL_HATE_SPEECH_KEYWORDS.find((keyword) => folded.includes(keyword)) ||
    LOCAL_HATE_SPEECH_REGEXES.find((regex) => regex.test(folded));

  if (hateMatch) {
    const matched = typeof hateMatch === 'string' ? hateMatch : hateMatch.source;
    return {
      label: 'hate_speech',
      action: 'kick',
      reason: `Local hate speech detection matched ${matched}`,
      confidence: 0.92,
      spam_score: 0.2,
      harassment_score: 0.95
    };
  }

  const harassmentMatch =
    LOCAL_HARASSMENT_KEYWORDS.find((keyword) => folded.includes(keyword)) ||
    LOCAL_HARASSMENT_REGEXES.find((regex) => regex.test(folded));

  if (harassmentMatch) {
    const matched = typeof harassmentMatch === 'string' ? harassmentMatch : harassmentMatch.source;
    return {
      label: 'harassment',
      action: 'delete_only',
      reason: `Local harassment detection matched ${matched}`,
      confidence: 0.85,
      spam_score: 0.2,
      harassment_score: 0.85
    };
  }

  let financialMatch =
    LOCAL_FINANCIAL_KEYWORDS.find((keyword) => lower.includes(keyword)) ||
    LOCAL_FINANCIAL_KEYWORDS_SPANISH.find((keyword) => folded.includes(keyword));

  if (!financialMatch) {
    const regexHit = LOCAL_FINANCIAL_REGEXES.find((regex) => regex.test(folded));
    financialMatch = regexHit ? regexHit.source : undefined;
  }

  if (financialMatch) {
    return {
      label: 'spam_financial',
      action: 'kick',
      reason: `Local scam detection matched ${financialMatch}`,
      confidence: 0.88,
      spam_score: 0.9,
      harassment_score: 0.1
    };
  }

  return {
    label: 'allowed',
    action: 'allow',
    reason: 'local heuristic allow',
    confidence: 0.25,
    spam_score: 0.1,
    harassment_score: 0.05
  };
}

async function moderateMessage(message) {
  const chat = await message.getChat();
  if (!chat?.isGroup) {
    return;
  }

  let contact = null;
  try {
    contact = await message.getContact();
  } catch (error) {
    writeBotLog('warn', `Failed to resolve contact: ${error.message}`);
  }

  const senderNumber = normalizeNumber(contact?.number || '');
  const senderJid = contact?.id?._serialized || message.author || message.from;
  const groupId = chat.id?._serialized;

  if (message.fromMe) {
    return;
  }

  if (isWhitelisted(senderNumber)) {
    writeBotLog('debug', `Skipping whitelisted sender ${senderNumber || senderJid}`);
    return;
  }

  const thresholds = config.thresholds || defaultConfig.thresholds;
  const originalBody = (message.body || '').trim();
  const metadata = {};
  const context = getGroupContext(chat);
  if (context) {
    metadata.groupContext = context;
  }

  const record = (entry) => {
    const metadataPayload = Object.keys(metadata).length > 0 ? metadata : undefined;
    recordEvent({
      chat,
      message,
      senderJid,
      senderNumber,
      ...entry,
      metadata: metadataPayload
    });
  };

  if (thresholds?.inviteLinkBlocking && containsInviteLink(originalBody)) {
    const deleteSuccess = await deleteMessageSafe(message);
    const kickSuccess = await kickParticipantSafe(chat, senderJid, senderNumber);
    writeBotLog('info', `Invite link blocked for ${senderNumber || senderJid} in ${groupId}`);
    record({
      action: 'kick',
      reason: 'invite_link_blocked',
      decisionSource: 'invite_link',
      warningSent: false,
      deleteSuccess,
      kickSuccess
    });
    return;
  }

  const initialRegexMatch = findRegexMatch(originalBody);
  if (initialRegexMatch) {
    metadata.regexPattern = initialRegexMatch;
    const deleteSuccess = await deleteMessageSafe(message);
    const kickSuccess = await kickParticipantSafe(chat, senderJid, senderNumber);
    writeBotLog('info', `Regex rule triggered (${initialRegexMatch}) for ${senderNumber || senderJid}`);
    record({
      action: 'kick',
      reason: `regex_rule:${initialRegexMatch}`,
      decisionSource: 'regex_rule',
      warningSent: false,
      deleteSuccess,
      kickSuccess
    });
    return;
  }

  const translationInfo = await translateTextForModeration(originalBody);
  const processedText = translationInfo?.processedText || originalBody;
  const translationMetadata = buildModerationMetadata(translationInfo);
  if (translationMetadata) {
    metadata.translation = translationMetadata;
  }

  if (
    thresholds?.inviteLinkBlocking &&
    processedText &&
    processedText !== originalBody &&
    containsInviteLink(processedText)
  ) {
    const deleteSuccess = await deleteMessageSafe(message);
    const kickSuccess = await kickParticipantSafe(chat, senderJid, senderNumber);
    writeBotLog('info', `Invite link blocked (translated) for ${senderNumber || senderJid} in ${groupId}`);
    record({
      action: 'kick',
      reason: 'invite_link_blocked_translation',
      decisionSource: 'invite_link',
      warningSent: false,
      deleteSuccess,
      kickSuccess
    });
    return;
  }

  const translatedRegexMatch =
    processedText && processedText !== originalBody ? findRegexMatch(processedText) : null;
  if (translatedRegexMatch) {
    metadata.regexPattern = translatedRegexMatch;
    const deleteSuccess = await deleteMessageSafe(message);
    const kickSuccess = await kickParticipantSafe(chat, senderJid, senderNumber);
    writeBotLog(
      'info',
      `Regex rule (normalized) triggered (${translatedRegexMatch}) for ${senderNumber || senderJid}`
    );
    record({
      action: 'kick',
      reason: `regex_rule:${translatedRegexMatch}`,
      decisionSource: 'regex_rule',
      warningSent: false,
      deleteSuccess,
      kickSuccess
    });
    return;
  }

  const evaluationText = processedText || originalBody;
  if (!evaluationText) {
    return;
  }

  const localCandidates = [];
  const localOriginal = classifyLocally(originalBody);
  if (localOriginal && localOriginal.action !== 'allow') {
    localCandidates.push({ ...localOriginal, source: 'original' });
  }
  if (processedText && processedText !== originalBody) {
    const localTranslated = classifyLocally(processedText);
    if (localTranslated && localTranslated.action !== 'allow') {
      localCandidates.push({ ...localTranslated, source: 'translated' });
    }
  }

  if (localCandidates.length) {
    metadata.localSignals = localCandidates.map((candidate) => ({
      source: candidate.source,
      label: candidate.label,
      action: candidate.action,
      reason: candidate.reason,
      confidence: candidate.confidence
    }));
  }

  let localDecision = null;
  for (const candidate of localCandidates) {
    localDecision = pickDecision(localDecision, candidate);
  }

  let decisionSource = localDecision ? `local_heuristic:${localDecision.source}` : null;
  let finalDecision = localDecision || null;

  const aiPayload = { ...context };
  if (translationMetadata?.language) {
    aiPayload.detectedLanguage = translationMetadata.language;
  }
  const aiDecision = await callAIService(evaluationText, aiPayload);
  if (aiDecision) {
    metadata.aiDecision = aiDecision;
    const preferred = pickDecision(finalDecision, aiDecision);
    if (preferred !== finalDecision) {
      finalDecision = preferred;
      decisionSource = preferred === aiDecision ? 'ai_service' : decisionSource;
    } else if (!decisionSource) {
      decisionSource = 'ai_service';
    }
  }

  if (!finalDecision || finalDecision.action === 'allow') {
    metadata.finalDecision = finalDecision || { action: 'allow' };
    return;
  }

  let executedAction = finalDecision.action;
  if (
    ['spam_financial', 'mass_invite'].includes(finalDecision.label) &&
    thresholds?.autoKickForSpam
  ) {
    executedAction = 'kick';
  }

  const isHarassmentLabel = ['harassment', 'hate_speech'].includes(finalDecision.label);
  metadata.finalDecision = {
    label: finalDecision.label,
    action: finalDecision.action,
    confidence: finalDecision.confidence,
    reason: finalDecision.reason
  };
  if (decisionSource) {
    metadata.decisionSource = decisionSource;
  }

  if (finalDecision.action === 'flag_for_review') {
    writeBotLog(
      'info',
      `Flagged message from ${senderNumber || senderJid} in ${groupId}: ${finalDecision.reason}`
    );
    record({
      action: 'flag_for_review',
      reason: finalDecision.reason,
      decisionSource: decisionSource || 'ai_service',
      warningSent: false
    });
    return;
  }

  const deleteSuccess = await deleteMessageSafe(message);

  if (isHarassmentLabel) {
    const warningContext = registerHarassmentWarning(groupId, senderNumber, senderJid);
    let warningSent = false;
    let kickSuccess = false;
    let warnings = undefined;
    if (warningContext) {
      warnings = {
        count: warningContext.count,
        remaining: warningContext.remaining
      };
      warningSent = await sendHarassmentWarning(
        chat,
        contact,
        warningContext.count,
        warningContext.policy.maxWarnings,
        warningContext.shouldKick
      );
      if (warningContext.shouldKick) {
        kickSuccess = await kickParticipantSafe(chat, senderJid, senderNumber);
        if (kickSuccess) {
          clearHarassmentWarning(groupId, warningContext.key);
        }
      }
      writeBotLog(
        'info',
        `Harassment warning for ${senderNumber || senderJid}: ${warningContext.count}/${
          warningContext.policy.maxWarnings
        }`
      );
    }
    record({
      action: warningContext?.shouldKick ? 'kick' : 'delete_only',
      reason: finalDecision.reason || 'harassment_policy',
      decisionSource: decisionSource || 'harassment_policy',
      warningSent,
      deleteSuccess,
      kickSuccess,
      warnings
    });
    return;
  }

  let kickSuccess = false;
  if (executedAction === 'kick') {
    kickSuccess = await kickParticipantSafe(chat, senderJid, senderNumber);
  }

  writeBotLog(
    'info',
    `Moderation action ${executedAction} for ${senderNumber || senderJid}: ${finalDecision.reason}`
  );
  record({
    action: executedAction === 'kick' && !kickSuccess ? 'delete_only' : executedAction,
    reason: finalDecision.reason,
    decisionSource: decisionSource || 'ai_service',
    warningSent: false,
    deleteSuccess,
    kickSuccess
  });
}

const { Client, LocalAuth } = whatsapp;

const client = new Client({
  authStrategy: new LocalAuth({ clientId: SESSION_ID }),
  webVersion: WWJS_WEB_VERSION,
  webVersionCache: {
    type: 'remote',
    remotePath: 'https://raw.githubusercontent.com/wppconnect-team/wa-version/main/last.json'
  },
  takeoverOnConflict: true,
  restartOnAuthFail: true,
  qrMaxRetries: 12,
  puppeteer: {
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--no-first-run',
      '--no-zygote',
      '--single-process'
    ]
  }
});

client.on('qr', (qr) => {
  console.log('Scan the QR code below to authenticate:');
  qrcode.generate(qr, { small: true });
  writeBotLog('info', 'QR code generated');
});

client.on('authenticated', () => {
  writeBotLog('info', 'Authenticated with WhatsApp');
});

client.on('auth_failure', (msg) => {
  writeBotLog('error', `Authentication failure: ${msg}`);
});

client.on('ready', () => {
  isReady = true;
  console.log('Bot is ready');
  writeBotLog('info', 'Bot is ready');
});

client.on('disconnected', (reason) => {
  isReady = false;
  writeBotLog('warn', `Client disconnected: ${reason}`);
});

client.on('loading_screen', (percent, message) => {
  writeBotLog('debug', `Loading ${percent}%: ${message}`);
});

client.on('change_state', (state) => {
  writeBotLog('debug', `Client state changed: ${state}`);
});

function recordEvent(event) {
  const {
    chat,
    message,
    senderJid,
    senderNumber,
    action,
    reason,
    decisionSource,
    warningSent = false,
    deleteSuccess,
    kickSuccess,
    warnings,
    metadata
  } = event;

  const entry = {
    ts: new Date().toISOString(),
    groupId: chat?.id?._serialized,
    groupName: chat?.name,
    messageId: message?.id?.id,
    senderJid,
    senderNumber,
    text: message?.body,
    action,
    reason,
    decisionSource,
    warningSent
  };

  if (typeof deleteSuccess === 'boolean') {
    entry.deleteSuccess = deleteSuccess;
  }
  if (typeof kickSuccess === 'boolean') {
    entry.kickSuccess = kickSuccess;
  }
  if (warnings) {
    entry.warnings = warnings;
  }
  if (metadata && Object.keys(metadata).length > 0) {
    entry.metadata = metadata;
  }

  appendModerationLog(entry);
  forwardModerationEvent(entry);
}

async function sendDm(clientInstance, jid, message) {
  try {
    await clientInstance.sendMessage(jid, message);
  } catch (error) {
    writeBotLog('warn', `Failed to send DM to ${jid}: ${error.message}`);
  }
}

async function sendHarassmentWarning(chat, contact, warningCount, maxWarnings, shouldKick) {
  const boundedCount = Math.min(warningCount, maxWarnings);
  const remaining = Math.max(maxWarnings - warningCount, 0);
  const contactId = contact?.id?._serialized;
  const mentionUser = contact?.id?.user;
  const displayName = contact?.pushname || contact?.name || 'member';
  const mentionTag = contactId && mentionUser ? `@${mentionUser}` : displayName;
  let warningMessage;
  if (shouldKick) {
    warningMessage = `${EMOJI.warning} Final warning ${mentionTag}\nYou have reached ${boundedCount}/${maxWarnings} warnings and will be removed from the group.`;
  } else {
    const plural = remaining === 1 ? '' : 's';
    warningMessage = `${EMOJI.warning} Warning ${mentionTag}\nPlease stop using abusive language. Warning ${boundedCount}/${maxWarnings}. ${remaining} warning${plural} remaining before removal.`;
  }
  warningMessage = `${warningMessage}\n${RULES_REMINDER_TEXT}`;
  try {
    if (contactId) {
      try {
        await chat.sendMessage(warningMessage, { mentions: [contactId] });
        return true;
      } catch (mentionError) {
        writeBotLog('debug', `Mention send failed, retrying without mention: ${mentionError.message}`);
      }
    }
    await chat.sendMessage(warningMessage);
    return true;
  } catch (error) {
    writeBotLog('warn', `Failed to send harassment warning: ${error.message}`);
    return false;
  }
}
async function handleTeachRequest(body, res) {
  try {
    const response = await withTimeout(
      fetch(`${AI_SERVICE_URL}/teach`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.AI_SERVICE_TOKEN || 'changeme-ai-token'}`
        },
        body: JSON.stringify(body)
      }),
      5000
    );
    const data = await response.json().catch(() => ({}));
    res.status(response.status).json(data);
  } catch (error) {
    res.status(502).json({ ok: false, error: 'AI service unreachable' });
  }
}

async function handleAiFeedback(body, res) {
  try {
    const response = await withTimeout(
      fetch(`${AI_SERVICE_URL}/review/feedback`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.AI_SERVICE_TOKEN || 'changeme-ai-token'}`
        },
        body: JSON.stringify(body)
      }),
      5000
    );
    const data = await response.json().catch(() => ({}));
    res.status(response.status).json(data);
  } catch (error) {
    res.status(502).json({ ok: false, error: 'AI service unreachable' });
  }
}

async function refreshChats() {
  try {
    return await client.getChats();
  } catch (error) {
    writeBotLog('warn', `Failed to fetch chats: ${error.message}`);
    return [];
  }
}

async function handleCommand(message) {
  const chat = await message.getChat();
  if (!chat.isGroup) return;

  const contact = await message.getContact();
  const senderNumber = contact.number || '';
  const senderJid = contact.id?._serialized;
  const senderRole = getRole(senderNumber) || 'admin';
  const isGroupAdmin = await isAdminInGroup(chat, senderJid);

  if (!message.fromMe && !isGroupAdmin) {
    await chat.sendMessage(`${EMOJI.noEntry} Only administrators can use commands.`);
    return;
  }

  const body = (message.body || '').trim();
  const [command, ...rest] = body.split(/\s+/);
  const lower = command.toLowerCase();
  const argsText = body.slice(command.length).trim();

  switch (lower) {
    case '/status': {
      await chat.sendMessage(`${EMOJI.statusOnline} Bot Online (v${BOT_VERSION})\nEverything is working fine ${EMOJI.check}`);
      break;
    }
    case '/rules': {
      await chat.sendMessage(config.groupRulesText || defaultConfig.groupRulesText);
      break;
    }
    case '/help': {
      await chat.sendMessage(
        [
          'Available admin commands:',
          '/status',
          '/rules',
          '/ban <number>',
          '/whitelist add <number>',
          '/whitelist remove <number>',
          '/whitelist list',
          '/regex add <pattern>',
          '/regex remove <pattern>',
          '/regex list [page]',
          '/test <text>',
          '/feedback <messageId> <false_positive|false_negative|correct>',
          '/roles list',
          '/roles set <number> <viewer|admin|superadmin>',
          '/roles remove <number>'
        ].join('\n')
      );
      break;
    }
    case '/report': {
      if (!hasPermission(senderRole, 'ban')) {
        await chat.sendMessage(`${EMOJI.noEntry} Permission denied.`);
        break;
      }
      if (!message.hasQuotedMsg) {
        await chat.sendMessage(`${EMOJI.warning} You must reply to the message you want to report with /report.`);
        break;
      }
      const quoted = await message.getQuotedMessage();
      if (!quoted) {
        await chat.sendMessage(`${EMOJI.warning} Unable to fetch the reported message.`);
        break;
      }
      let reportedContact = null;
      try {
        reportedContact = await quoted.getContact();
      } catch (error) {
        writeBotLog('debug', `Report: getContact failed for quoted message: ${error.message}`);
      }
      let reportedJid =
        reportedContact?.id?._serialized ||
        quoted.author ||
        quoted.id?.participant ||
        quoted._data?.author ||
        quoted._data?.participant ||
        '';
      let reportedNumber = normalizeNumber(
        reportedContact?.number ||
          reportedContact?.id?.user ||
          (reportedJid ? reportedJid.split('@')[0] : '') ||
          (quoted.id?.participant || '').split('@')[0] ||
          (quoted.author || '').split('@')[0]
      );

      if (!reportedJid && quoted.fromMe) {
        reportedJid = client.info?.wid?._serialized;
      }

      if (!reportedJid && reportedNumber) {
        reportedJid = numberToJid(reportedNumber);
      }

      if (reportedJid && !reportedJid.endsWith('@c.us') && !reportedJid.endsWith('@s.whatsapp.net')) {
        const inferred = reportedNumber ? numberToJid(reportedNumber) : '';
        if (inferred) {
          reportedJid = inferred;
        }
      }

      if (!reportedNumber && reportedJid) {
        reportedNumber = normalizeNumber(reportedJid.split('@')[0]);
      }

      if (chat?.participants?.length) {
        const participantMatch = chat.participants.find((participant) => {
          const candidate = participant.id?._serialized || '';
          return (
            candidate === reportedJid ||
            normalizeNumber(candidate.split('@')[0]) === reportedNumber
          );
        });
        if (participantMatch) {
          reportedJid = participantMatch.id?._serialized || reportedJid;
          if (!reportedNumber) {
            reportedNumber = normalizeNumber(participantMatch.id?.user || '');
          }
          if (!reportedContact) {
            try {
              reportedContact = await client.getContactById(participantMatch.id._serialized);
            } catch (contactError) {
              writeBotLog('debug', `Report: participant contact fetch failed: ${contactError.message}`);
            }
          }
        }
      }

      if (!reportedJid && !reportedNumber) {
        writeBotLog(
          'warn',
          `Report command failed to resolve participant. author=${quoted.author} participant=${quoted.id?.participant} from=${quoted.from}`
        );
        await chat.sendMessage(
          `${EMOJI.warning} Unable to identify the reported participant. Make sure you replied to a recent message in this group.`
        );
        break;
      }

      const reportedText = (quoted.body || '').trim();
      writeBotLog(
        'info',
        `Report targeting jid=${reportedJid || 'unknown'} number=${reportedNumber || 'unknown'} textLength=${reportedText.length}`
      );
      const deletedReported = await deleteMessageSafe(quoted);
      const kickedReported = await kickParticipantSafe(chat, reportedJid, reportedNumber);
      await deleteMessageSafe(message);
      let patternAdded = false;
      let storedPattern = null;
      if (reportedText && reportedText.length >= 4) {
        const collapsed = reportedText.replace(/\s+/g, ' ').trim();
        const snippet = collapsed.slice(0, 160);
        storedPattern = escapeRegexLiteral(snippet);
        if (storedPattern && !config.regexRules.includes(storedPattern)) {
          config.regexRules.push(storedPattern);
          saveConfig(config);
          patternAdded = true;
        }
      }
      const responseParts = [
        `${EMOJI.check} Report handled.`,
        deletedReported ? 'Message removed.' : 'Could not remove the message.',
        kickedReported ? 'Sender removed from group.' : 'Could not remove the sender.'
      ];
      if (patternAdded) {
        responseParts.push(`${EMOJI.shield} Pattern added to blacklist.`);
      }
      try {
        await chat.sendMessage(responseParts.join(' '));
      } catch (error) {
        writeBotLog('warn', `Report summary send failed: ${error.message}`);
        if (senderJid) {
          await sendDm(
            client,
            senderJid,
            `Report summary:\n${responseParts.join(' ')}`
          );
        }
      }
      await recordEvent({
        chat,
        message: quoted,
        senderJid: reportedJid,
        senderNumber: reportedNumber,
        action: kickedReported ? 'kick' : deletedReported ? 'delete_only' : 'flag_for_review',
        reason: 'manual_report',
        decisionSource: 'manual_report',
        warningSent: false,
        patternAdded,
        storedPattern
      });
      break;
    }
    case '/ban': {
      if (!hasPermission(senderRole, 'ban')) {
        await chat.sendMessage(`${EMOJI.noEntry} Permission denied.`);
        break;
      }
      const target = normalizeNumber(rest[0] || '');
      if (!target) {
        await chat.sendMessage('Usage: /ban <number>');
        break;
      }
      const jid = numberToJid(target);
      try {
        await chat.removeParticipants([jid]);
        await chat.sendMessage(`${EMOJI.info} Ban attempt sent.`);
      } catch (error) {
        await sendDm(client, senderJid, `Ban failed for ${target}: ${error.message}`);
      }
      break;
    }
    case '/whitelist': {
      if (!hasPermission(senderRole, 'whitelist')) {
        await chat.sendMessage(`${EMOJI.noEntry} Permission denied.`);
        break;
      }
      const sub = (rest[0] || '').toLowerCase();
      if (sub === 'add') {
        const number = normalizeNumber(rest[1] || '');
        if (!number) {
          await chat.sendMessage('Usage: /whitelist add <number>');
          break;
        }
        if (!config.whitelist.includes(number)) config.whitelist.push(number);
        saveConfig(config);
        await chat.sendMessage(`${EMOJI.check} Added to whitelist: ${number}`);
      } else if (sub === 'remove') {
        const number = normalizeNumber(rest[1] || '');
        if (!number) {
          await chat.sendMessage('Usage: /whitelist remove <number>');
          break;
        }
        config.whitelist = config.whitelist.filter((item) => item !== number);
        saveConfig(config);
        await chat.sendMessage(`${EMOJI.check} Removed from whitelist: ${number}`);
      } else if (sub === 'list') {
        const lines = (config.whitelist || []).map((num, idx) => `${idx + 1}. ${num}`);
        await chat.sendMessage(lines.length ? `Whitelist:\n${lines.join('\n')}` : 'Whitelist is empty.');
      } else {
        await chat.sendMessage('Usage: /whitelist add|remove|list');
      }
      break;
    }
    case '/warnings': {
      if (!hasPermission(senderRole, 'ban')) {
        await chat.sendMessage(`${EMOJI.noEntry} Permission denied.`);
        break;
      }
      const groupId = chat.id._serialized;
      const subcommand = (rest[0] || '').toLowerCase();
      if (subcommand === 'reset') {
        if ((rest[1] || '').toLowerCase() === 'all') {
          const hadEntries = harassmentWarningsState.groups[groupId] && Object.keys(harassmentWarningsState.groups[groupId]).length > 0;
          delete harassmentWarningsState.groups[groupId];
          persistWarningState();
          await chat.sendMessage(hadEntries ? 'All warnings cleared for this group.' : 'No warnings to clear.');
          break;
        }
        const targetMember = resolveWarningTarget(rest.slice(1), message);
        if (!targetMember) {
          await chat.sendMessage('Usage: /warnings reset <number or @mention | all>');
          break;
        }
        const snapshot = getWarningSnapshot(groupId, targetMember.key);
        if (!snapshot) {
          await chat.sendMessage(`No warnings found for ${targetMember.label}.`);
        } else {
          clearHarassmentWarning(groupId, targetMember.key);
          await chat.sendMessage(`Warnings reset for ${targetMember.label}.`);
        }
        break;
      }
      if (subcommand) {
        const targetMember = resolveWarningTarget(rest, message);
        if (!targetMember) {
          await chat.sendMessage('Usage: /warnings <number or @mention>');
          break;
        }
        const snapshot = getWarningSnapshot(groupId, targetMember.key);
        const policy = getWarningPolicy();
        if (!snapshot) {
          await chat.sendMessage(`No warnings recorded for ${targetMember.label}.`);
        } else {
          const remaining = Math.max(policy.maxWarnings - snapshot.count, 0);
          const lastWarningAt = snapshot.lastWarningAt ? new Date(snapshot.lastWarningAt).toISOString() : 'not recorded';
          await chat.sendMessage(`${targetMember.label} has ${snapshot.count}/${policy.maxWarnings} warnings. Remaining before removal: ${remaining}. Last warning: ${lastWarningAt}`);
        }
        break;
      }
      const summary = renderWarningsSummary(groupId);
      await chat.sendMessage(summary);
      break;
    }

    case '/regex': {
      if (!hasPermission(senderRole, 'regex')) {
        await chat.sendMessage(`${EMOJI.noEntry} Permission denied.`);
        break;
      }
      const sub = (rest[0] || '').toLowerCase();
      if (sub === 'add') {
        const pattern = argsText.replace(/^add\s+/, '').trim();
        if (!pattern) {
          await chat.sendMessage('Usage: /regex add <pattern>');
          break;
        }
        if (!config.regexRules.includes(pattern)) {
          config.regexRules.push(pattern);
          saveConfig(config);
        }
        await chat.sendMessage(`${EMOJI.check} Regex added: ${pattern}`);
      } else if (sub === 'remove') {
        const pattern = argsText.replace(/^remove\s+/, '').trim();
        if (!pattern) {
          await chat.sendMessage('Usage: /regex remove <pattern>');
          break;
        }
        config.regexRules = config.regexRules.filter((item) => item !== pattern);
        saveConfig(config);
        await chat.sendMessage(`${EMOJI.check} Regex removed: ${pattern}`);
      } else if (sub === 'list') {
        const page = parseInt(rest[1] || '1', 10) || 1;
        const perPage = 20;
        const start = (page - 1) * perPage;
        const slice = (config.regexRules || []).slice(start, start + perPage);
        const lines = slice.map((rule, idx) => `${start + idx + 1}. ${rule}`);
        const totalPages = Math.max(1, Math.ceil((config.regexRules || []).length / perPage));
        await chat.sendMessage(
          slice.length
            ? `Regex rules (page ${page}/${totalPages}):\n${lines.join('\n')}`
            : 'No regex rules configured.'
        );
      } else {
        await chat.sendMessage('Usage: /regex add|remove|list [page]');
      }
      break;
    }
    case '/test': {
      const sample = argsText.trim();
      if (!sample) {
        await chat.sendMessage('Usage: /test <text>');
        break;
      }
      const result = await callAIService(sample, getGroupContext(chat));
      if (!result) {
        await chat.sendMessage(`${EMOJI.magnifier} AI Result:
Service unavailable.`);
      } else {
        await chat.sendMessage(
          `${EMOJI.magnifier} AI Result:
Label: ${result.label}
Action: ${result.action}
Reason: ${result.reason}`
        );
      }
      break;
    }
    case '/feedback': {
      const messageId = rest[0];
      const verdict = rest[1];
      if (!messageId || !verdict) {
        await chat.sendMessage('Usage: /feedback <messageId> <false_positive|false_negative|correct>');
        break;
      }
      try {
        await withTimeout(
          fetch(`${AI_SERVICE_URL}/review/feedback`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${process.env.AI_SERVICE_TOKEN || 'changeme-ai-token'}`
            },
            body: JSON.stringify({ messageId, verdict })
          }),
          5000
        );
        await chat.sendMessage(`${EMOJI.check} Feedback sent. Thank you!`);
      } catch (error) {
        await chat.sendMessage(`${EMOJI.warning} Feedback could not be sent.`);
      }
      break;
    }
    case '/roles': {
      if (!hasPermission(senderRole, 'config')) {
        await chat.sendMessage(`${EMOJI.noEntry} Permission denied.`);
        break;
      }
      const sub = (rest[0] || '').toLowerCase();
      if (sub === 'list') {
        const entries = Object.entries(config.adminRoles || {});
        const lines = entries.map(([num, role]) => `${num}: ${role}`);
        await chat.sendMessage(lines.length ? `Roles:\n${lines.join('\n')}` : 'No custom roles configured.');
      } else if (sub === 'set') {
        const number = normalizeNumber(rest[1] || '');
        const role = (rest[2] || '').toLowerCase();
        if (!number || !['viewer', 'admin', 'superadmin'].includes(role)) {
          await chat.sendMessage('Usage: /roles set <number> <viewer|admin|superadmin>');
          break;
        }
        config.adminRoles[number] = role;
        saveConfig(config);
        await chat.sendMessage(`${EMOJI.check} Role set: ${number} -> ${role}`);
      } else if (sub === 'remove') {
        const number = normalizeNumber(rest[1] || '');
        if (!number) {
          await chat.sendMessage('Usage: /roles remove <number>');
          break;
        }
        delete config.adminRoles[number];
        saveConfig(config);
        await chat.sendMessage(`${EMOJI.check} Role removed: ${number}`);
      } else {
        await chat.sendMessage('Usage: /roles list | /roles set <number> <viewer|admin|superadmin> | /roles remove <number>');
      }
      break;
    }
    default: {
      await chat.sendMessage('Unknown command. Try /help');
      break;
    }
  }
}

client.on('message', async (message) => {
  try {
    const chat = await message.getChat();
    if (!chat.isGroup) return;

    if ((message.body || '').startsWith('/')) {
      await handleCommand(message);
      return;
    }

    await moderateMessage(message);
  } catch (error) {
    writeBotLog('error', `Failed to process message: ${error.message}`);
  }
});

const app = express();
app.use('/dashboard', express.static(publicDir));
app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
  if (req.path.startsWith('/dashboard')) return next();
  const header = req.headers['authorization'] || '';
  const expected = `Bearer ${BOT_INTERNAL_TOKEN}`;
  if (header !== expected) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }
  next();
});

app.get('/status', async (_req, res) => {
  try {
    const chats = isReady ? await refreshChats() : [];
    const groups = chats
      .filter((chat) => chat.isGroup)
      .map((chat) => ({ id: chat.id._serialized, name: chat.name }));
    res.json({ ok: true, connected: isReady, version: BOT_VERSION, monitoredGroups: groups });
  } catch (error) {
    res.json({ ok: true, connected: isReady, version: BOT_VERSION, monitoredGroups: [] });
  }
});

app.get('/config', (_req, res) => {
  res.json({ ok: true, config });
});

app.post('/config/update', (req, res) => {
  const payload = req.body || {};
  const errors = validateConfigPayload(payload);
  if (errors.length) {
    return res.status(400).json({ ok: false, errors });
  }

  const { whitelist, regexRules, groupRulesText, thresholds, adminRoles, groupContexts, warningPolicy } = payload;
  const updated = { ...config };
  if (Array.isArray(whitelist)) updated.whitelist = whitelist.map((item) => normalizeNumber(item)).filter(Boolean);
  if (Array.isArray(regexRules)) updated.regexRules = regexRules;
  if (typeof groupRulesText === 'string') updated.groupRulesText = groupRulesText;
  if (thresholds && typeof thresholds === 'object') updated.thresholds = thresholds;
  if (adminRoles && typeof adminRoles === 'object') updated.adminRoles = adminRoles;
  if (groupContexts && typeof groupContexts === 'object') updated.groupContexts = groupContexts;
  if (warningPolicy && typeof warningPolicy === 'object') updated.warningPolicy = warningPolicy;

  saveConfig(updated);
  res.json({ ok: true, config });
});

app.get('/logs/recent', (req, res) => {
  const limit = parseInt(req.query.limit || '100', 10) || 100;
  res.json({ ok: true, logs: readModerationLog(limit) });
});

app.get('/analytics', (_req, res) => {
  const entries = readModerationLog(500);
  const stats = {
    total_events: entries.length,
    kicks: 0,
    deletions: 0,
    flags: 0,
    by_reason: {}
  };
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    if (entry.action === 'kick') stats.kicks += 1;
    if (entry.action === 'delete_only') stats.deletions += 1;
    if (entry.action === 'flag_for_review') stats.flags += 1;
    if (entry.reason) stats.by_reason[entry.reason] = (stats.by_reason[entry.reason] || 0) + 1;
  }
  res.json({ ok: true, stats });
});

app.post('/ban', async (req, res) => {
  const { number, groupId } = req.body || {};
  if (!number || !groupId) {
    return res.status(400).json({ ok: false, error: 'number and groupId required' });
  }
  try {
    const chat = await client.getChatById(groupId);
    if (!chat.isGroup) {
      return res.status(400).json({ ok: false, error: 'not a group' });
    }
    await chat.removeParticipants([numberToJid(number)]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message || 'ban failed' });
  }
});

app.post('/teach', async (req, res) => {
  await handleTeachRequest(req.body || {}, res);
});

app.get('/ai/metrics', async (_req, res) => {
  try {
    const response = await withTimeout(fetch(`${AI_SERVICE_URL}/metrics`), 5000);
    const data = await response.json().catch(() => ({}));
    res.status(response.status).json(data);
  } catch (error) {
    res.status(502).json({ ok: false, error: 'AI metrics unavailable' });
  }
});

app.post('/ai/feedback', async (req, res) => {
  await handleAiFeedback(req.body || {}, res);
});

app.listen(PORT, () => {
  const message = `Internal API listening on port ${PORT}`;
  console.log(message);
  writeBotLog('info', message);
});

client.initialize();




