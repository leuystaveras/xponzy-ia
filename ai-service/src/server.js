import 'dotenv/config';
import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../../');
const storageDir = path.join(repoRoot, 'storage');
const logsDir = path.join(repoRoot, 'logs');
const logFile = path.join(logsDir, 'ai-service.log');
const trainingFile = path.join(storageDir, 'ai-training.json');

const PORT = parseInt(process.env.PORT || '8080', 10);
const LOG_LEVEL = (process.env.LOG_LEVEL || 'info').toLowerCase();
const AI_SERVICE_TOKEN = process.env.AI_SERVICE_TOKEN || 'changeme-ai-token';

function ensureInitialFiles() {
  [storageDir, logsDir].forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });

  if (!fs.existsSync(logFile)) {
    fs.writeFileSync(logFile, '', 'utf8');
  }

  if (!fs.existsSync(trainingFile)) {
    const seed = {
      samples: [],
      feedback: [],
      metrics: {
        false_positive_reports: 0,
        false_negative_reports: 0,
        spam_seen_today: 0,
        harassment_seen_today: 0,
        precision_estimate: 0.9,
        recall_estimate: 0.9
      }
    };
    fs.writeFileSync(trainingFile, JSON.stringify(seed, null, 2), 'utf8');
  }
}

ensureInitialFiles();

function writeLog(level, message) {
  if (!message) return;
  const levels = ['error', 'warn', 'info', 'debug'];
  const currentIdx = levels.indexOf(LOG_LEVEL);
  const msgIdx = levels.indexOf(level);
  if (msgIdx === -1 || (currentIdx !== -1 && msgIdx > currentIdx)) return;
  const line = `[${new Date().toISOString()}] [${level.toUpperCase()}] ${message}`;
  try {
    fs.appendFileSync(logFile, `${line}\n`, 'utf8');
  } catch {
    // ignore disk errors to keep service running
  }
}

function readTraining() {
  try {
    const raw = fs.readFileSync(trainingFile, 'utf8');
    const parsed = JSON.parse(raw);
    trainingCache = parsed;
    return parsed;
  } catch (error) {
    writeLog('error', `Failed to read training file: ${error.message}`);
    const fallback = {
      samples: [],
      feedback: [],
      metrics: {
        false_positive_reports: 0,
        false_negative_reports: 0,
        spam_seen_today: 0,
        harassment_seen_today: 0,
        precision_estimate: 0.9,
        recall_estimate: 0.9
      }
    };
    trainingCache = fallback;
    return fallback;
  }
}

function saveTraining(data) {
  try {
    fs.writeFileSync(trainingFile, JSON.stringify(data, null, 2), 'utf8');
    trainingCache = data;
  } catch (error) {
    writeLog('error', `Failed to persist training file: ${error.message}`);
  }
}

function decayMetric(value) {
  return Math.max(0, Math.round(value * 0.92));
}

function applyDailyDecay(metrics) {
  const now = Date.now();
  if (!metrics._last_decay) {
    metrics._last_decay = now;
    return metrics;
  }
  const ONE_HOUR = 1000 * 60 * 60;
  if (now - metrics._last_decay < ONE_HOUR) {
    return metrics;
  }
  metrics._last_decay = now;
  metrics.spam_seen_today = decayMetric(metrics.spam_seen_today || 0);
  metrics.harassment_seen_today = decayMetric(metrics.harassment_seen_today || 0);
  return metrics;
}

const FINANCIAL_PATTERNS = [
  'forex',
  'signals',
  'binary option',
  'crypto',
  'passive income',
  'stock group',
  'portfolio',
  'guaranteed return',
  'investment program',
  'copy trading',
  'pump signal',
  'pump group',
  'trade alert',
  'vip signal'
];

const FINANCIAL_PATTERNS_SPANISH = [
  'grupo de senales',
  'grupo senales',
  'senales vip',
  'senales crypto',
  'senales cripto',
  'senales forex',
  'senales binarias',
  'dobla tu dinero',
  'doblar tu dinero',
  'multiplica tu dinero',
  'multiplicar el dinero',
  'ganancias garantizadas',
  'ingresos pasivos',
  'dinero facil',
  'retiro diario',
  'alertas de trading',
  'alertas trading',
  'grupo de inversion',
  'canal de inversion',
  'grupo trading',
  'grupo de trading',
  'invierte con nosotros',
  'acciones vip',
  'rentabilidad segura'
];

const FINANCIAL_REGEXES = [
  /(grupo|canal|chat).{0,30}(signal|signals|senal|senales|alerta|alertas)/i,
  /(dobla|duplica|multiplica).{0,20}(dinero|ganancia|ingreso|capital)/i,
  /(ganancias?|rendimiento|rentabilidad).{0,20}(garantizado|seguro|asegurado)/i,
  /(crypto|cripto).{0,10}(signal|signals|senal|senales|alerta|alertas)/i,
  /(vip).{0,10}(signal|signals|senal|senales)/i
];

const HARASSMENT_PATTERNS = [
  'idiot',
  'stupid',
  'kill yourself',
  'retard',
  'racist',
  'nazi',
  'bigot',
  'hate you',
  'dumbass',
  'loser',
  'trash',
  'bastard',
  'asshole',
  'pendejo',
  'pendeja',
  'cabron',
  'cabrona',
  'imbecil',
  'estupido',
  'estupida',
  'maricon',
  'maricona',
  'puta',
  'perra',
  'zorra',
  'muerto de hambre',
  'india de mierda',
  'sudaca',
  'negro de mierda',
  'maldito negro',
  'chink',
  'spic',
  'beaner',
  'wetback'
];
const HATE_SPEECH_SEVERE = new Set([
  'nazi',
  'kkk',
  'white power',
  'supremacy',
  'subhuman',
  'negro de mierda',
  'maldito negro',
  'chink',
  'spic',
  'beaner',
  'wetback',
  'india de mierda',
  'sudaca'
]);


const SEXUAL_PATTERNS = [
  'nude',
  'xxx',
  'porn',
  'sexual',
  'onlyfans',
  'nsfw',
  'explicit pic'
];

const RECRUITMENT_LINKS = [
  'chat.whatsapp.com',
  'whatsapp.com/invite',
  'wa.me/join',
  't.me/',
  'discord.gg/',
  'discord.com/invite'
];

const ACTION_PRIORITY = Object.freeze({
  allow: 0,
  flag_for_review: 1,
  delete_only: 2,
  kick: 3
});

const MODEL_SPAM_LABELS = new Set(['spam_financial', 'investment_scam', 'mass_invite']);
const MODEL_HARASSMENT_LABELS = new Set(['harassment', 'hate_speech', 'sexual_content']);

let trainingCache = null;
let currentModel = createEmptyModel();
let modelReady = false;
let rebuildTimer = null;
const MIN_MODEL_DOCS = 5;

function classifyHeuristic(text, context = {}) {
  const sample = (text || '').toLowerCase();
  const folded = sample.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const domain = (context.domain || 'general').toLowerCase();
  const severityModifier = Number(context.severityModifier || 1);

  const hasRecruitmentLinks = RECRUITMENT_LINKS.some((link) => sample.includes(link));

  let matchedFinancialPhrase =
    FINANCIAL_PATTERNS.find((pattern) => sample.includes(pattern)) ||
    FINANCIAL_PATTERNS_SPANISH.find((pattern) => folded.includes(pattern));

  if (!matchedFinancialPhrase) {
    const regexMatch = FINANCIAL_REGEXES.find((regex) => regex.test(folded));
    matchedFinancialPhrase = regexMatch ? regexMatch.source : undefined;
  }

  const financialHit = Boolean(matchedFinancialPhrase);
  const harassmentMatch = HARASSMENT_PATTERNS.find((pattern) => sample.includes(pattern) || folded.includes(pattern));
  const sexualHit = SEXUAL_PATTERNS.some((pattern) => sample.includes(pattern));

  let label = 'allowed';
  let action = 'allow';
  let reason = 'no issues detected';
  let confidence = 0.55;
  let harassment_score = 0;
  let spam_score = 0;

  if (harassmentMatch) {
    const matchedHarassment = typeof harassmentMatch === 'string' ? harassmentMatch : harassmentMatch.source;
    const severe = typeof harassmentMatch !== 'string' || HATE_SPEECH_SEVERE.has(matchedHarassment);
    label = severe ? 'hate_speech' : 'harassment';
    harassment_score = severe ? 0.95 * severityModifier : 0.82 * severityModifier;
    confidence = Math.min(1, (severe ? 0.92 : 0.85) * severityModifier);
    action = severe || severityModifier >= 1.1 ? 'delete_only' : 'flag_for_review';
    if (severe) {
      action = 'kick';
    }
    reason = severe ? 'hate speech language detected' : 'harassment language detected';
  }

  if (sexualHit) {
    label = 'sexual_content';
    harassment_score = 0.1;
    spam_score = 0.4;
    confidence = Math.min(1, 0.8 * severityModifier);
    action = severityModifier >= 1.1 ? 'delete_only' : 'flag_for_review';
    reason = 'sexual content detected';
  }

  if (financialHit || hasRecruitmentLinks) {
    label = hasRecruitmentLinks ? 'mass_invite' : 'spam_financial';
    spam_score = Math.min(
      1,
      hasRecruitmentLinks ? 0.96 * severityModifier : 0.88 * severityModifier
    );
    confidence = Math.min(1, 0.92 * severityModifier);
    action = 'kick';
    reason = hasRecruitmentLinks
      ? 'external recruitment link detected'
      : `investment solicitation detected (${matchedFinancialPhrase || 'financial_spam'})`;

    if (domain === 'finance' || domain === 'trading') {
      confidence = Math.min(1, confidence + 0.04);
      spam_score = Math.min(1, spam_score + 0.05);
    }
  }

  return {
    label,
    confidence: Math.min(1, Math.max(0.4, confidence)),
    harassment_score: Number(harassment_score.toFixed(2)),
    spam_score: Number(spam_score.toFixed(2)),
    action,
    reason,
    source: 'heuristic'
  };
}

const KNOWN_MODEL_LABELS = new Set([
  'allowed',
  'spam_financial',
  'investment_scam',
  'mass_invite',
  'harassment',
  'hate_speech',
  'sexual_content'
]);

const MODEL_DECISION_TEMPLATES = Object.freeze({
  allowed: {
    action: 'allow',
    reason: 'learned model: allowed',
    harassment_score: 0.08,
    spam_score: 0.08
  },
  spam_financial: {
    action: 'kick',
    reason: 'learned model: financial spam detected',
    harassment_score: 0.15,
    spam_score: 0.9
  },
  investment_scam: {
    action: 'kick',
    reason: 'learned model: investment scam detected',
    harassment_score: 0.18,
    spam_score: 0.92
  },
  mass_invite: {
    action: 'kick',
    reason: 'learned model: external recruitment detected',
    harassment_score: 0.12,
    spam_score: 0.94
  },
  harassment: {
    action: 'delete_only',
    reason: 'learned model: harassment detected',
    harassment_score: 0.86,
    spam_score: 0.22
  },
  hate_speech: {
    action: 'kick',
    reason: 'learned model: hate speech detected',
    harassment_score: 0.95,
    spam_score: 0.18
  },
  sexual_content: {
    action: 'delete_only',
    reason: 'learned model: sexual content detected',
    harassment_score: 0.25,
    spam_score: 0.32
  }
});

function createEmptyModel() {
  return {
    docCounts: {},
    labelTotals: {},
    tokenCounts: {},
    totalDocs: 0,
    vocabulary: new Set()
  };
}

function normalizeLabelForModel(label) {
  const normalized = (label || '').toLowerCase().trim();
  if (KNOWN_MODEL_LABELS.has(normalized)) {
    return normalized;
  }
  if (MODEL_SPAM_LABELS.has(normalized)) {
    return 'spam_financial';
  }
  if (MODEL_HARASSMENT_LABELS.has(normalized)) {
    return normalized;
  }
  return 'allowed';
}

function tokenizeForModel(text) {
  if (!text) return [];
  const lowered = text
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9\s]/g, ' ');
  return lowered
    .split(/\s+/)
    .map((token) => token.trim())
    .filter((token) => token.length >= 3 && token.length <= 32);
}

function buildModelFromSamples(samples = []) {
  const model = createEmptyModel();
  if (!Array.isArray(samples)) {
    return model;
  }
  for (const sample of samples) {
    if (!sample || typeof sample.text !== 'string') continue;
    const tokens = tokenizeForModel(sample.text);
    if (tokens.length === 0) continue;
    const label = normalizeLabelForModel(sample.label);
    model.totalDocs += 1;
    model.docCounts[label] = (model.docCounts[label] || 0) + 1;
    if (!model.tokenCounts[label]) {
      model.tokenCounts[label] = {};
    }
    for (const token of tokens) {
      model.vocabulary.add(token);
      model.tokenCounts[label][token] = (model.tokenCounts[label][token] || 0) + 1;
      model.labelTotals[label] = (model.labelTotals[label] || 0) + 1;
    }
  }
  return model;
}

function getTemplateForLabel(label) {
  return MODEL_DECISION_TEMPLATES[label] || MODEL_DECISION_TEMPLATES.allowed;
}

function classifyWithModel(text) {
  if (!modelReady || !currentModel || currentModel.totalDocs < MIN_MODEL_DOCS) {
    return null;
  }
  const tokens = tokenizeForModel(text);
  if (tokens.length === 0) {
    return null;
  }
  const labels = Object.keys(currentModel.docCounts || {});
  if (labels.length === 0) {
    return null;
  }

  const vocabularySize = Math.max(1, currentModel.vocabulary.size);
  const totalDocs = currentModel.totalDocs;
  const labelCount = labels.length;
  const logScores = {};
  let maxLog = -Infinity;

  for (const label of labels) {
    const docCount = currentModel.docCounts[label] || 0;
    const tokenBucket = currentModel.tokenCounts[label] || {};
    const labelTotalTokens = currentModel.labelTotals[label] || 0;
    let logProb = Math.log((docCount + 1) / (totalDocs + labelCount));
    for (const token of tokens) {
      const freq = tokenBucket[token] || 0;
      logProb += Math.log((freq + 1) / (labelTotalTokens + vocabularySize));
    }
    logScores[label] = logProb;
    if (logProb > maxLog) {
      maxLog = logProb;
    }
  }

  const probabilities = {};
  let sum = 0;
  for (const label of labels) {
    const prob = Math.exp(logScores[label] - maxLog);
    probabilities[label] = prob;
    sum += prob;
  }
  if (sum === 0) {
    return null;
  }
  const sortedProbabilities = labels
    .map((label) => ({
      label,
      probability: probabilities[label] / sum
    }))
    .sort((a, b) => b.probability - a.probability);

  const best = sortedProbabilities[0];
  if (!best) {
    return null;
  }
  const runnerUp = sortedProbabilities[1] || { probability: 0 };
  const template = getTemplateForLabel(best.label);
  const baseConfidence = 0.58 + best.probability * 0.35;
  const marginBoost = Math.min(0.15, Math.max(0, best.probability - runnerUp.probability));
  const confidence = Math.min(0.98, baseConfidence + marginBoost);

  return {
    label: best.label,
    action: template.action,
    reason: `${template.reason} (p=${best.probability.toFixed(2)})`,
    confidence: Number(confidence.toFixed(2)),
    harassment_score: template.harassment_score,
    spam_score: template.spam_score,
    source: 'learned_model',
    model_probability: Number(best.probability.toFixed(3))
  };
}

function pickBetterDecision(baseDecision, candidateDecision) {
  if (!baseDecision && !candidateDecision) return null;
  if (!baseDecision) return { ...candidateDecision };
  if (!candidateDecision) return { ...baseDecision };

  const basePriority = ACTION_PRIORITY[baseDecision.action] ?? 0;
  const candidatePriority = ACTION_PRIORITY[candidateDecision.action] ?? 0;
  if (candidatePriority > basePriority) {
    return { ...candidateDecision };
  }
  if (candidatePriority < basePriority) {
    return { ...baseDecision };
  }
  const baseConfidence = baseDecision.confidence ?? 0;
  const candidateConfidence = candidateDecision.confidence ?? 0;
  if (candidateConfidence > baseConfidence + 0.05) {
    return { ...candidateDecision };
  }
  if (baseConfidence > candidateConfidence + 0.05) {
    return { ...baseDecision };
  }
  return { ...(candidateDecision.source === 'learned_model' ? candidateDecision : baseDecision) };
}

function classifyEnsemble(text, context = {}) {
  const heuristicDecision = classifyHeuristic(text, context);
  const learnedDecision = classifyWithModel(text);
  if (!learnedDecision) {
    return heuristicDecision;
  }
  const finalDecision = pickBetterDecision(heuristicDecision, learnedDecision);
  if (finalDecision.source === 'learned_model') {
    finalDecision.reason = `${finalDecision.reason} via learned model`;
  }
  return finalDecision;
}

function refreshModel(samples = []) {
  currentModel = buildModelFromSamples(samples);
  modelReady = currentModel.totalDocs >= MIN_MODEL_DOCS;
  writeLog(
    'info',
    `AI model refreshed: docs=${currentModel.totalDocs} vocab=${currentModel.vocabulary.size} ready=${modelReady}`
  );
}

function loadModelFromDisk() {
  try {
    const data = readTraining();
    trainingCache = data;
    refreshModel(data.samples || []);
  } catch (error) {
    writeLog('error', `Failed to load model from disk: ${error.message}`);
    currentModel = createEmptyModel();
    modelReady = false;
  }
}

function scheduleModelRebuild(delayMs = 200) {
  if (rebuildTimer) {
    clearTimeout(rebuildTimer);
  }
  rebuildTimer = setTimeout(() => {
    rebuildTimer = null;
    try {
      const data = trainingCache || readTraining();
      refreshModel(data.samples || []);
    } catch (error) {
      writeLog('error', `Model rebuild failed: ${error.message}`);
    }
  }, Math.max(50, delayMs));
}

loadModelFromDisk();

function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const expected = `Bearer ${AI_SERVICE_TOKEN}`;
  if (AI_SERVICE_TOKEN && AI_SERVICE_TOKEN.length > 0 && header !== expected) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }
  next();
}

const app = express();
app.use(express.json());

app.use((req, _res, next) => {
  writeLog('debug', `${req.method} ${req.url}`);
  next();
});

app.post('/classify', (req, res) => {
  try {
    const { text, context } = req.body || {};
    const result = classifyEnsemble(text || '', context || {});
    res.json(result);
  } catch (error) {
    writeLog('error', `Classify error: ${error.message}`);
    res.json({
      label: 'allowed',
      confidence: 0.5,
      harassment_score: 0,
      spam_score: 0,
      action: 'allow',
      reason: 'fallback'
    });
  }
});

app.post('/teach', requireAuth, (req, res) => {
  try {
    const { text, label } = req.body || {};
    if (!text || !label) {
      return res.status(400).json({ ok: false, error: 'text and label required' });
    }
    const data = readTraining();
    const now = new Date().toISOString();
    data.samples.push({ text, label, ts: now });
    data.metrics = applyDailyDecay(data.metrics || {});
    if (label === 'spam_financial' || label === 'mass_invite') {
      data.metrics.spam_seen_today = (data.metrics.spam_seen_today || 0) + 1;
    }
    if (label === 'harassment') {
      data.metrics.harassment_seen_today = (data.metrics.harassment_seen_today || 0) + 1;
    }
    saveTraining(data);
    scheduleModelRebuild(150);
    res.json({ ok: true });
  } catch (error) {
    writeLog('error', `Teach error: ${error.message}`);
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

app.post('/review/feedback', requireAuth, (req, res) => {
  try {
    const { messageId, verdict } = req.body || {};
    if (!messageId || !verdict) {
      return res.status(400).json({ ok: false, error: 'messageId and verdict required' });
    }
    const data = readTraining();
    const now = new Date().toISOString();
    data.feedback.push({ messageId, verdict, ts: now });
    data.metrics = applyDailyDecay(data.metrics || {});
    if (verdict === 'false_positive') {
      data.metrics.false_positive_reports = (data.metrics.false_positive_reports || 0) + 1;
    }
    if (verdict === 'false_negative') {
      data.metrics.false_negative_reports = (data.metrics.false_negative_reports || 0) + 1;
    }
    const totalFeedback = (data.feedback || []).length || 1;
    const falsePosRate = (data.metrics.false_positive_reports || 0) / totalFeedback;
    const falseNegRate = (data.metrics.false_negative_reports || 0) / totalFeedback;
    data.metrics.precision_estimate = Number((1 - falsePosRate).toFixed(2));
    data.metrics.recall_estimate = Number((1 - falseNegRate).toFixed(2));
    saveTraining(data);
    res.json({ ok: true });
  } catch (error) {
    writeLog('error', `Feedback error: ${error.message}`);
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

app.get('/metrics', (req, res) => {
  try {
    const data = readTraining();
    data.metrics = applyDailyDecay(data.metrics || {});
    saveTraining(data);
    const metrics = data.metrics || {};
    res.json({
      samples_tracked: (data.samples || []).length,
      spam_seen_today: metrics.spam_seen_today || 0,
      harassment_seen_today: metrics.harassment_seen_today || 0,
      false_positive_reports: metrics.false_positive_reports || 0,
      false_negative_reports: metrics.false_negative_reports || 0,
      precision_estimate: metrics.precision_estimate ?? 0.9,
      recall_estimate: metrics.recall_estimate ?? 0.9
    });
  } catch (error) {
    writeLog('error', `Metrics error: ${error.message}`);
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, status: 'healthy' });
});

app.listen(PORT, () => {
  const msg = `AI service running on port ${PORT}`;
  console.log(msg);
  writeLog('info', msg);
});
