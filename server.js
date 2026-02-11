const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// ===== Server =====
const HOST = '0.0.0.0';
const PORT = process.env.PORT || 8080;
const IS_PROD = process.env.NODE_ENV === 'production';

// ===== ENV =====
const SESSION_SECRET = process.env.SESSION_SECRET || 'CHANGE_ME_SESSION_SECRET';
const APP_BASE_URL = process.env.APP_BASE_URL || '';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase();
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const ADMIN_PASSWORD_PLAIN = process.env.ADMIN_PASSWORD_PLAIN || '';
const ADMIN_ACTIVATE_TOKEN = process.env.ADMIN_ACTIVATE_TOKEN || 'CHANGE_ME_ADMIN_ACTIVATE_TOKEN';

// ===== Timing =====
const LOCK_SCREEN_MS = 5000;
const SESSION_TTL_DAYS = 7;
const AI_JOB_DELAY_MS = Number(process.env.AI_JOB_DELAY_MS || 20000);

// ===== Pilot / Retention =====
const PILOT_DAYS = 30;
const RETENTION_DAYS_AFTER_PILOT = 14;

// ===== Limits (LOCKED) =====
const PILOT_LIMITS = {
  max_cases_total: 25,
  max_files_per_case: 3,
  max_file_size_mb: 10,
  max_ai_jobs_per_hour: 2,
  max_concurrent_analyzing: 2,
  payment_records_included: 2000,
};
const MONTHLY_DEFAULTS = {
  case_credits_per_month: 40,
  payment_tracking_credits_per_month: 10,
  max_files_per_case: 3,
  max_file_size_mb: 20,
  max_ai_jobs_per_hour: 5,
  max_concurrent_analyzing: 5,
  overage_price_per_case: 50,
  payment_records_per_credit: 1000,
};
const PAYMENT_RECORDS_PER_CREDIT = 1000;

// ===== Storage =====
const BASE_DIR = __dirname;
const DATA_DIR = path.join(BASE_DIR, 'data');
const UPLOADS_DIR = path.join(BASE_DIR, 'uploads');
const FILES = {
  orgs: path.join(DATA_DIR, 'orgs.json'),
  users: path.join(DATA_DIR, 'users.json'),
  pilots: path.join(DATA_DIR, 'pilots.json'),
  subscriptions: path.join(DATA_DIR, 'subscriptions.json'),
  cases: path.join(DATA_DIR, 'cases.json'),
  payments: path.join(DATA_DIR, 'payments.json'),
  expectations: path.join(DATA_DIR, 'expectations.json'),
  flags: path.join(DATA_DIR, 'flags.json'),
  usage: path.join(DATA_DIR, 'usage.json'),
  audit: path.join(DATA_DIR, 'audit.json'),
  // New storage for contracts and feedback
  contracts: path.join(DATA_DIR, 'contracts.json'),
  feedback: path.join(DATA_DIR, 'feedback.json'),
};

// ===== Helpers =====
function uuid() {
  return crypto.randomUUID();
}
function nowISO() {
  return new Date().toISOString();
}
function addDaysISO(iso, days) {
  const d = new Date(iso);
  d.setDate(d.getDate() + days);
  return d.toISOString();
}
function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}
function ensureFile(p, defaultVal) {
  if (!fs.existsSync(p)) fs.writeFileSync(p, JSON.stringify(defaultVal, null, 2));
}
function readJSON(p, fallback) {
  ensureFile(p, fallback);
  return JSON.parse(fs.readFileSync(p, 'utf8') || JSON.stringify(fallback));
}
function writeJSON(p, val) {
  fs.writeFileSync(p, JSON.stringify(val, null, 2));
}
function safeStr(s) {
  return String(s ?? '').replace(/[<>&"]/g, (c) => ({
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    '"': '&quot;',
  }[c]));
}
function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header
    .split(';')
    .map((x) => x.trim())
    .filter(Boolean)
    .forEach((pair) => {
      const idx = pair.indexOf('=');
      if (idx > -1) out[pair.slice(0, idx)] = decodeURIComponent(pair.slice(idx + 1));
    });
  return out;
}
function setCookie(res, name, value, maxAgeSeconds) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'SameSite=Lax',
    'HttpOnly',
  ];
  if (IS_PROD) parts.push('Secure');
  if (maxAgeSeconds) parts.push(`Max-Age=${maxAgeSeconds}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}
function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly${IS_PROD ? '; Secure' : ''}`);
}
function send(res, status, body, type = 'text/html') {
  res.writeHead(status, { 'Content-Type': type });
  res.end(body);
}
function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}
function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => resolve(body));
  });
}

// ===== Session =====
function hmacSign(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('hex');
}
function makeSession(payload) {
  const json = JSON.stringify(payload);
  const b64 = Buffer.from(json).toString('base64url');
  const sig = hmacSign(b64, SESSION_SECRET);
  return `${b64}.${sig}`;
}
function verifySession(token) {
  if (!token || !token.includes('.')) return null;
  const [b64, sig] = token.split('.');
  const expected = hmacSign(b64, SESSION_SECRET);
  if (sig !== expected) return null;
  try {
    const json = Buffer.from(b64, 'base64url').toString('utf8');
    const payload = JSON.parse(json);
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}
function getAuth(req) {
  const cookies = parseCookies(req);
  return verifySession(cookies.tjhp_session);
}

// ===== Init storage =====
ensureDir(DATA_DIR);
ensureDir(UPLOADS_DIR);
Object.values(FILES).forEach((p) => ensureFile(p, []));

// ===== Admin password =====
function adminHash() {
  if (ADMIN_PASSWORD_HASH) return ADMIN_PASSWORD_HASH;
  if (ADMIN_PASSWORD_PLAIN) return bcrypt.hashSync(ADMIN_PASSWORD_PLAIN, 10);
  return '';
}

// ===== Stub for cleanupIfExpired =====
function cleanupIfExpired(org_id) {
  // In this simplified reference server, data cleanup is not performed.
  // Implement retention cleanup logic here if needed.
}

// ===== OCR & NLP Helpers =====
async function performOCR(files) {
  let text = '';
  for (const f of files) {
    try {
      const str = f.buffer.toString('utf8');
      if (str.trim()) text += '\n' + str;
      else text += `\n[[binary file: ${f.filename}]]`;
    } catch (err) {
      text += `\n[[binary file: ${f.filename}]]`;
    }
  }
  return text;
}
function extractStructuredData(text) {
  const lines = text.split(/\r?\n/);
  let claimNumber = '';
  let payer = '';
  const codes = [];
  const claimRegex = /claim\s*(?:number|#|id)[:\s]*([A-Za-z0-9\-]+)/i;
  const payerRegex = /payer[:\s]*([A-Za-z \-]+)/i;
  const codeRegex = /(?:CPT|HCPCS|Code)[:\s]*([A-Za-z0-9]{4,6})/i;
  for (const line of lines) {
    if (!claimNumber) {
      const m = claimRegex.exec(line);
      if (m) claimNumber = m[1];
    }
    if (!payer) {
      const m2 = payerRegex.exec(line);
      if (m2) payer = m2[1].trim();
    }
    const m3 = codeRegex.exec(line);
    if (m3) codes.push(m3[1]);
  }
  return { claimNumber, payer, codes };
}
function analyseDenial(text, structured) {
  const lower = text.toLowerCase();
  let category = 'Unknown';
  let summary = 'Unable to determine reason for denial.';
  let suggestions = [];
  if (lower.includes('documentation') || lower.includes('missing')) {
    category = 'Documentation missing';
    summary = 'The payer indicated that required documentation is missing.';
    suggestions = [
      'Review the medical records and include all necessary notes.',
      'Double-check that all attachments are uploaded.',
    ];
  } else if (lower.includes('coverage') || lower.includes('not covered')) {
    category = 'Coverage issues';
    summary = 'The service may not be covered under the patient’s plan.';
    suggestions = [
      'Verify the patient’s coverage and benefits.',
      'Consider obtaining a pre-authorization or submitting an appeal if coverage applies.',
    ];
  } else if (lower.includes('coding') || lower.includes('code')) {
    category = 'Coding mismatch';
    summary = 'There appears to be a mismatch between billed codes and payer policy.';
    suggestions = [
      'Check CPT/HCPCS codes for accuracy.',
      'Ensure modifiers and units are correct.',
    ];
  }
  return { category, summary, suggestions };
}
function predictDenialRisk(structured, text) {
  let score = 0;
  score += Math.min(structured.codes.length / 10, 0.3);
  if (!structured.claimNumber) score += 0.3;
  if (!structured.payer) score += 0.2;
  const lower = text.toLowerCase();
  if (lower.includes('appeal')) score += 0.1;
  if (lower.includes('denied')) score += 0.2;
  return Math.min(score, 1.0);
}

// ===== Payment & Contract Parsing Helpers =====
function parseCSV(text) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length);
  if (!lines.length) return { headers: [], rows: [] };
  function splitLine(line) {
    const out = [];
    let cur = '';
    let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQ && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else inQ = !inQ;
      } else if (ch === ',' && !inQ) {
        out.push(cur);
        cur = '';
      } else {
        cur += ch;
      }
    }
    out.push(cur);
    return out.map((s) => s.trim());
  }
  const headers = splitLine(lines[0]).map((h) => h.replace(/^"|"$/g, '').trim());
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = splitLine(lines[i]).map((c) => c.replace(/^"|"$/g, ''));
    const obj = {};
    headers.forEach((h, idx) => (obj[h] = cols[idx] || ''));
    rows.push(obj);
  }
  return { headers, rows };
}
function parsePaymentFile(buffer, filename) {
  const lower = filename.toLowerCase();
  let rows = [];
  if (lower.endsWith('.csv')) {
    const text = buffer.toString('utf8');
    const parsed = parseCSV(text);
    rows = parsed.rows;
  } else {
    // Excel parsing disabled – instruct users to upload CSV
    return [];
  }
  const payments = [];
  for (const row of rows) {
    const getField = (keys) => {
      for (const k of keys) {
        const key = Object.keys(row).find((x) => x.toLowerCase().includes(k));
        if (key) return row[key];
      }
      return '';
    };
    const claimNumber = getField(['claim', 'claim number', 'claim#', 'clm']);
    const payer = getField(['payer', 'insurance', 'carrier', 'plan']);
    const amt = parseFloat(getField(['paid', 'amount', 'payment', 'paid amount', 'allowed'])) || 0;
    const expected = parseFloat(getField(['expected', 'contract', 'allowable']));
    const claimDate = getField(['service date', 'claim date', 'dos']);
    const datePaid = getField(['date', 'paid date', 'payment date', 'remit date']);
    let variance = null;
    if (!Number.isNaN(expected)) variance = expected - amt;
    let daysToPay = null;
    if (claimDate && datePaid) {
      try {
        const t1 = new Date(claimDate).getTime();
        const t2 = new Date(datePaid).getTime();
        daysToPay = Math.round((t2 - t1) / (24 * 60 * 60 * 1000));
      } catch {
        daysToPay = null;
      }
    }
    payments.push({
      claimNumber: claimNumber || '',
      payer: payer || '',
      amountPaid: amt,
      expectedAmount: Number.isNaN(expected) ? null : expected,
      variance,
      claimDate: claimDate || '',
      datePaid: datePaid || '',
      daysToPay,
    });
  }
  return payments;
}
function parseContractFile(buffer, filename) {
  const lower = filename.toLowerCase();
  if (!lower.endsWith('.csv')) return [];
  const text = buffer.toString('utf8');
  const { rows } = parseCSV(text);
  return rows.map((r) => {
    return {
      payer: r.payer || r.Payer || '',
      code: r.code || r.CPT || r.HCPCS || '',
      rate: parseFloat(r.rate || r.allowed || r.allowable) || 0,
    };
  });
}

function expectedAmountForClaim(claim, contracts) {
  let expected = 0;
  for (const code of claim.codes || []) {
    const match = contracts.find((c) => c.payer === claim.payer && c.code === code);
    if (match) expected += match.rate;
  }
  return expected;
}
function comparePaymentsAgainstContracts(payments, contracts) {
  return payments.map((p) => {
    const expected = expectedAmountForClaim({ payer: p.payer, codes: [p.claimNumber] }, contracts);
    const variance = expected ? expected - p.amountPaid : null;
    const underpaid = variance !== null && variance > 0;
    return { ...p, expectedAmount: expected, variance, underpaid };
  });
}

// ===== Analytics Helpers =====
function computePaymentAnalytics(payments, threshold = 0) {
  const byPayer = {};
  let totalReimbursement = 0;
  let underpaymentCount = 0;
  let underpaymentValue = 0;
  for (const p of payments) {
    const payer = (p.payer || 'Unknown').trim() || 'Unknown';
    if (!byPayer[payer]) byPayer[payer] = { count: 0, total: 0, days: [] };
    byPayer[payer].count++;
    byPayer[payer].total += p.amountPaid;
    totalReimbursement += p.amountPaid;
    if (p.daysToPay !== null) byPayer[payer].days.push(p.daysToPay);
    if (p.variance !== null && Math.abs(p.variance) > threshold) {
      underpaymentCount++;
      underpaymentValue += p.variance;
    }
  }
  for (const payer in byPayer) {
    const arr = byPayer[payer].days;
    if (arr.length > 0) {
      const sum = arr.reduce((a, b) => a + b, 0);
      byPayer[payer].avgDays = sum / arr.length;
      arr.sort((a, b) => a - b);
      const mid = Math.floor(arr.length / 2);
      byPayer[payer].medianDays = arr.length % 2 === 1 ? arr[mid] : (arr[mid - 1] + arr[mid]) / 2;
    } else {
      byPayer[payer].avgDays = null;
      byPayer[payer].medianDays = null;
    }
  }
  return { byPayer, totalReimbursement, underpaymentCount, underpaymentValue };
}
function computeDenialAnalytics(cases) {
  const byCategory = {};
  let riskSum = 0;
  let riskCount = 0;
  for (const c of cases) {
    if (!c.ai || !c.ai.denial_category) continue;
    const cat = c.ai.denial_category || 'Unknown';
    byCategory[cat] = (byCategory[cat] || 0) + 1;
    if (typeof c.ai.denial_risk === 'number') {
      riskSum += c.ai.denial_risk;
      riskCount++;
    }
  }
  return { byCategory, avgRisk: riskCount ? riskSum / riskCount : null };
}
function computePayerTimeliness(payments) {
  const byPayer = {};
  payments.forEach((p) => {
    if (p.daysToPay === null) return;
    const payer = (p.payer || 'Unknown').trim() || 'Unknown';
    if (!byPayer[payer]) byPayer[payer] = [];
    byPayer[payer].push(p.daysToPay);
  });
  const timeliness = {};
  Object.keys(byPayer).forEach((payer) => {
    const arr = byPayer[payer];
    const avg = arr.reduce((a, b) => a + b, 0) / arr.length;
    arr.sort((a, b) => a - b);
    const mid = Math.floor(arr.length / 2);
    const median = arr.length % 2 ? arr[mid] : (arr[mid - 1] + arr[mid]) / 2;
    timeliness[payer] = { avgDays: avg, medianDays: median };
  });
  return timeliness;
}
function computeServiceLineAnalytics(payments, cases) {
  const byCode = {};
  payments.forEach((p) => {
    const code = p.claimNumber || 'Unknown';
    byCode[code] = byCode[code] || { payments: [], cases: [] };
    byCode[code].payments.push(p);
  });
  cases.forEach((c) => {
    const codes = c.ai && c.ai.structured_data && c.ai.structured_data.codes ? c.ai.structured_data.codes : [];
    codes.forEach((code) => {
      byCode[code] = byCode[code] || { payments: [], cases: [] };
      byCode[code].cases.push(c);
    });
  });
  const analytics = {};
  Object.keys(byCode).forEach((code) => {
    const pList = byCode[code].payments;
    const cList = byCode[code].cases;
    const totalPaid = pList.reduce((a, p) => a + p.amountPaid, 0);
    const expected = pList.reduce((a, p) => a + (p.expectedAmount || 0), 0);
    const variance = expected ? expected - totalPaid : null;
    const denialRate = cList.length ? cList.filter((c) => c.status === 'DENIED').length / cList.length : 0;
    analytics[code] = {
      totalPaid,
      expected,
      variance,
      denialRate,
      countPayments: pList.length,
      countCases: cList.length,
    };
  });
  return analytics;
}

// ===== Admin Attention Helper =====
function buildAdminAttentionSet(orgs) {
  const flagged = new Set();
  const now = Date.now();
  const allUsage = readJSON(FILES.usage, []);
  const cases = readJSON(FILES.cases, []);
  const payments = readJSON(FILES.payments, []);
  orgs.forEach((org) => {
    const pilot = getPilot(org.org_id) || ensurePilot(org.org_id);
    const limits = getLimitProfile(org.org_id);
    const usage = allUsage.find((u) => u.org_id === org.org_id) || getUsage(org.org_id);
    let casePct = 0;
    if (limits.mode === 'pilot') {
      casePct = (usage.pilot_cases_used / PILOT_LIMITS.max_cases_total) * 100;
    } else {
      casePct = (usage.monthly_case_credits_used / limits.case_credits_per_month) * 100;
    }
    let last = 0;
    cases.forEach((c) => {
      if (c.org_id === org.org_id) last = Math.max(last, new Date(c.created_at).getTime());
    });
    payments.forEach((p) => {
      if (p.org_id === org.org_id) last = Math.max(last, new Date(p.created_at).getTime());
    });
    const pilotEnd = pilot ? new Date(pilot.ends_at).getTime() : 0;
    const pilotEndingSoon = pilotEnd && pilotEnd - now <= 7 * 24 * 60 * 60 * 1000;
    const nearLimit = casePct >= 80;
    const noRecentActivity = !last || now - last >= 14 * 24 * 60 * 60 * 1000;
    const noPayments = payments.filter((p) => p.org_id === org.org_id).length === 0;
    if (pilotEndingSoon || nearLimit || noRecentActivity || noPayments) {
      flagged.add(org.org_id);
    }
  });
  return flagged;
}

// ===== Session Models helpers (getOrg, getUserByEmail etc.) =====
function getOrg(org_id) {
  return readJSON(FILES.orgs, []).find((o) => o.org_id === org_id);
}
function getUserByEmail(email) {
  const e = (email || '').toLowerCase();
  return readJSON(FILES.users, []).find((u) => (u.email || '').toLowerCase() === e);
}
function getUserById(user_id) {
  return readJSON(FILES.users, []).find((u) => u.user_id === user_id);
}
function getPilot(org_id) {
  return readJSON(FILES.pilots, []).find((p) => p.org_id === org_id);
}
function ensurePilot(org_id) {
  const pilots = readJSON(FILES.pilots, []);
  let p = pilots.find((x) => x.org_id === org_id);
  if (!p) {
    const started = nowISO();
    const ends = addDaysISO(started, PILOT_DAYS);
    p = { pilot_id: uuid(), org_id, status: 'active', started_at: started, ends_at: ends, retention_delete_at: null };
    pilots.push(p);
    writeJSON(FILES.pilots, pilots);
  }
  return p;
}
function getSub(org_id) {
  return readJSON(FILES.subscriptions, []).find((s) => s.org_id === org_id);
}
function currentMonthKey() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}
function getUsage(org_id) {
  const usage = readJSON(FILES.usage, []);
  let u = usage.find((x) => x.org_id === org_id);
  if (!u) {
    u = {
      org_id,
      pilot_cases_used: 0,
      pilot_payment_rows_used: 0,
      month_key: currentMonthKey(),
      monthly_case_credits_used: 0,
      monthly_case_overage_count: 0,
      monthly_payment_rows_used: 0,
      monthly_payment_credits_used: 0,
      ai_job_timestamps: [],
    };
    usage.push(u);
    writeJSON(FILES.usage, usage);
  }
  if (u.month_key !== currentMonthKey()) {
    u.month_key = currentMonthKey();
    u.monthly_case_credits_used = 0;
    u.monthly_case_overage_count = 0;
    u.monthly_payment_rows_used = 0;
    u.monthly_payment_credits_used = 0;
    writeJSON(FILES.usage, usage);
  }
  return u;
}
function saveUsage(u) {
  const usage = readJSON(FILES.usage, []);
  const idx = usage.findIndex((x) => x.org_id === u.org_id);
  if (idx >= 0) usage[idx] = u;
  else usage.push(u);
  writeJSON(FILES.usage, usage);
}
function auditLog(entry) {
  const audit = readJSON(FILES.audit, []);
  audit.push({ ...entry, at: nowISO() });
  writeJSON(FILES.audit, audit);
}

// ===== Account status =====
function getOrgStatus(org_id) {
  const org = getOrg(org_id);
  return org?.account_status || 'active';
}
function setOrgStatus(org_id, status, reason = '') {
  const orgs = readJSON(FILES.orgs, []);
  const idx = orgs.findIndex((o) => o.org_id === org_id);
  if (idx < 0) return;
  orgs[idx].account_status = status;
  orgs[idx].status_reason = reason || null;
  orgs[idx].status_updated_at = nowISO();
  writeJSON(FILES.orgs, orgs);
}

// ===== Limits =====
function getLimitProfile(org_id) {
  const sub = getSub(org_id);
  if (sub && sub.status === 'active') {
    return {
      mode: 'monthly',
      case_credits_per_month: sub.case_credits_per_month || MONTHLY_DEFAULTS.case_credits_per_month,
      payment_tracking_credits_per_month: sub.payment_tracking_credits_per_month || MONTHLY_DEFAULTS.payment_tracking_credits_per_month,
      max_files_per_case: MONTHLY_DEFAULTS.max_files_per_case,
      max_file_size_mb: MONTHLY_DEFAULTS.max_file_size_mb,
      max_ai_jobs_per_hour: MONTHLY_DEFAULTS.max_ai_jobs_per_hour,
      max_concurrent_analyzing: MONTHLY_DEFAULTS.max_concurrent_analyzing,
      overage_price_per_case: MONTHLY_DEFAULTS.overage_price_per_case,
      payment_records_per_credit: MONTHLY_DEFAULTS.payment_records_per_credit,
    };
  }
  return { mode: 'pilot', ...PILOT_LIMITS };
}
function countOrgCases(org_id) {
  return readJSON(FILES.cases, []).filter((c) => c.org_id === org_id).length;
}
function countOrgAnalyzing(org_id) {
  return readJSON(FILES.cases, []).filter((c) => c.org_id === org_id && c.status === 'ANALYZING').length;
}
function canStartAI(org_id) {
  const limits = getLimitProfile(org_id);
  const usage = getUsage(org_id);
  const analyzing = countOrgAnalyzing(org_id);
  const cap = limits.max_concurrent_analyzing;
  if (analyzing >= cap) return { ok: false, reason: `Concurrent processing limit reached (${cap}). Try again shortly.` };
  const perHour = limits.max_ai_jobs_per_hour;
  const cutoff = Date.now() - 60 * 60 * 1000;
  usage.ai_job_timestamps = (usage.ai_job_timestamps || []).filter((ts) => ts > cutoff);
  if (usage.ai_job_timestamps.length >= perHour) {
    saveUsage(usage);
    return { ok: false, reason: `AI job rate limit reached (${perHour}/hour). Try again shortly.` };
  }
  return { ok: true };
}
function recordAIJob(org_id) {
  const usage = getUsage(org_id);
  const cutoff = Date.now() - 60 * 60 * 1000;
  usage.ai_job_timestamps = (usage.ai_job_timestamps || []).filter((ts) => ts > cutoff);
  usage.ai_job_timestamps.push(Date.now());
  saveUsage(usage);
}
function pilotCanCreateCase(org_id) {
  const limits = getLimitProfile(org_id);
  if (limits.mode !== 'pilot') return { ok: true };
  const total = countOrgCases(org_id);
  if (total >= limits.max_cases_total) return { ok: false, reason: `Pilot case limit reached (${limits.max_cases_total}). Continue monthly access to review more.` };
  return { ok: true };
}
function pilotConsumeCase(org_id) {
  const usage = getUsage(org_id);
  usage.pilot_cases_used += 1;
  saveUsage(usage);
}
function monthlyConsumeCaseCredit(org_id) {
  const limits = getLimitProfile(org_id);
  if (limits.mode !== 'monthly') return { ok: true, overage: false };
  const usage = getUsage(org_id);
  usage.monthly_case_credits_used += 1;
  let overage = false;
  if (usage.monthly_case_credits_used > limits.case_credits_per_month) {
    overage = true;
    usage.monthly_case_overage_count += 1;
  }
  saveUsage(usage);
  return { ok: true, overage };
}
function paymentRowsAllowance(org_id) {
  const limits = getLimitProfile(org_id);
  const usage = getUsage(org_id);
  if (limits.mode === 'pilot') {
    const remaining = Math.max(0, PILOT_LIMITS.payment_records_included - (usage.pilot_payment_rows_used || 0));
    return { remaining, mode: 'pilot' };
  }
  const allowedRows = (limits.payment_tracking_credits_per_month || 0) * PAYMENT_RECORDS_PER_CREDIT;
  const used = usage.monthly_payment_rows_used || 0;
  return { remaining: Math.max(0, allowedRows - used), mode: 'monthly' };
}
function consumePaymentRows(org_id, rowCount) {
  const limits = getLimitProfile(org_id);
  const usage = getUsage(org_id);
  if (limits.mode === 'pilot') {
    usage.pilot_payment_rows_used = (usage.pilot_payment_rows_used || 0) + rowCount;
    saveUsage(usage);
    return;
  }
  usage.monthly_payment_rows_used = (usage.monthly_payment_rows_used || 0) + rowCount;
  usage.monthly_payment_credits_used = (usage.monthly_payment_credits_used || 0) + Math.ceil(rowCount / PAYMENT_RECORDS_PER_CREDIT);
  saveUsage(usage);
}

// ===== Multipart Parser =====
async function parseMultipart(req, boundary) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const buffer = Buffer.concat(chunks);
      const boundaryBuf = Buffer.from(`--${boundary}`);
      const parts = [];
      let start = buffer.indexOf(boundaryBuf);
      while (start !== -1) {
        const end = buffer.indexOf(boundaryBuf, start + boundaryBuf.length);
        if (end === -1) break;
        const part = buffer.slice(start + boundaryBuf.length, end);
        if (part.length < 4) break;
        parts.push(part);
        start = end;
      }
      const files = [];
      const fields = {};
      for (const raw of parts) {
        const part = raw.slice(2);
        const headerEnd = part.indexOf(Buffer.from('\r\n\r\n'));
        if (headerEnd === -1) continue;
        const headerText = part.slice(0, headerEnd).toString('utf8');
        const content = part.slice(headerEnd + 4, part.length - 2);
        const nameMatch = /name="([^\"]+)"/i.exec(headerText);
        if (!nameMatch) continue;
        const fieldName = nameMatch[1];
        const fileMatch = /filename="([^\"]*)"/i.exec(headerText);
        if (fileMatch && fileMatch[1]) {
          const filename = fileMatch[1];
          const mimeMatch = /Content-Type:\s*([^\r\n]+)/i.exec(headerText);
          const mime = mimeMatch ? mimeMatch[1].trim() : 'application/octet-stream';
          files.push({ fieldName, filename, mime, buffer: content });
        } else {
          fields[fieldName] = content.toString('utf8');
        }
      }
      resolve({ files, fields });
    });
    req.on('error', reject);
  });
}

// ===== Router =====
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const method = req.method;
  const sess = getAuth(req);
  // Cleanup expired data if logged in
  if (sess && sess.org_id) cleanupIfExpired(sess.org_id);
  // Health check
  if (method === 'GET' && pathname === '/health') return send(res, 200, 'ok', 'text/plain');
  // Admin login
  if (method === 'GET' && pathname === '/admin/login') {
    const html = `<html><body><h2>Admin Login</h2><form method="POST" action="/admin/login"><input name="email" placeholder="email"/><input name="password" type="password" placeholder="password"/><button type="submit">Sign In</button></form></body></html>`;
    return send(res, 200, html);
  }
  if (method === 'POST' && pathname === '/admin/login') {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const email = (params.get('email') || '').trim().toLowerCase();
    const pass = params.get('password') || '';
    const aHash = adminHash();
    if (!ADMIN_EMAIL || !aHash) return send(res, 403, 'Admin mode not configured', 'text/plain');
    if (email !== ADMIN_EMAIL || !bcrypt.compareSync(pass, aHash)) return send(res, 401, 'Invalid credentials', 'text/plain');
    const exp = Date.now() + SESSION_TTL_DAYS * 86400 * 1000;
    const token = makeSession({ role: 'admin', exp });
    setCookie(res, 'tjhp_session', token, SESSION_TTL_DAYS * 86400);
    return redirect(res, '/admin/dashboard');
  }
  // TODO: Add UI pages (omitted for brevity)
  // For this reference implementation we focus on API routes and data
  // manipulations instead of HTML rendering.  In a full system,
  // existing UI code would be merged here.
  // --- API: Upload Contracts ---
  if (method === 'POST' && pathname === '/api/contracts') {
    const ct = req.headers['content-type'] || '';
    if (!ct.includes('multipart/form-data')) return send(res, 400, JSON.stringify({ error: 'Invalid upload' }), 'application/json');
    const boundaryMatch = /boundary=([^;]+)/.exec(ct);
    if (!boundaryMatch) return send(res, 400, JSON.stringify({ error: 'Missing boundary' }), 'application/json');
    const boundary = boundaryMatch[1];
    const { files } = await parseMultipart(req, boundary);
    const f = files[0];
    if (!f || !f.filename.toLowerCase().endsWith('.csv')) return send(res, 400, JSON.stringify({ error: 'Only CSV contracts accepted' }), 'application/json');
    const contracts = parseContractFile(f.buffer, f.filename);
    const existing = readJSON(FILES.contracts, []);
    writeJSON(FILES.contracts, existing.concat(contracts));
    return send(res, 200, JSON.stringify({ imported: contracts.length }), 'application/json');
  }
  // --- API: Upload case (with documents) ---
  if (method === 'POST' && pathname === '/api/upload-case') {
    if (!sess || sess.role !== 'user') return send(res, 401, JSON.stringify({ error: 'Unauthorized' }), 'application/json');
    const ct = req.headers['content-type'] || '';
    if (!ct.includes('multipart/form-data')) return send(res, 400, JSON.stringify({ error: 'Invalid upload' }), 'application/json');
    const boundaryMatch = /boundary=([^;]+)/.exec(ct);
    if (!boundaryMatch) return send(res, 400, JSON.stringify({ error: 'Missing boundary' }), 'application/json');
    const boundary = boundaryMatch[1];
    const { files, fields } = await parseMultipart(req, boundary);
    if (!files.length) return send(res, 400, JSON.stringify({ error: 'No files' }), 'application/json');
    const can = pilotCanCreateCase(sess.org_id);
    if (!can.ok) return send(res, 403, JSON.stringify({ error: can.reason }), 'application/json');
    // Create case record
    const case_id = uuid();
    const caseDir = path.join(UPLOADS_DIR, sess.org_id, case_id);
    ensureDir(caseDir);
    const storedFiles = files.map((f) => {
      const safeName = (f.filename || 'file').replace(/[^a-zA-Z0-9._-]/g, '_');
      const file_id = uuid();
      const stored_path = path.join(caseDir, `${file_id}_${safeName}`);
      fs.writeFileSync(stored_path, f.buffer);
      return { file_id, filename: safeName, mime: f.mime, size_bytes: f.buffer.length, stored_path, uploaded_at: nowISO() };
    });
    const cases = readJSON(FILES.cases, []);
    const caseObj = {
      case_id,
      org_id: sess.org_id,
      created_by_user_id: sess.user_id,
      created_at: nowISO(),
      status: 'UPLOAD_RECEIVED',
      notes: fields.notes || '',
      files: storedFiles,
      ai_started_at: null,
      ai: {
        structured_data: null,
        denial_category: null,
        denial_summary: null,
        denial_suggestions: [],
        denial_risk: null,
        draft_text: null,
        time_to_draft_seconds: 0,
      },
      // Task fields (for future workflow enhancements)
      assigned_to: null,
      due_date: null,
      task_status: 'open',
      resolution_notes: '',
      resolved_at: null,
    };
    cases.push(caseObj);
    writeJSON(FILES.cases, cases);
    // Trigger OCR and denial analysis
    const ocrText = await performOCR(files);
    const structured = extractStructuredData(ocrText);
    const denialInfo = analyseDenial(ocrText, structured);
    const risk = predictDenialRisk(structured, ocrText);
    caseObj.ai.structured_data = structured;
    caseObj.ai.denial_category = denialInfo.category;
    caseObj.ai.denial_summary = denialInfo.summary;
    caseObj.ai.denial_suggestions = denialInfo.suggestions;
    caseObj.ai.denial_risk = risk;
    writeJSON(FILES.cases, cases);
    return send(res, 201, JSON.stringify({ case_id, denial: caseObj.ai }), 'application/json');
  }
  // --- API: Upload payments ---
  if (method === 'POST' && pathname === '/api/payments') {
    if (!sess || sess.role !== 'user') return send(res, 401, JSON.stringify({ error: 'Unauthorized' }), 'application/json');
    const ct = req.headers['content-type'] || '';
    if (!ct.includes('multipart/form-data')) return send(res, 400, JSON.stringify({ error: 'Invalid upload' }), 'application/json');
    const boundaryMatch = /boundary=([^;]+)/.exec(ct);
    if (!boundaryMatch) return send(res, 400, JSON.stringify({ error: 'Missing boundary' }), 'application/json');
    const boundary = boundaryMatch[1];
    const { files } = await parseMultipart(req, boundary);
    const f = files[0];
    if (!f) return send(res, 400, JSON.stringify({ error: 'No file' }), 'application/json');
    const limits = getLimitProfile(sess.org_id);
    const maxBytes = limits.max_file_size_mb * 1024 * 1024;
    if (f.buffer.length > maxBytes) return send(res, 400, JSON.stringify({ error: `File too large. Max size is ${limits.max_file_size_mb} MB.` }), 'application/json');
    const payments = parsePaymentFile(f.buffer, f.filename);
    // Compare against contracts
    const contracts = readJSON(FILES.contracts, []);
    const enhanced = comparePaymentsAgainstContracts(payments, contracts);
    // Limit number of rows used
    const allowance = paymentRowsAllowance(sess.org_id);
    const remaining = allowance.remaining;
    const toUse = Math.min(remaining, enhanced.length);
    const storeLimit = Math.min(toUse, 500);
    const paymentsData = readJSON(FILES.payments, []);
    for (let i = 0; i < storeLimit; i++) {
      const p = enhanced[i];
      paymentsData.push({
        payment_id: uuid(),
        org_id: sess.org_id,
        claim_number: p.claimNumber,
        payer: p.payer,
        amount_paid: p.amountPaid,
        date_paid: p.datePaid,
        claim_date: p.claimDate,
        expected_amount: p.expectedAmount,
        variance: p.variance,
        days_to_pay: p.daysToPay,
        underpaid: p.underpaid,
        source_file: f.filename,
        created_at: nowISO(),
      });
    }
    writeJSON(FILES.payments, paymentsData);
    consumePaymentRows(sess.org_id, toUse);
    const metrics = computePaymentAnalytics(enhanced, 0);
    return send(res, 200, JSON.stringify({ imported: enhanced.length, metrics }), 'application/json');
  }
  // --- API: Feedback ---
  if (method === 'POST' && pathname === '/api/feedback') {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const feedbacks = readJSON(FILES.feedback, []);
      feedbacks.push({ id: uuid(), caseId: params.get('caseId') || '', rating: parseInt(params.get('rating'), 10) || null, comments: params.get('comments') || '', submittedAt: nowISO() });
      writeJSON(FILES.feedback, feedbacks);
      send(res, 201, JSON.stringify({ success: true }), 'application/json');
    });
    return;
  }
  // --- API: Analytics ---
  if (method === 'GET' && pathname === '/api/analytics') {
    if (!sess || sess.role !== 'user') return send(res, 401, JSON.stringify({ error: 'Unauthorized' }), 'application/json');
    const cases = readJSON(FILES.cases, []).filter((c) => c.org_id === sess.org_id);
    const payments = readJSON(FILES.payments, []).filter((p) => p.org_id === sess.org_id);
    const denialAnalytics = computeDenialAnalytics(cases);
    const paymentAnalytics = computePaymentAnalytics(payments, 0);
    const timeliness = computePayerTimeliness(payments);
    const serviceLines = computeServiceLineAnalytics(payments, cases);
    return send(res, 200, JSON.stringify({ denialAnalytics, paymentAnalytics, timeliness, serviceLines }), 'application/json');
  }
  // --- API: Payer report ---
  if (method === 'GET' && pathname === '/export/payer-report.csv') {
    if (!sess || sess.role !== 'user') return send(res, 401, 'Unauthorized', 'text/plain');
    const payments = readJSON(FILES.payments, []).filter((p) => p.org_id === sess.org_id);
    const cases = readJSON(FILES.cases, []).filter((c) => c.org_id === sess.org_id);
    const payers = [...new Set(payments.map((p) => p.payer || 'Unknown'))];
    const cards = payers.map((payer) => {
      const payerPayments = payments.filter((p) => (p.payer || 'Unknown') === payer);
      const metrics = computePaymentAnalytics(payerPayments, 0);
      const time = computePayerTimeliness(payerPayments)[payer] || {};
      const payerCases = cases.filter((c) => c.ai && c.ai.structured_data && c.ai.structured_data.payer === payer);
      const denialMetrics = computeDenialAnalytics(payerCases);
      const topCategory = Object.keys(denialMetrics.byCategory || {}).sort((a, b) => (denialMetrics.byCategory[b] || 0) - (denialMetrics.byCategory[a] || 0))[0] || 'N/A';
      return {
        payer,
        totalPaid: metrics.byPayer[payer]?.total || 0,
        underpaymentCount: metrics.underpaymentCount || 0,
        avgDaysToPay: time.avgDays || null,
        medianDaysToPay: time.medianDays || null,
        topDenialCategory: topCategory,
        avgDenialRisk: denialMetrics.avgRisk || 0,
      };
    });
    if (!cards.length) return send(res, 200, '', 'text/csv');
    const header = Object.keys(cards[0]).join(',');
    const rows = cards.map((c) => Object.values(c).map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const csv = [header, rows].join('\n');
    res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=payer_report.csv' });
    return res.end(csv);
  }
  // Fallback
  return send(res, 404, 'Not Found', 'text/plain');
});

server.listen(PORT, HOST, () => {
  console.log(`Enhanced TJHP server listening on ${HOST}:${PORT}`);
});
