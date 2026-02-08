/**
 * TJ Healthcare Pro — V1 Pilot App (single-file)
 * - Pro UI, Signup/Login/Reset Password
 * - Org isolation + Admin console
 * - Pilot limits + Monthly credits + Payment tracking (CSV/XLS allowed; CSV parsed)
 * - Case upload (any 1–3 files) -> AI stub (minutes) -> editable draft
 * - Analytics + Exports
 * - Post-pilot: 14-day retention delete if not subscribed
 * - Shopify activation hook (manual endpoint now; swap to webhook later)
 *
 * Dependency: bcryptjs
 */

const http = require("http");
const url = require("url");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

// ===== Server =====
const HOST = "0.0.0.0";
const PORT = process.env.PORT || 8080;

// ===== ENV =====
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_ME_SESSION_SECRET";
const APP_BASE_URL = process.env.APP_BASE_URL || ""; // e.g. https://app.tjhealthpro.com
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").toLowerCase();
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";
const ADMIN_PASSWORD_PLAIN = process.env.ADMIN_PASSWORD_PLAIN || "";
const ADMIN_ACTIVATE_TOKEN = process.env.ADMIN_ACTIVATE_TOKEN || "CHANGE_ME_ADMIN_ACTIVATE_TOKEN";

// ===== Timing =====
const LOCK_SCREEN_MS = 5000;
const SESSION_TTL_DAYS = 7;
const AI_JOB_DELAY_MS = Number(process.env.AI_JOB_DELAY_MS || 20000); // demo default 20s

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
  payment_records_included: 2000, // pilot payment tracking rows
};

const MONTHLY_DEFAULTS = {
  case_credits_per_month: 40,         // Standard default
  payment_tracking_credits_per_month: 10, // 10k rows/mo if 1 credit=1k rows
  max_files_per_case: 3,
  max_file_size_mb: 20,
  max_ai_jobs_per_hour: 5,
  max_concurrent_analyzing: 5,
  overage_price_per_case: 50,
  payment_records_per_credit: 1000,
};

// Payment tracking credits
const PAYMENT_RECORDS_PER_CREDIT = 1000;

// ===== Storage =====
const BASE_DIR = __dirname;
const DATA_DIR = path.join(BASE_DIR, "data");
const UPLOADS_DIR = path.join(BASE_DIR, "uploads");

const FILES = {
  orgs: path.join(DATA_DIR, "orgs.json"),
  users: path.join(DATA_DIR, "users.json"),
  pilots: path.join(DATA_DIR, "pilots.json"),
  subscriptions: path.join(DATA_DIR, "subscriptions.json"),
  cases: path.join(DATA_DIR, "cases.json"),
  payments: path.join(DATA_DIR, "payments.json"), // parsed payment rows (limited)
  expectations: path.join(DATA_DIR, "expectations.json"),
  flags: path.join(DATA_DIR, "flags.json"),
  usage: path.join(DATA_DIR, "usage.json"),
  audit: path.join(DATA_DIR, "audit.json"),
};

// ===== Helpers =====
function uuid() { return crypto.randomUUID(); }
function nowISO() { return new Date().toISOString(); }
function addDaysISO(iso, days) { const d = new Date(iso); d.setDate(d.getDate() + days); return d.toISOString(); }

function ensureDir(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); }
function ensureFile(p, defaultVal) { if (!fs.existsSync(p)) fs.writeFileSync(p, JSON.stringify(defaultVal, null, 2)); }
function readJSON(p, fallback) { ensureFile(p, fallback); return JSON.parse(fs.readFileSync(p, "utf8") || JSON.stringify(fallback)); }
function writeJSON(p, val) { fs.writeFileSync(p, JSON.stringify(val, null, 2)); }

function safeStr(s) {
  return String(s ?? "").replace(/[<>&"]/g, (c) => ({ "<":"&lt;", ">":"&gt;", "&":"&amp;", '"':"&quot;" }[c]));
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").map(x => x.trim()).filter(Boolean).forEach(pair => {
    const idx = pair.indexOf("=");
    if (idx > -1) out[pair.slice(0, idx)] = decodeURIComponent(pair.slice(idx+1));
  });
  return out;
}

function setCookie(res, name, value, maxAgeSeconds) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "SameSite=Lax",
    "HttpOnly",
    "Secure"
  ];
  if (maxAgeSeconds) parts.push(`Max-Age=${maxAgeSeconds}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", `${name}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly; Secure`);
}

function send(res, status, body, type="text/html") {
  res.writeHead(status, { "Content-Type": type });
  res.end(body);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function parseBody(req) {
  return new Promise(resolve => {
    let body = "";
    req.on("data", c => body += c);
    req.on("end", () => resolve(body));
  });
}

// ===== Session =====
function hmacSign(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}
function makeSession(payload) {
  const json = JSON.stringify(payload);
  const b64 = Buffer.from(json).toString("base64url");
  const sig = hmacSign(b64, SESSION_SECRET);
  return `${b64}.${sig}`;
}
function verifySession(token) {
  if (!token || !token.includes(".")) return null;
  const [b64, sig] = token.split(".");
  const expected = hmacSign(b64, SESSION_SECRET);
  if (sig !== expected) return null;
  try {
    const json = Buffer.from(b64, "base64url").toString("utf8");
    const payload = JSON.parse(json);
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}
function getAuth(req) {
  const cookies = parseCookies(req);
  return verifySession(cookies.tjhp_session);
}

// ===== Init storage =====
ensureDir(DATA_DIR);
ensureDir(UPLOADS_DIR);
ensureFile(FILES.orgs, []);
ensureFile(FILES.users, []);
ensureFile(FILES.pilots, []);
ensureFile(FILES.subscriptions, []);
ensureFile(FILES.cases, []);
ensureFile(FILES.payments, []);
ensureFile(FILES.expectations, []);
ensureFile(FILES.flags, []);
ensureFile(FILES.usage, []);
ensureFile(FILES.audit, []);

// ===== Admin password =====
function adminHash() {
  if (ADMIN_PASSWORD_HASH) return ADMIN_PASSWORD_HASH;
  if (ADMIN_PASSWORD_PLAIN) return bcrypt.hashSync(ADMIN_PASSWORD_PLAIN, 10);
  return "";
}

// ===== UI =====
const css = `
:root{
  --bg:#f6f7fb; --card:#fff; --text:#111827; --muted:#6b7280;
  --border:#e5e7eb; --primary:#111827; --primaryText:#fff;
  --danger:#b91c1c; --warn:#92400e; --ok:#065f46;
  --shadow:0 12px 30px rgba(17,24,39,.06);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);}
.wrap{max-width:980px;margin:28px auto;padding:0 16px;}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;}
.brand{display:flex;flex-direction:column;gap:2px;}
.brand h1{font-size:18px;margin:0;}
.brand .sub{font-size:12px;color:var(--muted);}
.nav{display:flex;gap:12px;flex-wrap:wrap;}
.nav a{text-decoration:none;color:var(--muted);font-weight:700;font-size:13px;}
.nav a:hover{color:var(--text);}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:var(--shadow);}
.row{display:flex;gap:14px;flex-wrap:wrap;}
.col{flex:1;min-width:280px;}
h2{margin:0 0 10px;font-size:22px;}
h3{margin:16px 0 8px;font-size:15px;}
p{margin:8px 0;line-height:1.5;}
.muted{color:var(--muted);font-size:13px;}
.hr{height:1px;background:var(--border);margin:14px 0;}
.btn{display:inline-block;background:var(--primary);color:var(--primaryText);border:none;border-radius:10px;padding:10px 14px;font-weight:800;text-decoration:none;cursor:pointer;font-size:13px;}
.btn.secondary{background:#fff;color:var(--text);border:1px solid var(--border);}
.btn.danger{background:var(--danger);}
.btnRow{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;}
label{font-size:12px;color:var(--muted);font-weight:800;}
input,textarea{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:10px;font-size:14px;outline:none;margin-top:6px;}
input:focus,textarea:focus{border-color:#c7d2fe;box-shadow:0 0 0 3px rgba(99,102,241,.12);}
textarea{min-height:220px;}
.badge{display:inline-block;border:1px solid var(--border);background:#fff;border-radius:999px;padding:4px 10px;font-size:12px;font-weight:900;}
.badge.ok{border-color:#a7f3d0;background:#ecfdf5;color:var(--ok);}
.badge.warn{border-color:#fde68a;background:#fffbeb;color:var(--warn);}
.badge.err{border-color:#fecaca;background:#fef2f2;color:var(--danger);}
.footer{margin-top:14px;padding-top:12px;border-top:1px solid var(--border);font-size:12px;color:var(--muted);}
.error{color:var(--danger);font-weight:900;}
.small{font-size:12px;}
table{width:100%;border-collapse:collapse;font-size:13px;}
th,td{padding:8px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;}
`;

function page(title, content, navHtml="") {
  return `<!doctype html>
<html><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${safeStr(title)}</title>
<style>${css}</style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <h1>TJ Healthcare Pro</h1>
        <div class="sub">AI-Assisted Claim Review & Analytics</div>
      </div>
      <div class="nav">${navHtml}</div>
    </div>
    <div class="card">
      ${content}
      <div class="footer">
        No EMR access · No payer portal access · No automated submissions · Human review required before use.
      </div>
    </div>
  </div>
</body></html>`;
}

function navPublic() {
  return `<a href="/login">Login</a><a href="/signup">Create Account</a><a href="/admin/login">Owner</a>`;
}
function navUser() {
  return `<a href="/dashboard">Dashboard</a><a href="/upload">Case Upload</a><a href="/payments">Payment Tracking</a><a href="/analytics">Analytics</a><a href="/exports">Exports</a><a href="/logout">Logout</a>`;
}
function navAdmin() {
  return `<a href="/admin/dashboard">Admin</a><a href="/admin/orgs">Organizations</a><a href="/admin/audit">Audit</a><a href="/logout">Logout</a>`;
}

// ===== Models helpers =====
function getOrg(org_id) {
  return readJSON(FILES.orgs, []).find(o => o.org_id === org_id);
}
function getUserByEmail(email) {
  const e = (email || "").toLowerCase();
  return readJSON(FILES.users, []).find(u => (u.email || "").toLowerCase() === e);
}
function getUserById(user_id) {
  return readJSON(FILES.users, []).find(u => u.user_id === user_id);
}
function getPilot(org_id) {
  return readJSON(FILES.pilots, []).find(p => p.org_id === org_id);
}
function ensurePilot(org_id) {
  const pilots = readJSON(FILES.pilots, []);
  let p = pilots.find(x => x.org_id === org_id);
  if (!p) {
    const started = nowISO();
    const ends = addDaysISO(started, PILOT_DAYS);
    p = { pilot_id: uuid(), org_id, status:"active", started_at: started, ends_at: ends, retention_delete_at: null };
    pilots.push(p);
    writeJSON(FILES.pilots, pilots);
  }
  return p;
}
function getSub(org_id) {
  return readJSON(FILES.subscriptions, []).find(s => s.org_id === org_id);
}
function getUsage(org_id) {
  const usage = readJSON(FILES.usage, []);
  let u = usage.find(x => x.org_id === org_id);
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
      ai_job_timestamps: []
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
  const idx = usage.findIndex(x => x.org_id === u.org_id);
  if (idx >= 0) usage[idx] = u; else usage.push(u);
  writeJSON(FILES.usage, usage);
}
function currentMonthKey() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}`;
}
function auditLog(entry) {
  const audit = readJSON(FILES.audit, []);
  audit.push({ ...entry, at: nowISO() });
  writeJSON(FILES.audit, audit);
}

// ===== Account status =====
function getOrgStatus(org_id) {
  const org = getOrg(org_id);
  return org?.account_status || "active";
}
function setOrgStatus(org_id, status, reason="") {
  const orgs = readJSON(FILES.orgs, []);
  const idx = orgs.findIndex(o => o.org_id === org_id);
  if (idx < 0) return;
  orgs[idx].account_status = status; // active|suspended|terminated
  orgs[idx].status_reason = reason || null;
  orgs[idx].status_updated_at = nowISO();
  writeJSON(FILES.orgs, orgs);
}

// ===== Pilot/sub access =====
function markPilotComplete(org_id) {
  const pilots = readJSON(FILES.pilots, []);
  const idx = pilots.findIndex(p => p.org_id === org_id);
  if (idx < 0) return;
  pilots[idx].status = "complete";
  pilots[idx].retention_delete_at = addDaysISO(pilots[idx].ends_at, RETENTION_DAYS_AFTER_PILOT);
  writeJSON(FILES.pilots, pilots);
}

function isAccessEnabled(org_id) {
  const status = getOrgStatus(org_id);
  if (status === "terminated" || status === "suspended") return false;

  const sub = getSub(org_id);
  if (sub && sub.status === "active") return true;

  const pilot = getPilot(org_id) || ensurePilot(org_id);
  if (new Date(pilot.ends_at).getTime() < Date.now() && pilot.status !== "complete") {
    markPilotComplete(org_id);
  }
  const p2 = getPilot(org_id);
  return p2 && p2.status === "active";
}

function cleanupIfExpired(org_id) {
  const sub = getSub(org_id);
  if (sub && sub.status === "active") return;

  const pilot = getPilot(org_id);
  if (!pilot) return;

  if (pilot.status !== "complete") {
    if (new Date(pilot.ends_at).getTime() < Date.now()) markPilotComplete(org_id);
    return;
  }
  if (!pilot.retention_delete_at) return;

  const delAt = new Date(pilot.retention_delete_at).getTime();
  if (Date.now() < delAt) return;

  // Delete org-scoped files and data
  const cases = readJSON(FILES.cases, []).filter(c => c.org_id !== org_id);
  const payments = readJSON(FILES.payments, []).filter(p => p.org_id !== org_id);
  const expectations = readJSON(FILES.expectations, []).filter(e => e.org_id !== org_id);
  const flags = readJSON(FILES.flags, []).filter(f => f.org_id !== org_id);

  writeJSON(FILES.cases, cases);
  writeJSON(FILES.payments, payments);
  writeJSON(FILES.expectations, expectations);
  writeJSON(FILES.flags, flags);

  const orgUploads = path.join(UPLOADS_DIR, org_id);
  if (fs.existsSync(orgUploads)) fs.rmSync(orgUploads, { recursive:true, force:true });
}

// ===== Limits =====
function getLimitProfile(org_id) {
  const sub = getSub(org_id);
  if (sub && sub.status === "active") {
    return {
      mode: "monthly",
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
  return { mode:"pilot", ...PILOT_LIMITS };
}

function countOrgCases(org_id) {
  return readJSON(FILES.cases, []).filter(c => c.org_id === org_id).length;
}
function countOrgAnalyzing(org_id) {
  return readJSON(FILES.cases, []).filter(c => c.org_id === org_id && c.status === "ANALYZING").length;
}

function canStartAI(org_id) {
  const limits = getLimitProfile(org_id);
  const usage = getUsage(org_id);

  const analyzing = countOrgAnalyzing(org_id);
  const cap = limits.max_concurrent_analyzing;
  if (analyzing >= cap) return { ok:false, reason:`Concurrent processing limit reached (${cap}). Try again shortly.` };

  const perHour = limits.max_ai_jobs_per_hour;
  const cutoff = Date.now() - 60*60*1000;
  usage.ai_job_timestamps = (usage.ai_job_timestamps || []).filter(ts => ts > cutoff);

  if (usage.ai_job_timestamps.length >= perHour) {
    saveUsage(usage);
    return { ok:false, reason:`AI job rate limit reached (${perHour}/hour). Try again shortly.` };
  }
  return { ok:true };
}
function recordAIJob(org_id) {
  const usage = getUsage(org_id);
  const cutoff = Date.now() - 60*60*1000;
  usage.ai_job_timestamps = (usage.ai_job_timestamps || []).filter(ts => ts > cutoff);
  usage.ai_job_timestamps.push(Date.now());
  saveUsage(usage);
}

function pilotCanCreateCase(org_id) {
  const limits = getLimitProfile(org_id);
  if (limits.mode !== "pilot") return { ok:true };
  const total = countOrgCases(org_id);
  if (total >= limits.max_cases_total) return { ok:false, reason:`Pilot case limit reached (${limits.max_cases_total}). Continue monthly access to review more.` };
  return { ok:true };
}
function pilotConsumeCase(org_id) {
  const usage = getUsage(org_id);
  usage.pilot_cases_used += 1;
  saveUsage(usage);
}
function monthlyConsumeCaseCredit(org_id) {
  const limits = getLimitProfile(org_id);
  if (limits.mode !== "monthly") return { ok:true, overage:false };
  const usage = getUsage(org_id);
  usage.monthly_case_credits_used += 1;
  let overage = false;
  if (usage.monthly_case_credits_used > limits.case_credits_per_month) {
    overage = true;
    usage.monthly_case_overage_count += 1;
  }
  saveUsage(usage);
  return { ok:true, overage };
}

function paymentRowsAllowance(org_id) {
  const limits = getLimitProfile(org_id);
  const usage = getUsage(org_id);

  if (limits.mode === "pilot") {
    const remaining = Math.max(0, PILOT_LIMITS.payment_records_included - (usage.pilot_payment_rows_used || 0));
    return { remaining, mode:"pilot" };
  }
  const allowedRows = (limits.payment_tracking_credits_per_month || 0) * PAYMENT_RECORDS_PER_CREDIT;
  const used = usage.monthly_payment_rows_used || 0;
  return { remaining: Math.max(0, allowedRows - used), mode:"monthly" };
}

function consumePaymentRows(org_id, rowCount) {
  const limits = getLimitProfile(org_id);
  const usage = getUsage(org_id);

  if (limits.mode === "pilot") {
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
    req.on("data", c => chunks.push(c));
    req.on("end", () => {
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
        const headerEnd = part.indexOf(Buffer.from("\r\n\r\n"));
        if (headerEnd === -1) continue;

        const headerText = part.slice(0, headerEnd).toString("utf8");
        const content = part.slice(headerEnd + 4, part.length - 2);

        const nameMatch = /name="([^"]+)"/.exec(headerText);
        if (!nameMatch) continue;
        const fieldName = nameMatch[1];

        const fileMatch = /filename="([^"]*)"/.exec(headerText);
        if (fileMatch && fileMatch[1]) {
          const filename = fileMatch[1];
          const mimeMatch = /Content-Type:\s*([^\r\n]+)/.exec(headerText);
          const mime = mimeMatch ? mimeMatch[1].trim() : "application/octet-stream";
          files.push({ fieldName, filename, mime, buffer: content });
        } else {
          fields[fieldName] = content.toString("utf8");
        }
      }

      resolve({ files, fields });
    });
    req.on("error", reject);
  });
}

// ===== CSV parser =====
function parseCSV(text) {
  const lines = text.split(/\r?\n/).filter(l => l.trim().length);
  if (!lines.length) return { headers: [], rows: [] };

  function splitLine(line) {
    const out = [];
    let cur = "";
    let inQ = false;
    for (let i=0;i<line.length;i++){
      const ch = line[i];
      if (ch === '"') {
        if (inQ && line[i+1] === '"') { cur += '"'; i++; }
        else inQ = !inQ;
      } else if (ch === "," && !inQ) {
        out.push(cur); cur="";
      } else {
        cur += ch;
      }
    }
    out.push(cur);
    return out.map(s => s.trim());
  }

  const headers = splitLine(lines[0]).map(h => h.replace(/^"|"$/g,"").trim());
  const rows = [];
  for (let i=1;i<lines.length;i++){
    const cols = splitLine(lines[i]).map(c => c.replace(/^"|"$/g,""));
    const obj = {};
    headers.forEach((h, idx) => obj[h] = cols[idx] || "");
    rows.push(obj);
  }
  return { headers, rows };
}

function pickField(row, candidates) {
  const keys = Object.keys(row || {});
  for (const c of candidates) {
    const k = keys.find(x => x.toLowerCase().includes(c));
    if (k) return row[k];
  }
  return "";
}

// ===== AI stub =====
function aiGenerate(orgName) {
  return {
    denial_summary: "Based on the uploaded documents, this case includes denial/payment language that benefits from structured review and consistent appeal framing.",
    appeal_considerations: "This draft is prepared from uploaded materials only. Validate documentation supports medical necessity and payer requirements before use.",
    draft_text:
`To Whom It May Concern,

We are writing to appeal the denial associated with this claim. Based on the documentation provided, the services rendered were medically necessary and appropriately supported. Please reconsider the determination after reviewing the attached materials.

Sincerely,
${orgName || "[Organization Billing Team]"}
`,
    denial_reason_category: "Documentation missing",
    missing_info: []
  };
}

function maybeCompleteAI(caseObj, orgName) {
  if (caseObj.status !== "ANALYZING") return caseObj;
  const started = new Date(caseObj.ai_started_at).getTime();
  if (!started) return caseObj;
  if (Date.now() - started < AI_JOB_DELAY_MS) return caseObj;

  const out = aiGenerate(orgName);
  caseObj.ai.denial_summary = out.denial_summary;
  caseObj.ai.appeal_considerations = out.appeal_considerations;
  caseObj.ai.draft_text = out.draft_text;
  caseObj.ai.denial_reason_category = out.denial_reason_category;
  caseObj.ai.missing_info = out.missing_info;
  caseObj.ai.time_to_draft_seconds = Math.max(1, Math.floor((Date.now()-started)/1000));
  caseObj.status = "DRAFT_READY";
  return caseObj;
}

// ===== Analytics =====
function computeAnalytics(org_id) {
  const cases = readJSON(FILES.cases, []).filter(c => c.org_id === org_id);
  const payments = readJSON(FILES.payments, []).filter(p => p.org_id === org_id);

  const totalCases = cases.length;
  const drafts = cases.filter(c => c.status === "DRAFT_READY" || c.ai?.draft_text).length;

  const avgDraftSeconds = (() => {
    const xs = cases.map(c => c.ai?.time_to_draft_seconds).filter(v => typeof v === "number" && v > 0);
    if (!xs.length) return null;
    return Math.round(xs.reduce((a,b)=>a+b,0) / xs.length);
  })();

  const payerDenials = {}; // best-effort from payments/notes/files names; keep simple
  const denialReasons = {};
  for (const c of cases) {
    const reason = c.ai?.denial_reason_category || "Unknown";
    denialReasons[reason] = (denialReasons[reason] || 0) + 1;
  }

  const payByPayer = {};
  for (const p of payments) {
    const payer = (p.payer || "Unknown").trim() || "Unknown";
    payByPayer[payer] = payByPayer[payer] || { count: 0, total: 0 };
    payByPayer[payer].count += 1;
    payByPayer[payer].total += Number(p.amount_paid || 0);
  }

  return { totalCases, drafts, avgDraftSeconds, denialReasons, payByPayer };
}
// ===== ROUTER =====
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const method = req.method;

  // health
  if (method === "GET" && pathname === "/health") return send(res, 200, "ok", "text/plain");

  // auth
  const sess = getAuth(req);
  if (sess && sess.org_id) cleanupIfExpired(sess.org_id);

  // ---------- PUBLIC: Admin login ----------
  if (method === "GET" && pathname === "/admin/login") {
    const html = page("Owner Login", `
      <h2>Owner Login</h2>
      <p class="muted">This area is for the system owner only.</p>
      <form method="POST" action="/admin/login">
        <label>Email</label>
        <input name="email" type="email" required />
        <label>Password</label>
        <input name="password" type="password" required />
        <div class="btnRow">
          <button class="btn" type="submit">Sign In</button>
          <a class="btn secondary" href="/login">Back</a>
        </div>
      </form>
      <p class="muted small">Set ADMIN_EMAIL and ADMIN_PASSWORD_PLAIN (or ADMIN_PASSWORD_HASH) in Railway.</p>
    `, navPublic());
    return send(res, 200, html);
  }

  if (method === "POST" && pathname === "/admin/login") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const email = (params.get("email") || "").trim().toLowerCase();
    const pass = params.get("password") || "";

    const aHash = adminHash();
    if (!ADMIN_EMAIL || !aHash) {
      const html = page("Owner Login", `
        <h2>Owner Login</h2>
        <p class="error">Admin mode not configured. Set ADMIN_EMAIL and ADMIN_PASSWORD_PLAIN (or ADMIN_PASSWORD_HASH) in Railway.</p>
        <div class="btnRow"><a class="btn secondary" href="/admin/login">Back</a></div>
      `, navPublic());
      return send(res, 403, html);
    }

    if (email !== ADMIN_EMAIL || !bcrypt.compareSync(pass, aHash)) {
      const html = page("Owner Login", `
        <h2>Owner Login</h2>
        <p class="error">Invalid owner credentials.</p>
        <div class="btnRow"><a class="btn secondary" href="/admin/login">Try again</a></div>
      `, navPublic());
      return send(res, 401, html);
    }

    const exp = Date.now() + SESSION_TTL_DAYS * 86400 * 1000;
    const token = makeSession({ role:"admin", exp });
    setCookie(res, "tjhp_session", token, SESSION_TTL_DAYS * 86400);
    return redirect(res, "/admin/dashboard");
  }

  // ---------- PUBLIC: Signup/Login/Reset ----------
  if (method === "GET" && pathname === "/signup") {
    const html = page("Create Account", `
      <h2>Create Account</h2>
      <p class="muted">Secure, organization-based access to AI-assisted claim review and analytics.</p>
      <form method="POST" action="/signup">
        <label>Work Email</label>
        <input name="email" type="email" required />
        <label>Password (8+ characters)</label>
        <input name="password" type="password" required />
        <label>Confirm Password</label>
        <input name="password2" type="password" required />
        <label>Organization Name</label>
        <input name="org_name" type="text" required />
        <label style="display:flex;gap:10px;align-items:flex-start;margin-top:12px;">
          <input type="checkbox" name="ack" required style="width:auto;margin:0;margin-top:2px;">
          <span class="muted">I understand this system does not access EMRs or payer portals and does not submit appeals automatically.</span>
        </label>
        <div class="btnRow">
          <button class="btn" type="submit">Create Account</button>
          <a class="btn secondary" href="/login">Sign In</a>
        </div>
      </form>
    `, navPublic());
    return send(res, 200, html);
  }

  if (method === "POST" && pathname === "/signup") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);

    const email = (params.get("email") || "").trim().toLowerCase();
    const p1 = params.get("password") || "";
    const p2 = params.get("password2") || "";
    const orgName = (params.get("org_name") || "").trim();
    const ack = params.get("ack");

    if (!email || p1.length < 8 || p1 !== p2 || !orgName || !ack) {
      const html = page("Create Account", `
        <h2>Create Account</h2>
        <p class="error">Please complete all fields, confirm password, and accept the acknowledgement.</p>
        <div class="btnRow"><a class="btn secondary" href="/signup">Back</a></div>
      `, navPublic());
      return send(res, 400, html);
    }

    const users = readJSON(FILES.users, []);
    if (users.find(u => (u.email || "").toLowerCase() === email)) {
      const html = page("Create Account", `
        <h2>Create Account</h2>
        <p class="error">An account with this email already exists.</p>
        <div class="btnRow"><a class="btn" href="/login">Sign In</a></div>
      `, navPublic());
      return send(res, 400, html);
    }

    const orgs = readJSON(FILES.orgs, []);
    const org_id = uuid();
    orgs.push({ org_id, org_name: orgName, created_at: nowISO(), account_status:"active" });
    writeJSON(FILES.orgs, orgs);

    users.push({
      user_id: uuid(),
      org_id,
      email,
      password_hash: bcrypt.hashSync(p1, 10),
      created_at: nowISO(),
      last_login_at: nowISO(),
    });
    writeJSON(FILES.users, users);

    ensurePilot(org_id);
    getUsage(org_id);

    const exp = Date.now() + SESSION_TTL_DAYS * 86400 * 1000;
    const token = makeSession({ role:"user", user_id: users[users.length-1].user_id, org_id, exp });
    setCookie(res, "tjhp_session", token, SESSION_TTL_DAYS * 86400);

    return redirect(res, "/lock");
  }

  if (method === "GET" && pathname === "/login") {
    const html = page("Login", `
      <h2>Sign In</h2>
      <p class="muted">Access your organization’s claim review and analytics workspace.</p>
      <form method="POST" action="/login">
        <label>Email</label>
        <input name="email" type="email" required />
        <label>Password</label>
        <input name="password" type="password" required />
        <div class="btnRow">
          <button class="btn" type="submit">Sign In</button>
          <a class="btn secondary" href="/signup">Create Account</a>
        </div>
      </form>
      <div class="btnRow">
        <a class="btn secondary" href="/forgot-password">Forgot password?</a>
      </div>
    `, navPublic());
    return send(res, 200, html);
  }

  if (method === "POST" && pathname === "/login") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const email = (params.get("email") || "").trim().toLowerCase();
    const pass = params.get("password") || "";

    const user = getUserByEmail(email);
    if (!user || !bcrypt.compareSync(pass, user.password_hash)) {
      const html = page("Login", `
        <h2>Sign In</h2>
        <p class="error">The email or password you entered is incorrect.</p>
        <div class="btnRow"><a class="btn secondary" href="/login">Try again</a></div>
      `, navPublic());
      return send(res, 401, html);
    }

    const org = getOrg(user.org_id);
    if (!org) return redirect(res, "/login");
    if (org.account_status === "terminated") return redirect(res, "/terminated");
    if (org.account_status === "suspended") return redirect(res, "/suspended");

    ensurePilot(user.org_id);
    const exp = Date.now() + SESSION_TTL_DAYS * 86400 * 1000;
    const token = makeSession({ role:"user", user_id:user.user_id, org_id:user.org_id, exp });
    setCookie(res, "tjhp_session", token, SESSION_TTL_DAYS * 86400);

    return redirect(res, "/lock");
  }

  if (method === "GET" && pathname === "/forgot-password") {
    const html = page("Reset Password", `
      <h2>Reset Password</h2>
      <p class="muted">Enter your email to generate a reset link (expires in 20 minutes). For v1, the link is shown on-screen.</p>
      <form method="POST" action="/forgot-password">
        <label>Email</label>
        <input name="email" type="email" required />
        <div class="btnRow">
          <button class="btn" type="submit">Generate Reset Link</button>
          <a class="btn secondary" href="/login">Back</a>
        </div>
      </form>
    `, navPublic());
    return send(res, 200, html);
  }

  if (method === "POST" && pathname === "/forgot-password") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const email = (params.get("email") || "").trim().toLowerCase();

    const token = uuid();
    const expiresAt = Date.now() + 20*60*1000;
    const users = readJSON(FILES.users, []);
    const idx = users.findIndex(u => (u.email||"").toLowerCase() === email);
    if (idx >= 0) {
      users[idx].reset_token = token;
      users[idx].reset_expires_at = expiresAt;
      writeJSON(FILES.users, users);
    }

    const resetPath = `/reset-password?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;
    const resetLink = APP_BASE_URL ? `${APP_BASE_URL}${resetPath}` : resetPath;

    const html = page("Reset Link", `
      <h2>Reset Link Generated</h2>
      <p class="muted">For v1, the reset link is displayed here.</p>
      <div class="btnRow">
        <a class="btn" href="${safeStr(resetLink)}">Reset Password Now</a>
        <a class="btn secondary" href="/login">Back to login</a>
      </div>
    `, navPublic());
    return send(res, 200, html);
  }

  if (method === "GET" && pathname === "/reset-password") {
    const token = parsed.query.token || "";
    const email = (parsed.query.email || "").toLowerCase();
    const html = page("Set New Password", `
      <h2>Set a New Password</h2>
      <form method="POST" action="/reset-password">
        <input type="hidden" name="email" value="${safeStr(email)}"/>
        <input type="hidden" name="token" value="${safeStr(token)}"/>
        <label>New Password (8+ characters)</label>
        <input name="password" type="password" required />
        <label>Confirm New Password</label>
        <input name="password2" type="password" required />
        <div class="btnRow">
          <button class="btn" type="submit">Update Password</button>
          <a class="btn secondary" href="/login">Cancel</a>
        </div>
      </form>
    `, navPublic());
    return send(res, 200, html);
  }

  if (method === "POST" && pathname === "/reset-password") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const email = (params.get("email") || "").trim().toLowerCase();
    const token = params.get("token") || "";
    const p1 = params.get("password") || "";
    const p2 = params.get("password2") || "";

    if (p1.length < 8 || p1 !== p2) {
      const html = page("Set New Password", `
        <h2>Set a New Password</h2>
        <p class="error">Passwords must match and be at least 8 characters.</p>
        <div class="btnRow"><a class="btn secondary" href="/forgot-password">Try again</a></div>
      `, navPublic());
      return send(res, 400, html);
    }

    const users = readJSON(FILES.users, []);
    const idx = users.findIndex(u => (u.email||"").toLowerCase() === email);
    if (idx < 0) return redirect(res, "/login");

    const u = users[idx];
    if (!u.reset_token || u.reset_token !== token || !u.reset_expires_at || Date.now() > u.reset_expires_at) {
      const html = page("Reset Error", `
        <h2>Reset Link Invalid</h2>
        <p class="error">This reset link is expired or invalid.</p>
        <div class="btnRow"><a class="btn secondary" href="/forgot-password">Generate new link</a></div>
      `, navPublic());
      return send(res, 400, html);
    }

    users[idx].password_hash = bcrypt.hashSync(p1, 10);
    delete users[idx].reset_token;
    delete users[idx].reset_expires_at;
    writeJSON(FILES.users, users);

    return redirect(res, "/login");
  }

  if (method === "GET" && pathname === "/logout") {
    clearCookie(res, "tjhp_session");
    return redirect(res, "/login");
  }

  if (method === "GET" && pathname === "/suspended") {
    return send(res, 200, page("Suspended", `
      <h2>Account Suspended</h2>
      <p>Your organization’s access is currently suspended.</p>
      <p class="muted">If you believe this is an error, contact support.</p>
      <div class="btnRow"><a class="btn secondary" href="/logout">Logout</a></div>
    `, navPublic()));
  }

  if (method === "GET" && pathname === "/terminated") {
    return send(res, 200, page("Terminated", `
      <h2>Account Terminated</h2>
      <p>This account has been terminated. Access to the workspace is no longer available.</p>
      <p class="muted">If you believe this is an error, contact support.</p>
      <div class="btnRow"><a class="btn secondary" href="/logout">Logout</a></div>
    `, navPublic()));
  }

  // Shopify activation (manual now)
  if (method === "GET" && pathname === "/shopify/activate") {
    const token = parsed.query.token || "";
    const email = (parsed.query.email || "").toLowerCase();
    const status = parsed.query.status || "inactive";
    if (token !== ADMIN_ACTIVATE_TOKEN) return send(res, 401, "Unauthorized", "text/plain");
    const user = getUserByEmail(email);
    if (!user) return send(res, 404, "User not found", "text/plain");

    const subs = readJSON(FILES.subscriptions, []);
    let s = subs.find(x => x.org_id === user.org_id);
    if (!s) {
      s = {
        sub_id: uuid(),
        org_id: user.org_id,
        status: "inactive",
        customer_email: email,
        case_credits_per_month: MONTHLY_DEFAULTS.case_credits_per_month,
        payment_tracking_credits_per_month: MONTHLY_DEFAULTS.payment_tracking_credits_per_month,
        updated_at: nowISO()
      };
      subs.push(s);
    }
    s.status = (status === "active") ? "active" : "inactive";
    s.updated_at = nowISO();
    writeJSON(FILES.subscriptions, subs);

    if (s.status === "active") {
      // cancel deletion schedule
      const pilots = readJSON(FILES.pilots, []);
      const pidx = pilots.findIndex(p => p.org_id === user.org_id);
      if (pidx >= 0) {
        pilots[pidx].retention_delete_at = null;
        writeJSON(FILES.pilots, pilots);
      }
    }
    return send(res, 200, `Subscription set to ${s.status} for ${email}`, "text/plain");
  }

  // ---------- ADMIN ROUTES ----------
  if (pathname.startsWith("/admin/")) {
    const isAdmin = sess && sess.role === "admin";
    if (!isAdmin && pathname !== "/admin/login") return redirect(res, "/admin/login");

    if (method === "GET" && pathname === "/admin/dashboard") {
      const orgs = readJSON(FILES.orgs, []);
      const users = readJSON(FILES.users, []);
      const pilots = readJSON(FILES.pilots, []);
      const subs = readJSON(FILES.subscriptions, []);
      const cases = readJSON(FILES.cases, []);

      const activePilots = pilots.filter(p => p.status === "active").length;
      const activeSubs = subs.filter(s => s.status === "active").length;
      const suspended = orgs.filter(o => o.account_status === "suspended").length;
      const terminated = orgs.filter(o => o.account_status === "terminated").length;

      const html = page("Owner Admin", `
        <h2>Owner Admin</h2>
        <div class="row">
          <div class="col">
            <div class="card" style="box-shadow:none;">
              <table>
                <tr><th>Organizations</th><td>${orgs.length}</td></tr>
                <tr><th>Users</th><td>${users.length}</td></tr>
                <tr><th>Active pilots</th><td>${activePilots}</td></tr>
                <tr><th>Active subscriptions</th><td>${activeSubs}</td></tr>
                <tr><th>Suspended</th><td>${suspended}</td></tr>
                <tr><th>Terminated</th><td>${terminated}</td></tr>
                <tr><th>Total cases</th><td>${cases.length}</td></tr>
              </table>
              <div class="btnRow">
                <a class="btn" href="/admin/orgs">Organizations</a>
                <a class="btn secondary" href="/admin/audit">Audit Log</a>
              </div>
            </div>
          </div>
          <div class="col">
            <div class="card" style="box-shadow:none;">
              <h3>Notes</h3>
              <p class="muted">Admin can view org plans and analytics, suspend/terminate, extend pilot, and force reset links. Admin does not impersonate users.</p>
            </div>
          </div>
        </div>
      `, navAdmin());
      return send(res, 200, html);
    }

    if (method === "GET" && pathname === "/admin/orgs") {
      const orgs = readJSON(FILES.orgs, []);
      const pilots = readJSON(FILES.pilots, []);
      const subs = readJSON(FILES.subscriptions, []);
      const usage = readJSON(FILES.usage, []);

      const rows = orgs.map(o => {
        const p = pilots.find(x => x.org_id === o.org_id);
        const s = subs.find(x => x.org_id === o.org_id);
        const u = usage.find(x => x.org_id === o.org_id) || {};
        const status = o.account_status || "active";
        const plan = (s && s.status==="active") ? "Monthly" : (p && p.status==="active" ? "Pilot" : "Expired");
        const badge = status==="active" ? "ok" : (status==="suspended" ? "warn" : "err");
        return `
          <tr>
            <td>${safeStr(o.org_name)}</td>
            <td><span class="badge ${badge}">${safeStr(status)}</span></td>
            <td>${plan}</td>
            <td class="muted small">${p ? new Date(p.ends_at).toLocaleDateString() : "—"}</td>
            <td class="muted small">${p?.retention_delete_at ? new Date(p.retention_delete_at).toLocaleDateString() : "—"}</td>
            <td class="muted small">${u.pilot_cases_used || 0}/${PILOT_LIMITS.max_cases_total}</td>
            <td><a class="btn secondary" href="/admin/org?org_id=${encodeURIComponent(o.org_id)}">Open</a></td>
          </tr>`;
      }).join("");

      const html = page("Organizations", `
        <h2>Organizations</h2>
        <div style="overflow:auto;">
          <table>
            <thead>
              <tr><th>Organization</th><th>Status</th><th>Plan</th><th>Pilot End</th><th>Delete At</th><th>Pilot Cases Used</th><th></th></tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `, navAdmin());
      return send(res, 200, html);
    }

    if (method === "GET" && pathname === "/admin/org") {
      const org_id = parsed.query.org_id || "";
      const org = getOrg(org_id);
      if (!org) return redirect(res, "/admin/orgs");

      const users = readJSON(FILES.users, []).filter(u => u.org_id === org_id);
      const pilot = getPilot(org_id) || ensurePilot(org_id);
      const sub = getSub(org_id);
      const usage = getUsage(org_id);
      const a = computeAnalytics(org_id);

      const plan = (sub && sub.status==="active") ? "Monthly (active)" : (pilot.status==="active" ? "Pilot (active)" : "Expired");

      // create reset links (v1 display)
      const resetList = users.map(usr => {
        const token = uuid();
        const expiresAt = Date.now() + 20*60*1000;
        const all = readJSON(FILES.users, []);
        const idx = all.findIndex(x => x.user_id === usr.user_id);
        if (idx >= 0) {
          all[idx].reset_token = token;
          all[idx].reset_expires_at = expiresAt;
          writeJSON(FILES.users, all);
        }
        const pathOnly = `/reset-password?token=${encodeURIComponent(token)}&email=${encodeURIComponent(usr.email)}`;
        const full = APP_BASE_URL ? `${APP_BASE_URL}${pathOnly}` : pathOnly;
        return `<li class="muted small">${safeStr(usr.email)} — <a href="${safeStr(full)}">Reset Link</a></li>`;
      }).join("");

      const html = page("Org Detail", `
        <h2>${safeStr(org.org_name)}</h2>
        <div class="row">
          <div class="col">
            <h3>Account</h3>
            <table>
              <tr><th>Status</th><td>${safeStr(org.account_status || "active")}</td></tr>
              <tr><th>Plan</th><td>${plan}</td></tr>
              <tr><th>Pilot ends</th><td>${new Date(pilot.ends_at).toLocaleDateString()}</td></tr>
              <tr><th>Deletion date</th><td>${pilot.retention_delete_at ? new Date(pilot.retention_delete_at).toLocaleDateString() : "—"}</td></tr>
              <tr><th>Pilot cases used</th><td>${usage.pilot_cases_used || 0}/${PILOT_LIMITS.max_cases_total}</td></tr>
              <tr><th>Pilot payment rows</th><td>${usage.pilot_payment_rows_used || 0}/${PILOT_LIMITS.payment_records_included}</td></tr>
              <tr><th>Drafts generated</th><td>${a.drafts}</td></tr>
              <tr><th>Avg draft time</th><td>${a.avgDraftSeconds ? `${a.avgDraftSeconds}s` : "—"}</td></tr>
            </table>

            <h3>Actions</h3>
            <form method="POST" action="/admin/action">
              <input type="hidden" name="org_id" value="${safeStr(org_id)}"/>
              <label>Reason (required)</label>
              <input name="reason" required />
              <div class="btnRow">
                <button class="btn secondary" name="action" value="extend_pilot_7">Extend Pilot +7 days</button>
                <button class="btn secondary" name="action" value="suspend">Suspend</button>
                <button class="btn danger" name="action" value="terminate">Terminate</button>
              </div>
            </form>
          </div>

          <div class="col">
            <h3>Users</h3>
            <ul class="muted">${users.map(x => `<li>${safeStr(x.email)}</li>`).join("") || "<li>—</li>"}</ul>

            <div class="hr"></div>
            <h3>Force Password Reset (v1 display)</h3>
            <ul>${resetList || "<li class='muted small'>No users</li>"}</ul>
          </div>
        </div>
      `, navAdmin());
      return send(res, 200, html);
    }

    if (method === "POST" && pathname === "/admin/action") {
      const body = await parseBody(req);
      const params = new URLSearchParams(body);
      const org_id = params.get("org_id") || "";
      const action = params.get("action") || "";
      const reason = (params.get("reason") || "").trim();
      if (!org_id || !action || !reason) return redirect(res, "/admin/orgs");

      if (action === "suspend") {
        setOrgStatus(org_id, "suspended", reason);
        auditLog({ actor:"admin", action:"suspend", org_id, reason });
      } else if (action === "terminate") {
        setOrgStatus(org_id, "terminated", reason);
        // schedule deletion 14 days from now
        const pilots = readJSON(FILES.pilots, []);
        const idx = pilots.findIndex(p => p.org_id === org_id);
        if (idx >= 0) {
          pilots[idx].status = "complete";
          pilots[idx].retention_delete_at = addDaysISO(nowISO(), RETENTION_DAYS_AFTER_PILOT);
          writeJSON(FILES.pilots, pilots);
        }
        auditLog({ actor:"admin", action:"terminate", org_id, reason });
      } else if (action === "extend_pilot_7") {
        const pilots = readJSON(FILES.pilots, []);
        const idx = pilots.findIndex(p => p.org_id === org_id);
        if (idx >= 0) {
          pilots[idx].ends_at = addDaysISO(pilots[idx].ends_at, 7);
          writeJSON(FILES.pilots, pilots);
        }
        auditLog({ actor:"admin", action:"extend_pilot_7", org_id, reason });
      }
      return redirect(res, `/admin/org?org_id=${encodeURIComponent(org_id)}`);
    }

    if (method === "GET" && pathname === "/admin/audit") {
      const audit = readJSON(FILES.audit, []);
      const rows = audit.slice(-200).reverse().map(a => `
        <tr>
          <td class="muted small">${safeStr(a.at)}</td>
          <td>${safeStr(a.action)}</td>
          <td class="muted small">${safeStr(a.org_id || "")}</td>
          <td class="muted small">${safeStr(a.reason || "")}</td>
        </tr>`).join("");

      const html = page("Audit Log", `
        <h2>Audit Log</h2>
        <p class="muted">Latest 200 admin actions.</p>
        <div style="overflow:auto;">
          <table>
            <thead><tr><th>Time</th><th>Action</th><th>Org</th><th>Reason</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `, navAdmin());
      return send(res, 200, html);
    }

    return redirect(res, "/admin/dashboard");
  }

  // ---------- USER PROTECTED ROUTES ----------
  if (!sess || sess.role !== "user") return redirect(res, "/login");

  const user = getUserById(sess.user_id);
  if (!user) return redirect(res, "/login");

  const org = getOrg(user.org_id);
  if (!org) return redirect(res, "/login");

  cleanupIfExpired(org.org_id);

  if (org.account_status === "terminated") return redirect(res, "/terminated");
  if (org.account_status === "suspended") return redirect(res, "/suspended");

  ensurePilot(org.org_id);
  getUsage(org.org_id);

  if (!isAccessEnabled(org.org_id)) return redirect(res, "/pilot-complete");

  // lock screen
  if (method === "GET" && pathname === "/lock") {
    const html = page("Starting", `
      <h2 class="center">Pilot Started</h2>
      <p class="center">We’re preparing your secure workspace to help you track what was billed, denied, appealed, and paid — and surface patterns that are easy to miss when data lives in different places.</p>
      <p class="muted center">You’ll be guided to the next step automatically.</p>
      <div class="center"><span class="badge warn">Initializing</span></div>
      <script>setTimeout(()=>{window.location.href="/upload";}, ${LOCK_SCREEN_MS});</script>
    `, navUser());
    return send(res, 200, html);
  }

  // dashboard
  if (method === "GET" && (pathname === "/" || pathname === "/dashboard")) {
    const limits = getLimitProfile(org.org_id);
    const usage = getUsage(org.org_id);
    const pilot = getPilot(org.org_id) || ensurePilot(org.org_id);

    const paymentAllowance = paymentRowsAllowance(org.org_id);
    const planBadge = (limits.mode==="monthly") ? `<span class="badge ok">Monthly Active</span>` : `<span class="badge warn">Pilot Active</span>`;

    const html = page("Dashboard", `
      <div class="row">
        <div class="col">
          <h2>Dashboard</h2>
          <p class="muted">Organization: ${safeStr(org.org_name)} · Pilot ends: ${new Date(pilot.ends_at).toLocaleDateString()}</p>
          ${planBadge}
          <div class="hr"></div>
          <h3>Usage</h3>
          ${limits.mode==="pilot" ? `
            <ul class="muted">
              <li>Cases remaining: ${PILOT_LIMITS.max_cases_total - countOrgCases(org.org_id)} / ${PILOT_LIMITS.max_cases_total}</li>
              <li>AI jobs/hour: ${PILOT_LIMITS.max_ai_jobs_per_hour}</li>
              <li>Concurrent processing: ${PILOT_LIMITS.max_concurrent_analyzing}</li>
              <li>Payment rows remaining: ${paymentAllowance.remaining} (pilot includes ${PILOT_LIMITS.payment_records_included})</li>
            </ul>
          ` : `
            <ul class="muted">
              <li>Case credits used: ${usage.monthly_case_credits_used} / ${limits.case_credits_per_month}</li>
              <li>Overage cases: ${usage.monthly_case_overage_count} (est. $${usage.monthly_case_overage_count * limits.overage_price_per_case})</li>
              <li>Payment rows remaining: ${paymentAllowance.remaining}</li>
            </ul>
          `}
          <div class="btnRow">
            <a class="btn" href="/upload">Start Case Review</a>
            <a class="btn secondary" href="/payments">Payment Tracking</a>
            <a class="btn secondary" href="/analytics">Analytics</a>
          </div>
        </div>
        <div class="col">
          <h3>What this does</h3>
          <ul class="muted">
            <li>Denial patterns by payer & reason</li>
            <li>Appeal preparation (editable drafts)</li>
            <li>Claim lifecycle visibility</li>
            <li>Payment timelines (early/late/unpaid)</li>
            <li>Optional expected vs paid flags (future UI)</li>
          </ul>
        </div>
      </div>
    `, navUser());
    return send(res, 200, html);
  }

  // --------- CASE UPLOAD ----------
  if (method === "GET" && pathname === "/upload") {
    const html = page("Case Upload", `
      <h2>Case Upload</h2>
      <p class="muted">Upload any combination of up to <strong>3 documents</strong> for this case. Denial/payment notices alone are enough to begin. Additional docs can improve analytics.</p>
      <form method="POST" action="/upload" enctype="multipart/form-data">
        <label>Documents (up to 3)</label>
        <input name="file1" type="file" required />
        <input name="file2" type="file" />
        <input name="file3" type="file" />
        <label>Optional notes</label>
        <textarea name="notes" placeholder="Any context to help review (optional)"></textarea>
        <div class="btnRow">
          <button class="btn" type="submit">Submit for Review</button>
          <a class="btn secondary" href="/dashboard">Back</a>
        </div>
      </form>
      <div class="hr"></div>
      <p class="muted small">Limits: 3 files/case · ${getLimitProfile(org.org_id).mode==="pilot" ? "10MB/file" : "20MB/file"}</p>
    `, navUser());
    return send(res, 200, html);
  }

  if (method === "POST" && pathname === "/upload") {
    // limit: pilot cases
    const can = pilotCanCreateCase(org.org_id);
    if (!can.ok) {
      const html = page("Limit", `
        <h2>Limit Reached</h2>
        <p class="error">${safeStr(can.reason)}</p>
        <div class="btnRow"><a class="btn secondary" href="/dashboard">Back</a></div>
      `, navUser());
      return send(res, 403, html);
    }

    const contentType = req.headers["content-type"] || "";
    if (!contentType.includes("multipart/form-data")) return send(res, 400, "Invalid upload", "text/plain");
    const boundaryMatch = /boundary=([^;]+)/.exec(contentType);
    if (!boundaryMatch) return send(res, 400, "Missing boundary", "text/plain");
    const boundary = boundaryMatch[1];

    const { files, fields } = await parseMultipart(req, boundary);

    const limits = getLimitProfile(org.org_id);
    const maxFiles = limits.max_files_per_case;
    if (!files.length) return redirect(res, "/upload");
    if (files.length > maxFiles) {
      const html = page("Upload", `
        <h2>Upload</h2>
        <p class="error">Please upload no more than ${maxFiles} files per case.</p>
        <div class="btnRow"><a class="btn secondary" href="/upload">Back</a></div>
      `, navUser());
      return send(res, 400, html);
    }

    const maxBytes = limits.max_file_size_mb * 1024 * 1024;
    for (const f of files) {
      if (f.buffer.length > maxBytes) {
        const html = page("Upload", `
          <h2>Upload</h2>
          <p class="error">File too large. Max size is ${limits.max_file_size_mb} MB.</p>
          <div class="btnRow"><a class="btn secondary" href="/upload">Back</a></div>
        `, navUser());
        return send(res, 400, html);
      }
    }

    // monthly credit consumption (case)
    if (limits.mode === "monthly") monthlyConsumeCaseCredit(org.org_id);
    else pilotConsumeCase(org.org_id);

    // create case record
    const case_id = uuid();
    const caseDir = path.join(UPLOADS_DIR, org.org_id, case_id);
    ensureDir(caseDir);

    const storedFiles = files.map((f) => {
      const safeName = f.filename.replace(/[^a-zA-Z0-9._-]/g, "_");
      const file_id = uuid();
      const stored_path = path.join(caseDir, `${file_id}_${safeName}`);
      fs.writeFileSync(stored_path, f.buffer);
      return {
        file_id,
        filename: safeName,
        mime: f.mime,
        size_bytes: f.buffer.length,
        stored_path,
        uploaded_at: nowISO()
      };
    });

    const cases = readJSON(FILES.cases, []);
    cases.push({
      case_id,
      org_id: org.org_id,
      created_by_user_id: user.user_id,
      created_at: nowISO(),
      status: "UPLOAD_RECEIVED",
      notes: fields.notes || "",
      files: storedFiles,
      ai_started_at: null,
      ai: {
        denial_summary: null,
        appeal_considerations: null,
        draft_text: null,
        denial_reason_category: null,
        missing_info: [],
        time_to_draft_seconds: 0
      }
    });
    writeJSON(FILES.cases, cases);

    // queue AI (respect concurrency + rate)
    const okAI = canStartAI(org.org_id);
    if (!okAI.ok) {
      // leave case in UPLOAD_RECEIVED (queued)
      return redirect(res, `/status?case_id=${encodeURIComponent(case_id)}`);
    }

    // start analyzing
    const cases2 = readJSON(FILES.cases, []);
    const c = cases2.find(x => x.case_id === case_id && x.org_id === org.org_id);
    if (c) {
      c.status = "ANALYZING";
      c.ai_started_at = nowISO();
      writeJSON(FILES.cases, cases2);
      recordAIJob(org.org_id);
    }

    return redirect(res, `/status?case_id=${encodeURIComponent(case_id)}`);
  }

  // status (poll)
  if (method === "GET" && pathname === "/status") {
    const case_id = parsed.query.case_id || "";
    const cases = readJSON(FILES.cases, []);
    const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
    if (!c) return redirect(res, "/dashboard");

    // If queued, attempt to start AI now if capacity available
    if (c.status === "UPLOAD_RECEIVED") {
      const okAI = canStartAI(org.org_id);
      if (okAI.ok) {
        c.status = "ANALYZING";
        c.ai_started_at = nowISO();
        writeJSON(FILES.cases, cases);
        recordAIJob(org.org_id);
      }
    }

    // If analyzing, maybe complete based on timer
    if (c.status === "ANALYZING") {
      maybeCompleteAI(c, org.org_name);
      writeJSON(FILES.cases, cases);
    }

    if (c.status === "DRAFT_READY") return redirect(res, `/draft?case_id=${encodeURIComponent(case_id)}`);

    const badge = c.status === "UPLOAD_RECEIVED"
      ? `<span class="badge warn">Queued</span><p class="muted small">Waiting for capacity (rate/concurrency limits).</p>`
      : `<span class="badge warn">Analyzing</span><p class="muted small">Draft typically prepared within minutes.</p>`;

    const html = page("Status", `
      <h2>Review in Progress</h2>
      <p class="muted">Our AI agent is analyzing your uploaded documents and preparing a draft. This is decision support only.</p>
      ${badge}
      <div class="hr"></div>
      <div class="muted small"><strong>Case ID:</strong> ${safeStr(case_id)}</div>
      <script>setTimeout(()=>window.location.reload(), 2500);</script>
      <div class="btnRow"><a class="btn secondary" href="/dashboard">Back</a></div>
    `, navUser());

    return send(res, 200, html);
  }

  // draft view + edit
  if (method === "GET" && pathname === "/draft") {
    const case_id = parsed.query.case_id || "";
    const cases = readJSON(FILES.cases, []);
    const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
    if (!c) return redirect(res, "/dashboard");

    const html = page("Draft Ready", `
      <h2>Draft Ready for Review</h2>
      <p class="muted">This workspace supports denial review, appeal preparation, claim tracking, and payment analytics using only the documents you provide.</p>
      <div class="badge warn">DRAFT — Editable · For Review Only</div>
      <div class="hr"></div>

      <h3>Denial Summary</h3>
      <p>${safeStr(c.ai.denial_summary || "—")}</p>

      <h3>Appeal Considerations</h3>
      <p>${safeStr(c.ai.appeal_considerations || "—")}</p>

      <h3>Draft Appeal Letter</h3>
      <form method="POST" action="/draft">
        <input type="hidden" name="case_id" value="${safeStr(case_id)}"/>
        <textarea name="draft_text">${safeStr(c.ai.draft_text || "")}</textarea>
        <div class="btnRow">
          <button class="btn" type="submit">Save Edits</button>
          <a class="btn secondary" href="/download-draft?case_id=${encodeURIComponent(case_id)}">Download TXT</a>
          <a class="btn secondary" href="/analytics">Analytics</a>
        </div>
      </form>

      <p class="muted small">Time to draft: ${c.ai.time_to_draft_seconds ? `${c.ai.time_to_draft_seconds}s` : "—"}</p>
    `, navUser());
    return send(res, 200, html);
  }

  if (method === "POST" && pathname === "/draft") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const case_id = params.get("case_id") || "";
    const draft = params.get("draft_text") || "";

    const cases = readJSON(FILES.cases, []);
    const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
    if (!c) return redirect(res, "/dashboard");
    c.ai.draft_text = draft;
    writeJSON(FILES.cases, cases);
    return redirect(res, `/draft?case_id=${encodeURIComponent(case_id)}`);
  }

  if (method === "GET" && pathname === "/download-draft") {
    const case_id = parsed.query.case_id || "";
    const cases = readJSON(FILES.cases, []);
    const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
    if (!c) return redirect(res, "/dashboard");

    res.writeHead(200, {
      "Content-Type": "text/plain",
      "Content-Disposition": `attachment; filename="draft_${case_id}.txt"`
    });
    return res.end(c.ai.draft_text || "");
  }

  // -------- PAYMENT TRACKING (CSV/XLS allowed; CSV parsed) --------
  if (method === "GET" && pathname === "/payments") {
    const allow = paymentRowsAllowance(org.org_id);
    const html = page("Payment Tracking", `
      <h2>Payment Tracking (Analytics Only)</h2>
      <p class="muted">Upload bulk payment files in CSV or Excel format. CSV will be parsed immediately. Excel files are stored and you may export as CSV for best results.</p>
      <p class="muted small"><strong>Rows remaining:</strong> ${allow.remaining}</p>

      <form method="POST" action="/payments" enctype="multipart/form-data">
        <label>Upload CSV/XLS/XLSX (analytics-only)</label>
        <input name="payfile" type="file" required />
        <div class="btnRow">
          <button class="btn" type="submit">Upload for Analytics</button>
          <a class="btn secondary" href="/dashboard">Back</a>
        </div>
      </form>
      <div class="hr"></div>
      <p class="muted small">Note: This does not create appeal drafts. It updates payer and payment timeline analytics.</p>
    `, navUser());
    return send(res, 200, html);
  }

  if (method === "POST" && pathname === "/payments") {
    const contentType = req.headers["content-type"] || "";
    if (!contentType.includes("multipart/form-data")) return send(res, 400, "Invalid upload", "text/plain");
    const boundaryMatch = /boundary=([^;]+)/.exec(contentType);
    if (!boundaryMatch) return send(res, 400, "Missing boundary", "text/plain");
    const boundary = boundaryMatch[1];

    const { files } = await parseMultipart(req, boundary);
    const f = files.find(x => x.fieldName === "payfile") || files[0];
    if (!f) return redirect(res, "/payments");

    // validate extension
    const nameLower = (f.filename || "").toLowerCase();
    const isCSV = nameLower.endsWith(".csv");
    const isXLS = nameLower.endsWith(".xls") || nameLower.endsWith(".xlsx");
    if (!isCSV && !isXLS) {
      const html = page("Payment Tracking", `
        <h2>Payment Tracking</h2>
        <p class="error">Only CSV or Excel files are allowed for payment tracking.</p>
        <div class="btnRow"><a class="btn secondary" href="/payments">Back</a></div>
      `, navUser());
      return send(res, 400, html);
    }

    // file size cap (use same as plan)
    const limits = getLimitProfile(org.org_id);
    const maxBytes = limits.max_file_size_mb * 1024 * 1024;
    if (f.buffer.length > maxBytes) {
      const html = page("Payment Tracking", `
        <h2>Payment Tracking</h2>
        <p class="error">File too large. Max size is ${limits.max_file_size_mb} MB.</p>
        <div class="btnRow"><a class="btn secondary" href="/payments">Back</a></div>
      `, navUser());
      return send(res, 400, html);
    }

    // store raw file
    const dir = path.join(UPLOADS_DIR, org.org_id, "payments");
    ensureDir(dir);
    const stored = path.join(dir, `${Date.now()}_${f.filename.replace(/[^a-zA-Z0-9._-]/g,"_")}`);
    fs.writeFileSync(stored, f.buffer);

    // parse CSV now (rows count & limited record storage)
    let rowsAdded = 0;
    if (isCSV) {
      const text = f.buffer.toString("utf8");
      const parsedCSV = parseCSV(text);
      const rows = parsedCSV.rows;

      const allowance = paymentRowsAllowance(org.org_id);
      const remaining = allowance.remaining;
      const toUse = Math.min(remaining, rows.length);

      // store up to 500 records per upload for demo, but count all used
      const storeLimit = Math.min(toUse, 500);
      const payments = readJSON(FILES.payments, []);

      for (let i=0;i<storeLimit;i++){
        const r = rows[i];
        const claim = pickField(r, ["claim", "claim#", "claim number", "claimnumber", "clm"]);
        const payer = pickField(r, ["payer", "insurance", "carrier", "plan"]);
        const amt = pickField(r, ["paid", "amount", "payment", "paid amount", "allowed"]);
        const datePaid = pickField(r, ["date", "paid date", "payment date", "remit date"]);

        payments.push({
          payment_id: uuid(),
          org_id: org.org_id,
          claim_number: claim || "",
          payer: payer || "",
          amount_paid: amt || "",
          date_paid: datePaid || "",
          source_file: path.basename(stored),
          created_at: nowISO()
        });
      }
      writeJSON(FILES.payments, payments);

      rowsAdded = toUse;
      consumePaymentRows(org.org_id, rowsAdded);
    } else {
      // Excel stored but not parsed in v1 (still counts as 0 rows until CSV provided)
      rowsAdded = 0;
    }

    const html = page("Payment Tracking", `
      <h2>Payment File Received</h2>
      <p class="muted">Your file was uploaded successfully.</p>
      <ul class="muted">
        <li><strong>File:</strong> ${safeStr(f.filename)}</li>
        <li><strong>Rows processed:</strong> ${rowsAdded} ${isXLS ? "(Excel not parsed — export to CSV for full analytics)" : ""}</li>
      </ul>
      <div class="btnRow">
        <a class="btn" href="/analytics">View Analytics</a>
        <a class="btn secondary" href="/payments">Upload more</a>
      </div>
    `, navUser());
    return send(res, 200, html);
  }

  // analytics
  if (method === "GET" && pathname === "/analytics") {
    const a = computeAnalytics(org.org_id);
    const usage = getUsage(org.org_id);
    const limits = getLimitProfile(org.org_id);

    const denialRows = Object.entries(a.denialReasons).sort((x,y)=>y[1]-x[1]).map(([k,v]) => `<li>${safeStr(k)}: ${v}</li>`).join("") || "<li>—</li>";
    const payRows = Object.entries(a.payByPayer).sort((x,y)=>y[1].total-y[1].total).map(([k,v]) => `<li>${safeStr(k)}: ${v.count} payments, $${v.total.toFixed ? v.total.toFixed(2) : v.total}</li>`).join("") || "<li>—</li>";

    const html = page("Analytics", `
      <h2>Claim & Payment Analytics</h2>
      <p class="muted">Derived solely from uploaded documents and user-provided context.</p>
      <div class="row">
        <div class="col">
          <h3>Pilot Snapshot</h3>
          <ul class="muted">
            <li>Cases uploaded: ${a.totalCases}</li>
            <li>Drafts generated: ${a.drafts}</li>
            <li>Avg time to draft: ${a.avgDraftSeconds ? `${a.avgDraftSeconds}s` : "—"}</li>
          </ul>
        </div>
        <div class="col">
          <h3>Usage</h3>
          ${limits.mode==="pilot" ? `
            <ul class="muted">
              <li>Pilot cases used: ${usage.pilot_cases_used}/${PILOT_LIMITS.max_cases_total}</li>
              <li>Pilot payment rows used: ${usage.pilot_payment_rows_used}/${PILOT_LIMITS.payment_records_included}</li>
            </ul>
          ` : `
            <ul class="muted">
              <li>Monthly case credits used: ${usage.monthly_case_credits_used}/${limits.case_credits_per_month}</li>
              <li>Overage cases: ${usage.monthly_case_overage_count} (est $${usage.monthly_case_overage_count*limits.overage_price_per_case})</li>
              <li>Monthly payment rows used: ${usage.monthly_payment_rows_used}</li>
            </ul>
          `}
        </div>
      </div>

      <div class="hr"></div>
      <div class="row">
        <div class="col">
          <h3>Denial Reasons (AI-categorized)</h3>
          <ul class="muted">${denialRows}</ul>
        </div>
        <div class="col">
          <h3>Payments by Payer (from uploads)</h3>
          <ul class="muted">${payRows}</ul>
        </div>
      </div>
    `, navUser());
    return send(res, 200, html);
  }

  // exports hub
  if (method === "GET" && pathname === "/exports") {
    const html = page("Exports", `
      <h2>Exports</h2>
      <p class="muted">Download pilot outputs for leadership and operations review.</p>
      <div class="btnRow">
        <a class="btn secondary" href="/export/cases.csv">Cases CSV</a>
        <a class="btn secondary" href="/export/payments.csv">Payments CSV</a>
        <a class="btn secondary" href="/export/analytics.csv">Analytics CSV</a>
        <a class="btn secondary" href="/report">Printable Pilot Summary</a>
      </div>
    `, navUser());
    return send(res, 200, html);
  }

  if (method === "GET" && pathname === "/export/cases.csv") {
    const cases = readJSON(FILES.cases, []).filter(c => c.org_id === org.org_id);
    const header = ["case_id","status","created_at","time_to_draft_seconds","denial_reason"].join(",");
    const rows = cases.map(c => [
      c.case_id,
      c.status,
      c.created_at,
      c.ai?.time_to_draft_seconds || "",
      c.ai?.denial_reason_category || ""
    ].map(x => `"${String(x).replace(/"/g,'""')}"`).join(","));
    const csv = [header, ...rows].join("\n");

    res.writeHead(200, { "Content-Type":"text/csv", "Content-Disposition":"attachment; filename=cases.csv" });
    return res.end(csv);
  }

  if (method === "GET" && pathname === "/export/payments.csv") {
    const payments = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id);
    const header = ["payment_id","claim_number","payer","amount_paid","date_paid","source_file","created_at"].join(",");
    const rows = payments.map(p => [
      p.payment_id, p.claim_number, p.payer, p.amount_paid, p.date_paid, p.source_file, p.created_at
    ].map(x => `"${String(x||"").replace(/"/g,'""')}"`).join(","));
    const csv = [header, ...rows].join("\n");

    res.writeHead(200, { "Content-Type":"text/csv", "Content-Disposition":"attachment; filename=payments.csv" });
    return res.end(csv);
  }

  if (method === "GET" && pathname === "/export/analytics.csv") {
    const a = computeAnalytics(org.org_id);
    const header = ["metric","value"].join(",");
    const rows = [
      ["cases_uploaded", a.totalCases],
      ["drafts_generated", a.drafts],
      ["avg_time_to_draft_seconds", a.avgDraftSeconds || ""],
    ].map(r => r.map(x => `"${String(x).replace(/"/g,'""')}"`).join(","));
    const csv = [header, ...rows].join("\n");

    res.writeHead(200, { "Content-Type":"text/csv", "Content-Disposition":"attachment; filename=analytics.csv" });
    return res.end(csv);
  }

  if (method === "GET" && pathname === "/report") {
    const a = computeAnalytics(org.org_id);
    const pilot = getPilot(org.org_id) || ensurePilot(org.org_id);
    const html = page("Pilot Summary", `
      <h2>Pilot Summary Report</h2>
      <p class="muted">Organization: ${safeStr(org.org_name)}</p>
      <div class="hr"></div>
      <ul class="muted">
        <li>Pilot start: ${new Date(pilot.started_at).toLocaleDateString()}</li>
        <li>Pilot end: ${new Date(pilot.ends_at).toLocaleDateString()}</li>
      </ul>
      <h3>Snapshot</h3>
      <ul class="muted">
        <li>Cases uploaded: ${a.totalCases}</li>
        <li>Drafts generated: ${a.drafts}</li>
        <li>Avg time to draft: ${a.avgDraftSeconds ? `${a.avgDraftSeconds}s` : "—"}</li>
      </ul>
      <div class="btnRow">
        <button class="btn secondary" onclick="window.print()">Print / Save as PDF</button>
        <a class="btn secondary" href="/exports">Back</a>
      </div>
      <p class="muted small">All insights are derived from uploaded documents during the pilot period.</p>
    `, navUser());
    return send(res, 200, html);
  }

  // pilot complete page
  if (method === "GET" && pathname === "/pilot-complete") {
    const pilot = getPilot(org.org_id) || ensurePilot(org.org_id);
    if (new Date(pilot.ends_at).getTime() < Date.now() && pilot.status !== "complete") markPilotComplete(org.org_id);
    const p2 = getPilot(org.org_id);

    const html = page("Pilot Complete", `
      <h2>Pilot Complete</h2>
      <p>Your 30-day pilot has ended. Existing work remains available during the retention period.</p>
      <div class="hr"></div>
      <p class="muted">
        To limit unnecessary data retention, documents and analytics from this pilot will be securely deleted
        <strong>14 days after the pilot end date</strong> unless you continue monthly access.
      </p>
      <ul class="muted">
        <li>Pilot end date: ${new Date(p2.ends_at).toLocaleDateString()}</li>
        <li>Scheduled deletion date: ${p2.retention_delete_at ? new Date(p2.retention_delete_at).toLocaleDateString() : "—"}</li>
      </ul>
      <div class="btnRow">
        <a class="btn" href="https://tjhealthpro.com">Continue Monthly Access (via Shopify)</a>
        <a class="btn secondary" href="/exports">Download Exports</a>
        <a class="btn secondary" href="/logout">Logout</a>
      </div>
    `, navUser());
    return send(res, 200, html);
  }

  // fallback
  return redirect(res, "/dashboard");
});

server.listen(PORT, HOST, () => {
  console.log(`TJHP server listening on ${HOST}:${PORT}`);
});
