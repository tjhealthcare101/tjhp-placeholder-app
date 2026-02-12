const http = require("http");
const url = require("url");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

// ===== Server =====
const HOST = "0.0.0.0";
const PORT = process.env.PORT || 8080;
const IS_PROD = process.env.NODE_ENV === "production";

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
  case_credits_per_month: 40,              // Standard default
  payment_tracking_credits_per_month: 10,  // 10k rows/mo if 1 credit=1k rows
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
  // New storage for user-uploaded letter templates
  templates: path.join(DATA_DIR, "templates.json"),
};

// Directory for storing uploaded template files
const TEMPLATES_DIR = path.join(DATA_DIR, "templates");

// ===== Helpers =====
function uuid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  return (
    hex.slice(0, 8) + "-" +
    hex.slice(8, 12) + "-" +
    hex.slice(12, 16) + "-" +
    hex.slice(16, 20) + "-" +
    hex.slice(20)
  );
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

/**
 * FIX: Railway-safe cookies.
 * In production browsers require Secure for SameSite=None; but you use SameSite=Lax.
 * Still, "Secure" should only be set when behind HTTPS.
 */
function setCookie(res, name, value, maxAgeSeconds) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "SameSite=Lax",
    "HttpOnly",
  ];
  if (IS_PROD) parts.push("Secure");
  if (maxAgeSeconds) parts.push(`Max-Age=${maxAgeSeconds}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", `${name}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly${IS_PROD ? "; Secure" : ""}`);
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
// Initialize templates storage
ensureDir(TEMPLATES_DIR);
ensureFile(FILES.templates, []);

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
.center{text-align:center}

/* Tooltip system */
.tooltip{position:relative;display:inline-block;cursor:pointer;color:var(--muted);}
.tooltip .tooltiptext{visibility:hidden;width:220px;background-color:#555;color:#fff;text-align:center;border-radius:6px;padding:5px;position:absolute;z-index:1;bottom:125%;left:50%;margin-left:-110px;opacity:0;transition:opacity 0.3s;font-size:12px;}
.tooltip:hover .tooltiptext{visibility:visible;opacity:1;}

/* Chart and KPI placeholders */
.chart-placeholder{height:200px;border:1px solid var(--border);display:flex;align-items:center;justify-content:center;margin-bottom:10px;}
.kpi-card{display:inline-block;margin:10px;padding:15px;border:1px solid var(--border);border-radius:8px;width:200px;text-align:center;background:#fff;box-shadow:var(--shadow);}
.alert{background:#ffeded;border:1px solid #ffb0b0;padding:10px;margin:5px 0;border-radius:6px;font-size:13px;}
.attention{background-color:#fff8e1;}

/* Drop‑zone styling */
.dropzone{display:flex;align-items:center;justify-content:center;border:2px dashed var(--border);border-radius:8px;height:150px;cursor:pointer;background:#fafafa;color:var(--muted);margin-bottom:10px;transition:background 0.2s ease;}
.dropzone.dragover{background:#e5e7eb;}

/* ===== AUTH UI PATCH ===== */
.password-wrap { position: relative; }
.password-wrap input { padding-right: 48px; }
.toggle-password {
  position: absolute;
  right: 12px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 13px;
  font-weight: 700;
  cursor: pointer;
  color: #374151;
  user-select: none;
}

/* Mobile spacing fix for auth screens */
@media (max-width: 640px) {
  .card { padding: 16px !important; }
  input, textarea, button { font-size: 16px !important; }
  .btnRow { flex-direction: column; }
  .btn { width: 100%; }
}
`;

/**
 * FIX: all HTML + scripts must live inside returned strings.
 * Password toggle preserved.
 */
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

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>

<script>
/* ===== PASSWORD VISIBILITY TOGGLE (GLOBAL) ===== */
document.querySelectorAll('input[type="password"]').forEach(input => {
  if (input.parentNode && input.parentNode.classList && input.parentNode.classList.contains("password-wrap")) return;

  const wrap = document.createElement("div");
  wrap.className = "password-wrap";
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);

  const toggle = document.createElement("span");
  toggle.className = "toggle-password";
  toggle.textContent = "Show";
  wrap.appendChild(toggle);

  toggle.addEventListener("click", () => {
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    toggle.textContent = hidden ? "Hide" : "Show";
  });
});
</script>
</body></html>`;
}

function navPublic() {
  return `<a href="/login">Login</a><a href="/signup">Create Account</a><a href="/admin/login">Owner</a>`;
}
function navUser() {
  return `<a href="/dashboard">Dashboard</a><a href="/upload">Upload</a><a href="/exports">Exports</a><a href="/account">Account</a><a href="/logout">Logout</a>`;
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
function currentMonthKey() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}`;
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
    // Default appeal letter template (extended)
    denial_summary: "Based on the uploaded documents, this case includes denial/payment language that benefits from structured review and consistent appeal framing.",
    appeal_considerations: "This draft is prepared from uploaded materials only. Validate documentation supports medical necessity and payer requirements before use.",
    draft_text:
`(Your Name or Practice Name)
(Street Address)
(City, State ZIP)

(Date)

(Name of Insurance Company)
(Street Address)
(City, State ZIP)

Re: (Patient's Name)
(Type of Coverage)
(Group number/Policy number)

Dear (Name of contact person at insurance company),

Please accept this letter as (patient's name) appeal to (insurance company name) decision to deny coverage for (state the name of the specific procedure denied). It is my understanding based on your letter of denial dated (insert date) that this procedure has been denied because:

(Quote the specific reason for the denial stated in denial letter)

As you know, (patient's name) was diagnosed with (disease) on (date). Currently Dr. (name) believes that (patient's name) will significantly benefit from (state procedure name). Please see the enclosed letter from Dr. (name) that discusses (patient's name) medical history in more detail.

(Patient's name) believes that you did not have all the necessary information at the time of your initial review. (Patient's name) has also included with this letter, a letter from Dr. (name) from (name of treating facility). Dr. (name) is a specialist in (name of specialty). (His/Her) letter discusses the procedure in more detail. Also included are medical records and several journal articles explaining the procedure and the results.

Based on this information, (patient's name) is asking that you reconsider your previous decision and allow coverage for the procedure Dr. (name) outlines in his letter. The treatment is scheduled to begin on (date). Should you require additional information, please do not hesitate to contact (patient's name) at (phone number). (patient's name) will look forward to hearing from you in the near future.

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

  // Determine if a custom template should be used for the draft.  If
  // `template_id` is set on the case object, attempt to read the
  // corresponding template file and use its contents for the draft
  // letter.  Otherwise, fall back to the AI stub generator.
  let draftText = null;
  if (caseObj.template_id) {
    try {
      // Load template metadata and find the matching template for this org
      const templates = readJSON(FILES.templates, []);
      const tpl = templates.find(t => t.template_id === caseObj.template_id && t.org_id === caseObj.org_id);
      if (tpl && tpl.stored_path && fs.existsSync(tpl.stored_path)) {
        draftText = fs.readFileSync(tpl.stored_path).toString('utf8');
      }
    } catch {
      draftText = null;
    }
  }
  // Always generate denial summary and appeal considerations using the AI
  const out = aiGenerate(orgName);
  caseObj.ai.denial_summary = out.denial_summary;
  caseObj.ai.appeal_considerations = out.appeal_considerations;
  caseObj.ai.denial_reason_category = out.denial_reason_category;
  caseObj.ai.missing_info = out.missing_info;
  caseObj.ai.time_to_draft_seconds = Math.max(1, Math.floor((Date.now()-started)/1000));
  // If a draft template was loaded, use it.  Otherwise use the AI
  // generated draft text.
  caseObj.ai.draft_text = draftText || out.draft_text;
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

  const denialReasons = {};
  for (const c of cases) {
    const reason = c.ai?.denial_reason_category || "Unknown";
    denialReasons[reason] = (denialReasons[reason] || 0) + 1;
  }

  const payByPayer = {};
  for (const p of payments) {
    const payer = (p.payer || "Unknown").trim() || "Unknown";
    payByPayer[payer] = payByPayer[payer] || { count: 0, total: 0, deniedWins: 0 };
    payByPayer[payer].count += 1;
    payByPayer[payer].total += Number(p.amount_paid || 0);
    if (p.denied_approved) payByPayer[payer].deniedWins += 1;
  }

  const deniedPayments = payments.filter(p => p.denied_approved);
  const totalRecoveredFromDenials = deniedPayments.reduce((sum, p) => sum + Number(p.amount_paid || 0), 0);

  const totalRecoveredCases = cases.filter(c => c.paid).length;
  const recoveryRate = totalCases > 0 ? ((totalRecoveredCases / totalCases) * 100).toFixed(1) : "0.0";

  // Denial Aging (unpaid)
  const now = Date.now();
  const aging = { over30: 0, over60: 0, over90: 0 };
  cases.filter(c => !c.paid).forEach(c => {
    const days = (now - new Date(c.created_at).getTime()) / (1000*60*60*24);
    if (days > 90) aging.over90++;
    else if (days > 60) aging.over60++;
    else if (days > 30) aging.over30++;
  });

  // Projected Lost Revenue (unpaid * avg recovered)
  const unpaidCases = cases.filter(c => !c.paid);
  const avgRecovered = deniedPayments.length > 0 ? (totalRecoveredFromDenials / deniedPayments.length) : 0;
  const projectedLostRevenue = unpaidCases.length * avgRecovered;

  return { totalCases, drafts, avgDraftSeconds, denialReasons, payByPayer, totalRecoveredFromDenials, recoveryRate, aging, projectedLostRevenue };
}

// ===== Risk scoring + strategy suggestions + weekly summary helpers =====
function clamp(n, min, max){ return Math.max(min, Math.min(max, n)); }

function computeRiskScore(a) {
  const recovery = Number(a.recoveryRate || 0);
  const aging60 = (a.aging?.over60 || 0);
  const aging90 = (a.aging?.over90 || 0);
  const lost = Number(a.projectedLostRevenue || 0);

  const recoveryRisk = clamp(100 - recovery, 0, 100);
  const agingRisk = clamp((aging60 * 6) + (aging90 * 10), 0, 100);
  const lostRisk = clamp(lost > 0 ? Math.log10(lost + 1) * 20 : 0, 0, 100);

  const score = (0.45 * recoveryRisk) + (0.35 * agingRisk) + (0.20 * lostRisk);
  return Math.round(clamp(score, 0, 100));
}

function riskLabel(score){
  if (score >= 75) return { label:"High", cls:"err" };
  if (score >= 45) return { label:"Medium", cls:"warn" };
  return { label:"Low", cls:"ok" };
}

function buildRecoveryStrategies(a) {
  const tips = [];
  const recovery = Number(a.recoveryRate || 0);
  const aging60 = a.aging?.over60 || 0;
  const aging90 = a.aging?.over90 || 0;

  if (recovery < 40 && a.totalCases > 5) {
    tips.push("Run a denial category review: focus on the top 1–2 denial reasons and standardize your supporting documentation bundle.");
  }
  if (aging90 > 0) {
    tips.push("Prioritize >90 day denials: assign same-week follow-ups, confirm appeal deadlines, and escalate payer contact paths.");
  } else if (aging60 > 0) {
    tips.push("Work the 60+ day queue: verify appeal status, resubmit missing documentation, and document payer call reference numbers.");
  }

  const payers = Object.entries(a.payByPayer || {}).map(([payer, info]) => ({
    payer,
    total: Number(info.total || 0),
    wins: Number(info.deniedWins || 0),
    count: Number(info.count || 0)
  })).sort((x,y)=>y.count-x.count);

  const topPayer = payers[0];
  if (topPayer && topPayer.count >= 5 && topPayer.wins === 0) {
    tips.push(`Target payer friction: ${topPayer.payer} shows volume but no denial wins recorded—validate required forms, medical necessity language, and appeal routing.`);
  }

  if (!tips.length) tips.push("Keep consistency: continue documenting denial reasons, standardizing appeal templates, and tracking paid amounts to strengthen payer trend analytics.");
  return tips;
}

function computeWeeklySummary(org_id) {
  const now = Date.now();
  const weekAgo = now - 7*24*60*60*1000;

  const cases = readJSON(FILES.cases, []).filter(c => c.org_id === org_id);
  const payments = readJSON(FILES.payments, []).filter(p => p.org_id === org_id);

  const newCases = cases.filter(c => new Date(c.created_at).getTime() >= weekAgo);

  const paidThisWeek = payments.filter(p => {
    const dt = p.date_paid || p.created_at;
    return new Date(dt).getTime() >= weekAgo;
  });

  const deniedRecoveredThisWeek = paidThisWeek.filter(p => p.denied_approved);
  const recoveredDollarsThisWeek = deniedRecoveredThisWeek.reduce((s,p)=>s + Number(p.amount_paid || 0), 0);

  const topPayers = {};
  paidThisWeek.forEach(p => {
    const payer = (p.payer || "Unknown").trim() || "Unknown";
    topPayers[payer] = (topPayers[payer] || 0) + Number(p.amount_paid || 0);
  });

  const top3 = Object.entries(topPayers).sort((a,b)=>b[1]-a[1]).slice(0,3).map(([payer,total])=>({ payer, total }));

  return { newCasesCount: newCases.length, paymentsCount: paidThisWeek.length, recoveredDollarsThisWeek, deniedWinsCount: deniedRecoveredThisWeek.length, top3 };
}


// ===== Payment & Denial Trends =====
/**
 * Compute monthly payment trends. Returns an object with:
 * - byMonth: { YYYY-MM: { total: number, count: number } }
 * - avgMonthlyTotal: average monthly total paid across all months.
 * If org_id is provided, payments are filtered to that organisation; otherwise all payments are used.
 */
function computePaymentTrends(org_id) {
  let payments = readJSON(FILES.payments, []);
  if (org_id) {
    payments = payments.filter(p => p.org_id === org_id);
  }
  const byMonth = {};
  payments.forEach(p => {
    // Use payment date if available, otherwise created_at
    let dtStr = p.date_paid || p.datePaid || p.created_at || p.created_at;
    let d;
    try {
      d = dtStr ? new Date(dtStr) : new Date();
    } catch {
      d = new Date();
    }
    const key = `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}`;
    if (!byMonth[key]) byMonth[key] = { total: 0, count: 0 };
    byMonth[key].total += Number(p.amount_paid || p.amountPaid || 0);
    byMonth[key].count += 1;
  });
  const keys = Object.keys(byMonth);
  let avgMonthlyTotal = null;
  if (keys.length) {
    const sum = keys.reduce((acc, k) => acc + byMonth[k].total, 0);
    avgMonthlyTotal = sum / keys.length;
  }
  return { byMonth, avgMonthlyTotal };
}

/**
 * Compute monthly denial and appeal trends. Returns an object keyed by month with:
 *  - total: number of cases created in that month
 *  - drafts: number of cases that reached DRAFT_READY status (appeal drafts generated)
 *  - categories: a map of denial categories and counts
 * If org_id is provided, cases are filtered to that organisation; otherwise all cases are used.
 */
function computeDenialTrends(org_id) {
  let cases = readJSON(FILES.cases, []);
  if (org_id) {
    cases = cases.filter(c => c.org_id === org_id);
  }
  const byMonth = {};
  cases.forEach(c => {
    const dtStr = c.created_at;
    let d;
    try {
      d = dtStr ? new Date(dtStr) : new Date();
    } catch {
      d = new Date();
    }
    const key = `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}`;
    if (!byMonth[key]) byMonth[key] = { total: 0, drafts: 0, categories: {} };
    byMonth[key].total += 1;
    if (c.status === "DRAFT_READY" || (c.ai && c.ai.draft_text)) {
      byMonth[key].drafts += 1;
    }
    const cat = (c.ai && c.ai.denial_reason_category) ? c.ai.denial_reason_category : "Unknown";
    byMonth[key].categories[cat] = (byMonth[key].categories[cat] || 0) + 1;
  });
  return byMonth;
}

// ===== Admin Attention Helper =====
/**
 * Compute a set of organisation IDs requiring admin attention.
 * Rules:
 *  - Pilot ending within 7 days
 *  - Case usage ≥ 80%
 *  - No activity for 14+ days
 *  - No payment uploads across platform
 */
function buildAdminAttentionSet(orgs) {
  const flagged = new Set();
  const now = Date.now();
  const allUsage = readJSON(FILES.usage, []);
  const cases = readJSON(FILES.cases, []);
  const payments = readJSON(FILES.payments, []);
  orgs.forEach(org => {
    const pilot = getPilot(org.org_id) || ensurePilot(org.org_id);
    const limits = getLimitProfile(org.org_id);
    const usage = allUsage.find(u => u.org_id === org.org_id) || getUsage(org.org_id);
    let casePct = 0;
    if (limits.mode === 'pilot') {
      casePct = (usage.pilot_cases_used / PILOT_LIMITS.max_cases_total) * 100;
    } else {
      casePct = (usage.monthly_case_credits_used / limits.case_credits_per_month) * 100;
    }
    // last activity (latest case or payment)
    let last = 0;
    cases.forEach(c => { if (c.org_id === org.org_id) last = Math.max(last, new Date(c.created_at).getTime()); });
    payments.forEach(p => { if (p.org_id === org.org_id) last = Math.max(last, new Date(p.created_at).getTime()); });
    const pilotEnd = pilot ? new Date(pilot.ends_at).getTime() : 0;
    const pilotEndingSoon = pilotEnd && pilotEnd - now <= 7 * 24 * 60 * 60 * 1000;
    const nearLimit = casePct >= 80;
    const noRecentActivity = !last || now - last >= 14 * 24 * 60 * 60 * 1000;
    const noPayments = payments.filter(p => p.org_id === org.org_id).length === 0;
    if (pilotEndingSoon || nearLimit || noRecentActivity || noPayments) {
      flagged.add(org.org_id);
    }
  });
  return flagged;
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
          <a class "btn secondary" href="/login">Sign In</a>
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
          <button class "btn" type="submit">Sign In</button>
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
        <div class "btnRow">
          <button class "btn" type="submit">Generate Reset Link</button>
          <a class "btn secondary" href="/login">Back</a>
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
        <div class "btnRow"><a class "btn secondary" href="/forgot-password">Try again</a></div>
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
      <p class "muted">If you believe this is an error, contact support.</p>
      <div class "btnRow"><a class "btn secondary" href="/logout">Logout</a></div>
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

    // Reworked admin dashboard
    if (method === "GET" && pathname === "/admin/dashboard") {
      const orgs = readJSON(FILES.orgs, []);
      const users = readJSON(FILES.users, []);
      const pilots = readJSON(FILES.pilots, []);
      const subs = readJSON(FILES.subscriptions, []);
      const casesData = readJSON(FILES.cases, []);
      const payments = readJSON(FILES.payments, []);
      // counts
      const totalOrgs = orgs.length;
      const totalUsers = users.length;
      const activePilots = pilots.filter(p => p.status === "active").length;
      const activeSubs = subs.filter(s => s.status === "active").length;
      // status counts for donut
      const statusCounts = orgs.reduce((acc, org) => {
        acc[org.account_status || "active"] = (acc[org.account_status || "active"] || 0) + 1;
        return acc;
      }, {});
      // compute attention set and last activity
      const attentionSet = buildAdminAttentionSet(orgs);
      const orgActivities = orgs.map(org => {
        let last = 0;
        casesData.forEach(c => { if (c.org_id === org.org_id) last = Math.max(last, new Date(c.created_at).getTime()); });
        payments.forEach(p => { if (p.org_id === org.org_id) last = Math.max(last, new Date(p.created_at).getTime()); });
        return { org, last };
      });
      // compile alerts
      const alerts = [];
      orgActivities.forEach(({ org, last }) => {
        const pilot = getPilot(org.org_id) || ensurePilot(org.org_id);
        const limits = getLimitProfile(org.org_id);
        const usage = getUsage(org.org_id);
        const pilotEnd = pilot ? new Date(pilot.ends_at).getTime() : 0;
        if (pilotEnd && pilotEnd - Date.now() <= 7 * 24 * 60 * 60 * 1000) {
          alerts.push(`Pilot for ${safeStr(org.org_name)} ends soon`);
        }
        let casePct = 0;
        if (limits.mode === "pilot") {
          casePct = (usage.pilot_cases_used / PILOT_LIMITS.max_cases_total) * 100;
        } else {
          casePct = (usage.monthly_case_credits_used / limits.case_credits_per_month) * 100;
        }
        if (casePct >= 80) {
          alerts.push(`${safeStr(org.org_name)} near case limit (${casePct.toFixed(0)}%)`);
        }
        if (!last || Date.now() - last >= 14 * 24 * 60 * 60 * 1000) {
          alerts.push(`${safeStr(org.org_name)} has no activity for 14+ days`);
        }
      });
      if (payments.length === 0) {
        alerts.push("No payment uploads across platform");
      }
      let alertsHtml = alerts.length ? alerts.map(msg => `<div class="alert">${msg}</div>`).join("") : "<p class='muted'>No alerts</p>";
      // recent activity table
      const rows = orgActivities.map(({ org, last }) => {
        const sub = getSub(org.org_id);
        const pilot = getPilot(org.org_id) || ensurePilot(org.org_id);
        const plan = (sub && sub.status === "active") ? "Subscribed" : (pilot.status === "active" ? "Pilot" : "Expired");
        const att = attentionSet.has(org.org_id) ? "⚠️" : "";
        return `<tr class="${att ? 'attention' : ''}">
          <td><a href="/admin/org?org_id=${encodeURIComponent(org.org_id)}">${safeStr(org.org_name)}</a></td>
          <td>${plan}</td>
          <td>${safeStr(org.account_status || 'active')}</td>
          <td>${last ? new Date(last).toLocaleDateString() : "—"}</td>
          <td>${att}</td>
        </tr>`;
      }).join("");
      const html = page("Admin Dashboard", `
        <h2>Admin Dashboard</h2>
        <section>
          <div class="kpi-card"><h4>Total Organisations</h4><p>${totalOrgs}</p></div>
          <div class="kpi-card"><h4>Total Users</h4><p>${totalUsers}</p></div>
          <div class="kpi-card"><h4>Active Pilots</h4><p>${activePilots}</p></div>
          <div class="kpi-card"><h4>Active Subscriptions</h4><p>${activeSubs}</p></div>
        </section>
        <h3>Organisation Status</h3>
        <div class="chart-placeholder">Donut chart will render here: Active ${statusCounts['active']||0}, Suspended ${statusCounts['suspended']||0}, Terminated ${statusCounts['terminated']||0}</div>
        <h3>Total Case Activity</h3>
        <div class="chart-placeholder">Case activity charts will be displayed when data is available.</div>
        <h3>Admin Alerts</h3>
        ${alertsHtml}
        <h3>Recent Organisation Activity</h3>
        <table>
          <thead><tr><th>Name</th><th>Plan</th><th>Status</th><th>Last Activity</th><th>Attention</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      `, navAdmin());
      return send(res, 200, html);
    }

    // Enhanced Organisations page
    if (method === "GET" && pathname === "/admin/orgs") {
      const orgs = readJSON(FILES.orgs, []);
      const pilots = readJSON(FILES.pilots, []);
      const subs = readJSON(FILES.subscriptions, []);
      // build attention set
      const attSet = buildAdminAttentionSet(orgs);
      // read filters from query
      const search = (parsed.query.search || "").toLowerCase();
      const statusFilter = parsed.query.status || "";
      const planFilter = parsed.query.plan || "";
      const needAtt = parsed.query.attention === "1";
      // filter organisations
      let filtered = orgs.filter(org => {
        const nameMatch = !search || (org.org_name || "").toLowerCase().includes(search);
        const statusMatch = !statusFilter || (org.account_status || "active") === statusFilter;
        const plan = (() => {
          const p = pilots.find(x => x.org_id === org.org_id);
          const s = subs.find(x => x.org_id === org.org_id);
          return (s && s.status === "active") ? "Subscribed" : (p && p.status === "active" ? "Pilot" : "Expired");
        })();
        const planMatch = !planFilter || plan === planFilter;
        const attMatch = !needAtt || attSet.has(org.org_id);
        return nameMatch && statusMatch && planMatch && attMatch;
      });
      // build table rows
      const rows = filtered.map(org => {
        const p = pilots.find(x => x.org_id === org.org_id);
        const s = subs.find(x => x.org_id === org.org_id);
        const plan = (s && s.status === "active") ? "Subscribed" : (p && p.status === "active" ? "Pilot" : "Expired");
        const att = attSet.has(org.org_id) ? "⚠️" : "";
        return `<tr class="${att ? 'attention' : ''}">
          <td><a href="/admin/org?org_id=${encodeURIComponent(org.org_id)}">${safeStr(org.org_name)}</a></td>
          <td>${plan}</td>
          <td>${safeStr(org.account_status || 'active')}</td>
          <td>${att}</td>
        </tr>`;
      }).join("");
      const html = page("Organizations", `
        <h2>Organizations</h2>
        <form method="GET" action="/admin/orgs">
          <input type="text" name="search" placeholder="Search org name" value="${safeStr(parsed.query.search || '')}">
          <select name="status">
            <option value="">All statuses</option>
            <option value="active"${statusFilter==="active"?" selected":""}>Active</option>
            <option value="suspended"${statusFilter==="suspended"?" selected":""}>Suspended</option>
            <option value="terminated"${statusFilter==="terminated"?" selected":""}>Terminated</option>
          </select>
          <select name="plan">
            <option value="">All plans</option>
            <option value="Pilot"${planFilter==="Pilot"?" selected":""}>Pilot</option>
            <option value="Subscribed"${planFilter==="Subscribed"?" selected":""}>Subscribed</option>
            <option value="Expired"${planFilter==="Expired"?" selected":""}>Expired</option>
          </select>
          <label><input type="checkbox" name="attention" value="1"${needAtt?" checked":""}> Needs Attention</label>
          <button class="btn" type="submit">Filter</button>
        </form>
        <div style="overflow:auto;">
          <table>
            <thead><tr><th>Name</th><th>Plan</th><th>Status</th><th>Attention</th></tr></thead>
            <tbody>${rows || '<tr><td colspan="4">No organisations match your filters.</td></tr>'}</tbody>
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
    <button class="btn secondary" name="action" value="suspend">Pause Plan</button>
    <button class="btn secondary" name="action" value="reactivate">Reactivate</button>
    <button class="btn danger" name="action" value="terminate">Terminate</button>
  </div>

  <div class="hr"></div>
  <h3>Free Trial</h3>
  <label>Trial Days</label>
  <select name="trial_days">
    <option value="7">7 Days</option>
    <option value="14" selected>14 Days</option>
    <option value="30">30 Days</option>
  </select>
  <div class="btnRow">
    <button class="btn secondary" name="action" value="grant_trial">Grant Trial</button>
    <button class="btn secondary" name="action" value="extend_trial">Extend Trial</button>
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
} else if (action === "reactivate") {
  setOrgStatus(org_id, "active", reason);
  auditLog({ actor:"admin", action:"reactivate", org_id, reason });
} else if (action === "grant_trial") {
  // Restart/Grant trial from today for N days (defaults handled by form)
  const days = Number(params.get("trial_days") || 14);
  const pilots = readJSON(FILES.pilots, []);
  let p = pilots.find(x => x.org_id === org_id);
  if (!p) {
    p = { pilot_id: uuid(), org_id, status:"active", started_at: nowISO(), ends_at: addDaysISO(nowISO(), days), retention_delete_at: null };
    pilots.push(p);
  } else {
    p.status = "active";
    p.started_at = nowISO();
    p.ends_at = addDaysISO(nowISO(), days);
    p.retention_delete_at = null;
  }
  writeJSON(FILES.pilots, pilots);
  setOrgStatus(org_id, "active", reason);
  auditLog({ actor:"admin", action:"grant_trial", org_id, reason, trial_days: days });
} else if (action === "extend_trial") {
  const days = Number(params.get("trial_days") || 7);
  const pilots = readJSON(FILES.pilots, []);
  let p = pilots.find(x => x.org_id === org_id);
  if (!p) {
    p = { pilot_id: uuid(), org_id, status:"active", started_at: nowISO(), ends_at: addDaysISO(nowISO(), days), retention_delete_at: null };
    pilots.push(p);
  } else {
    p.status = "active";
    p.ends_at = addDaysISO(p.ends_at || nowISO(), days);
    p.retention_delete_at = null;
  }
  writeJSON(FILES.pilots, pilots);
  auditLog({ actor:"admin", action:"extend_trial", org_id, reason, trial_days: days });

      }
      return redirect(res, `/admin/org?org_id=${encodeURIComponent(org_id)}`);
    }

    if (method === "GET" && pathname === "/admin/audit") {
      const audit = readJSON(FILES.audit, []);
      const rows = audit.slice(-200).reverse().map(a => `
        <tr> <td class="muted small">${safeStr(a.at)}</td> <td>${safeStr(a.action)}</td> <td class="muted small">${safeStr(a.org_id || "")}</td> <td class="muted small">${safeStr(a.reason || "")}</td> </tr>`).join("");
      const html = page("Audit Log", ` <h2>Audit Log</h2> <p class="muted">Latest 200 admin actions.</p> <div style="overflow:auto;"> <table>
        <thead><tr><th>Time</th><th>Action</th><th>Org</th><th>Reason</th></tr></thead>
        <tbody>${rows}</tbody> </table> </div> `, navAdmin());
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



// executive dashboard
if (method === "GET" && pathname === "/executive") {
  const a = computeAnalytics(org.org_id);
  const score = computeRiskScore(a);
  const r = riskLabel(score);
  const tips = buildRecoveryStrategies(a);

  const agingData = [a.aging.over30, a.aging.over60, a.aging.over90];

  const payerEntries = Object.entries(a.payByPayer || {})
    .map(([payer, info]) => ({ payer, total: Number(info.total || 0) }))
    .sort((x,y)=>y.total-x.total)
    .slice(0,5);

  const payerLabels = payerEntries.map(x => x.payer);
  const payerTotals = payerEntries.map(x => x.total);

  const html = page("Executive Dashboard", `
    <h2>Executive Dashboard</h2>
    <p class="muted">High-level denial → revenue performance for leadership review.</p>

    <div class="row">
      <div class="col">
        <div class="kpi-card"><h4>Recovered from Denials</h4><p>$${Number(a.totalRecoveredFromDenials||0).toFixed(2)}</p></div>
        <div class="kpi-card"><h4>Recovery Rate</h4><p>${a.recoveryRate}%</p></div>
        <div class="kpi-card"><h4>Projected Lost Revenue</h4><p>$${Number(a.projectedLostRevenue||0).toFixed(2)}</p></div>
      </div>

      <div class="col">
        <h3>Risk Score</h3>
        <p class="muted small">Heuristic score (0–100) based on recovery %, aging, and revenue leakage signals.</p>
        <div class="badge ${r.cls}">Risk: ${r.label} — ${score}/100</div>

        <div class="hr"></div>
        <h3>Recommended Actions</h3>
        <ul class="muted">
          ${tips.map(t => `<li>${safeStr(t)}</li>`).join("")}
        </ul>
      </div>
    </div>

    <div class="hr"></div>
    <h3>Denial Aging (Unpaid)</h3>
    <canvas id="agingChart" height="120"></canvas>

    <div class="hr"></div>
    <h3>Top Payers by Total Paid</h3>
    <canvas id="payerChart" height="140"></canvas>

    <script>
      (function(){
        if (!window.Chart) return;

        new Chart(document.getElementById('agingChart'), {
          type: 'bar',
          data: { labels: ['30+ days','60+ days','90+ days'], datasets: [{ label: 'Unpaid Denials', data: ${JSON.stringify(agingData)} }] },
          options: { responsive: true }
        });

        new Chart(document.getElementById('payerChart'), {
          type: 'bar',
          data: { labels: ${JSON.stringify(payerLabels)}, datasets: [{ label: 'Total Paid', data: ${JSON.stringify(payerTotals)} }] },
          options: { responsive: true }
        });
      })();
    </script>

    <div class="btnRow">
      <a class="btn secondary" href="/weekly-summary">Weekly Summary</a>
      <a class="btn secondary" href="/analytics">Analytics</a>
      <a class="btn secondary" href="/dashboard">Back</a>
    </div>
  `, navUser());
  return send(res, 200, html);
}

// weekly summary
if (method === "GET" && pathname === "/weekly-summary") {
  const a = computeAnalytics(org.org_id);
  const w = computeWeeklySummary(org.org_id);
  const proj = projectNextMonthDenials(org.org_id);

  const html = page("Weekly Summary", `
    <h2>Weekly Denial Performance Summary</h2>
    <p class="muted">Last 7 days. Use this for quick leadership updates.</p>

    <div class="row">
      <div class="col">
        <div class="kpi-card"><h4>New Denial Cases</h4><p>${w.newCasesCount}</p></div>
        <div class="kpi-card"><h4>Payments Logged</h4><p>${w.paymentsCount}</p></div>
      </div>
      <div class="col">
        <div class="kpi-card"><h4>Denied → Approved Wins</h4><p>${w.deniedWinsCount}</p></div>
        <div class="kpi-card"><h4>Recovered Dollars</h4><p>$${Number(w.recoveredDollarsThisWeek||0).toFixed(2)}</p></div>
      </div>
    </div>

    <div class="hr"></div>
    <h3>Top Payers This Week</h3>
    ${
      w.top3.length
        ? `<table><thead><tr><th>Payer</th><th>Total Paid</th></tr></thead><tbody>${w.top3.map(x => `<tr><td>${safeStr(x.payer)}</td><td>$${Number(x.total).toFixed(2)}</td></tr>`).join("")}</tbody></table>`
        : `<p class="muted">No payments recorded in the last 7 days.</p>`
    }

    <div class="hr"></div>
    <h3>Current Operating Snapshot</h3>
    <ul class="muted">
      <li><strong>Recovery rate:</strong> ${a.recoveryRate}%</li>
      <li><strong>Unpaid aging:</strong> 30+ ${a.aging.over30}, 60+ ${a.aging.over60}, 90+ ${a.aging.over90}</li>
      <li><strong>Projected lost revenue:</strong> $${Number(a.projectedLostRevenue||0).toFixed(2)}</li>
      <li><strong>Next month denial projection:</strong> ${proj === null ? "Insufficient data" : proj}</li>
    </ul>

    <div class="btnRow">
      <a class="btn" href="/executive">Executive Dashboard</a>
      <a class="btn secondary" href="/dashboard">Back</a>
    </div>
  `, navUser());
  return send(res, 200, html);
}
  // dashboard with empty-state previews and tooltips
  if (method === "GET" && (pathname === "/" || pathname === "/dashboard")) {
    const limits = getLimitProfile(org.org_id);
    const usage = getUsage(org.org_id);
    const pilot = getPilot(org.org_id) || ensurePilot(org.org_id);
    const paymentAllowance = paymentRowsAllowance(org.org_id);
    const planBadge = (limits.mode==="monthly") ? `<span class="badge ok">Monthly Active</span>` : `<span class="badge warn">Pilot Active</span>`;
    // counts for empty-state charts
    const caseCount = countOrgCases(org.org_id);
    const paymentCount = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id).length;

    // Build "My Cases" listing
    const allCases = readJSON(FILES.cases, []).filter(c => c.org_id === org.org_id && !c.paid);
    let caseTable = "";
    if (allCases.length === 0) {
      caseTable = `<p class="muted">No cases yet. Upload denial documents to begin.</p>`;
    } else {
      // sort by created_at desc
      allCases.sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
      // Determine whether a case is paid and the date
      const todayStr = new Date().toISOString().split('T')[0];
      const rows = allCases.map(c => {
        const displayStatus = c.paid ? "Complete" : c.status;
        let link = "";
        if (status === "DRAFT_READY") link = `<a href="/draft?case_id=${encodeURIComponent(c.case_id)}">${safeStr(c.case_id)}</a>`;
        else link = `<a href="/status?case_id=${encodeURIComponent(c.case_id)}">${safeStr(c.case_id)}</a>`;
        // Payment cell: if paid show date, else show form
        let paymentCell = "";
        if (c.paid) {
          paymentCell = `<span class="badge ok">Paid</span><br><span class="small">${new Date(c.paid_at).toLocaleDateString()}</span>`;
        } else {
          paymentCell = `<form method="POST" action="/case/mark-paid" style="display:flex;align-items:center;gap:4px;flex-wrap:wrap;">
            <input type="hidden" name="case_id" value="${safeStr(c.case_id)}"/>
            <input type="date" name="paid_at" value="${todayStr}" required/>
            <input type="text" name="paid_amount" placeholder="Paid amount" required style="width:100px"/>
            <button class="btn small" type="submit">Mark Paid</button>
          </form>`;
        }
        return `<tr>
          <td>${link}</td>
          <td>${safeStr(displayStatus)}</td>
          <td>${new Date(c.created_at).toLocaleDateString()}</td>
          <td>${paymentCell}</td>
        </tr>`;
      }).join("");
      caseTable = `<table><thead><tr><th>Case ID</th><th>Status</th><th>Created</th><th>Payment</th></tr></thead><tbody>${rows}</tbody></table>`;
    }

    const html = page("Dashboard", `
      <h2>Dashboard</h2>
      <p class="muted">Organization: ${safeStr(org.org_name)} · Pilot ends: ${new Date(pilot.ends_at).toLocaleDateString()}</p>
      ${planBadge}
      <div class="hr"></div>

      <h3>Denial Cases</h3>
      ${caseTable}

      <div class="hr"></div>
      <h3>Summary</h3>
      <div class="row">
        <div class="col">
          <h4>Payer Summary</h4>
          ${
            (() => {
              const a = computeAnalytics(org.org_id);
              const payers = Object.entries(a.payByPayer);
              if (payers.length === 0) return "<p class='muted small'>No payment data yet.</p>";
              const list = payers.sort((x,y) => y[1].total - x[1].total).slice(0,4).map(([payer, info]) => `<div><strong>${safeStr(payer)}</strong>: $${Number(info.total).toFixed(2)} (${info.count} payments)</div>`).join("");
              return list;
            })()
          }
        </div>
        <div class="col">
          <h4>Usage</h4>
          ${
            limits.mode === "pilot" ? `
            <ul class="muted small">
              <li>Cases used: ${usage.pilot_cases_used}/${PILOT_LIMITS.max_cases_total}</li>
              <li>Payment rows used: ${usage.pilot_payment_rows_used}/${PILOT_LIMITS.payment_records_included}</li>
            </ul>
            ` : `
            <ul class="muted small">
              <li>Cases used: ${usage.monthly_case_credits_used}/${limits.case_credits_per_month}</li>
              <li>Overage cases: ${usage.monthly_case_overage_count}</li>
              <li>Payment rows used: ${usage.monthly_payment_rows_used}</li>
            </ul>
            `
          }
        </div>
      </div>

      <div class="hr"></div>
      <h3>Activity</h3>
      <div class="chart-placeholder">${caseCount === 0 ? "No cases uploaded yet." : "Case activity chart will appear here."}</div>
      <div class="chart-placeholder">${paymentCount === 0 ? "No payments uploaded yet." : "Payment activity chart will appear here."}</div>
      ${caseCount === 0 && paymentCount === 0 ? `
      <section><h3>Recommended Next Step</h3><p>Get started by uploading your first denial document or payment data to unlock analytics.</p></section>
      ` : ""}
      <div class="hr"></div>
      <h3>Usage Limits</h3>
      ${
        limits.mode==="pilot" ? `
        <ul class="muted">
          <li>Cases remaining: ${PILOT_LIMITS.max_cases_total - caseCount} / ${PILOT_LIMITS.max_cases_total} <span class="tooltip">ⓘ<span class="tooltiptext">Maximum number of cases you can upload during your current plan.</span></span></li>
          <li>AI jobs/hour: ${PILOT_LIMITS.max_ai_jobs_per_hour} <span class="tooltip">ⓘ<span class="tooltiptext">Number of AI processing jobs you can run per hour.</span></span></li>
          <li>Concurrent processing: ${PILOT_LIMITS.max_concurrent_analyzing} <span class="tooltip">ⓘ<span class="tooltiptext">Maximum number of cases or payments processed at the same time.</span></span></li>
          <li>Payment rows remaining: ${paymentRowsAllowance(org.org_id).remaining} of ${PILOT_LIMITS.payment_records_included}</li>
        </ul>
        ` : `
        <ul class="muted">
          <li>Case credits used: ${usage.monthly_case_credits_used} / ${limits.case_credits_per_month} <span class="tooltip">ⓘ<span class="tooltiptext">Number of cases processed out of your monthly allotment.</span></span></li>
          <li>Overage cases: ${usage.monthly_case_overage_count} (est. $${usage.monthly_case_overage_count * limits.overage_price_per_case})</li>
          <li>Payment rows remaining: ${paymentRowsAllowance(org.org_id).remaining}</li>
        </ul>
        `
      }

      <div class="btnRow">
        <a class="btn" href="/upload">Start Denial & Appeal Mgmt</a>
        <a class="btn secondary" href="/payments">Revenue Mgmt</a>
        <a class="btn secondary" href="/payments/list">Payment Details</a>
        <a class="btn secondary" href="/exports">Exports</a>
      </div>
    `, navUser());
    return send(res, 200, html);
  }

  // --------- CASE UPLOAD ----------
  if (method === "GET" && pathname === "/upload") {
    const allTemplates = readJSON(FILES.templates, []).filter(t => t.org_id === org.org_id);
    const templateOptions = allTemplates.map(t => `<option value="${safeStr(t.template_id)}">${safeStr(t.filename)}</option>`).join("");

    const allow = paymentRowsAllowance(org.org_id);
    const paymentCount = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id).length;

    const html = page("Uploads", `
      <h2>Uploads</h2>
      <p class="muted">Upload denial documents to generate appeal drafts, and upload payment files to power revenue analytics. All results appear on your Dashboard.</p>

      <div class="hr"></div>
      <h3>Denial &amp; Appeal Upload</h3>
      <p class="muted">Upload up to <strong>3 denial documents</strong>. Each document becomes its own case using the selected template.</p>

      <form method="POST" action="/upload" enctype="multipart/form-data">
        <label>Denial Documents (up to 3)</label>
        <div id="case-dropzone" class="dropzone">Drop up to 3 documents here or click to select</div>
        <input id="case-files" type="file" name="files" multiple required accept=".pdf,.doc,.docx,.jpg,.png" style="display:none" />

        <label>Optional notes</label>
        <textarea name="notes" placeholder="Any context to help review (optional)"></textarea>

        <div class="hr"></div>
        <h3>Appeal Letter Template</h3>
        <p class="small muted">Choose an uploaded template or select AI Draft (default).</p>
        <div style="display:flex;flex-direction:column;gap:8px;">
          <select name="template_id">
            <option value="">AI Draft (no template)</option>
            ${templateOptions}
          </select>
          <label>Upload new template (optional)</label>
          <input type="file" name="templateFile" accept=".txt,.doc,.docx,.pdf" />
        </div>

        <div class="btnRow" style="margin-top:16px;">
          <button class="btn" type="submit">Submit Denials</button>
          <a class="btn secondary" href="/dashboard">Back</a>
        </div>
      </form>

      <div class="hr"></div>
      <h3 id="payments">Payment Upload</h3>
      <p class="muted">Upload bulk payment files in CSV or Excel format. CSV drives analytics.</p>
      <p class="muted small"><strong>Rows remaining:</strong> ${allow.remaining}</p>

      <form method="POST" action="/payments" enctype="multipart/form-data">
        <label>Upload CSV/XLS/XLSX</label>
        <div id="pay-dropzone" class="dropzone">Drop a CSV/XLS/XLSX file here or click to select</div>
        <input id="pay-file" type="file" name="payfile" accept=".csv,.xls,.xlsx" required style="display:none" />
        <div class="btnRow">
          <button class="btn" type="submit">Upload Payments</button>
          <a class="btn secondary" href="/payments/list">View Payment Details</a>
        </div>
      </form>

      <div class="hr"></div>
      <p class="muted small">Payment records on file: ${paymentCount}. Uploading payments improves payer insights and denial recovery tracking.</p>

      <script>
        // Denial dropzone
        const caseDrop = document.getElementById('case-dropzone');
        const caseInput = document.getElementById('case-files');
        caseDrop.addEventListener('click', () => caseInput.click());
        ['dragenter','dragover'].forEach(evt => {
          caseDrop.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); caseDrop.classList.add('dragover'); });
        });
        ['dragleave','drop'].forEach(evt => {
          caseDrop.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); caseDrop.classList.remove('dragover'); });
        });
        caseDrop.addEventListener('drop', e => {
          const files = e.dataTransfer.files;
          if (files.length > 3) { alert('You can upload up to 3 documents.'); return; }
          const dt2 = new DataTransfer();
          for (let i=0; i<files.length && i<3; i++) dt2.items.add(files[i]);
          caseInput.files = dt2.files;
          caseDrop.textContent = files.length + ' file' + (files.length>1 ? 's' : '') + ' selected';
        });
        caseInput.addEventListener('change', () => {
          if (caseInput.files.length > 3) {
            alert('You can upload up to 3 documents. Only the first 3 will be used.');
            const dt2 = new DataTransfer();
            for (let i=0; i<3; i++) dt2.items.add(caseInput.files[i]);
            caseInput.files = dt2.files;
          }
          if (caseInput.files.length) {
            caseDrop.textContent = caseInput.files.length + ' file' + (caseInput.files.length>1 ? 's' : '') + ' selected';
          }
        });

        // Payment dropzone
        const payDrop = document.getElementById('pay-dropzone');
        const payInput = document.getElementById('pay-file');
        payDrop.addEventListener('click', () => payInput.click());
        ['dragenter','dragover'].forEach(evt => {
          payDrop.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); payDrop.classList.add('dragover'); });
        });
        ['dragleave','drop'].forEach(evt => {
          payDrop.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); payDrop.classList.remove('dragover'); });
        });
        payDrop.addEventListener('drop', e => {
          const files = e.dataTransfer.files;
          if (files.length > 1) { alert('Only one file at a time.'); return; }
          const dt = new DataTransfer();
          dt.items.add(files[0]);
          payInput.files = dt.files;
          payDrop.textContent = files[0].name;
        });
        payInput.addEventListener('change', () => {
          const file = payInput.files[0];
          if (file) payDrop.textContent = file.name;
        });
      </script>
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

    // Handle template file upload and multiple document cases
    // Separate document files (named "files") and optional template upload
    const docFiles = files.filter(f => f.fieldName === "files");
    const templateUpload = files.find(f => f.fieldName === "templateFile");
    // Ensure at least one document file
    if (!docFiles.length) return redirect(res, "/upload");
    // Determine selected template from dropdown
    let selectedTemplateId = (fields.template_id || "").trim();
    // If a new template file is provided, store it and override selection
    if (templateUpload && templateUpload.filename) {
      const safeNameT = (templateUpload.filename || "template").replace(/[^a-zA-Z0-9._-]/g, "_");
      const newTemplateId = uuid();
      const templatePath = path.join(TEMPLATES_DIR, `${newTemplateId}_${safeNameT}`);
      fs.writeFileSync(templatePath, templateUpload.buffer);
      const allTemplates = readJSON(FILES.templates, []);
      allTemplates.push({
        template_id: newTemplateId,
        org_id: org.org_id,
        filename: safeNameT,
        stored_path: templatePath,
        uploaded_at: nowISO()
      });
      writeJSON(FILES.templates, allTemplates);
      selectedTemplateId = newTemplateId;
    }
    // Create a new case per uploaded document
    const cases = readJSON(FILES.cases, []);
    const createdCaseIds = [];
    let limitReason = null;
    for (const doc of docFiles) {
      // Check pilot/credit limits before creating each case
      const canCase = pilotCanCreateCase(org.org_id);
      if (!canCase.ok) {
        limitReason = canCase.reason;
        break;
      }
      // Consume a case credit per document
      if (limits.mode === "monthly") {
        monthlyConsumeCaseCredit(org.org_id);
      } else {
        pilotConsumeCase(org.org_id);
      }
      // Create unique case ID and directory
      const cid = uuid();
      const caseDir = path.join(UPLOADS_DIR, org.org_id, cid);
      ensureDir(caseDir);
      const safeName = (doc.filename || "file").replace(/[^a-zA-Z0-9._-]/g, "_");
      const file_id = uuid();
      const stored_path = path.join(caseDir, `${file_id}_${safeName}`);
      fs.writeFileSync(stored_path, doc.buffer);
      const storedFiles = [{
        file_id,
        filename: safeName,
        mime: doc.mime,
        size_bytes: doc.buffer.length,
        stored_path,
        uploaded_at: nowISO()
      }];
      cases.push({
        case_id: cid,
        org_id: org.org_id,
        created_by_user_id: user.user_id,
        created_at: nowISO(),
        status: "UPLOAD_RECEIVED",
        notes: fields.notes || "",
        files: storedFiles,
        template_id: selectedTemplateId || "",
        // Track payment status for each case. A case is marked paid when appeals have resulted in payment.
        paid: false,
        paid_at: null,
        paid_amount: null,
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
      createdCaseIds.push(cid);
    }
    writeJSON(FILES.cases, cases);
    // For each created case, attempt to start AI if capacity allows
    const cases2 = readJSON(FILES.cases, []);
    for (const cid of createdCaseIds) {
      const cObj = cases2.find(x => x.case_id === cid && x.org_id === org.org_id);
      if (cObj && cObj.status === "UPLOAD_RECEIVED") {
        const okAI = canStartAI(org.org_id);
        if (okAI.ok) {
          cObj.status = "ANALYZING";
          cObj.ai_started_at = nowISO();
          writeJSON(FILES.cases, cases2);
          recordAIJob(org.org_id);
        }
      }
    }
    // Redirect to status page for first created case
    if (createdCaseIds.length > 0) {
      return redirect(res, `/status?case_id=${encodeURIComponent(createdCaseIds[0])}`);
    }
    // If no cases were created (limit reached), show limit message
    const html = page("Limit", `
      <h2>Limit Reached</h2>
      <p class="error">${safeStr(limitReason || "Case limit reached")}</p>
      <div class="btnRow"><a class="btn secondary" href="/dashboard">Back</a></div>
    `, navUser());
    return send(res, 403, html);
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
          <a class="btn secondary" href="/download-draft?case_id=${encodeURIComponent(case_id)}&fmt=doc">Download Word</a>
          <a class="btn secondary" href="/download-draft?case_id=${encodeURIComponent(case_id)}&fmt=pdf">Download PDF</a>
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

  // New route: handle marking a case as paid (captures paid amount + logs denied->approved payment)
if (method === "POST" && pathname === "/case/mark-paid") {
  const body = await parseBody(req);
  const params = new URLSearchParams(body);
  const case_id = params.get("case_id") || "";
  const paid_at = params.get("paid_at") || "";
  const paid_amount = (params.get("paid_amount") || "").trim();

  const cases = readJSON(FILES.cases, []);
  const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);

  if (c) {
    const wasAlreadyPaid = !!c.paid;

    c.paid = true;
    c.paid_at = paid_at;
    c.paid_amount = paid_amount;

    writeJSON(FILES.cases, cases);

    // Append payment row (only once)
    if (!wasAlreadyPaid) {
      const paymentsData = readJSON(FILES.payments, []);
      paymentsData.push({
        payment_id: uuid(),
        org_id: c.org_id,
        claim_number: c.case_id,
        payer: "Denied Appeal",
        amount_paid: paid_amount,
        date_paid: paid_at,
        source_file: "denial",
        created_at: nowISO(),
        denied_approved: true
      });
      writeJSON(FILES.payments, paymentsData);
    }

    auditLog({ actor: "user", action: "mark_paid", case_id, org_id: org.org_id, paid_at, paid_amount });
  }
  return redirect(res, "/dashboard");
}

  // -------- PAYMENT DETAILS LIST --------
  // Display a detailed list of payments for the organisation with filtering options.
  if (method === "GET" && pathname === "/payments/list") {
    // Load all payments for this organisation
    let payments = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id);
    // Build sets for year, month, quarter and payer filters from all payments (not filtered yet)
    const yearsSet = new Set();
    const payersSet = new Set();
    const monthsSet = new Set();
    payments.forEach(p => {
      let dtStr = p.date_paid || p.datePaid || p.created_at || p.created_at;
      let d;
      try {
        d = dtStr ? new Date(dtStr) : new Date();
      } catch {
        d = new Date();
      }
      yearsSet.add(d.getFullYear());
      const monthKey = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
      monthsSet.add(monthKey);
      const payerName = (p.payer || "Unknown").trim() || "Unknown";
      payersSet.add(payerName);
    });
    // Read filter parameters
    const yearFilter = parsed.query.year || "";
    const quarterFilter = parsed.query.quarter || "";
    const monthFilter = parsed.query.month || "";
    const payerFilter = parsed.query.payer || "";
    const deniedFilter = parsed.query.denied || "";
    // Apply year filter
    if (yearFilter) {
      payments = payments.filter(p => {
        let dtStr = p.date_paid || p.datePaid || p.created_at || p.created_at;
        let d;
        try { d = dtStr ? new Date(dtStr) : new Date(); } catch { d = new Date(); }
        return d.getFullYear() === Number(yearFilter);
      });
    }
    // Apply quarter filter (Q1..Q4)
    if (quarterFilter) {
      payments = payments.filter(p => {
        let dtStr = p.date_paid || p.datePaid || p.created_at || p.created_at;
        let d;
        try { d = dtStr ? new Date(dtStr) : new Date(); } catch { d = new Date(); }
        const month = d.getMonth() + 1;
        const q = Math.floor((month - 1) / 3) + 1;
        return `Q${q}` === quarterFilter;
      });
    }
    // Apply month filter (YYYY-MM)
    if (monthFilter) {
      payments = payments.filter(p => {
        let dtStr = p.date_paid || p.datePaid || p.created_at || p.created_at;
        let d;
        try { d = dtStr ? new Date(dtStr) : new Date(); } catch { d = new Date(); }
        const key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
        return key === monthFilter;
      });
    }
    // Apply payer filter
    if (payerFilter) {
      payments = payments.filter(p => {
        const name = (p.payer || "Unknown").trim() || "Unknown";
        return name === payerFilter;
      });
    }
    // Apply denied-only filter
    if (deniedFilter === "1") {
      payments = payments.filter(p => p.denied_approved);
    }
    // Compute aggregated stats by payer
    const stats = {};
    payments.forEach(p => {
      const payerName = (p.payer || "Unknown").trim() || "Unknown";
      const amt = Number(p.amount_paid || p.amountPaid || 0);
      if (!stats[payerName]) stats[payerName] = { total: 0, count: 0 };
      stats[payerName].total += amt;
      stats[payerName].count += 1;
    });
    // Build options for filters
    const yearOptions = Array.from(yearsSet).sort().map(y => `<option value="${y}"${yearFilter == y ? ' selected' : ''}>${y}</option>`).join('');
    const quarterOptions = ["Q1","Q2","Q3","Q4"].map(q => `<option value="${q}"${quarterFilter === q ? ' selected' : ''}>${q}</option>`).join('');
    const monthOptions = Array.from(monthsSet).sort().map(m => `<option value="${m}"${monthFilter === m ? ' selected' : ''}>${m}</option>`).join('');
    const payerOptions = Array.from(payersSet).sort().map(p => `<option value="${safeStr(p)}"${payerFilter === p ? ' selected' : ''}>${safeStr(p)}</option>`).join('');
    // Build summary table rows
    let summaryRows = '';
    Object.keys(stats).sort((a,b) => stats[b].total - stats[a].total).forEach(p => {
      const s = stats[p];
      summaryRows += `<tr><td>${safeStr(p)}</td><td>${s.count}</td><td>$${s.total.toFixed(2)}</td></tr>`;
    });
    const summaryTable = summaryRows ? `<table><thead><tr><th>Payer</th><th># Payments</th><th>Total Paid</th></tr></thead><tbody>${summaryRows}</tbody></table>` : `<p class='muted'>No payments found.</p>`;
    // Build detailed table (limit to 500 rows)
    let detailRows = '';
    payments.slice(0, 500).forEach(p => {
      let dtStr = p.date_paid || p.datePaid || p.created_at || p.created_at;
      let d;
      try { d = dtStr ? new Date(dtStr) : new Date(); } catch { d = new Date(); }
      const dateStr = d.toLocaleDateString();
      const deniedFlag = p.denied_approved ? "Yes" : "";
      detailRows += `<tr><td>${safeStr(p.claim_number || p.claimNumber || '')}</td><td>${safeStr((p.payer || 'Unknown').trim() || 'Unknown')}</td><td>$${Number(p.amount_paid || p.amountPaid || 0).toFixed(2)}</td><td>${dateStr}</td><td>${deniedFlag}</td></tr>`;
    });
    const detailTable = detailRows ? `<table><thead><tr><th>Claim Number</th><th>Payer</th><th>Amount Paid</th><th>Payment Date</th><th>Denied?</th></tr></thead><tbody>${detailRows}</tbody></table>` : `<p class='muted'>No payments found.</p>`;
    const html = page("Payment Details", `
      <h2>Payment Details</h2>
      <form method="GET" action="/payments/list" style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
        <div style="display:flex;flex-direction:column;">
          <label>Year</label>
          <select name="year">
            <option value="">All</option>
            ${yearOptions}
          </select>
        </div>
        <div style="display:flex;flex-direction:column;">
          <label>Quarter</label>
          <select name="quarter">
            <option value="">All</option>
            ${quarterOptions}
          </select>
        </div>
        <div style="display:flex;flex-direction:column;">
          <label>Month</label>
          <select name="month">
            <option value="">All</option>
            ${monthOptions}
          </select>
        </div>
        <div style="display:flex;flex-direction:column;">
          <label>Payer</label>
          <select name="payer">
            <option value="">All</option>
            ${payerOptions}
          </select>
        </div>
<div style="display:flex;flex-direction:column;">
  <label>Denied Recovery</label>
  <select name="denied">
    <option value="">All</option>
    <option value="1"${deniedFilter==="1"?" selected":""}>Denied → Approved Only</option>
  </select>
</div>
        <div>
          <button class="btn" type="submit" style="margin-top:1.6em;">Filter</button>
          <a class="btn secondary" href="/payments/list" style="margin-top:1.6em;">Reset</a>
        </div>
      </form>
      <div class="hr"></div>
      <h3>Summary by Payer</h3>
      ${summaryTable}
      <div class="hr"></div>
      <h3>Payments (${payments.length} rows${payments.length > 500 ? ', showing first 500' : ''})</h3>
      ${detailTable}
      <div class="hr"></div>
      <div class="btnRow"><a class="btn secondary" href="/dashboard">Back to Dashboard</a></div>
    `, navUser());
    return send(res, 200, html);
  }

  // -------- PAYMENT TRACKING (CSV/XLS allowed; CSV parsed) --------
  if (method === "GET" && pathname === "/payments") {
    return redirect(res, "/upload#payments");
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
      const html = page("Revenue Management", `
        <h2>Revenue Management</h2>
        <p class="error">Only CSV or Excel files are allowed for payment tracking.</p>
        <div class="btnRow"><a class="btn secondary" href="/payments">Back</a></div>
      `, navUser());
      return send(res, 400, html);
    }

    // file size cap (use same as plan)
    const limits = getLimitProfile(org.org_id);
    const maxBytes = limits.max_file_size_mb * 1024 * 1024;
    if (f.buffer.length > maxBytes) {
      const html = page("Revenue Management", `
        <h2>Revenue Management</h2>
        <p class="error">File too large. Max size is ${limits.max_file_size_mb} MB.</p>
        <div class "btnRow"><a class "btn secondary" href="/payments">Back</a></div>
      `, navUser());
      return send(res, 400, html);
    }

    // store raw file
    const dir = path.join(UPLOADS_DIR, org.org_id, "payments");
    ensureDir(dir);
    const stored = path.join(dir, `${Date.now()}_${(f.filename || "payments").replace(/[^a-zA-Z0-9._-]/g,"_")}`);
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
      const paymentsData = readJSON(FILES.payments, []);

      for (let i=0;i<storeLimit;i++){
        const r = rows[i];
        const claim = pickField(r, ["claim", "claim#", "claim number", "claimnumber", "clm"]);
        const payer = pickField(r, ["payer", "insurance", "carrier", "plan"]);
        const amt = pickField(r, ["paid", "amount", "payment", "paid amount", "allowed"]);
        const datePaid = pickField(r, ["date", "paid date", "payment date", "remit date"]);

        paymentsData.push({
          payment_id: uuid(),
          org_id: org.org_id,
          claim_number: claim || "",
          payer: payer || "",
          amount_paid: amt || "",
          date_paid: datePaid || "",
          source_file: path.basename(stored),
          created_at: nowISO(),
          denied_approved: false
        });
      }
      writeJSON(FILES.payments, paymentsData);

      rowsAdded = toUse;
      consumePaymentRows(org.org_id, rowsAdded);
    } else {
      // Excel stored but not parsed in v1 (still counts as 0 rows until CSV provided)
      rowsAdded = 0;
    }

    const html = page("Revenue Management", `
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

  // analytics page with placeholders and bar chart preview
  if (method === "GET" && pathname === "/analytics") {
    return redirect(res, "/dashboard");
  }

  // -------- ACCOUNT --------
  if (method === "GET" && pathname === "/account") {
    const sub = getSub(org.org_id);
    const pilot = getPilot(org.org_id) || ensurePilot(org.org_id);
    const limits = getLimitProfile(org.org_id);

    const planName = (sub && sub.status === "active") ? "Monthly" : (pilot && pilot.status === "active" ? "Pilot" : "Expired");
    const planEnds = (sub && sub.status === "active") ? "—" : (pilot?.ends_at ? new Date(pilot.ends_at).toLocaleDateString() : "—");

    const html = page("Account", `
      <h2>Account</h2>
      <p class="muted"><strong>Email:</strong> ${safeStr(user.email || "")}</p>
      <p class="muted"><strong>Organization:</strong> ${safeStr(org.org_name)}</p>

      <div class="hr"></div>
      <h3>Plan</h3>
      <table>
        <tr><th>Current Plan</th><td>${safeStr(planName)}</td></tr>
        <tr><th>Pilot End Date</th><td>${safeStr(planEnds)}</td></tr>
        <tr><th>Access Mode</th><td>${safeStr(limits.mode)}</td></tr>
      </table>

      <div class="hr"></div>
      <h3>Change Password</h3>
      <form method="POST" action="/account/password">
        <label>Current Password</label>
        <input name="current_password" type="password" required />
        <label>New Password (8+ characters)</label>
        <input name="new_password" type="password" required />
        <label>Confirm New Password</label>
        <input name="new_password2" type="password" required />
        <div class="btnRow">
          <button class="btn" type="submit">Update Password</button>
          <a class="btn secondary" href="/dashboard">Back</a>
        </div>
      </form>

      <div class="hr"></div>
      <h3>Upgrade Plan</h3>
      <p class="muted">To upgrade plans or manage billing, use the link below.</p>
      <div class="btnRow">
        <a class="btn secondary" href="https://tjhealthpro.com">Upgrade / Manage Plan</a>
      </div>
    `, navUser());
    return send(res, 200, html);
  }

  if (method === "POST" && pathname === "/account/password") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const current = params.get("current_password") || "";
    const p1 = params.get("new_password") || "";
    const p2 = params.get("new_password2") || "";

    if (p1.length < 8 || p1 !== p2) {
      const html = page("Account", `
        <h2>Account</h2>
        <p class="error">New passwords must match and be at least 8 characters.</p>
        <div class="btnRow"><a class="btn secondary" href="/account">Back</a></div>
      `, navUser());
      return send(res, 400, html);
    }

    const users = readJSON(FILES.users, []);
    const uidx = users.findIndex(u => u.user_id === user.user_id);
    if (uidx < 0) return redirect(res, "/logout");

    if (!bcrypt.compareSync(current, users[uidx].password_hash)) {
      const html = page("Account", `
        <h2>Account</h2>
        <p class="error">Current password is incorrect.</p>
        <div class="btnRow"><a class="btn secondary" href="/account">Back</a></div>
      `, navUser());
      return send(res, 401, html);
    }

    users[uidx].password_hash = bcrypt.hashSync(p1, 10);
    writeJSON(FILES.users, users);
    auditLog({ actor:"user", action:"change_password", org_id: org.org_id, user_id: user.user_id });

    const html = page("Account", `
      <h2>Account</h2>
      <p class="muted">Password updated successfully.</p>
      <div class="btnRow"><a class="btn" href="/dashboard">Back to Dashboard</a></div>
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
        <a class "btn secondary" href="/export/analytics.csv">Analytics CSV</a>
        <a class "btn secondary" href="/report">Printable Pilot Summary</a>
      </div>
    `, navUser());
    return send(res, 200, html);
  }

  if (method === "GET" && pathname === "/export/cases.csv") {
    const casesExport = readJSON(FILES.cases, []).filter(c => c.org_id === org.org_id);
    const header = ["case_id","status","created_at","time_to_draft_seconds","denial_reason"].join(",");
    const rows = casesExport.map(c => [
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
    const paymentsExport = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id);
    const header = ["payment_id","claim_number","payer","amount_paid","date_paid","source_file","denied_approved","created_at"].join(",");
    const rows = paymentsExport.map(p => [
      p.payment_id, p.claim_number, p.payer, p.amount_paid, p.date_paid, p.source_file, (p.denied_approved ? "Yes" : ""), p.created_at
    ].map(x =>
    `"${String(x||"").replace(/"/g,'""')}"`).join(","));
    const csv = [header, ...rows].join("\n");
    res.writeHead(200, { "Content-Type":"text/csv", "Content-Disposition":"attachment; filename=payments.csv" });
    return res.end(csv);
  }

  if (method === "GET" && pathname === "/export/analytics.csv") {
    const aExport = computeAnalytics(org.org_id);
    const header = ["metric","value"].join(",");
    const rows = [
      ["cases_uploaded", aExport.totalCases],
      ["drafts_generated", aExport.drafts],
      ["avg_time_to_draft_seconds", aExport.avgDraftSeconds || ""],
    ].map(r => r.map(x => `"${String(x).replace(/"/g,'""')}"`).join(","));
    const csv = [header, ...rows].join("\n");
    res.writeHead(200, { "Content-Type":"text/csv", "Content-Disposition":"attachment; filename=analytics.csv" });
    return res.end(csv);
  }

  if (method === "GET" && pathname === "/report") {
    const aReport = computeAnalytics(org.org_id);
    const pilotRep = getPilot(org.org_id) || ensurePilot(org.org_id);
    const html = page("Pilot Summary", `
      <h2>Pilot Summary Report</h2>
      <p class="muted">Organization: ${safeStr(org.org_name)}</p>
      <div class="hr"></div>
      <ul class="muted">
        <li>Pilot start: ${new Date(pilotRep.started_at).toLocaleDateString()}</li>
        <li>Pilot end: ${new Date(pilotRep.ends_at).toLocaleDateString()}</li>
      </ul>
      <h3>Snapshot</h3>
      <ul class="muted">
        <li>Cases uploaded: ${aReport.totalCases}</li>
        <li>Drafts generated: ${aReport.drafts}</li>
        <li>Avg time to draft: ${aReport.avgDraftSeconds ? `${aReport.avgDraftSeconds}s` : "—"}</li>
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
    const pilotEnd = getPilot(org.org_id) || ensurePilot(org.org_id);
    if (new Date(pilotEnd.ends_at).getTime() < Date.now() && pilotEnd.status !== "complete") markPilotComplete(org.org_id);
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

