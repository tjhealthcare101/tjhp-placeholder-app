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
const PILOT_DAYS = 14;
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
  templates: path.join(DATA_DIR, "templates.json"),
  billed: path.join(DATA_DIR, "billed.json"),
  billed_submissions: path.join(DATA_DIR, "billed_submissions.json"),
  negotiations: path.join(DATA_DIR, "negotiations.json"),
  ai_queries: path.join(DATA_DIR, "ai_queries.json"),
  saved_queries: path.join(DATA_DIR, "saved_queries.json"),
  deleted_payment_batches: path.join(DATA_DIR, "deleted_payment_batches.json"),
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
ensureFile(FILES.billed, []);
ensureFile(FILES.billed_submissions, []);
ensureFile(FILES.negotiations, []);
ensureFile(FILES.ai_queries, []);
ensureFile(FILES.saved_queries, []);
ensureFile(FILES.deleted_payment_batches, []);

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
.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;position:sticky;top:0;z-index:999;background:var(--card);padding:12px 16px;box-shadow:0 2px 4px rgba(0,0,0,.05);}
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
.btn.success{background:#16a34a;color:#fff;}
.btn.success:hover{background:#15803d;}
.btnRow{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;}
label{font-size:12px;color:var(--muted);font-weight:800;}
input,textarea{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:10px;font-size:14px;outline:none;margin-top:6px;}
input:focus,textarea:focus{border-color:#c7d2fe;box-shadow:0 0 0 3px rgba(99,102,241,.12);}
textarea{min-height:220px;}
.badge{display:inline-block;border:1px solid var(--border);background:#fff;border-radius:999px;padding:4px 10px;font-size:12px;font-weight:900;}
.badge.ok{border-color:#a7f3d0;background:#ecfdf5;color:var(--ok);}
.badge.warn{border-color:#fde68a;background:#fffbeb;color:var(--warn);}
.badge.err{border-color:#fecaca;background:#fef2f2;color:var(--danger);}
.badge.underpaid{border-color:#fdba74;background:#fff7ed;color:#9a3412;}
.badge.writeoff{border-color:#d1d5db;background:#f3f4f6;color:#374151;}
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

/* Print styling */
@media print {
  .nav, .btn, .btnRow, form { display:none !important; }
  body { background:white !important; }
  .card { box-shadow:none !important; border:none !important; }
}
`;
/**
 * FIX: all HTML + scripts must live inside returned strings.
 * Password toggle preserved.
 */
function renderPage(title, content, navHtml="", opts={}) {
  const orgName = (opts && opts.orgName) ? safeStr(opts.orgName) : "";
  const showChat = !!(opts && opts.showChat);
  const chatHtml = showChat ? `
<div id="aiChat" style="position:fixed;bottom:18px;right:18px;z-index:9999;">
  <button class="btn" type="button" onclick="window.__tjhpToggleChat()">AI Assistant</button>
  <div id="aiChatBox" style="display:none;width:320px;height:420px;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:10px;margin-top:8px;box-shadow:0 12px 30px rgba(17,24,39,.10);">
    <div class="muted small" style="margin-bottom:6px;">Ask questions about your denials, payments, trends, and what pages do.</div>
    <div id="aiChatMsgs" style="height:300px;overflow:auto;border:1px solid #e5e7eb;border-radius:10px;padding:8px;"></div>
    <input id="aiChatInput" placeholder="Ask about your data..." style="margin-top:8px;" />
    <div class="btnRow" style="margin-top:8px;">
      <button class="btn secondary" type="button" onclick="window.__tjhpSendChat()">Send</button>
      <button class="btn secondary" type="button" onclick="window.__tjhpToggleChat()">Close</button>
    </div>
  </div>
</div>` : "";

  const chatScript = showChat ? `
<script>
window.__tjhpToggleChat = function(){
  const box = document.getElementById("aiChatBox");
  if (!box) return;
  box.style.display = (box.style.display === "none" || !box.style.display) ? "block" : "none";
};

window.__tjhpSendChat = async function(){
  const input = document.getElementById("aiChatInput");
  const msgs = document.getElementById("aiChatMsgs");
  if (!input || !msgs) return;
  const text = (input.value || "").trim();
  if (!text) return;

  const esc = (s)=>String(s).replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
  const addMsg = (who, t) => {
    const div = document.createElement("div");
    div.style.margin = "6px 0";
    div.innerHTML = "<strong>" + who + ":</strong> " + esc(t);
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
  };

  addMsg("You", text);
  input.value = "";

  try{
    const r = await fetch("/ai/chat", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({ message: text })
    });
    const data = await r.json();
    addMsg("AI", (data && data.answer) ? data.answer : "No response.");
  }catch(e){
    addMsg("AI", "Error contacting assistant. Try again.");
  }
};
</script>` : "";

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
        <div class="sub">AI Revenue Intelligence Platform</div>
        ${orgName ? `<div class="sub">Organization: ${orgName}</div>` : ``}
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

${chatHtml}

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

${chatScript}
</body></html>`;
}


function navPublic() {
  return `<a href="/login">Login</a><a href="/signup">Create Account</a><a href="/admin/login">Owner</a>`;
}
function navUser() {
  return `<a href="/dashboard">Revenue Overview</a><a href="/claims">Claims Lifecycle</a><a href="/intelligence">Revenue Intelligence (AI)</a><a href="/actions">Action Center</a><a href="/report">Reports</a><a href="/account">Account</a><a href="/logout">Logout</a>`;
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
      ai_job_timestamps: [],
      ai_chat_used: 0
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
    u.ai_chat_used = 0;
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


// ===== Plans (Pricing + Limits) =====
// Pricing (for partner summary / UI display): Starter $249, Growth $599, Pro $1200, Enterprise $2000
const PLAN_CONFIG = {
  starter:   { price_monthly: 249, ai_chat_limit: 50,  case_credits_per_month: 50,  payment_tracking_credits_per_month: 10 },
  growth:    { price_monthly: 599, ai_chat_limit: 150, case_credits_per_month: 150, payment_tracking_credits_per_month: 50 },
  pro:       { price_monthly: 1200, ai_chat_limit: 400, case_credits_per_month: 400, payment_tracking_credits_per_month: 150 },
  enterprise:{ price_monthly: 2000, ai_chat_limit: 999999, case_credits_per_month: 999999, payment_tracking_credits_per_month: 999999 },
};

function getActivePlanName(org_id) {
  const sub = getSub(org_id);
  if (sub && sub.status === "active" && sub.plan) return String(sub.plan);
  return "pilot";
}

function getAIChatLimit(org_id) {
  const sub = getSub(org_id);
  if (sub && sub.status === "active") {
    const plan = (sub.plan || "starter").toLowerCase();
    return (PLAN_CONFIG[plan]?.ai_chat_limit) ?? 50;
  }
  // Pilot = 10 total questions for the 14-day trial
  const pilot = getPilot(org_id) || ensurePilot(org_id);
  if (pilot && pilot.status === "active") return 10;
  return 0;
}

function ensureSubscriptionForOrg(org_id) {
  const subs = readJSON(FILES.subscriptions, []);
  let s = subs.find(x => x.org_id === org_id);
  if (!s) {
    s = {
      sub_id: uuid(),
      org_id,
      status: "inactive",
      plan: "",
      customer_email: "",
      case_credits_per_month: MONTHLY_DEFAULTS.case_credits_per_month,
      payment_tracking_credits_per_month: MONTHLY_DEFAULTS.payment_tracking_credits_per_month,
      updated_at: nowISO()
    };
    subs.push(s);
    writeJSON(FILES.subscriptions, subs);
  }
  return s;
}

function applyPlanToSubscription(sub, planName) {
  const key = (planName || "").toLowerCase();
  const cfg = PLAN_CONFIG[key] || PLAN_CONFIG.starter;
  sub.plan = key;
  sub.case_credits_per_month = cfg.case_credits_per_month;
  sub.payment_tracking_credits_per_month = cfg.payment_tracking_credits_per_month;
  sub.ai_chat_limit = cfg.ai_chat_limit;
  sub.status = "active";
  sub.updated_at = nowISO();
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


function money(n){
  const x = Number(n || 0);
  return "$" + x.toFixed(2);
}

function num(v){
  const n = Number(String(v||"").replace(/[^0-9.\-]/g,""));
  return isFinite(n) ? n : 0;
}

function computeExpectedInsurance(allowedAmount, patientResp){
  const allowed = num(allowedAmount);
  const pr = Math.max(0, num(patientResp));
  return Math.max(0, allowed - pr);
}

function computeUnderpaidAmount(expectedInsurance, actualInsurancePaid){
  const exp = num(expectedInsurance);
  const act = num(actualInsurancePaid);
  return Math.max(0, exp - act);
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


function aiGenerateUnderpayment(orgName, meta) {
  const claim = meta?.claim_number || "(claim #)";
  const dos = meta?.dos || "(DOS)";
  const payer = meta?.payer || "(payer)";
  const allowed = meta?.allowed_amount != null ? money(meta.allowed_amount) : "(allowed)";
  const expected = meta?.expected_insurance != null ? money(meta.expected_insurance) : "(expected)";
  const paid = meta?.actual_paid != null ? money(meta.actual_paid) : "(paid)";
  const diff = meta?.underpaid_amount != null ? money(meta.underpaid_amount) : "(difference)";

  return {
    denial_summary: "This case reflects an insurance underpayment relative to expected contracted/allowed reimbursement.",
    appeal_considerations: "Validate contract/fee schedule language and attach EOB/ERA evidence before submission. Confirm timely filing and payer dispute window.",
    draft_text:
`(Your Name or Practice Name)
(Street Address)
(City, State ZIP)

(Date)

${payer}
(Street Address)
(City, State ZIP)

RE: Underpayment Dispute / Reconsideration
Claim #: ${claim}
Date(s) of Service: ${dos}

To Whom It May Concern,

We are submitting this letter to dispute an underpayment on the above-referenced claim. Based on the Explanation of Benefits (EOB/ERA), the expected payment for covered services is ${expected}, however the payment issued was ${paid}, resulting in an underpayment of ${diff}.

Summary:
- Allowed Amount: ${allowed}
- Expected Insurance Payment: ${expected}
- Actual Insurance Payment: ${paid}
- Underpaid Difference: ${diff}

Request:
Please reprocess and remit the underpaid amount in accordance with the applicable contract/fee schedule and any referenced reimbursement provisions.

Enclosures (as applicable):
1) Original claim submission (CMS-1500/UB-04) and itemized charges
2) EOB/ERA showing payment issued and any adjustment codes
3) Evidence of contracted rates / fee schedule excerpts (attach)
4) Supporting medical documentation (as applicable)
5) Proof of timely filing
6) Log of previous correspondence/calls with reference numbers

If additional information is required, please contact our office.

Sincerely,
${orgName || "[Organization Billing Team]"}
`,
    denial_reason_category: "Underpayment",
    missing_info: []
  };
}

// ===== Appeal Packet Builder (De‑Identified / Non‑PHI mode) =====
// NOTE: Do NOT store patient identifiers (name, DOB, member ID). Use placeholders.
// Attachments should be de‑identified only. Files are stored temporarily and auto-deleted.
const APPEAL_ATTACHMENT_TTL_MS = 60 * 60 * 1000; // 60 minutes

function appealPacketDefaults(orgName) {
  return {
    deid_confirmed: false,
    claim_number: "",
    payer: "",
    dos: "",
    cpt_hcpcs_codes: "",
    icd10_codes: "",
    authorization_number: "",
    provider_npi: "",
    provider_tax_id: "",
    provider_address: "",
    contact_log: "",
    lmn_text:
`LETTER OF MEDICAL NECESSITY (TEMPLATE — DE‑IDENTIFIED)
Patient Name: ____________________
DOB: ____/____/______
Member ID: ____________________

To Whom It May Concern,

I am writing to support the medical necessity of the requested service for the patient listed above.

Clinical Summary (de‑identified):
- Diagnosis / ICD‑10: ____________________
- Requested Service / CPT/HCPCS: ____________________
- Date(s) of Service: ____________________
- Prior treatments attempted and outcomes: ____________________

Medical Necessity Rationale:
1) The requested service is medically necessary because ____________________.
2) Alternative treatments have been attempted and were ineffective / contraindicated because ____________________.
3) The requested service aligns with accepted standards of care and clinical guidelines.

Supporting References (attach as needed):
- Peer‑reviewed literature and/or clinical guidelines supporting standard of care.

Sincerely,
${orgName || "[Provider / Practice]"}
`,
    checklist_notes:
`APPEAL PACKET CHECKLIST (DE‑IDENTIFIED)
Essential Documentation:
[ ] Denial letter / EOB copy (de‑identified)
[ ] Appeal letter (formal)
[ ] Letter of Medical Necessity (LMN)
[ ] Relevant medical records (de‑identified: chart notes, imaging, labs, op reports)
[ ] Authorization number proof (if applicable)
[ ] Patient identifiers (to be filled AFTER export, outside this system)

Administrative Items:
[ ] Claim number, DOS, payer
[ ] CPT/HCPCS codes + ICD‑10 codes
[ ] Provider NPI, Tax ID, address
[ ] Appeal / reconsideration form (payer-specific, if required)
[ ] Interaction log (dates/times/rep names — no patient identifiers)

Supporting Documents:
[ ] Clinical guidelines or peer‑reviewed literature
[ ] Coding crosswalk / code validation notes (if needed)
`,
    compiled_packet_text: "",
    compiled_at: null
  };
}

function normalizeAppealPacket(c, orgName) {
  if (!c.appeal_packet) c.appeal_packet = appealPacketDefaults(orgName);
  // Ensure all keys exist (forward compatible)
  const d = appealPacketDefaults(orgName);
  for (const k of Object.keys(d)) {
    if (typeof c.appeal_packet[k] === "undefined") c.appeal_packet[k] = d[k];
  }
  if (!Array.isArray(c.appeal_attachments)) c.appeal_attachments = []; // {file_id, filename, stored_path, uploaded_at, expires_at}
  return c;
}

function cleanupExpiredAppealAttachments(org_id) {
  const now = Date.now();
  const cases = readJSON(FILES.cases, []).filter(c => c.org_id === org_id);
  let changed = false;

  for (const c of cases) {
    if (!Array.isArray(c.appeal_attachments) || c.appeal_attachments.length === 0) continue;
    const keep = [];
    for (const a of c.appeal_attachments) {
      const exp = a && a.expires_at ? new Date(a.expires_at).getTime() : 0;
      if (exp && exp <= now) {
        try { if (a.stored_path && fs.existsSync(a.stored_path)) fs.rmSync(a.stored_path, { force:true }); } catch {}
        changed = true;
      } else {
        keep.push(a);
      }
    }
    if (keep.length !== c.appeal_attachments.length) c.appeal_attachments = keep;
  }

  if (changed) {
    const all = readJSON(FILES.cases, []);
    // replace org cases with updated ones
    const out = all.map(x => {
      if (x.org_id !== org_id) return x;
      const updated = cases.find(y => y.case_id === x.case_id);
      return updated || x;
    });
    writeJSON(FILES.cases, out);
  }
}

function compileAppealPacketText(c, orgName) {
  normalizeAppealPacket(c, orgName);
  const ap = c.appeal_packet;

  const attachmentsIndex = (c.appeal_attachments || []).map(a => `- ${a.filename || "attachment"}`).join("\n") || "- (none uploaded)";

  const header =
`APPEAL PACKET (DE‑IDENTIFIED)
Organization: ${orgName || ""}
Case ID: ${c.case_id}
Generated: ${new Date().toLocaleString()}

IMPORTANT: This packet is DE‑IDENTIFIED. Do not include patient name, DOB, or member ID in this system.
Fill patient identifiers AFTER export, outside this platform.
`;

  const admin =
`ADMIN + CODING SUMMARY (DE‑IDENTIFIED)
Claim #: ${ap.claim_number || "(enter claim #)"}
Payer: ${ap.payer || "(enter payer)"}
DOS: ${ap.dos || "(enter DOS)"}
CPT/HCPCS: ${ap.cpt_hcpcs_codes || "(enter codes)"}
ICD‑10: ${ap.icd10_codes || "(enter codes)"}
Authorization #: ${ap.authorization_number || "(enter auth #)"}

Provider NPI: ${ap.provider_npi || "(enter NPI)"}
Provider Tax ID: ${ap.provider_tax_id || "(enter Tax ID)"}
Provider Address: ${ap.provider_address || "(enter address)"}
`;

  const log =
`INTERACTION LOG (NO PATIENT IDENTIFIERS)
${ap.contact_log || "(no log entered)"}
`;

  const compiled =
`${header}
==============================
1) APPEAL LETTER
------------------------------
${(c.ai && c.ai.draft_text) ? c.ai.draft_text : "(appeal letter not available)"}

==============================
2) LETTER OF MEDICAL NECESSITY
------------------------------
${ap.lmn_text || "(LMN not available)"}

==============================
3) CHECKLIST
------------------------------
${ap.checklist_notes || ""}

==============================
4) ADMIN + CODING SUMMARY
------------------------------
${admin}

==============================
5) ATTACHMENTS INDEX (DE‑IDENTIFIED)
------------------------------
${attachmentsIndex}

==============================
6) NOTES / LOG
------------------------------
${log}
`;

  ap.compiled_packet_text = compiled;
  ap.compiled_at = nowISO();
  return c;
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
  // Choose generator based on case_type
  const isUnderpay = (caseObj.case_type || "").toLowerCase() === "underpayment";
  const out = isUnderpay ? aiGenerateUnderpayment(orgName, caseObj.underpayment_meta || {}) : aiGenerate(orgName);
  caseObj.ai.denial_summary = out.denial_summary;
  caseObj.ai.appeal_considerations = out.appeal_considerations;
  caseObj.ai.denial_reason_category = out.denial_reason_category;
  caseObj.ai.missing_info = out.missing_info;
  caseObj.ai.time_to_draft_seconds = Math.max(1, Math.floor((Date.now()-started)/1000));
  // If a draft template was loaded, use it.  Otherwise use the AI
  // generated draft text.
  caseObj.ai.draft_text = draftText || out.draft_text;
  // Seed de‑identified appeal packet scaffolding
  normalizeAppealPacket(caseObj, orgName);
  if (!caseObj.appeal_packet.lmn_text) caseObj.appeal_packet.lmn_text = appealPacketDefaults(orgName).lmn_text;
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


  const billed = readJSON(FILES.billed, []).filter(b => b.org_id === org_id);
  const billed_total = billed.length;
  const billed_paid = billed.filter(b => (b.status || "Pending") === "Paid").length;
  const billed_denied = billed.filter(b => (b.status || "Pending") === "Denied").length;
  const billed_pending = billed.filter(b => !["Paid","Denied"].includes((b.status || "Pending"))).length;
  const billed_denial_rate = billed_total > 0 ? ((billed_denied / billed_total) * 100).toFixed(1) : "0.0";
  const billed_payment_conversion = billed_total > 0 ? ((billed_paid / billed_total) * 100).toFixed(1) : "0.0";


 
  // ===== Lifecycle KPIs (Billed → Denied → Paid) =====
  const paymentDurations = billed
    .filter(b => (b.status || "Pending") === "Paid" && b.paid_at)
    .map(b => {
      const start = b.denied_at ? new Date(b.denied_at) : new Date(b.created_at);
      const end = new Date(b.paid_at);
      return (end - start) / (1000*60*60*24);
    })
    .filter(d => typeof d === "number" && d >= 0 && isFinite(d));

  const avgDaysToPayment = paymentDurations.length
    ? Math.round(paymentDurations.reduce((a,b)=>a+b,0) / paymentDurations.length)
    : null;

  const denialTurnarounds = billed
    .filter(b => (b.status || "Pending") === "Denied" && b.denied_at && b.denial_case_id)
    .map(b => {
      const c = cases.find(x => x.case_id === b.denial_case_id && x.org_id === org_id);
      if (!c || !c.created_at) return null;
      return (new Date(c.created_at) - new Date(b.denied_at)) / (1000*60*60*24);
    })
    .filter(d => typeof d === "number" && d >= 0 && isFinite(d));

  const avgDenialTurnaround = denialTurnarounds.length
    ? Math.round(denialTurnarounds.reduce((a,b)=>a+b,0) / denialTurnarounds.length)
    : null;

  const agingFromDenial = { over30: 0, over60: 0, over90: 0 };
  billed
    .filter(b => (b.status || "Pending") !== "Paid" && b.denied_at)
    .forEach(b => {
      const days = (Date.now() - new Date(b.denied_at).getTime()) / (1000*60*60*24);
      if (days > 90) agingFromDenial.over90++;
      else if (days > 60) agingFromDenial.over60++;
      else if (days > 30) agingFromDenial.over30++;
    });

  const resolutionDurations = billed
    .filter(b => (b.status || "Pending") === "Paid" && b.created_at && b.paid_at)
    .map(b => (new Date(b.paid_at) - new Date(b.created_at)) / (1000*60*60*24))
    .filter(d => typeof d === "number" && d >= 0 && isFinite(d));

  const avgTimeToResolution = resolutionDurations.length
    ? Math.round(resolutionDurations.reduce((a,b)=>a+b,0) / resolutionDurations.length)
    : null;
return {totalCases, drafts, avgDraftSeconds, denialReasons, payByPayer, totalRecoveredFromDenials, recoveryRate, aging, projectedLostRevenue, billed_total, billed_paid, billed_denied, billed_pending, billed_denial_rate, billed_payment_conversion, avgDaysToPayment, avgDenialTurnaround, agingFromDenial, avgTimeToResolution};
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


function projectNextMonthDenials(org_id) {
  // Simple v1 projection based on last 3 months average denial volume.
  try {
    const byMonth = computeDenialTrends(org_id);
    const months = Object.keys(byMonth).sort();
    if (months.length < 2) return null;
    const last = months.slice(-3);
    const vals = last.map(k => Number(byMonth[k]?.total || 0)).filter(n => isFinite(n));
    if (!vals.length) return null;
    const avg = vals.reduce((a,b)=>a+b,0) / vals.length;
    return Math.round(avg);
  } catch {
    return null;
  }
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


function parseDateOnly(s){
  if (!s) return null;
  const d = new Date(String(s).trim() + "T00:00:00.000Z");
  return isNaN(d.getTime()) ? null : d;
}
function rangeFromPreset(preset){
  const now = new Date();
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 23,59,59,999));
  let start = new Date(end);
  const p = String(preset || "last30").toLowerCase();
  if (p === "today") start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0,0,0,0));
  else if (p === "last7") start = new Date(end.getTime() - 7*24*60*60*1000);
  else if (p === "last30") start = new Date(end.getTime() - 30*24*60*60*1000);
  else if (p === "thismonth") start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0,0,0,0));
  else if (p === "thisyear") start = new Date(Date.UTC(now.getUTCFullYear(), 0, 1, 0,0,0,0));
  else start = new Date(end.getTime() - 30*24*60*60*1000);
  return { start, end, preset: p };
}
function fmtMoney(n){ const x = Number(n||0); return "$" + x.toFixed(2); }
function safeNum(n){ const x = Number(n||0); return isFinite(x) ? x : 0; }
function groupKeyForDate(d, gran){
  const dt = new Date(d);
  if (gran === "day") return dt.toISOString().slice(0,10);
  if (gran === "week"){
    const day = (dt.getUTCDay()+6)%7;
    const monday = new Date(Date.UTC(dt.getUTCFullYear(), dt.getUTCMonth(), dt.getUTCDate()-day));
    return monday.toISOString().slice(0,10);
  }
  return dt.getUTCFullYear() + "-" + String(dt.getUTCMonth()+1).padStart(2,"0");
}
function chooseGranularity(preset){
  const p = String(preset||"last30");
  if (p === "today" || p === "last7") return "day";
  if (p === "thisyear") return "month";
  return "week";
}

function computeDashboardMetrics(org_id, start, end, preset){
  const billedAll = readJSON(FILES.billed, []).filter(b => b.org_id === org_id);
  const paymentsAll = readJSON(FILES.payments, []).filter(p => p.org_id === org_id);
  const casesAll = readJSON(FILES.cases, []).filter(c => c.org_id === org_id);

  const inRange = (dtStr) => {
    const d = dtStr ? new Date(dtStr) : null;
    if (!d || isNaN(d.getTime())) return false;
    return d >= start && d <= end;
  };

  const billed = billedAll.filter(b => inRange(b.created_at || b.paid_at || b.denied_at));
  const payments = paymentsAll.filter(p => inRange(p.date_paid || p.created_at));
  const underpayCases = casesAll.filter(c => (c.case_type||"").toLowerCase()==="underpayment" && inRange(c.created_at));

  // --- Per-claim reconciliation helpers (Option 2: full transparency) ---
  const rec = (b) => {
    const billedAmt = safeNum(b.amount_billed);
    const insurancePaid = safeNum(b.insurance_paid || b.paid_amount);
    const patientCollected = safeNum(b.patient_collected);

    // Write-off: explicit write_off_amount wins; otherwise billed - allowed when allowed present; otherwise contractual_adjustment if present
    const allowedRaw = safeNum(b.allowed_amount);
    const explicitWO = (b.write_off_amount != null && String(b.write_off_amount).trim() !== "") ? safeNum(b.write_off_amount) : null;
    const contractualAdj = safeNum(b.contractual_adjustment);

    let writeOff = 0;
    if (explicitWO != null) writeOff = Math.max(0, explicitWO);
    else if (allowedRaw > 0) writeOff = Math.max(0, billedAmt - allowedRaw);
    else if (contractualAdj > 0) writeOff = Math.max(0, contractualAdj);

    const allowed = (allowedRaw > 0) ? allowedRaw : Math.max(0, billedAmt - writeOff);

    // Underpaid (dynamic): per requirement (prevents stale stored values)
    const underpaidDyn = Math.max(0, billedAmt - insurancePaid - patientCollected);

    // Denied dollars: if claim is marked Denied, treat denied dollars as allowed (or billed if allowed missing)
    const st = String(b.status || "Pending");
    const deniedDollars = (st === "Denied") ? Math.max(0, (allowed > 0 ? allowed : billedAmt)) : 0;

    return { billedAmt, allowed, insurancePaid, patientCollected, writeOff, underpaidDyn, deniedDollars, status: st };
  };

  const totals = billed.reduce((acc, b) => {
    const r = rec(b);
    acc.totalBilled += r.billedAmt;
    acc.allowedTotal += r.allowed;
    acc.insuranceCollected += r.insurancePaid;
    acc.patientCollected += r.patientCollected;
    acc.patientRespTotal += safeNum(b.patient_responsibility);
    acc.writeOffTotal += r.writeOff;

    // KPI underpaid: sum of dynamic underpaid dollars for Underpaid + Appeal (money still at-risk from payer)
    if (r.status === "Underpaid" || r.status === "Appeal") acc.underpaidAmt += r.underpaidDyn;
    return acc;
  }, { totalBilled:0, allowedTotal:0, insuranceCollected:0, patientCollected:0, patientRespTotal:0, writeOffTotal:0, underpaidAmt:0 });

  const patientOutstanding = Math.max(0, totals.patientRespTotal - totals.patientCollected);

  const collectedTotal = totals.insuranceCollected + totals.patientCollected;

  // Revenue at risk should exclude write-offs (non-collectible)
  const revenueAtRisk = Math.max(0, totals.totalBilled - totals.writeOffTotal - collectedTotal);

  const grossCollectionRate = totals.totalBilled > 0 ? (collectedTotal / totals.totalBilled) * 100 : 0;
  const netCollectionRate = totals.allowedTotal > 0 ? (collectedTotal / totals.allowedTotal) * 100 : 0;

  // Status counts (align labels with charts)
  const statusCounts = { Paid:0, "Patient Balance":0, Underpaid:0, Denied:0, "Write-Off":0, Pending:0 };
  billed.forEach(b=>{
    const st = String(b.status || "Pending");
    if (st === "Paid") statusCounts.Paid++;
    else if (st === "Denied") statusCounts.Denied++;
    else if (st === "Underpaid") statusCounts.Underpaid++;
    else if (st === "Patient Balance") statusCounts["Patient Balance"]++;
    else if (st === "Contractual") statusCounts["Write-Off"]++;
    else statusCounts.Pending++;
  });

  // Time series (billed vs collected vs at-risk)
  const gran = chooseGranularity(preset);
  const billedSeries = {};
  const collectedSeries = {};
  const atRiskSeries = {};

  billed.forEach(b=>{
    const d = new Date(b.created_at || b.paid_at || b.denied_at || Date.now());
    const k = groupKeyForDate(d, gran);
    billedSeries[k] = (billedSeries[k]||0) + safeNum(b.amount_billed);
  });
  payments.forEach(p=>{
    const d = new Date(p.date_paid || p.created_at || Date.now());
    const k = groupKeyForDate(d, gran);
    collectedSeries[k] = (collectedSeries[k]||0) + safeNum(p.amount_paid);
  });

  const keys = Array.from(new Set([...Object.keys(billedSeries), ...Object.keys(collectedSeries)])).sort();
  keys.forEach(k=>{
    const bsum = safeNum(billedSeries[k]);
    const csum = safeNum(collectedSeries[k]);
    // at-risk excludes write-offs at the claim level, but we only have series totals here -> conservative view
    atRiskSeries[k] = Math.max(0, bsum - csum);
  });

  // Payer reconciliation aggregation (Option 2)
  const payerAgg = {};
  billed.forEach(b=>{
    const payer = (b.payer || "Unknown").trim() || "Unknown";
    const r = rec(b);
    if (!payerAgg[payer]) payerAgg[payer] = { billed:0, allowed:0, paid:0, denied:0, writeOff:0, underpaid:0, count:0 };
    payerAgg[payer].billed += r.billedAmt;
    payerAgg[payer].allowed += r.allowed;
    payerAgg[payer].paid += r.insurancePaid;
    payerAgg[payer].denied += r.deniedDollars;
    payerAgg[payer].writeOff += r.writeOff;

    // Underpaid dollars attributed to Underpaid + Appeal statuses (payer-side at-risk)
    if (r.status === "Underpaid" || r.status === "Appeal") payerAgg[payer].underpaid += r.underpaidDyn;

    payerAgg[payer].count += 1;
  });

  const payerTop = Object.entries(payerAgg)
    .sort((a,b)=> (b[1].underpaid - a[1].underpaid) || (b[1].billed - a[1].billed))
    .slice(0,8)
    .map(([payer,v])=>({ payer, ...v }));

  return {
    kpis: {
      totalBilled: totals.totalBilled,
      allowedTotal: totals.allowedTotal,
      writeOffTotal: totals.writeOffTotal,
      collectedTotal,
      revenueAtRisk,
      grossCollectionRate,
      netCollectionRate,
      underpaidAmt: totals.underpaidAmt,
      underpaidCount: billed.filter(b => ["Underpaid","Appeal"].includes(String(b.status||""))).length,
      patientRespTotal: totals.patientRespTotal,
      patientCollected: totals.patientCollected,
      patientOutstanding,
      negotiationCases: underpayCases.length
    },
    statusCounts,
    series: { gran, keys, billed: keys.map(k=>safeNum(billedSeries[k])), collected: keys.map(k=>safeNum(collectedSeries[k])), atRisk: keys.map(k=>safeNum(atRiskSeries[k])) },
    payerTop
  };
}



// ===== Negotiations (NEW) =====
function getNegotiations(org_id){
  return readJSON(FILES.negotiations, []).filter(n => n.org_id === org_id);
}
function getNegotiationById(org_id, negotiation_id){
  return readJSON(FILES.negotiations, []).find(n => n.org_id === org_id && n.negotiation_id === negotiation_id);
}
function saveNegotiation(rec){
  const all = readJSON(FILES.negotiations, []);
  const idx = all.findIndex(n => n.negotiation_id === rec.negotiation_id);
  if (idx >= 0) all[idx] = rec; else all.push(rec);
  writeJSON(FILES.negotiations, all);
}
function updateBilledClaim(billed_id, updater){
  const billedAll = readJSON(FILES.billed, []);
  const idx = billedAll.findIndex(b => b.billed_id === billed_id);
  if (idx < 0) return null;
  const b = billedAll[idx];
  updater(b);
  billedAll[idx] = b;
  writeJSON(FILES.billed, billedAll);
  return b;
}

// ===== Pagination + Filtering Helpers =====
const PAGE_SIZE_OPTIONS = [30, 50, 100];

function clampInt(v, minV, maxV, fallback){
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(minV, Math.min(maxV, Math.floor(n)));
}

function parsePageParams(qs){
  const pageSize = clampInt(qs.pageSize || qs.per_page || 50, 30, 100, 50);
  const page = clampInt(qs.page || 1, 1, 999999, 1);
  const startIdx = (page - 1) * pageSize;
  return { page, pageSize, startIdx };
}

function buildPageNav(basePath, qsObj, page, totalPages){
  if (totalPages <= 1) return "";
  const qsBase = { ...qsObj };
  delete qsBase.page;
  const links = [];

  const prev = Math.max(1, page - 1);
  const next = Math.min(totalPages, page + 1);

  const qsPrev = new URLSearchParams({ ...qsBase, page: String(prev) }).toString();
  const qsNext = new URLSearchParams({ ...qsBase, page: String(next) }).toString();

  links.push(`<a class="btn secondary small" href="${basePath}?${qsPrev}">Prev</a>`);

  const windowSize = 7;
  let start = Math.max(1, page - Math.floor(windowSize/2));
  let end = Math.min(totalPages, start + windowSize - 1);
  start = Math.max(1, end - windowSize + 1);

  for (let p = start; p <= end; p++){
    const qsP = new URLSearchParams({ ...qsBase, page: String(p) }).toString();
    links.push(`<a href="${basePath}?${qsP}" style="margin:0 6px;${p===page?'font-weight:900;text-decoration:underline;':''}">${p}</a>`);
  }

  links.push(`<a class="btn secondary small" href="${basePath}?${qsNext}">Next</a>`);
  return `<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:10px;">${links.join("")}</div>`;
}

// ===== Negotiation Status =====
const NEGOTIATION_STATUSES = [
  "Open",
  "Packet Generated",
  "Submitted",
  "In Review",
  "Counter Offered",
  "Approved (Pending Payment)",
  "Payment Received",
  "Denied",
  "Closed"
];

function normalizeNegotiation(rec){
  if (!rec) return rec;
  if (!rec.status) rec.status = "Open";
  if (!NEGOTIATION_STATUSES.includes(rec.status)) rec.status = "Open";
  if (!Array.isArray(rec.documents)) rec.documents = [];
  if (!rec.created_at) rec.created_at = nowISO();
  rec.updated_at = nowISO();
  rec.approved_amount = num(rec.approved_amount);
  rec.collected_amount = num(rec.collected_amount);
  rec.requested_amount = num(rec.requested_amount);
  return rec;
}

function getNegotiationsByBilled(org_id, billed_id){
  return getNegotiations(org_id).filter(n => n.billed_id === billed_id);
}

function computeClaimAtRisk(b){
  const billedAmt = num(b.amount_billed);
  const insurancePaid = num(b.insurance_paid || b.paid_amount);
  const patientCollected = num(b.patient_collected);
  const allowed = num(b.allowed_amount);
  const patientResp = num(b.patient_responsibility);
  const expectedInsurance = (b.expected_insurance != null && String(b.expected_insurance).trim() !== "")
    ? num(b.expected_insurance)
    : computeExpectedInsurance((allowed > 0 ? allowed : billedAmt), patientResp);

  const st = String(b.status || "Pending");
  if (st === "Underpaid" || st === "Appeal") return Math.max(0, expectedInsurance - insurancePaid);
  if (st === "Patient Balance") return Math.max(0, patientResp - patientCollected);
  if (st === "Contractual") return 0;
  if (st === "Paid") return 0;
  return Math.max(0, billedAmt - insurancePaid);
}

function computeUrgency(b){
  // heuristic: older claims + higher at-risk + certain statuses bubble up
  const st = String(b.status || "Pending");
  const atRisk = computeClaimAtRisk(b);
  const base = (st === "Denied") ? 45 : (st === "Underpaid" ? 35 : (st === "Appeal" ? 30 : (st === "Patient Balance" ? 20 : 10)));
  const dt = new Date(b.dos || b.denied_at || b.created_at || Date.now()).getTime();
  const days = Math.max(0, (Date.now() - dt) / (1000*60*60*24));
  const ageScore = Math.min(35, days * 0.5);
  const moneyScore = Math.min(35, Math.log10(atRisk + 1) * 12);
  return Math.round(base + ageScore + moneyScore);
}

function badgeClassForStatus(st){
  const s = String(st||"Pending");
  if (s === "Paid") return "ok";
  if (s === "Denied") return "err";
  if (s === "Underpaid") return "underpaid";
  if (s === "Appeal") return "warn";
  if (s === "Patient Balance") return "warn";
  if (s === "Contractual") return "writeoff";
  return "";
}



// ===== Revenue Intelligence AI: Saved Queries + Query History =====
function getAIQueries(org_id){
  return readJSON(FILES.ai_queries, []).filter(q => q.org_id === org_id);
}
function saveAIQuery(rec){
  const all = readJSON(FILES.ai_queries, []);
  all.push(rec);
  const perOrg = all.filter(x => x.org_id === rec.org_id);
  if (perOrg.length > 500){
    const sorted = perOrg.sort((a,b)=> new Date(a.created_at||0).getTime() - new Date(b.created_at||0).getTime());
    const toRemove = sorted.slice(0, perOrg.length - 500).map(x=>x.query_id);
    const filtered = all.filter(x => !(x.org_id === rec.org_id && toRemove.includes(x.query_id)));
    writeJSON(FILES.ai_queries, filtered);
  } else {
    writeJSON(FILES.ai_queries, all);
  }
}
function getSavedQueries(org_id){
  return readJSON(FILES.saved_queries, []).filter(q => q.org_id === org_id);
}
function saveSavedQuery(rec){
  const all = readJSON(FILES.saved_queries, []);
  const idx = all.findIndex(x => x.org_id === rec.org_id && x.saved_id === rec.saved_id);
  if (idx >= 0) all[idx] = rec; else all.push(rec);
  writeJSON(FILES.saved_queries, all);
}
function deleteSavedQuery(org_id, saved_id){
  const all = readJSON(FILES.saved_queries, []);
  writeJSON(FILES.saved_queries, all.filter(x => !(x.org_id === org_id && x.saved_id === saved_id)));
}

// ===== Payment Batch Helpers + Soft Delete Log =====
function getDeletedPaymentBatches(org_id){
  return readJSON(FILES.deleted_payment_batches, []).filter(x => x.org_id === org_id);
}
function logDeletedPaymentBatch(rec){
  const all = readJSON(FILES.deleted_payment_batches, []);
  all.push(rec);
  writeJSON(FILES.deleted_payment_batches, all);
}
function normalizeClaimDigits(x){ return String(x || "").replace(/[^0-9]/g, ""); }
function findBilledByClaim(org_id, billedAll, claimNumber){
  const norm = normalizeClaimDigits(claimNumber);
  if (!norm) return null;
  return billedAll.find(b => b.org_id === org_id && normalizeClaimDigits(b.claim_number) === norm) || null;
}
const AI_RESPONSE_STYLES = [
  { key:"exec", label:"Executive Summary + Action Plan" },
  { key:"narrative", label:"Narrative Analysis" },
  { key:"bullets", label:"Bullet Insights" },
  { key:"technical", label:"Technical Breakdown" },
];

function pickChartsForPrompt(prompt){
  const p = String(prompt||"").toLowerCase();
  const charts = new Set();
  charts.add("denial_trend");
  charts.add("payment_trend");
  charts.add("underpay_by_payer");
  if (p.includes("aging") || p.includes("60") || p.includes("90") || p.includes("overdue") || p.includes("at risk")) charts.add("aging_buckets");
  if (p.includes("negotiat")) charts.add("negotiation_success");
  if (p.includes("patient")) charts.add("patient_balance");
  return Array.from(charts);
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
    const html = renderPage("Owner Login", `
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
      const html = renderPage("Owner Login", `
        <h2>Owner Login</h2>
        <p class="error">Admin mode not configured. Set ADMIN_EMAIL and ADMIN_PASSWORD_PLAIN (or ADMIN_PASSWORD_HASH) in Railway.</p>
        <div class="btnRow"><a class="btn secondary" href="/admin/login">Back</a></div>
      `, navPublic());
      return send(res, 403, html);
    }

    if (email !== ADMIN_EMAIL || !bcrypt.compareSync(pass, aHash)) {
      const html = renderPage("Owner Login", `
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
    const html = renderPage("Create Account", `
      <h2>Create Account</h2>
      <p class="muted">Secure, organization-based access to an AI revenue analytics workspace.</p>
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
      const html = renderPage("Create Account", `
        <h2>Create Account</h2>
        <p class="error">Please complete all fields, confirm password, and accept the acknowledgement.</p>
        <div class="btnRow"><a class="btn secondary" href="/signup">Back</a></div>
      `, navPublic());
      return send(res, 400, html);
    }

    const users = readJSON(FILES.users, []);
    if (users.find(u => (u.email || "").toLowerCase() === email)) {
      const html = renderPage("Create Account", `
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
    const html = renderPage("Login", `
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
      const html = renderPage("Login", `
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
    const html = renderPage("Reset Password", `
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

    const html = renderPage("Reset Link", `
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
    const html = renderPage("Set New Password", `
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
      const html = renderPage("Set New Password", `
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
      const html = renderPage("Reset Error", `
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
    return send(res, 200, renderPage("Suspended", `
      <h2>Account Suspended</h2>
      <p>Your organization’s access is currently suspended.</p>
      <p class="muted">If you believe this is an error, contact support.</p>
      <div class="btnRow"><a class="btn secondary" href="/logout">Logout</a></div>
    `, navPublic()));
  }

  if (method === "GET" && pathname === "/terminated") {
    return send(res, 200, renderPage("Terminated", `
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

 
  // Shopify webhook (automatic plan sync)
  if (method === "POST" && pathname === "/shopify/webhook") {
    const rawBody = await parseBody(req);

    // Optional: Verify webhook signature if SHOPIFY_WEBHOOK_SECRET is set
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET || "";
    if (secret) {
      try {
        const hmacHeader = req.headers["x-shopify-hmac-sha256"] || "";
        const digest = crypto.createHmac("sha256", secret).update(rawBody, "utf8").digest("base64");
        if (digest !== hmacHeader) {
          return send(res, 401, "Invalid HMAC", "text/plain");
        }
      } catch {
        return send(res, 401, "Invalid HMAC", "text/plain");
      }
    }

    let data = {};
    try { data = JSON.parse(rawBody); } catch { data = {}; }

    // Try to resolve customer email and plan name from webhook payload
    const email = (data.customer_email || data.customer?.email || "").toLowerCase();
    const planTitle = (data.plan || data.plan_name || data.line_items?.[0]?.title || data.title || "").toLowerCase();
    const status = (data.status || data.subscription_status || "active").toLowerCase();

    if (!email) return send(res, 200, "No email in webhook", "text/plain");

    const u = getUserByEmail(email);
    if (!u) return send(res, 200, "User not found", "text/plain");

    const subs = readJSON(FILES.subscriptions, []);
    let sub = subs.find(x => x.org_id === u.org_id);
    if (!sub) {
      sub = { sub_id: uuid(), org_id: u.org_id, status: "inactive", plan: "", customer_email: email, updated_at: nowISO() };
      subs.push(sub);
    }
    sub.customer_email = email;

    // Determine plan key
    let planKey = "starter";
    if (planTitle.includes("growth")) planKey = "growth";
    else if (planTitle.includes("pro")) planKey = "pro";
    else if (planTitle.includes("enterprise")) planKey = "enterprise";
    else if (planTitle.includes("starter")) planKey = "starter";

    if (status === "cancelled" || status === "canceled" || status === "inactive" || status === "paused") {
      sub.status = "inactive";
      sub.updated_at = nowISO();
    } else {
      applyPlanToSubscription(sub, planKey);
    }

    writeJSON(FILES.subscriptions, subs);
    return send(res, 200, "OK", "text/plain");
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
          alerts.push(`Trial for ${safeStr(org.org_name)} ends soon`);
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
        const plan = (sub && sub.status === "active") ? "Subscribed" : (pilot.status === "active" ? "Free Trial" : "Expired");
        const att = attentionSet.has(org.org_id) ? "⚠️" : "";
        return `<tr class="${att ? 'attention' : ''}">
          <td><a href="/admin/org?org_id=${encodeURIComponent(org.org_id)}">${safeStr(org.org_name)}</a></td>
          <td>${plan}</td>
          <td>${safeStr(org.account_status || 'active')}</td>
          <td>${last ? new Date(last).toLocaleDateString() : "—"}</td>
          <td>${att}</td>
        </tr>`;
      }).join("");
      const html = renderPage("Admin Dashboard", `
        <h2>Admin Dashboard</h2>
        <section>
          <div class="kpi-card"><h4>Total Organisations</h4><p>${totalOrgs}</p></div>
          <div class="kpi-card"><h4>Total Users</h4><p>${totalUsers}</p></div>
          <div class="kpi-card"><h4>Active Trials</h4><p>${activePilots}</p></div>
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
          return (s && s.status === "active") ? "Subscribed" : (p && p.status === "active" ? "Free Trial" : "Expired");
        })();
        const planMatch = !planFilter || plan === planFilter;
        const attMatch = !needAtt || attSet.has(org.org_id);
        return nameMatch && statusMatch && planMatch && attMatch;
      });
      // build table rows
      const rows = filtered.map(org => {
        const p = pilots.find(x => x.org_id === org.org_id);
        const s = subs.find(x => x.org_id === org.org_id);
        const plan = (s && s.status === "active") ? "Subscribed" : (p && p.status === "active" ? "Free Trial" : "Expired");
        const att = attSet.has(org.org_id) ? "⚠️" : "";
        return `<tr class="${att ? 'attention' : ''}">
          <td><a href="/admin/org?org_id=${encodeURIComponent(org.org_id)}">${safeStr(org.org_name)}</a></td>
          <td>${plan}</td>
          <td>${safeStr(org.account_status || 'active')}</td>
          <td>${att}</td>
        </tr>`;
      }).join("");
      const html = renderPage("Organizations", `
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
            <option value="Free Trial"${planFilter==="Free Trial"?" selected":""}>Free Trial</option>
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

      const html = renderPage("Org Detail", `
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
    <button class="btn secondary" name="action" value="extend_trial_7">Extend Trial +7 days</button>
    <button class="btn secondary" name="action" value="suspend">Pause Plan</button>
    <button class="btn secondary" name="action" value="reactivate">Reactivate</button>
    <button class="btn danger" name="action" value="terminate">Terminate</button>
  </div>

  <div class="hr"></div>
  <h3>Plan Override</h3>
  <label>Set Plan</label>
  <select name="plan_override">
    <option value="">Select plan</option>
    <option value="starter">Starter ($249)</option>
    <option value="growth">Growth ($599)</option>
    <option value="pro">Pro ($1200)</option>
    <option value="enterprise">Enterprise ($2000)</option>
  </select>
  <div class="btnRow">
    <button class="btn secondary" name="action" value="override_plan">Apply Plan</button>
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
      } else if (action === "override_plan") {
        const planKey = (params.get("plan_override") || "").toLowerCase();
        if (!planKey) return redirect(res, `/admin/org?org_id=${encodeURIComponent(org_id)}`);
        const subs = readJSON(FILES.subscriptions, []);
        let sub = subs.find(x => x.org_id === org_id);
        if (!sub) {
          sub = { sub_id: uuid(), org_id, status: "inactive", plan: "", customer_email: "", updated_at: nowISO() };
          subs.push(sub);
        }
        applyPlanToSubscription(sub, planKey);
        writeJSON(FILES.subscriptions, subs);
        setOrgStatus(org_id, "active", reason);
        auditLog({ actor:"admin", action:"override_plan", org_id, reason, plan: planKey });
      } else if (action === "extend_trial_7") {
        const pilots = readJSON(FILES.pilots, []);
        const idx = pilots.findIndex(p => p.org_id === org_id);
        if (idx >= 0) {
          pilots[idx].ends_at = addDaysISO(pilots[idx].ends_at, 7);
          writeJSON(FILES.pilots, pilots);
        }
        auditLog({ actor:"admin", action:"extend_trial_7", org_id, reason });
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
      const html = renderPage("Audit Log", ` <h2>Audit Log</h2> <p class="muted">Latest 200 admin actions.</p> <div style="overflow:auto;"> <table>
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
  // Clean up expired de‑identified appeal attachments (non‑PHI mode)
  cleanupExpiredAppealAttachments(org.org_id);

  if (!isAccessEnabled(org.org_id)) return redirect(res, "/pilot-complete");


// ---------- FILE VIEWER (org-scoped) ----------
// Allows viewing uploaded source files (CSV/PDF/Excel/Word) linked from claim detail pages.
if (method === "GET" && pathname === "/file") {
  const name = String(parsed.query.name || "").trim();
  if (!name) return redirect(res, "/dashboard");

  // Only allow base filenames (no path traversal)
  const safeName = path.basename(name);
  if (safeName !== name) return send(res, 400, "Invalid filename", "text/plain");

  const orgRoot = path.join(UPLOADS_DIR, org.org_id);

  let found = null;
  const maxFilesToScan = 5000;
  let scanned = 0;

  function scanDir(dir) {
    if (found || scanned > maxFilesToScan) return;
    let items = [];
    try { items = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const it of items) {
      if (found || scanned > maxFilesToScan) break;
      const full = path.join(dir, it.name);
      if (it.isDirectory()) {
        scanDir(full);
      } else {
        scanned++;
        if (it.name === safeName) { found = full; break; }
      }
    }
  }

  scanDir(orgRoot);

  if (!found || !fs.existsSync(found)) return send(res, 404, "File not found", "text/plain");

  const ext = path.extname(found).toLowerCase();
  const mimeMap = {
    ".csv": "text/csv",
    ".pdf": "application/pdf",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
  };
  const contentType = mimeMap[ext] || "application/octet-stream";

  res.writeHead(200, {
    "Content-Type": contentType,
    "Content-Disposition": `inline; filename="${safeName}"`
  });
  return fs.createReadStream(found).pipe(res);
}

  // ---------- AI Chat (Org-scoped assistant) ----------
  if (method === "POST" && pathname === "/ai/chat") {
    const usage = getUsage(org.org_id);
    const limit = getAIChatLimit(org.org_id);

    if ((usage.ai_chat_used || 0) >= limit) {
      return send(res, 200, JSON.stringify({ answer: "You have reached your AI question limit for your current plan. Please upgrade to continue." }), "application/json");
    }

    // Count usage (pilot total; monthly resets via month_key rollover)
    usage.ai_chat_used = (usage.ai_chat_used || 0) + 1;
    saveUsage(usage);

    const body = await parseBody(req);
    let msg = "";
    try {
      msg = (JSON.parse(body).message || "").trim();
    } catch {
      msg = "";
    }

    const analytics = computeAnalytics(org.org_id);
    const casesAll = readJSON(FILES.cases, []).filter(c => c.org_id === org.org_id).slice(-20);
    const paymentsAll = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id).slice(-50);

    const context = {
      organization: org.org_name,
      plan: getActivePlanName(org.org_id),
      analytics,
      recent_cases: casesAll,
      recent_payments: paymentsAll
    };

    // If OPENAI_API_KEY not set, return helpful fallback
    if (!process.env.OPENAI_API_KEY) {
      return send(res, 200, JSON.stringify({
        answer: "AI Assistant is not configured (missing OPENAI_API_KEY). I can only answer once the key is set. Your current recovery rate is " + analytics.recoveryRate + "% with total recovered $" + Number(analytics.totalRecoveredFromDenials||0).toFixed(2) + "."
      }), "application/json");
    }

    const model = process.env.OPENAI_MODEL || "gpt-4o-mini";

    const systemMsg = "You are TJ Healthcare Pro's internal AI assistant. Only answer using the organization's uploaded denial and payment data and computed analytics provided. If asked about unrelated topics, explain you can only answer questions about their uploaded data and what the app does. Do not provide medical advice. Be concise and actionable.";
    const userMsg = "ORG DATA (JSON):\n" + JSON.stringify(context, null, 2) + "\n\nUSER QUESTION:\n" + msg;

    try {
      const resp = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + process.env.OPENAI_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: "system", content: systemMsg },
            { role: "user", content: userMsg }
          ],
          temperature: 0.2
        })
      });
      const data = await resp.json();
      const answer = data?.choices?.[0]?.message?.content || "I couldn't generate an answer right now.";
      return send(res, 200, JSON.stringify({ answer }), "application/json");
    } catch (e) {
      return send(res, 200, JSON.stringify({ answer: "AI Assistant error. Please try again." }), "application/json");
    }
  }



  // ---------- Revenue Intelligence (AI) Query Endpoint ----------
  if (method === "POST" && pathname === "/intelligence/query") {
    const body = await parseBody(req);
    let payload = {};
    try { payload = JSON.parse(body || "{}"); } catch { payload = {}; }

    const prompt = String(payload.prompt || "").trim();
    const style = String(payload.style || "exec").trim();
    const save = String(payload.save || "") === "1";
    const saveName = String(payload.save_name || "").trim();

    if (!prompt) {
      return send(res, 200, JSON.stringify({ ok:false, error:"Missing prompt" }), "application/json");
    }

    const denialByMonth = computeDenialTrends(org.org_id);
    const payTrend = computePaymentTrends(org.org_id);

    const denialMonths = Object.keys(denialByMonth || {}).sort();
    const denialTotals = denialMonths.map(k => Number(denialByMonth[k]?.total || 0));
    const draftTotals = denialMonths.map(k => Number(denialByMonth[k]?.drafts || 0));

    const payMonths = Object.keys(payTrend.byMonth || {}).sort();
    const payTotals = payMonths.map(k => Number(payTrend.byMonth[k]?.total || 0));

    const r30 = rangeFromPreset("last30");
    const dash30 = computeDashboardMetrics(org.org_id, r30.start, r30.end, "last30");
    const payerTop = (dash30.payerTop || []).slice(0, 10);
    const payerLabels = payerTop.map(x=>x.payer);
    const payerUnderpaid = payerTop.map(x=>Number(x.underpaid||0));

    const billedAll = readJSON(FILES.billed, []).filter(b => b.org_id === org.org_id);
    const now = Date.now();
    const aging = { "0-30":0, "31-60":0, "61-90":0, "90+":0 };
    billedAll.filter(b => String(b.status||"Pending") !== "Paid").forEach(b=>{
      const dt = new Date(b.denied_at || b.created_at || b.dos || nowISO()).getTime();
      const days = Math.max(0, (now - dt) / (1000*60*60*24));
      if (days > 90) aging["90+"]++;
      else if (days > 60) aging["61-90"]++;
      else if (days > 30) aging["31-60"]++;
      else aging["0-30"]++;
    });

    const negs = getNegotiations(org.org_id);
    const negApproved = negs.filter(n => n.status === "Approved (Pending Payment)" || n.status === "Payment Received");
    const negPaid = negs.filter(n => n.status === "Payment Received");
    const negApprovedTotal = negApproved.reduce((s,n)=> s + num(n.approved_amount), 0);
    const negCollectedTotal = negPaid.reduce((s,n)=> s + num(n.collected_amount), 0);
    const negSuccessRate = negApproved.length ? ((negPaid.length / negApproved.length) * 100) : 0;

    const charts = (Array.isArray(payload.charts) && payload.charts.length) ? payload.charts : pickChartsForPrompt(prompt);

    const analytics = computeAnalytics(org.org_id);

    const styleMap = {
      exec: "Write an executive summary and a short action plan (3-5 bullets).",
      narrative: "Write a concise narrative analysis (2-4 short paragraphs) with practical recommendations.",
      bullets: "Write bullet insights (8-12 bullets) with clear takeaways.",
      technical: "Write a technical breakdown (structured sections) focusing on metrics, definitions, and what to check next."
    };
    const styleInstr = styleMap[style] || styleMap.exec;

    let answer = "";
    if (!process.env.OPENAI_API_KEY) {
      answer =
`(AI not configured: missing OPENAI_API_KEY)

Snapshot:
- Recovery rate: ${analytics.recoveryRate}%
- Projected lost revenue: $${Number(analytics.projectedLostRevenue||0).toFixed(2)}
- Underpaid (last 30 days): $${Number(dash30.kpis.underpaidAmt||0).toFixed(2)}
- Aging 60+: ${Number(analytics.aging?.over60||0)}
- Negotiation success: ${negSuccessRate.toFixed(1)}%

Question:
${prompt}

Next steps:
- Upload payments if missing and re-run this insight.
- Review top underpaid payer and highest at-risk claims in Action Center.`;
    } else {
      const model = process.env.OPENAI_MODEL || "gpt-4o-mini";
      const systemMsg = "You are TJ Healthcare Pro's Revenue Intelligence assistant. Only use the provided organization analytics and uploaded data. Be accurate, concise, and operational. Do not invent numbers. Do not provide medical advice.";
      const context = {
        organization: org.org_name,
        plan: getActivePlanName(org.org_id),
        response_style: style,
        question: prompt,
        analytics,
        dashboard_last30: dash30,
        trends: { denialMonths, denialTotals, draftTotals, payMonths, payTotals, payerLabels, payerUnderpaid, aging },
        negotiations: { total: negs.length, approved_total: negApprovedTotal, collected_total: negCollectedTotal, success_rate: Number(negSuccessRate.toFixed(1)) }
      };
      const userMsg = styleInstr + "\n\nORG DATA (JSON):\n" + JSON.stringify(context, null, 2);

      try {
        const resp = await fetch("https://api.openai.com/v1/chat/completions", {
          method: "POST",
          headers: { "Authorization": "Bearer " + process.env.OPENAI_API_KEY, "Content-Type": "application/json" },
          body: JSON.stringify({ model, messages: [ { role: "system", content: systemMsg }, { role: "user", content: userMsg } ], temperature: 0.2 })
        });
        const data = await resp.json();
        answer = data?.choices?.[0]?.message?.content || "I couldn't generate an answer right now.";
      } catch {
        answer = "AI Assistant error. Please try again.";
      }
    }

    const queryRec = { query_id: uuid(), org_id: org.org_id, prompt, style, charts, answer, created_at: nowISO() };
    saveAIQuery(queryRec);

    if (save) {
      const savedRec = {
        saved_id: uuid(),
        org_id: org.org_id,
        name: saveName || prompt.slice(0, 48),
        prompt,
        style,
        charts,
        created_by: user.user_id,
        created_at: nowISO(),
        updated_at: nowISO()
      };
      saveSavedQuery(savedRec);
    }

    const dataOut = {
      denialMonths, denialTotals, draftTotals,
      payMonths, payTotals,
      payerLabels, payerUnderpaid,
      agingLabels: Object.keys(aging),
      agingCounts: Object.values(aging),
      negotiationApprovedTotal: negApprovedTotal,
      negotiationCollectedTotal: negCollectedTotal,
      negotiationSuccessRate: Number(negSuccessRate.toFixed(1))
    };

    return send(res, 200, JSON.stringify({ ok:true, answer, charts, data: dataOut }), "application/json");
  }

  if (method === "POST" && pathname === "/intelligence/saved/delete") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const saved_id = (params.get("saved_id") || "").trim();
    if (saved_id) deleteSavedQuery(org.org_id, saved_id);
    return redirect(res, "/intelligence");
  }


  // lock screen
  if (method === "GET" && pathname === "/lock") {
    const html = renderPage("Starting", `
      <h2 class="center">Free Trial Started</h2>
      <p class="center">We’re preparing your secure workspace to help you track what was billed, denied, appealed, and paid — and surface patterns that are easy to miss when data lives in different places.</p>
      <p class="muted center">You’ll be guided to the next step automatically.</p>
      <div class="center"><span class="badge warn">Initializing</span></div>
      <script>setTimeout(()=>{window.location.href="/dashboard";}, ${LOCK_SCREEN_MS});
        // Countdown timers for analyzing cases
        document.querySelectorAll(".countdown").forEach(el => {
          let s = parseInt(el.getAttribute("data-seconds") || "0", 10);
          if (!s || s <= 0) return;
          const t = setInterval(() => {
            s--;
            if (s <= 0) {
              el.textContent = "Ready";
              clearInterval(t);
              window.location.reload();
            } else {
              el.textContent = s + "s";
            }
          }, 1000);
        });

      </script>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
    return send(res, 200, html);
  }



// executive dashboard
// Executive Dashboard (CLEAN SAFE VERSION)

if (method === "GET" && pathname === "/executive") {

  const a = computeAnalytics(org.org_id);
  const score = computeRiskScore(a);
  const r = riskLabel(score);
  const tips = buildRecoveryStrategies(a);

  const html = renderPage("Executive Dashboard", `

    <h2>Executive Dashboard</h2>
    <p class="muted">High-level denial → revenue performance for leadership review.</p>

    <div class="row">
      <div class="col">
        <div class="kpi-card">
          <h4>Recovered from Denials</h4>
          <p>$${Number(a.totalRecoveredFromDenials || 0).toFixed(2)}</p>
        </div>

        <div class="kpi-card">
          <h4>Recovery Rate</h4>
          <p>${a.recoveryRate}%</p>
        </div>

        <div class="kpi-card">
          <h4>Projected Lost Revenue</h4>
          <p>$${Number(a.projectedLostRevenue || 0).toFixed(2)}</p>
        </div>
      </div>

      <div class="col">
        <h3>Risk Score</h3>
        <div class="badge ${r.cls}">
          Risk: ${r.label} — ${score}/100
        </div>

        <div class="hr"></div>

        <h3>Recommended Actions</h3>
        <ul class="muted">
          ${tips.map(t => `<li>${safeStr(t)}</li>`).join("")}
        </ul>
      </div>
    </div>

    <div class="btnRow">
      <a class="btn secondary" href="/weekly-summary">Weekly Summary</a>
      <a class="btn secondary" href="/dashboard">Back</a>
    </div>

  `, navUser(), { showChat: true, orgName: (typeof org!=="undefined" && org ? org.org_name : "") });

  return send(res, 200, html);
}

// weekly summary
if (method === "GET" && pathname === "/weekly-summary") {
  const a = computeAnalytics(org.org_id);
  const w = computeWeeklySummary(org.org_id);
  const proj = projectNextMonthDenials(org.org_id);

  const html = renderPage("Weekly Summary", `
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
        ? `<table><thead><tr><th>Payer</th><th>Total Paid</th></tr></thead><tbody>${w.top3.map(x => `<tr><td><a href="/payer-claims?payer=${encodeURIComponent(x.payer)}">${safeStr(x.payer)}</a></td><td>$${Number(x.total).toFixed(2)}</td></tr>`).join("")}</tbody></table>`
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
  `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
  return send(res, 200, html);
}
  // dashboard with empty-state previews and tooltips
  if (method === "GET" && (pathname === "/" || pathname === "/dashboard")) {

    const limits = getLimitProfile(org.org_id);
    const usage = getUsage(org.org_id);
    const pilot = getPilot(org.org_id) || ensurePilot(org.org_id);

    const preset = (parsed.query.range || "last30").toLowerCase();
    const customStart = parseDateOnly(parsed.query.start || "");
    const customEnd = parseDateOnly(parsed.query.end || "");

    let r = rangeFromPreset(preset);
    let startDate = r.start;
    let endDate = r.end;

    if (preset === "custom" && customStart && customEnd) {
      startDate = customStart;
      endDate = new Date(customEnd.getTime());
      endDate.setUTCHours(23,59,59,999);
    }

    const m = computeDashboardMetrics(org.org_id, startDate, endDate, preset);

    // --- SAFE DASHBOARD DATA ENCODING FOR CHARTS ---
    const seriesB64 = Buffer.from(JSON.stringify(m.series || {})).toString("base64");
    const statusB64 = Buffer.from(JSON.stringify(m.statusCounts || {})).toString("base64");
    const payerB64 = Buffer.from(JSON.stringify(m.payerTop || [])).toString("base64");


    const planBadge = (limits.mode==="monthly")
      ? `<span class="badge ok">Monthly Active</span>`
      : `<span class="badge warn">Free Trial</span>`;

    const percentCollected = m.kpis.totalBilled > 0 ? Math.round((m.kpis.collectedTotal / m.kpis.totalBilled) * 100) : 0;
    const barColor = percentCollected >= 70 ? "#16a34a" : (percentCollected >= 30 ? "#f59e0b" : "#dc2626");

    const rangeLabel = (() => {
      if (preset === "today") return "Today";
      if (preset === "last7") return "Last 7 days";
      if (preset === "last30") return "Last 30 days";
      if (preset === "thismonth") return "This month";
      if (preset === "thisyear") return "This year";
      if (preset === "custom") return "Custom range";
      return "Last 30 days";
    })();

    const payerRows = (m.payerTop || []).map(x => `
      <tr>
        <td><a href="/payer-claims?payer=${encodeURIComponent(x.payer)}">${safeStr(x.payer)}</a></td>
        <td>${fmtMoney(x.billed)}</td>
        <td>${fmtMoney(x.allowed)}</td>
        <td>${fmtMoney(x.paid)}</td>
        <td>${fmtMoney(x.denied)}</td>
        <td>${fmtMoney(x.writeOff)}</td>
        <td>${fmtMoney(x.underpaid)}</td>
      </tr>
    `).join("");

    const html = renderPage("Revenue Overview", `
      <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-end;">
        <div>
          <h2 style="margin-bottom:4px;">Revenue Overview</h2>
          <p class="muted" style="margin-top:0;">Organization: ${safeStr(org.org_name)} · Trial Ends: ${new Date(pilot.ends_at).toLocaleDateString()}</p>
          ${planBadge}
        </div>

        <form method="GET" action="/dashboard" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;">
          <div style="display:flex;flex-direction:column;min-width:220px;">
            <label>Date Range</label>
            <select name="range" onchange="this.form.submit()">
              <option value="today"${preset==="today"?" selected":""}>Today</option>
              <option value="last7"${preset==="last7"?" selected":""}>Last 7 Days</option>
              <option value="last30"${preset==="last30"?" selected":""}>Last 30 Days</option>
              <option value="thismonth"${preset==="thismonth"?" selected":""}>This Month</option>
              <option value="thisyear"${preset==="thisyear"?" selected":""}>This Year</option>
              <option value="custom"${preset==="custom"?" selected":""}>Custom</option>
            </select>
          </div>

          <div style="display:flex;flex-direction:column;min-width:150px;">
            <label>Start</label>
            <input type="date" name="start" value="${safeStr((parsed.query.start||""))}" ${preset==="custom"?"":"disabled"} />
          </div>

          <div style="display:flex;flex-direction:column;min-width:150px;">
            <label>End</label>
            <input type="date" name="end" value="${safeStr((parsed.query.end||""))}" ${preset==="custom"?"":"disabled"} />
          </div>

          <div style="padding-bottom:2px;">
            <button class="btn secondary" type="submit" ${preset==="custom"?"":"disabled"}>Apply</button>
          </div>
        </form>
      </div>

      <div class="hr"></div>

      <h3>Revenue Health <span class="tooltip">ⓘ<span class="tooltiptext">High-level revenue performance for the selected date range.</span></span></h3>

      <div style="margin-top:8px;">
        <div style="height:14px;background:#e5e7eb;border-radius:999px;overflow:hidden;">
          <div style="width:${percentCollected}%;height:100%;background:${barColor};transition:width .4s ease;"></div>
        </div>
        <div class="small muted" style="margin-top:6px;">${percentCollected}% of billed revenue collected · Range: ${safeStr(rangeLabel)}</div>
      </div>

      <div class="row" style="margin-top:14px;">
        <div class="col">
          <div class="kpi-card"><h4>Total Billed <span class="tooltip">ⓘ<span class="tooltiptext">Sum of billed charges in the selected date range.</span></span></h4><p>${fmtMoney(m.kpis.totalBilled)}</p></div>
          <div class="kpi-card"><h4>Write-Off <span class="tooltip">ⓘ<span class="tooltiptext">Billed minus allowed (or explicit write-off amount), when provided.</span></span></h4><p>${fmtMoney(m.kpis.writeOffTotal)}</p></div>
          <div class="kpi-card"><h4>Total Collected <span class="tooltip">ⓘ<span class="tooltiptext">Insurance collected + patient collected (based on uploaded data).</span></span></h4><p>${fmtMoney(m.kpis.collectedTotal)}</p></div>
          <div class="kpi-card"><h4>Revenue At Risk <span class="tooltip">ⓘ<span class="tooltiptext">Billed minus collected.</span></span></h4><p>${fmtMoney(m.kpis.revenueAtRisk)}</p></div>
        </div>

        <div class="col">
          <div class="kpi-card"><h4>Gross Collection Rate <span class="tooltip">ⓘ<span class="tooltiptext">Collected / Billed.</span></span></h4><p>${Number(m.kpis.grossCollectionRate||0).toFixed(1)}%</p></div>
          <div class="kpi-card"><h4>Net Collection Rate <span class="tooltip">ⓘ<span class="tooltiptext">Collected / Allowed (when allowed is provided).</span></span></h4><p>${Number(m.kpis.netCollectionRate||0).toFixed(1)}%</p></div>
          <div class="kpi-card"><h4>Negotiation Cases <span class="tooltip">ⓘ<span class="tooltiptext">Auto-created underpayment negotiation cases in this date range.</span></span></h4><p>${m.kpis.negotiationCases}</p></div>
        </div>

        <div class="col">
          <div class="kpi-card"><h4>Underpaid Amount <span class="tooltip">ⓘ<span class="tooltiptext">Total underpaid dollars based on expected insurance vs paid.</span></span></h4><p>${fmtMoney(m.kpis.underpaidAmt)}</p></div>
          <div class="kpi-card"><h4>Underpaid Claims <span class="tooltip">ⓘ<span class="tooltiptext">Count of billed claims marked Underpaid.</span></span></h4><p>${m.kpis.underpaidCount}</p></div>
          <div class="kpi-card"><h4>Patient Outstanding <span class="tooltip">ⓘ<span class="tooltiptext">Patient responsibility minus patient collected.</span></span></h4><p>${fmtMoney(m.kpis.patientOutstanding)}</p></div>
        </div>
      </div>

      <div class="hr"></div>

      <div class="row">
        <div class="col">
          <h3>Revenue Trend <span class="tooltip">ⓘ<span class="tooltiptext">Billed vs collected over time (bucketed by ${safeStr(m.series.gran)}).</span></span></h3>
          <canvas id="revTrend" height="140"></canvas>
        </div>
        <div class="col">
          <h3>Claim Status Mix <span class="tooltip">ⓘ<span class="tooltiptext">Distribution of claim statuses for the selected range.</span></span></h3>
          <canvas id="statusMix" height="140"></canvas>
        </div>
      </div>

      <div class="row">
        <div class="col">
          <h3>Underpayment by Payer <span class="tooltip">ⓘ<span class="tooltiptext">Top payers by total underpaid dollars.</span></span></h3>
          <canvas id="underpayPayer" height="160"></canvas>
          <div style="overflow:auto;margin-top:10px;">
            <table>
              <thead><tr><th>Payer</th><th>Billed</th><th>Allowed</th><th>Paid</th><th>Denied</th><th>Write-Off</th><th>Underpaid</th></tr></thead>
              <tbody>${payerRows || `<tr><td colspan="4" class="muted">No payer data in this range.</td></tr>`}</tbody>
            </table>
          </div>
          <div class="hr"></div>
          <h3>Top Insurance Payers (Reconciliation)</h3>
          <canvas id="payerBarChart" height="140"></canvas>
        </div>
        <div class="col">
          <h3>Patient Revenue <span class="tooltip">ⓘ<span class="tooltiptext">Patient responsibility vs collected and outstanding.</span></span></h3>
          <canvas id="patientRev" height="160"></canvas>

          <div class="btnRow" style="margin-top:10px;">
            <a class="btn" href="/claims">Open Claims Lifecycle</a>
            <a class="btn secondary" href="/upload-denials">Upload Denials</a><a class="btn secondary" href="/upload-negotiations">Upload Negotiations</a>
            <a class="btn secondary" href="/report">Reports</a>
          </div>
        </div>
      </div>

      <div class="hr"></div>

      <h3>Usage <span class="tooltip">ⓘ<span class="tooltiptext">Pilot or plan usage for your organization.</span></span></h3>
      ${
        limits.mode === "pilot" ? `
        <ul class="muted">
          <li>Cases used: ${usage.pilot_cases_used}/${PILOT_LIMITS.max_cases_total}</li>
          <li>Payment rows used: ${usage.pilot_payment_rows_used}/${PILOT_LIMITS.payment_records_included}</li>
        </ul>` : `
        <ul class="muted">
          <li>Cases used: ${usage.monthly_case_credits_used}/${limits.case_credits_per_month}</li>
          <li>Overage cases: ${usage.monthly_case_overage_count}</li>
          <li>Payment rows used: ${usage.monthly_payment_rows_used}</li>
        </ul>`
      }

     
<script>
(function(){

  if (!window.Chart) return;

  const series = JSON.parse(atob("${seriesB64}"));
  const st = JSON.parse(atob("${statusB64}"));
  const pt = JSON.parse(atob("${payerB64}"));

  // Revenue Trend
  const revEl = document.getElementById("revTrend");
  const hasRevData =
    series &&
    series.keys &&
    series.keys.length > 0 &&
    (
      (series.billed || []).some(v => Number(v) > 0) ||
      (series.collected || []).some(v => Number(v) > 0) ||
      (series.atRisk || []).some(v => Number(v) > 0)
    );

  if (hasRevData) {
    new Chart(revEl, {
      type: "line",
      data: {
        labels: series.keys,
        datasets: [
          { label: "Billed", data: series.billed },
          { label: "Collected", data: series.collected },
          { label: "At Risk", data: series.atRisk }
        ]
      },
      options: { responsive: true }
    });
  } else {
    revEl.outerHTML = "<p class='muted'>No revenue trend data.</p>";
  }

  // Claim Status Mix
  const statusEl = document.getElementById("statusMix");
  const sumStatus =
    (st["Paid"]||0) +
    (st["Patient Balance"]||0) +
    (st["Underpaid"]||0) +
    (st["Denied"]||0) +
    (st["Write-Off"]||0) +
    (st["Pending"]||0);

  if (sumStatus > 0) {
    new Chart(statusEl, {
      type: "doughnut",
      data: {
        labels: ["Paid","Patient Balance","Underpaid","Denied","Write-Off","Pending"],
        datasets: [{
          data: [
            st["Paid"]||0,
            st["Patient Balance"]||0,
            st["Underpaid"]||0,
            st["Denied"]||0,
            st["Write-Off"]||0,
            st["Pending"]||0
          ]
        }]
      },
      options: { responsive: true }
    });
  } else {
    statusEl.outerHTML = "<p class='muted'>No claim status data.</p>";
  }

  // Underpayment by Payer
  const underpayEl = document.getElementById("underpayPayer");
  const hasUnderpay =
    Array.isArray(pt) &&
    pt.some(x => Number(x.underpaid || 0) > 0);

  if (hasUnderpay) {
    new Chart(underpayEl, {
      type: "bar",
      data: {
        labels: pt.map(x => x.payer),
        datasets: [{
          label: "Underpaid ($)",
          data: pt.map(x => Number(x.underpaid||0))
        }]
      },
      options: { responsive: true }
    });
  } else {
    underpayEl.outerHTML = "<p class='muted'>No underpayment by payer data.</p>";
  }



// Top Payers (Reconciliation)
const payerBarEl = document.getElementById("payerBarChart");
const hasPayerBar =
  Array.isArray(pt) &&
  pt.some(x =>
    Number(x.billed || 0) > 0 ||
    Number(x.allowed || 0) > 0 ||
    Number(x.paid || 0) > 0 ||
    Number(x.denied || 0) > 0 ||
    Number(x.writeOff || 0) > 0 ||
    Number(x.underpaid || 0) > 0
  ) &&
  payerBarEl;

if (hasPayerBar) {
  new Chart(payerBarEl, {
    type: "bar",
    data: {
      labels: pt.map(x => x.payer),
      datasets: [
        { label: "Billed", data: pt.map(x => Number(x.billed || 0)) },
        { label: "Allowed", data: pt.map(x => Number(x.allowed || 0)) },
        { label: "Paid", data: pt.map(x => Number(x.paid || 0)) },
        { label: "Denied", data: pt.map(x => Number(x.denied || 0)) },
        { label: "Write-Off", data: pt.map(x => Number(x.writeOff || 0)) },
        { label: "Underpaid", data: pt.map(x => Number(x.underpaid || 0)) }
      ]
    },
    options: { responsive: true }
  });
} else if (payerBarEl) {
  payerBarEl.outerHTML = "<p class='muted'>No payer reconciliation data.</p>";
}
  // Patient Revenue
  const patientEl = document.getElementById("patientRev");
  const patientData = [
    ${Number(m.kpis.patientRespTotal||0)},
    ${Number(m.kpis.patientCollected||0)},
    ${Number(m.kpis.patientOutstanding||0)}
  ];

  const hasPatientData = patientData.some(v => Number(v) > 0);

  if (hasPatientData) {
    new Chart(patientEl, {
      type: "bar",
      data: {
        labels: ["Patient Responsibility","Collected","Outstanding"],
        datasets: [{
          label: "Patient $",
          data: patientData
        }]
      },
      options: { responsive: true }
    });
  } else {
    patientEl.outerHTML = "<p class='muted'>No patient revenue data.</p>";
  }

})();
</script>


    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});

    return send(res, 200, html);
  }
// ==============================
// CLAIMS LIFECYCLE (HUB + SUBTABS)
// ==============================
if (method === "GET" && pathname === "/claims") {

  // Sub-tabs: billed | payments | denials | negotiations | all
  const view = String(parsed.query.view || "billed").toLowerCase();

  const billedAll = readJSON(FILES.billed, []).filter(b => b.org_id === org.org_id);
  const subsAll = readJSON(FILES.billed_submissions, []).filter(s => s.org_id === org.org_id);

  // Snapshot counts across all claims (simple, fast)
  const counts = billedAll.reduce((acc,b)=>{
    const s = String(b.status||"Pending");
    acc.total++;
    acc[s] = (acc[s]||0)+1;
    return acc;
  }, {total:0});

  const tab = (key, label, tip) => {
    const active = (view === key);
    return `
      <a href="/claims?view=${encodeURIComponent(key)}"
         style="text-decoration:none;display:inline-flex;gap:6px;align-items:center;padding:8px 10px;border-radius:10px;border:1px solid #e5e7eb;background:${active ? "#111827" : "#fff"};color:${active ? "#fff" : "#111827"};font-weight:900;font-size:12px;">
        ${label}
        <span class="tooltip">ⓘ<span class="tooltiptext">${safeStr(tip)}</span></span>
      </a>
    `;
  };

  const subTabs = `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
      ${tab("billed","Billed Batches","Submission batches uploaded from your EMR/EHR. Click a batch to drill into claims.")}
      ${tab("payments","Payment Batches","Uploaded payment files. Open a batch to see payment rows + affected claims.")}
      ${tab("denials","Denial Queue","Denied claims and appeal cases. Open to edit appeal drafts and track status.")}
      ${tab("negotiations","Negotiation Queue","Underpaid claims tracked as negotiation cases. Open to update requested/approved/collected.")}
      ${tab("all","All Claims","All claims across all stages with filters, pagination, and clickable rows.")}
    </div>
  `;

  const uploadRow = `
    <div class="btnRow">
      <a class="btn" href="/upload-billed">Upload Billed Claims</a>
      <a class="btn secondary" href="/upload-payments">Upload Payments</a>
      <a class="btn secondary" href="/upload-denials">Upload Denials</a>
      <a class="btn secondary" href="/upload-negotiations">Upload Negotiations</a>
      <span class="tooltip">ⓘ<span class="tooltiptext">Uploads create batches/queues below. Use the sub-tabs to review and manage each stage.</span></span>
    </div>
  `;

  // ===== Shared header (always) =====
  let body = `
    <h2>Claims Lifecycle <span class="tooltip">ⓘ<span class="tooltiptext">This is your operational hub for billed batches, payment batches, denial appeals, negotiations, and all claims.</span></span></h2>
    <p class="muted">Everything that happens to claims — billed, denied, appealed, paid, and negotiated — in one place.</p>
    ${uploadRow}

    <div class="hr"></div>

    <h3>Quick Snapshot <span class="tooltip">ⓘ<span class="tooltiptext">Counts across your full claim population (not just the selected sub-tab).</span></span></h3>
    <div class="row">
      <div class="col">
        <div class="kpi-card"><h4>Total Claims</h4><p>${counts.total || 0}</p></div>
        <div class="kpi-card"><h4>Denied</h4><p>${counts["Denied"] || 0}</p></div>
      </div>
      <div class="col">
        <div class="kpi-card"><h4>Underpaid</h4><p>${counts["Underpaid"] || 0}</p></div>
        <div class="kpi-card"><h4>Appeal</h4><p>${counts["Appeal"] || 0}</p></div>
      </div>
      <div class="col">
        <div class="kpi-card"><h4>Paid</h4><p>${counts["Paid"] || 0}</p></div>
        <div class="kpi-card"><h4>Negotiations</h4><p>${getNegotiations(org.org_id).length}</p></div>
      </div>
    </div>

    <div class="hr"></div>

    ${subTabs}

    <div class="hr"></div>
  `;

  // ===== Subtab content =====

  // (1) Billed Batches
  if (view === "billed") {
    const batchRows = subsAll
      .sort((a,b)=> new Date(b.uploaded_at||0).getTime() - new Date(a.uploaded_at||0).getTime())
      .map(s=>{
        const claims = billedAll.filter(b => b.submission_id === s.submission_id);
        const totalClaims = claims.length;
        const paidCount = claims.filter(b => (b.status||"Pending")==="Paid").length;
        const deniedCount = claims.filter(b => (b.status||"Pending")==="Denied").length;
        const underpaidCount = claims.filter(b => (b.status||"Pending")==="Underpaid").length;
        const appealCount = claims.filter(b => (b.status||"Pending")==="Appeal").length;
        const pendingCount = claims.filter(b => (b.status||"Pending")==="Pending").length;

        const totalBilledAmt = claims.reduce((sum,b)=> sum + Number(b.amount_billed || 0), 0);
        const collectedAmt = claims.reduce((sum, b) => sum + Number(b.insurance_paid || b.paid_amount || 0), 0);
        const atRiskAmt = Math.max(0, totalBilledAmt - collectedAmt);

        return `<tr>
          <td><a href="/billed?submission_id=${encodeURIComponent(s.submission_id)}">${safeStr(s.original_filename || "batch")}</a></td>
          <td class="muted small">${s.uploaded_at ? new Date(s.uploaded_at).toLocaleDateString() : "—"}</td>
          <td>${totalClaims}</td>
          <td>${paidCount}</td>
          <td>${deniedCount}</td>
          <td>${underpaidCount}</td>
          <td>${appealCount}</td>
          <td>${pendingCount}</td>
          <td>$${Number(totalBilledAmt||0).toFixed(2)}</td>
          <td>$${Number(collectedAmt||0).toFixed(2)}</td>
          <td>$${Number(atRiskAmt||0).toFixed(2)}</td>
          <td><a href="/claims?view=all&submission_id=${encodeURIComponent(s.submission_id)}">View Claims</a></td>
        </tr>`;
      }).join("");

    body += `
      <h3>Billed Batches <span class="tooltip">ⓘ<span class="tooltiptext">These are your billed claim submissions. Use them to manage claims by batch.</span></span></h3>
      <div style="overflow:auto;">
        <table>
          <thead>
            <tr><th>Batch</th><th>Uploaded</th><th>Claims</th><th>Paid</th><th>Denied</th><th>Underpaid</th><th>Appeal</th><th>Pending</th><th>Total Billed</th><th>Collected</th><th>At Risk</th><th></th></tr>
          </thead>
          <tbody>${batchRows || `<tr><td colspan="12" class="muted">No billed batches yet. Upload a billed claims file to begin.</td></tr>`}</tbody>
        </table>
      </div>
    `;
  }

  // (2) Payment Batches
  if (view === "payments") {
    const allPay = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id);
    const paymentFilesMap = {};
    allPay.forEach(p => {
      const sf = (p.source_file || "").trim();
      if (!sf) return;
      if (!paymentFilesMap[sf]) paymentFilesMap[sf] = { source_file: sf, count: 0, latest: p.created_at || p.date_paid || nowISO(), totalPaid: 0 };
      paymentFilesMap[sf].count += 1;
      paymentFilesMap[sf].totalPaid += num(p.amount_paid);
      const dt = new Date(p.created_at || p.date_paid || Date.now()).getTime();
      const cur = new Date(paymentFilesMap[sf].latest || 0).getTime();
      if (dt > cur) paymentFilesMap[sf].latest = p.created_at || p.date_paid || nowISO();
    });

    const files = Object.values(paymentFilesMap).sort((a,b)=> new Date(b.latest).getTime() - new Date(a.latest).getTime());

    const { page, pageSize, startIdx } = parsePageParams(parsed.query || {});
    const total = files.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const pageItems = files.slice(startIdx, startIdx + pageSize);

    const rows = pageItems.map(x => `
      <tr>
        <td>${safeStr(x.source_file)}</td>
        <td>${x.count}</td>
        <td>$${Number(x.totalPaid||0).toFixed(2)}</td>
        <td>${x.latest ? new Date(x.latest).toLocaleDateString() : "—"}</td>
        <td><a href="/payment-batch-detail?file=${encodeURIComponent(x.source_file)}">Open</a></td>
      </tr>
    `).join("");

    const sizeSelect = `
      <label class="small muted" style="margin-right:8px;">Per page</label>
      <select onchange="window.location=this.value">
        ${PAGE_SIZE_OPTIONS.map(n=>{
          const qs = new URLSearchParams({ ...parsed.query, view:"payments", page: "1", pageSize: String(n) }).toString();
          return `<option value="/claims?${qs}" ${n===pageSize?"selected":""}>${n}</option>`;
        }).join("")}
      </select>
    `;
    const nav = buildPageNav("/claims", { ...parsed.query, view:"payments", pageSize: String(pageSize) }, page, totalPages);

    body += `
      <h3>Payment Batches <span class="tooltip">ⓘ<span class="tooltiptext">These are your uploaded payment files. Open a batch to see payment rows and affected claims.</span></span></h3>
      <div class="muted small" style="margin-bottom:8px;">Use this to audit what changed after each payment upload.</div>

      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
        <div class="muted small">Showing ${Math.min(pageSize, pageItems.length)} of ${total} (Page ${page}/${totalPages}).</div>
        <div>${sizeSelect}</div>
      </div>

      <div style="overflow:auto;">
        <table>
          <thead><tr><th>Source File</th><th>Records</th><th>Total Paid</th><th>Last Upload</th><th></th></tr></thead>
          <tbody>${rows || `<tr><td colspan="5" class="muted">No payment uploads yet.</td></tr>`}</tbody>
        </table>
      </div>
      ${nav}
    `;
  }

  // (3) Denial Queue
  if (view === "denials") {
    const billedOrg = billedAll;
    const allDenialCases = readJSON(FILES.cases, [])
      .filter(c => c.org_id === org.org_id && String(c.case_type||"denial").toLowerCase() !== "underpayment")
      .sort((a,b)=> new Date(b.created_at||0).getTime() - new Date(a.created_at||0).getTime());

    const { page, pageSize, startIdx } = parsePageParams(parsed.query || {});
    const total = allDenialCases.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const pageItems = allDenialCases.slice(startIdx, startIdx + pageSize);

    const rows = pageItems.map(c=>{
      const linked = billedOrg.find(b => b.denial_case_id === c.case_id) || null;
      const claimLink = linked ? `<a href="/claim-detail?billed_id=${encodeURIComponent(linked.billed_id)}">${safeStr(linked.claim_number||"")}</a>` : `<span class="muted small">—</span>`;
      const payer = linked ? (linked.payer || "") : "";
      const dos = linked ? (linked.dos || "") : "";
      const billedAmt = linked ? num(linked.amount_billed) : 0;
      return `<tr>
        <td>${claimLink}</td>
        <td>${safeStr(payer)}</td>
        <td>${safeStr(dos)}</td>
        <td>$${Number(billedAmt).toFixed(2)}</td>
        <td class="muted small">${safeStr(c.case_id)}</td>
        <td>${safeStr(c.status||"")}</td>
        <td><a href="/appeal-detail?case_id=${encodeURIComponent(c.case_id)}">Open Appeal</a></td>
      </tr>`;
    }).join("");

    const sizeSelect = `
      <label class="small muted" style="margin-right:8px;">Per page</label>
      <select onchange="window.location=this.value">
        ${PAGE_SIZE_OPTIONS.map(n=>{
          const qs = new URLSearchParams({ ...parsed.query, view:"denials", page: "1", pageSize: String(n) }).toString();
          return `<option value="/claims?${qs}" ${n===pageSize?"selected":""}>${n}</option>`;
        }).join("")}
      </select>
    `;
    const nav = buildPageNav("/claims", { ...parsed.query, view:"denials", pageSize: String(pageSize) }, page, totalPages);

    body += `
      <h3>Denial Queue <span class="tooltip">ⓘ<span class="tooltiptext">Denied claims and denial cases. Open to edit appeal drafts and track outcomes.</span></span></h3>
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
        <div class="muted small">Showing ${Math.min(pageSize, pageItems.length)} of ${total} (Page ${page}/${totalPages}).</div>
        <div>${sizeSelect}</div>
      </div>
      <div style="overflow:auto;">
        <table>
          <thead><tr><th>Claim #</th><th>Payer</th><th>DOS</th><th>Billed</th><th>Case ID</th><th>Status</th><th></th></tr></thead>
          <tbody>${rows || `<tr><td colspan="7" class="muted">No denial cases yet.</td></tr>`}</tbody>
        </table>
      </div>
      ${nav}
    `;
  }

  // (4) Negotiation Queue
  if (view === "negotiations") {
    const negs = getNegotiations(org.org_id).map(n => normalizeNegotiation(n));
    const q = String(parsed.query.q || "").trim().toLowerCase();
    let filt = negs;
    if (q) {
      filt = negs.filter(n => (`${n.claim_number||""} ${n.payer||""} ${n.status||""}`).toLowerCase().includes(q));
    }
    filt.sort((a,b)=> new Date(b.updated_at||b.created_at||0).getTime() - new Date(a.updated_at||a.created_at||0).getTime());

    const { page, pageSize, startIdx } = parsePageParams(parsed.query || {});
    const total = filt.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const pageItems = filt.slice(startIdx, startIdx + pageSize);

    const rows = pageItems.map(n=>`
      <tr>
        <td><a href="/negotiation-detail?negotiation_id=${encodeURIComponent(n.negotiation_id)}">${safeStr(n.claim_number||"")}</a></td>
        <td>${safeStr(n.payer||"")}</td>
        <td>${safeStr(n.status||"Open")}</td>
        <td>$${Number(n.requested_amount||0).toFixed(2)}</td>
        <td>$${Number(n.approved_amount||0).toFixed(2)}</td>
        <td>$${Number(n.collected_amount||0).toFixed(2)}</td>
        <td>${n.updated_at ? new Date(n.updated_at).toLocaleDateString() : "—"}</td>
        <td><a href="/negotiation-detail?negotiation_id=${encodeURIComponent(n.negotiation_id)}">Open</a></td>
      </tr>
    `).join("");

    const sizeSelect = `
      <label class="small muted" style="margin-right:8px;">Per page</label>
      <select onchange="window.location=this.value">
        ${PAGE_SIZE_OPTIONS.map(n=>{
          const qs = new URLSearchParams({ ...parsed.query, view:"negotiations", page: "1", pageSize: String(n) }).toString();
          return `<option value="/claims?${qs}" ${n===pageSize?"selected":""}>${n}</option>`;
        }).join("")}
      </select>
    `;
    const nav = buildPageNav("/claims", { ...parsed.query, view:"negotiations", pageSize: String(pageSize) }, page, totalPages);

    body += `
      <h3>Negotiation Queue <span class="tooltip">ⓘ<span class="tooltiptext">Track underpayment negotiations and outcomes (approved vs collected).</span></span></h3>

      <form method="GET" action="/claims" style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
        <input type="hidden" name="view" value="negotiations"/>
        <div style="display:flex;flex-direction:column;min-width:260px;">
          <label>Search</label>
          <input name="q" value="${safeStr(parsed.query.q || "")}" placeholder="Claim #, payer, status..." />
        </div>
        <div>
          <button class="btn secondary" type="submit" style="margin-top:1.6em;">Apply</button>
          <a class="btn secondary" href="/claims?view=negotiations" style="margin-top:1.6em;">Reset</a>
        </div>
      </form>

      <div class="hr"></div>

      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
        <div class="muted small">Showing ${Math.min(pageSize, pageItems.length)} of ${total} (Page ${page}/${totalPages}).</div>
        <div>${sizeSelect}</div>
      </div>

      <div style="overflow:auto;">
        <table>
          <thead><tr><th>Claim #</th><th>Payer</th><th>Status</th><th>Requested</th><th>Approved</th><th>Collected</th><th>Updated</th><th></th></tr></thead>
          <tbody>${rows || `<tr><td colspan="8" class="muted">No negotiations yet.</td></tr>`}</tbody>
        </table>
      </div>
      ${nav}
    `;
  }

  // (5) All Claims
  if (view === "all") {
    const q = String(parsed.query.q || "").trim().toLowerCase();
    const statusF = String(parsed.query.status || "").trim();
    const payerF = String(parsed.query.payer || "").trim();
    const start = String(parsed.query.start || "").trim();
    const end = String(parsed.query.end || "").trim();
    const minAmt = String(parsed.query.min || "").trim();
    const submissionF = String(parsed.query.submission_id || "").trim();

    let billed = billedAll.slice();
    if (submissionF) billed = billed.filter(b => String(b.submission_id||"") === submissionF);

    const fromDate = start ? new Date(start + "T00:00:00.000Z") : null;
    const toDate = end ? new Date(end + "T23:59:59.999Z") : null;
    const minAmount = minAmt ? num(minAmt) : null;

    billed = billed.filter(b=>{
      if (q) {
        const blob = `${b.claim_number||""} ${b.payer||""} ${b.dos||""}`.toLowerCase();
        if (!blob.includes(q)) return false;
      }
      if (statusF && String(b.status||"Pending") !== statusF) return false;
      if (payerF && String(b.payer||"") !== payerF) return false;
      if (fromDate || toDate) {
        const dt = new Date((b.dos || b.created_at || b.paid_at || b.denied_at || nowISO()));
        if (fromDate && dt < fromDate) return false;
        if (toDate && dt > toDate) return false;
      }
      if (minAmount != null) {
        const atRisk = computeClaimAtRisk(b);
        if (atRisk < minAmount) return false;
      }
      return true;
    });

    const payerOpts = Array.from(new Set(billedAll.map(b => (b.payer || "").trim()).filter(Boolean))).sort();
    const statusOpts = ["Pending","Paid","Denied","Underpaid","Appeal","Contractual","Patient Balance"];

    const { page, pageSize, startIdx } = parsePageParams(parsed.query || {});
    const totalFiltered = billed.length;
    const totalPages = Math.max(1, Math.ceil(totalFiltered / pageSize));
    const pageItems = billed.slice(startIdx, startIdx + pageSize);

    const rows = pageItems.map(b=>{
      const st = String(b.status || "Pending");
      const paidAmt = Number(b.insurance_paid || b.paid_amount || 0);
      const atRisk = computeClaimAtRisk(b);

      return `<tr>
        <td><a href="/claim-detail?billed_id=${encodeURIComponent(b.billed_id)}">${safeStr(b.claim_number || "")}</a></td>
        <td>${safeStr(b.dos || "")}</td>
        <td>${safeStr(b.payer || "")}</td>
        <td>$${Number(b.amount_billed || 0).toFixed(2)}</td>
        <td>$${paidAmt.toFixed(2)}</td>
        <td>$${Number(atRisk||0).toFixed(2)}</td>
        <td><span class="badge ${badgeClassForStatus(st)}">${safeStr(st)}</span></td>
        <td class="muted small">${b.submission_id ? `<a href="/billed?submission_id=${encodeURIComponent(b.submission_id)}">Batch</a>` : "—"}</td>
      </tr>`;
    }).join("");

    const sizeSelect = `
      <label class="small muted" style="margin-right:8px;">Per page</label>
      <select onchange="window.location=this.value">
        ${PAGE_SIZE_OPTIONS.map(n=>{
          const qs = new URLSearchParams({ ...parsed.query, view:"all", page: "1", pageSize: String(n) }).toString();
          return `<option value="/claims?${qs}" ${n===pageSize?"selected":""}>${n}</option>`;
        }).join("")}
      </select>
    `;
    const nav = buildPageNav("/claims", { ...parsed.query, view:"all", pageSize: String(pageSize) }, page, totalPages);

    body += `
      <h3>All Claims <span class="tooltip">ⓘ<span class="tooltiptext">Filter and review all claims across your organization.</span></span></h3>

      <form method="GET" action="/claims" style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
        <input type="hidden" name="view" value="all"/>
        ${submissionF ? `<input type="hidden" name="submission_id" value="${safeStr(submissionF)}"/>` : ``}

        <div style="display:flex;flex-direction:column;min-width:220px;">
          <label>Search</label>
          <input name="q" value="${safeStr(parsed.query.q || "")}" placeholder="Claim #, payer, DOS..." />
        </div>

        <div style="display:flex;flex-direction:column;">
          <label>Status</label>
          <select name="status">
            <option value="">All</option>
            ${statusOpts.map(s => `<option value="${safeStr(s)}"${statusF===s ? " selected":""}>${safeStr(s)}</option>`).join("")}
          </select>
        </div>

        <div style="display:flex;flex-direction:column;">
          <label>Payer</label>
          <select name="payer">
            <option value="">All</option>
            ${payerOpts.map(p => `<option value="${safeStr(p)}"${payerF===p ? " selected":""}>${safeStr(p)}</option>`).join("")}
          </select>
        </div>

        <div style="display:flex;flex-direction:column;">
          <label>Start</label>
          <input type="date" name="start" value="${safeStr(start)}" />
        </div>

        <div style="display:flex;flex-direction:column;">
          <label>End</label>
          <input type="date" name="end" value="${safeStr(end)}" />
        </div>

        <div style="display:flex;flex-direction:column;">
          <label>Min At-Risk $</label>
          <input name="min" value="${safeStr(minAmt)}" placeholder="e.g. 500" />
        </div>

        <div>
          <button class="btn secondary" type="submit" style="margin-top:1.6em;">Apply</button>
          <a class="btn secondary" href="/claims?view=all" style="margin-top:1.6em;">Reset</a>
        </div>
      </form>

      <div class="hr"></div>

      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
        <div class="muted small">Showing ${Math.min(pageSize, pageItems.length)} of ${totalFiltered} results (Page ${page}/${totalPages}).</div>
        <div>${sizeSelect}</div>
      </div>

      <div style="overflow:auto;">
        <table>
          <thead><tr><th>Claim #</th><th>DOS</th><th>Payer</th><th>Billed</th><th>Paid</th><th>At Risk</th><th>Status</th><th>Source</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="8" class="muted">No claims found.</td></tr>`}</tbody>
        </table>
      </div>

      ${nav}
    `;
  }

  const html = renderPage("Claims Lifecycle", body, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
  return send(res, 200, html);
}
// ==============================
// REVENUE INTELLIGENCE (AI)
// ==============================
if (method === "GET" && pathname === "/intelligence") {

  const saved = getSavedQueries(org.org_id)
    .sort((a,b)=> new Date(b.updated_at||b.created_at||0).getTime() - new Date(a.updated_at||a.created_at||0).getTime())
    .slice(0, 12);

  const recent = getAIQueries(org.org_id)
    .sort((a,b)=> new Date(b.created_at||0).getTime() - new Date(a.created_at||0).getTime())
    .slice(0, 12);

  const styleDefault = String(parsed.query.style || "exec").trim();
  const runBrief = (String(parsed.query.brief || "1") === "1");
  const defaultPrompt = "Monthly Revenue Briefing: summarize denials, underpayments, aging, and negotiation performance. Provide next best actions.";

  const starterPrompts = [
    "Why did my denial rate change last month?",
    "Show underpayments by payer for the last 90 days and what to do next.",
    "Which claims are highest at risk and should be worked first?",
    "How is negotiation performance trending and which payers respond best?"
  ];

  const styleOptions = AI_RESPONSE_STYLES.map(s=>`<option value="${safeStr(s.key)}"${styleDefault===s.key?" selected":""}>${safeStr(s.label)}</option>`).join("");

  const infoBox = `
    <div style="border:1px solid #e5e7eb;border-radius:12px;padding:12px;background:#fff;">
      <strong>What this page does</strong>
      <div class="muted" style="margin-top:6px;">
        Ask questions about denials, underpayments, aging, negotiations, and payer performance. The AI generates an answer in the style you select,
        and the platform automatically renders charts using your live uploaded data.
      </div>
      <div class="muted small" style="margin-top:8px;">
        <span class="tooltip">ⓘ<span class="tooltiptext">Charts are always system-generated from your uploaded claims/payments. AI does not invent numbers.</span></span>
        <span style="margin-left:10px;" class="tooltip">ⓘ<span class="tooltiptext">Saved Insights are shared across your organization.</span></span>
      </div>
    </div>
  `;

  const savedHtml = saved.length ? `
    <div style="overflow:auto;">
      <table>
        <thead><tr><th>Saved Insight</th><th>Style</th><th>Run</th><th></th></tr></thead>
        <tbody>
          ${saved.map(s=>`
            <tr>
              <td>${safeStr(s.name || s.prompt || "")}</td>
              <td class="muted small">${safeStr((AI_RESPONSE_STYLES.find(x=>x.key===s.style)||{}).label || s.style)}</td>
              <td><button class="btn secondary small" type="button" onclick="window.__tjhpRunSaved('${safeStr(s.saved_id)}')">Run</button></td>
              <td>
                <form method="POST" action="/intelligence/saved/delete" onsubmit="return confirm('Delete this saved insight?');" style="display:inline;">
                  <input type="hidden" name="saved_id" value="${safeStr(s.saved_id)}"/>
                  <button class="btn danger small" type="submit">Delete</button>
                </form>
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  ` : `<p class="muted">No saved insights yet.</p>`;

  const recentHtml = recent.length ? `
    <ul class="muted">
      ${recent.map(r=>`<li><a href="javascript:void(0)" onclick="window.__tjhpRunPrompt(${JSON.stringify(r.prompt)}, ${JSON.stringify(r.style||"exec")}, ${JSON.stringify(r.charts||[])} )">${safeStr(r.prompt)}</a> <span class="muted small">(${new Date(r.created_at).toLocaleDateString()})</span></li>`).join("")}
    </ul>
  ` : `<p class="muted">No recent questions yet.</p>`;

  const html = renderPage("Revenue Intelligence (AI)", `
    <h2>Revenue Intelligence (AI)</h2>
    ${infoBox}

    <div class="hr"></div>

    <div class="row">
      <div class="col">
        <h3>Saved Insights</h3>
        ${savedHtml}
      </div>
      <div class="col">
        <h3>Starter Prompts</h3>
        <div class="muted small">Click a prompt to auto-fill.</div>
        <ul class="muted">
          ${starterPrompts.map(p=>`<li><a href="javascript:void(0)" onclick="window.__tjhpFillPrompt(${JSON.stringify(p)})">${safeStr(p)}</a></li>`).join("")}
        </ul>

        <div class="hr"></div>

        <h3>Recent Questions</h3>
        ${recentHtml}
      </div>
    </div>

    <div class="hr"></div>

    <h3>Ask AI about your revenue data</h3>

    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;">
      <div style="flex:1;min-width:260px;">
        <label>Prompt</label>
        <textarea id="riPrompt" placeholder="Ask a question about denials, underpayments, aging, negotiations..." style="min-height:90px;"></textarea>
      </div>

      <div style="min-width:260px;">
        <label>Response Style</label>
        <select id="riStyle">${styleOptions}</select>
        <div class="muted small" style="margin-top:6px;">Charts always render below regardless of style.</div>
      </div>
    </div>

    <div class="btnRow">
      <button class="btn secondary" type="button" onclick="window.__tjhpRunPrompt()">Generate Insight</button>
      <button class="btn secondary" type="button" onclick="window.__tjhpRunBriefing()">Run Monthly Briefing</button>
    </div>

    <div class="hr"></div>

    <div id="riResultBox" style="border:1px solid #e5e7eb;border-radius:12px;padding:12px;background:#fff;display:none;">
      <div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;align-items:center;">
        <strong>AI Result</strong>
        <div class="muted small" id="riRefreshed"></div>
      </div>
      <div class="hr"></div>
      <div id="riAnswer" style="white-space:pre-wrap;"></div>

      <div class="hr"></div>

      <h3 style="margin-top:0;">Charts</h3>
      <div id="riCharts"></div>

      <div class="hr"></div>

      <h3>Save this insight</h3>
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;">
        <div style="min-width:260px;flex:1;">
          <label>Name (optional)</label>
          <input id="riSaveName" placeholder="e.g., Monthly denial review" />
        </div>
        <button class="btn" type="button" onclick="window.__tjhpSaveCurrent()">Save</button>
      </div>

      <div class="muted small" id="riSaveMsg" style="margin-top:8px;"></div>
    </div>

    <script>
      window.__tjhpLastRI = { prompt:"", style:"exec", charts:[], answer:"", data:null };

      window.__tjhpFillPrompt = function(p){
        const el = document.getElementById("riPrompt");
        if (el) el.value = p;
        el && el.focus();
      };

      window.__tjhpRunBriefing = function(){
        window.__tjhpRunPrompt(${JSON.stringify(defaultPrompt)}, "exec", []);
      };

      window.__tjhpRunSaved = function(savedId){
        const saved = ${JSON.stringify(saved)};
        const s = saved.find(x => x.saved_id === savedId);
        if (!s) return;
        window.__tjhpRunPrompt(s.prompt, s.style || "exec", s.charts || []);
      };

      function __riMakeCanvas(id, title){
        const wrap = document.createElement("div");
        wrap.style.margin = "14px 0";
        const h = document.createElement("div");
        h.style.fontWeight = "800";
        h.style.marginBottom = "6px";
        h.textContent = title;
        const c = document.createElement("canvas");
        c.id = id;
        c.height = 140;
        wrap.appendChild(h);
        wrap.appendChild(c);
        return { wrap, canvas: c };
      }

      function __riRenderCharts(charts, data){
        const box = document.getElementById("riCharts");
        box.innerHTML = "";
        if (!window.Chart || !data) {
          box.innerHTML = "<p class='muted'>Charts unavailable.</p>";
          return;
        }

        charts.forEach((ch, idx) => {
          if (ch === "denial_trend") {
            const {wrap, canvas} = __riMakeCanvas("riDenial"+idx, "Denial Trend");
            box.appendChild(wrap);
            new Chart(canvas, { type:"line", data:{ labels:data.denialMonths, datasets:[
              { label:"Denials", data:data.denialTotals },
              { label:"Drafts", data:data.draftTotals }
            ]}, options:{ responsive:true } });
          }
          if (ch === "payment_trend") {
            const {wrap, canvas} = __riMakeCanvas("riPay"+idx, "Payment Trend");
            box.appendChild(wrap);
            new Chart(canvas, { type:"bar", data:{ labels:data.payMonths, datasets:[
              { label:"Payments ($)", data:data.payTotals }
            ]}, options:{ responsive:true } });
          }
          if (ch === "underpay_by_payer") {
            const {wrap, canvas} = __riMakeCanvas("riUnderpay"+idx, "Underpayment by Payer (Last 30 Days)");
            box.appendChild(wrap);
            new Chart(canvas, { type:"bar", data:{ labels:data.payerLabels, datasets:[
              { label:"Underpaid ($)", data:data.payerUnderpaid }
            ]}, options:{ responsive:true } });
          }
          if (ch === "aging_buckets") {
            const {wrap, canvas} = __riMakeCanvas("riAging"+idx, "Aging Buckets (Unpaid)");
            box.appendChild(wrap);
            new Chart(canvas, { type:"bar", data:{ labels:data.agingLabels, datasets:[
              { label:"Claims", data:data.agingCounts }
            ]}, options:{ responsive:true } });
          }
          if (ch === "negotiation_success") {
            const {wrap, canvas} = __riMakeCanvas("riNeg"+idx, "Negotiation Performance");
            box.appendChild(wrap);
            new Chart(canvas, { type:"bar", data:{ labels:["Approved","Collected"], datasets:[
              { label:"$", data:[data.negotiationApprovedTotal, data.negotiationCollectedTotal] }
            ]}, options:{ responsive:true } });
            const p = document.createElement("div");
            p.className = "muted small";
            p.style.marginTop = "6px";
            p.textContent = "Success rate: " + (data.negotiationSuccessRate || 0) + "%";
            wrap.appendChild(p);
          }
        });

        if (!charts.length) box.innerHTML = "<p class='muted'>No charts selected.</p>";
      }

      window.__tjhpRunPrompt = async function(p, s, charts){
        const promptEl = document.getElementById("riPrompt");
        const styleEl = document.getElementById("riStyle");
        const resultBox = document.getElementById("riResultBox");
        const ansEl = document.getElementById("riAnswer");
        const refEl = document.getElementById("riRefreshed");
        const saveMsg = document.getElementById("riSaveMsg");

        const prompt = (typeof p === "string" && p.length) ? p : (promptEl ? (promptEl.value||"").trim() : "");
        const style = (typeof s === "string" && s.length) ? s : (styleEl ? styleEl.value : "exec");

        if (!prompt) return;

        saveMsg.textContent = "";
        ansEl.textContent = "Thinking...";
        resultBox.style.display = "block";
        refEl.textContent = "";

        try{
          const r = await fetch("/intelligence/query", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ prompt, style, charts: charts || [] }) });
          const data = await r.json();
          if (!data || !data.ok) { ansEl.textContent = (data && data.error) ? data.error : "No response."; return; }

          window.__tjhpLastRI = { prompt, style, charts: data.charts || [], answer: data.answer || "", data: data.data || null };

          ansEl.textContent = data.answer || "";
          refEl.textContent = "Refreshed: " + new Date().toLocaleString();
          __riRenderCharts(data.charts || [], data.data || null);
        }catch(e){
          ansEl.textContent = "Error contacting assistant. Try again.";
        }
      };

      window.__tjhpSaveCurrent = async function(){
        const nameEl = document.getElementById("riSaveName");
        const saveMsg = document.getElementById("riSaveMsg");
        const cur = window.__tjhpLastRI;
        if (!cur || !cur.prompt) return;
        saveMsg.textContent = "Saving...";

        try{
          const r = await fetch("/intelligence/query", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ prompt: cur.prompt, style: cur.style, charts: cur.charts, save:"1", save_name: (nameEl ? nameEl.value : "") }) });
          const data = await r.json();
          saveMsg.textContent = (data && data.ok) ? "Saved. Refresh to see it under Saved Insights." : "Could not save.";
        }catch(e){
          saveMsg.textContent = "Could not save.";
        }
      };

      if (${runBrief ? "true" : "false"}) {
        setTimeout(()=>window.__tjhpRunBriefing(), 350);
      }
    </script>
  `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});

  return send(res, 200, html);
}

// ==============================
// ACTION CENTER (WORKFLOW)
// ==============================
if (method === "GET" && pathname === "/actions") {
  const tab = String(parsed.query.tab || "denials").toLowerCase(); // denials|underpayments|awaiting|followup
  const q = String(parsed.query.q || "").trim().toLowerCase();
  const payerF = String(parsed.query.payer || "").trim();
  const sort = String(parsed.query.sort || "urgency").trim(); // urgency|atrisk|payer|dos

  const billedAll = readJSON(FILES.billed, []).filter(b => b.org_id === org.org_id);
  const casesAll = readJSON(FILES.cases, []).filter(c => c.org_id === org.org_id);
  const negAll = getNegotiations(org.org_id).map(n => normalizeNegotiation(n));

  // helpers
  const caseById = new Map(casesAll.map(c => [c.case_id, c]));
  const negByBilled = new Map();
  negAll.forEach(n => { if (n.billed_id) negByBilled.set(n.billed_id, n); });

  function denialStageForClaim(b){
    const cid = b.denial_case_id;
    if (!cid) return { stage:"Denied", caseStatus:"" };
    const c = caseById.get(cid);
    const cs = c ? String(c.status||"") : "";
    // normalize to our stage buckets
    if (cs.includes("Approved")) return { stage:"Awaiting Payment", caseStatus: cs };
    if (cs === "Submitted" || cs === "In Review") return { stage:"Follow-Up Needed", caseStatus: cs };
    if (cs === "DRAFT_READY" || cs === "ANALYZING" || cs === "UPLOAD_RECEIVED") return { stage:"Denials", caseStatus: cs };
    if (cs === "Denied" || cs === "Closed") return { stage:"Closed", caseStatus: cs };
    return { stage:"Denials", caseStatus: cs };
  }
  function negotiationStageForClaim(b){
    const n = negByBilled.get(b.billed_id);
    if (!n) return { stage:"Underpayments", negStatus:"" };
    const st = String(n.status||"Open");
    if (st === "Approved (Pending Payment)") return { stage:"Awaiting Payment", negStatus: st };
    if (st === "Submitted" || st === "In Review" || st === "Counter Offered") return { stage:"Follow-Up Needed", negStatus: st };
    if (st === "Payment Received" || st === "Closed" || st === "Denied") return { stage:"Closed", negStatus: st };
    return { stage:"Underpayments", negStatus: st };
  }

  // Build actionable items by tab
  const items = [];
  for (const b of billedAll){
    const st = String(b.status || "Pending");

    if (payerF && String(b.payer||"") !== payerF) continue;
    if (q){
      const blob = `${b.claim_number||""} ${b.payer||""} ${b.dos||""}`.toLowerCase();
      if (!blob.includes(q)) continue;
    }

    // Determine action center grouping
    let group = null;
    let secondaryStatus = "";
    let kind = null; // denial|negotiation|other
    if (st === "Denied" || st === "Appeal"){
      const d = denialStageForClaim(b);
      group = d.stage;
      secondaryStatus = d.caseStatus;
      kind = "denial";
    } else if (st === "Underpaid"){
      const n = negotiationStageForClaim(b);
      group = n.stage;
      secondaryStatus = n.negStatus;
      kind = "negotiation";
    } else if (st === "Patient Balance"){
      group = "Follow-Up Needed";
      kind = "other";
    } else {
      continue;
    }

    // map group to tab key
    const tabKey = (group === "Denials") ? "denials" :
                   (group === "Underpayments") ? "underpayments" :
                   (group === "Awaiting Payment") ? "awaiting" :
                   (group === "Follow-Up Needed") ? "followup" : "closed";

    if (tabKey !== tab) continue;

    const atRisk = computeClaimAtRisk(b);
    const urgency = computeUrgency(b);
    items.push({ b, st, kind, atRisk, urgency, secondaryStatus, tabKey });
  }

  // Sorting
  if (sort === "atrisk") items.sort((a,b)=> b.atRisk - a.atRisk);
  else if (sort === "payer") items.sort((a,b)=> String(a.b.payer||"").localeCompare(String(b.b.payer||"")));
  else if (sort === "dos") items.sort((a,b)=> new Date(a.b.dos||a.b.created_at||0) - new Date(b.b.dos||b.b.created_at||0));
  else items.sort((a,b)=> (b.urgency - a.urgency) || (b.atRisk - a.atRisk));

  // Pagination
  const { page, pageSize, startIdx } = parsePageParams(parsed.query || {});
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const pageItems = items.slice(startIdx, startIdx + pageSize);

  // Tabs UI
  const tabBtn = (key, label, tip) => {
    const active = (tab === key);
    const qs = new URLSearchParams({ ...parsed.query, tab: key, page: "1" }).toString();
    return `<a href="/actions?${qs}" style="text-decoration:none;display:inline-flex;gap:6px;align-items:center;padding:8px 10px;border-radius:10px;border:1px solid #e5e7eb;background:${active ? "#111827" : "#fff"};color:${active ? "#fff" : "#111827"};font-weight:900;font-size:12px;">
      ${label}
      <span class="tooltip">ⓘ<span class="tooltiptext">${safeStr(tip)}</span></span>
    </a>`;
  };

  const tabs = `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
      ${tabBtn("denials","Denials","Denied claims that need an appeal packet or appeal follow-up.")}
      ${tabBtn("underpayments","Underpayments","Underpaid claims that need negotiation work or follow-up.")}
      ${tabBtn("awaiting","Awaiting Payment","Approved disputes waiting for payment posting.")}
      ${tabBtn("followup","Follow-Up Needed","Submitted appeals/negotiations requiring follow-up actions.")}
    </div>
  `;

  const payerOpts = Array.from(new Set(billedAll.map(b => (b.payer||"").trim()).filter(Boolean))).sort();

  const rows = pageItems.map(x=>{
    const b = x.b;
    const claimLink = `/claim-detail?billed_id=${encodeURIComponent(b.billed_id)}`;
    const badgeCls = badgeClassForStatus(x.st);

    let actionsHtml = '';
    if (x.kind === "denial") {
      actionsHtml = `
        <a class="btn secondary small" href="/appeal-workspace?billed_id=${encodeURIComponent(b.billed_id)}">Appeal</a>
        <a class="btn secondary small" href="/claim-action?billed_id=${encodeURIComponent(b.billed_id)}&action=writeoff">Write Off</a>
      `;
    } else if (x.kind === "negotiation") {
      actionsHtml = `
        <a class="btn secondary small" href="/negotiation-workspace?billed_id=${encodeURIComponent(b.billed_id)}">Negotiate</a>
        <a class="btn secondary small" href="/claim-action?billed_id=${encodeURIComponent(b.billed_id)}&action=patient_resp">Adjust Patient Resp</a>
        <a class="btn secondary small" href="/claim-action?billed_id=${encodeURIComponent(b.billed_id)}&action=writeoff">Write Off</a>
      `;
    } else {
      actionsHtml = `
        <a class="btn secondary small" href="${claimLink}">Open Claim</a>
        <a class="btn secondary small" href="/claim-action?billed_id=${encodeURIComponent(b.billed_id)}&action=patient_resp">Adjust Patient Resp</a>
      `;
    }

    return `<tr>
      <td><a href="${claimLink}">${safeStr(b.claim_number||"")}</a></td>
      <td>${safeStr(b.payer||"")}</td>
      <td><span class="badge ${badgeCls}">${safeStr(x.st)}</span>${x.secondaryStatus ? `<div class="muted small">Stage: ${safeStr(x.secondaryStatus)}</div>` : ""}</td>
      <td>$${Number(x.atRisk||0).toFixed(2)}</td>
      <td>${x.urgency}</td>
      <td style="white-space:nowrap;">${actionsHtml}</td>
    </tr>`;
  }).join("");

  const sizeSelect = `
    <label class="small muted" style="margin-right:8px;">Per page</label>
    <select onchange="window.location=this.value">
      ${PAGE_SIZE_OPTIONS.map(n=>{
        const qs = new URLSearchParams({ ...parsed.query, tab, page:"1", pageSize:String(n) }).toString();
        return `<option value="/actions?${qs}" ${n===pageSize?"selected":""}>${n}</option>`;
      }).join("")}
    </select>
  `;
  const nav = buildPageNav("/actions", { ...parsed.query, tab, pageSize:String(pageSize) }, page, totalPages);

  const html = renderPage("Action Center", `
    <h2>Action Center <span class="tooltip">ⓘ<span class="tooltiptext">This page prevents revenue leakage by surfacing what needs action. Use the tabs to work denials and underpayments by urgency.</span></span></h2>
    <p class="muted">Work items are sorted by urgency and revenue at risk so nothing slips through the cracks.</p>
    ${tabs}

    <div class="hr"></div>

    <form method="GET" action="/actions" style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
      <input type="hidden" name="tab" value="${safeStr(tab)}"/>
      <div style="display:flex;flex-direction:column;min-width:220px;">
        <label>Search</label>
        <input name="q" value="${safeStr(parsed.query.q || "")}" placeholder="Claim #, payer, DOS..." />
      </div>
      <div style="display:flex;flex-direction:column;">
        <label>Payer</label>
        <select name="payer">
          <option value="">All</option>
          ${payerOpts.map(p=>`<option value="${safeStr(p)}"${payerF===p?" selected":""}>${safeStr(p)}</option>`).join("")}
        </select>
      </div>
      <div style="display:flex;flex-direction:column;">
        <label>Sort</label>
        <select name="sort">
          <option value="urgency"${sort==="urgency"?" selected":""}>Urgency</option>
          <option value="atrisk"${sort==="atrisk"?" selected":""}>At-Risk $</option>
          <option value="payer"${sort==="payer"?" selected":""}>Payer</option>
          <option value="dos"${sort==="dos"?" selected":""}>Oldest DOS</option>
        </select>
      </div>
      <div>
        <button class="btn secondary" type="submit" style="margin-top:1.6em;">Apply</button>
        <a class="btn secondary" href="/actions?tab=${encodeURIComponent(tab)}" style="margin-top:1.6em;">Reset</a>
      </div>
    </form>

    <div class="hr"></div>
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
      <div class="muted small">Showing ${Math.min(pageSize, pageItems.length)} of ${total} results (Page ${page}/${totalPages}).</div>
      <div>${sizeSelect}</div>
    </div>

    <div style="overflow:auto;">
      <table>
        <thead><tr><th>Claim #</th><th>Payer</th><th>Status / Stage</th><th>At-Risk $</th><th>Urgency</th><th>Actions</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="6" class="muted">No items in this tab.</td></tr>`}</tbody>
      </table>
    </div>
    ${nav}
  `, navUser(), {showChat:true, orgName: org.org_name});

  return send(res, 200, html);
}


// ==============================
// CLAIM ACTIONS (quick forms)
// ==============================
if (method === "GET" && pathname === "/claim-action") {
  const billed_id = String(parsed.query.billed_id || "").trim();
  const action = String(parsed.query.action || "").trim(); // writeoff|patient_resp
  if (!billed_id || !action) return redirect(res, "/actions");

  const billedAll = readJSON(FILES.billed, []);
  const b = billedAll.find(x => x.org_id === org.org_id && x.billed_id === billed_id);
  if (!b) return redirect(res, "/actions");

  const title = (action === "writeoff") ? "Write Off Claim" : "Adjust Patient Responsibility";
  const help = (action === "writeoff")
    ? "Marks this claim as Write-Off (Contractual) and removes it from at-risk totals."
    : "Updates patient responsibility fields and moves claim to Patient Balance if needed.";

  const formFields = (action === "writeoff") ? `
      <input type="hidden" name="mode" value="writeoff"/>
      <p class="muted small">Optional: enter write-off amount. If blank, system will estimate using billed vs allowed (when available).</p>
      <label>Write-Off Amount (optional)</label>
      <input name="write_off_amount" placeholder="e.g. 125.00" />
  ` : `
      <input type="hidden" name="mode" value="patient_resp"/>
      <label>Patient Responsibility Amount</label>
      <input name="patient_responsibility" placeholder="e.g. 50.00" required />
      <label>Patient Collected (optional)</label>
      <input name="patient_collected" placeholder="e.g. 0.00" />
  `;

  const html = renderPage(title, `
    <h2>${safeStr(title)}</h2>
    <p class="muted">${safeStr(help)}</p>
    <div class="hr"></div>
    <p class="muted"><strong>Claim:</strong> ${safeStr(b.claim_number||"")} · <strong>Payer:</strong> ${safeStr(b.payer||"")} · <strong>Status:</strong> ${safeStr(b.status||"Pending")}</p>

    <form method="POST" action="/claim-action">
      <input type="hidden" name="billed_id" value="${safeStr(billed_id)}"/>
      ${formFields}
      <div class="btnRow">
        <button class="btn" type="submit">Apply</button>
        <a class="btn secondary" href="/actions">Back</a>
      </div>
    </form>
  `, navUser(), {showChat:true, orgName: org.org_name});
  return send(res, 200, html);
}

if (method === "POST" && pathname === "/claim-action") {
  const body = await parseBody(req);
  const params = new URLSearchParams(body);
  const billed_id = String(params.get("billed_id") || "").trim();
  const mode = String(params.get("mode") || "").trim();
  if (!billed_id || !mode) return redirect(res, "/actions");

  const billedAll = readJSON(FILES.billed, []);
  const idx = billedAll.findIndex(x => x.org_id === org.org_id && x.billed_id === billed_id);
  if (idx < 0) return redirect(res, "/actions");

  const b = billedAll[idx];

  if (mode === "writeoff") {
    const wo = (params.get("write_off_amount") || "").trim();
    const woAmt = wo ? num(wo) : null;
    b.status = "Contractual";
    if (woAmt != null) b.write_off_amount = woAmt;
    b.contractual_adjustment = (woAmt != null) ? woAmt : Math.max(0, num(b.amount_billed) - num(b.allowed_amount || 0));
    auditLog({ actor:"user", action:"claim_writeoff", org_id: org.org_id, billed_id, write_off_amount: woAmt });
  }

  if (mode === "patient_resp") {
    b.patient_responsibility = num(params.get("patient_responsibility"));
    b.patient_collected = num(params.get("patient_collected"));
    b.status = "Patient Balance";
    auditLog({ actor:"user", action:"claim_patient_resp", org_id: org.org_id, billed_id });
  }

  billedAll[idx] = b;
  writeJSON(FILES.billed, billedAll);
  return redirect(res, `/claim-detail?billed_id=${encodeURIComponent(billed_id)}`);
}

// ==============================
// APPEAL WORKSPACE (execution page)
// ==============================
if (method === "GET" && pathname === "/appeal-workspace") {
  const billed_id = String(parsed.query.billed_id || "").trim();
  if (!billed_id) return redirect(res, "/actions");

  const billedAll = readJSON(FILES.billed, []);
  const b = billedAll.find(x => x.org_id === org.org_id && x.billed_id === billed_id);
  if (!b) return redirect(res, "/actions");

  // Ensure denial case exists
  let cases = readJSON(FILES.cases, []);
  let cid = b.denial_case_id || "";
  if (!cid) {
    cid = uuid();
    cases.push({
      case_id: cid,
      org_id: org.org_id,
      created_by_user_id: user.user_id,
      created_at: nowISO(),
      status: "UPLOAD_RECEIVED",
      notes: `Auto-created from Action Center. Claim #: ${b.claim_number} | Payer: ${b.payer} | DOS: ${b.dos}`,
      case_type: "denial",
      files: [],
      template_id: "",
      paid: false,
      paid_at: null,
      paid_amount: null,
      ai_started_at: null,
      appeal_packet: appealPacketDefaults(org.org_name),
      appeal_attachments: [],
      ai: { denial_summary:null, appeal_considerations:null, draft_text:null, denial_reason_category:null, missing_info:[], time_to_draft_seconds:0 }
    });
    writeJSON(FILES.cases, cases);
    b.denial_case_id = cid;
    b.status = "Denied";
    b.denied_at = b.denied_at || nowISO();
    writeJSON(FILES.billed, billedAll);
    auditLog({ actor:"user", action:"denial_case_autocreate", org_id: org.org_id, billed_id, case_id: cid });
  }

  // redirect into appeal-detail (already contains packet builder + AI assist + attachments)
  return redirect(res, `/appeal-detail?case_id=${encodeURIComponent(cid)}`);
}

// ==============================
// NEGOTIATION WORKSPACE (execution page)
// ==============================
if (method === "GET" && pathname === "/negotiation-workspace") {
  const billed_id = String(parsed.query.billed_id || "").trim();
  if (!billed_id) return redirect(res, "/actions");

  const billedAll = readJSON(FILES.billed, []);
  const b = billedAll.find(x => x.org_id === org.org_id && x.billed_id === billed_id);
  if (!b) return redirect(res, "/actions");

  // Ensure negotiation exists
  const existing = getNegotiations(org.org_id)
    .filter(n => n.billed_id === billed_id)
    .sort((a,b)=> new Date(b.updated_at||b.created_at||0).getTime() - new Date(a.updated_at||a.created_at||0).getTime())[0];

  if (existing) return redirect(res, `/negotiation-detail?negotiation_id=${encodeURIComponent(existing.negotiation_id)}`);

  // create new negotiation record
  const negotiation_id = uuid();
  const rec = normalizeNegotiation({
    negotiation_id,
    org_id: org.org_id,
    billed_id: b.billed_id,
    claim_number: b.claim_number || "",
    payer: b.payer || "",
    dos: b.dos || "",
    amount_billed: num(b.amount_billed),
    amount_paid: num(b.insurance_paid || b.paid_amount),
    amount_underpaid: computeClaimAtRisk({ ...b, status: "Underpaid" }),
    requested_amount: 0,
    approved_amount: 0,
    collected_amount: 0,
    status: "Open",
    notes: "",
    documents: [],
    packet_draft: aiGenerateUnderpayment(org.org_name, {
      claim_number: b.claim_number, dos: b.dos, payer: b.payer,
      allowed_amount: num(b.allowed_amount), expected_insurance: num(b.expected_insurance),
      actual_paid: num(b.insurance_paid||b.paid_amount), underpaid_amount: computeClaimAtRisk({ ...b, status:"Underpaid" })
    }).draft_text
  });

  saveNegotiation(rec);
  try { updateBilledClaim(b.billed_id, (x)=>{ x.negotiation_id = negotiation_id; }); } catch {}
  auditLog({ actor:"user", action:"negotiation_autocreate", org_id: org.org_id, billed_id, negotiation_id });

  return redirect(res, `/negotiation-detail?negotiation_id=${encodeURIComponent(negotiation_id)}`);
}

// ==============================
// UPLOAD PAGES (SEPARATED)
// ==============================

// /upload-billed (separate page, no mixed uploads) -> reuse existing billed submissions UI
if (method === "GET" && pathname === "/upload-billed") {
  return redirect(res, "/billed");
}

// Payments-only upload page (UI only; POST stays /payments)
if (method === "GET" && pathname === "/upload-payments") {
  const allow = paymentRowsAllowance(org.org_id);

  // Build payment upload queue (grouped by source_file)
  const allPay = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id);
  const paymentFilesMap = {};
  allPay.forEach(p => {
    const sf = (p.source_file || "").trim();
    if (!sf) return;
    if (!paymentFilesMap[sf]) {
      paymentFilesMap[sf] = { source_file: sf, count: 0, latest: p.created_at || p.date_paid || nowISO() };
    }
    paymentFilesMap[sf].count += 1;
    const dt = new Date(p.created_at || p.date_paid || Date.now()).getTime();
    const cur = new Date(paymentFilesMap[sf].latest || 0).getTime();
    if (dt > cur) paymentFilesMap[sf].latest = p.created_at || p.date_paid || nowISO();
  });

  const paymentQueue = Object.values(paymentFilesMap)
    .sort((a,b) => new Date(b.latest).getTime() - new Date(a.latest).getTime())
    .slice(0, 12);

  const html = renderPage("Upload Payments", `
    <h2>Upload Payments</h2>
    <p class="muted">Upload bulk payment files (CSV preferred). This powers analytics and claim reconciliation.</p>
    <p class="muted small"><strong>Rows remaining:</strong> ${allow.remaining}</p>

    <form method="POST" action="/payments" enctype="multipart/form-data">
      <label>Upload CSV/XLS/XLSX</label>
      <div id="pay-dropzone" class="dropzone">Drop a CSV/XLS/XLSX file here or click to select</div>
      <input id="pay-file" type="file" name="payfile" accept=".csv,.xls,.xlsx,.pdf,.doc,.docx" required style="display:none" />
      <div class="btnRow">
        <button class="btn" type="submit">Upload Payments</button>
        <a class="btn secondary" href="/report?type=payment_detail">View Payment Details</a>
        <a class="btn secondary" href="/claims">Back to Claims Lifecycle</a>
      </div>
    </form>

    <div class="hr"></div>
    <h3>Payment Queue</h3>
    ${
      paymentQueue.length === 0
        ? `<p class="muted">No payment uploads yet.</p>`
        : `<div style="overflow:auto;">
            <table>
              <thead><tr><th>Source File</th><th>Records</th><th>Last Upload</th><th>Open</th></tr></thead>
              <tbody>${
                paymentQueue.map(x => `
                  <tr>
                    <td>${safeStr(x.source_file)}</td>
                    <td>${x.count}</td>
                    <td>${new Date(x.latest).toLocaleDateString()}</td>
                    <td><a href="/payment-batch-detail?file=${encodeURIComponent(x.source_file)}">Open</a></td>
                  </tr>
                `).join("")
              }</tbody>
            </table>
          </div>`
    }

    <script>
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
  `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
  return send(res, 200, html);
}

// Denials-only upload page (POST handled by /upload-denials)

// ==============================
// PAYMENT BATCH DETAIL (NEW) - shows payment rows + affected claims + soft delete
// ==============================
if (method === "GET" && pathname === "/payment-batch-detail") {
  const file = String(parsed.query.file || "").trim();
  if (!file) return redirect(res, "/upload-payments");

  const safeFile = path.basename(file);
  if (safeFile !== file) return send(res, 400, "Invalid file", "text/plain");

  const allPayments = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id && String(p.source_file||"") === safeFile);
  const billedAll = readJSON(FILES.billed, []).filter(b => b.org_id === org.org_id);

  // Summary
  const totalRecords = allPayments.length;
  const totalPaid = allPayments.reduce((s,p)=> s + num(p.amount_paid), 0);
  const uploadedAt = allPayments.reduce((mx,p)=>{
    const t = new Date(p.created_at || p.date_paid || 0).getTime();
    return Math.max(mx, t || 0);
  }, 0);

  // Affected claims (match by normalized claim #)
  const claimMap = new Map()
  for (const p of allPayments){
    const norm = normalizeClaimDigits(p.claim_number);
    if (!norm) continue;
    claimMap.set(norm, true);
  }
  const affected = billedAll.filter(b => claimMap.has(normalizeClaimDigits(b.claim_number)));

  // Payment table pagination
  const { page: pPage, pageSize: pSize, startIdx: pStart } = parsePageParams(parsed.query || {});
  const pTotalPages = Math.max(1, Math.ceil(totalRecords / pSize));
  const payPage = allPayments.slice(pStart, pStart + pSize);

  // Claims table pagination uses same page params but separate query keys (cpage/cpageSize)
  const cPageSize = clampInt(parsed.query.cpageSize || 50, 30, 100, 50);
  const cPage = clampInt(parsed.query.cpage || 1, 1, 999999, 1);
  const cStart = (cPage - 1) * cPageSize;
  const cTotalPages = Math.max(1, Math.ceil(affected.length / cPageSize));
  const claimPage = affected.slice(cStart, cStart + cPageSize);

  const payRows = payPage.map(p=>`
    <tr>
      <td>${safeStr(p.claim_number||"")}</td>
      <td>${safeStr(p.date_paid||"")}</td>
      <td>${safeStr(p.payer||"")}</td>
      <td>$${num(p.amount_paid).toFixed(2)}</td>
      <td class="muted small">${p.source_file ? `<a href="/file?name=${encodeURIComponent(p.source_file)}" target="_blank">${safeStr(p.source_file)}</a>` : ""}</td>
    </tr>
  `).join("");

  const claimRows = claimPage.map(b=>{
    const paidAmt = num(b.insurance_paid || b.paid_amount);
    const atRisk = computeClaimAtRisk(b);
    return `
      <tr>
        <td><a href="/claim-detail?billed_id=${encodeURIComponent(b.billed_id)}">${safeStr(b.claim_number||"")}</a></td>
        <td>${safeStr(b.dos||"")}</td>
        <td>${safeStr(b.payer||"")}</td>
        <td>$${num(b.amount_billed).toFixed(2)}</td>
        <td>$${paidAmt.toFixed(2)}</td>
        <td>$${atRisk.toFixed(2)}</td>
        <td><span class="badge ${badgeClassForStatus(b.status||"Pending")}">${safeStr(b.status||"Pending")}</span></td>
      </tr>
    `;
  }).join("");

  // nav builders
  const payNav = buildPageNav("/payment-batch-detail", { file: safeFile, pageSize: String(pSize) }, pPage, pTotalPages);

  const buildClaimNav = ()=>{
    if (cTotalPages <= 1) return "";
    const links = [];
    const prev = Math.max(1, cPage - 1);
    const next = Math.min(cTotalPages, cPage + 1);
    const base = "/payment-batch-detail";
    const qsBase = { file: safeFile, page: String(pPage), pageSize: String(pSize), cpageSize: String(cPageSize) };

    const prevQs = new URLSearchParams({ ...qsBase, cpage: String(prev) }).toString();
    const nextQs = new URLSearchParams({ ...qsBase, cpage: String(next) }).toString();
    links.push(`<a class="btn secondary small" href="${base}?${prevQs}">Prev</a>`);

    const windowSize = 7;
    let start = Math.max(1, cPage - Math.floor(windowSize/2));
    let end = Math.min(cTotalPages, start + windowSize - 1);
    start = Math.max(1, end - windowSize + 1);

    for (let i=start;i<=end;i++){
      const qs = new URLSearchParams({ ...qsBase, cpage: String(i) }).toString();
      links.push(`<a href="${base}?${qs}" style="margin:0 6px;${i===cPage?'font-weight:900;text-decoration:underline;':''}">${i}</a>`);
    }
    links.push(`<a class="btn secondary small" href="${base}?${nextQs}">Next</a>`);
    return `<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:10px;">${links.join("")}</div>`;
  };

  const html = renderPage("Payment Batch Detail", `
    <h2>Payment Batch Detail</h2>
    <p class="muted"><strong>File:</strong> ${safeStr(safeFile)} · <strong>Records:</strong> ${totalRecords} · <strong>Total Paid:</strong> $${totalPaid.toFixed(2)} · <strong>Uploaded:</strong> ${uploadedAt ? new Date(uploadedAt).toLocaleDateString() : "—"}</p>

    <div class="btnRow">
      <a class="btn secondary" href="/upload-payments">Back to Upload Payments</a>
      <a class="btn secondary" href="/claims?view=all">View All Claims</a>
    </div>

    <div class="hr"></div>
    <h3>Payment Records</h3>
    <div class="muted small">Showing ${Math.min(pSize, payPage.length)} of ${totalRecords} (Page ${pPage}/${pTotalPages})</div>
    <div style="overflow:auto;">
      <table>
        <thead><tr><th>Claim #</th><th>Date Paid</th><th>Payer</th><th>Paid</th><th>Source</th></tr></thead>
        <tbody>${payRows || `<tr><td colspan="5" class="muted">No payment rows found.</td></tr>`}</tbody>
      </table>
    </div>
    ${payNav}

    <div class="hr"></div>
    <h3>Claims Affected</h3>
    <div class="muted small">Showing ${Math.min(cPageSize, claimPage.length)} of ${affected.length} (Page ${cPage}/${cTotalPages})</div>

    <div style="display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap;align-items:center;">
      <label class="small muted">Per page</label>
      <select onchange="window.location=this.value">
        ${PAGE_SIZE_OPTIONS.map(n=>{
          const qs = new URLSearchParams({ file: safeFile, page: String(pPage), pageSize: String(pSize), cpage: "1", cpageSize: String(n) }).toString();
          return `<option value="/payment-batch-detail?${qs}" ${n===cPageSize?"selected":""}>${n}</option>`;
        }).join("")}
      </select>
    </div>

    <div style="overflow:auto;">
      <table>
        <thead><tr><th>Claim #</th><th>DOS</th><th>Payer</th><th>Billed</th><th>Paid</th><th>At Risk</th><th>Status</th></tr></thead>
        <tbody>${claimRows || `<tr><td colspan="7" class="muted">No matching claims found.</td></tr>`}</tbody>
      </table>
    </div>
    ${buildClaimNav()}

    <div class="hr"></div>
    <h3>Danger Zone</h3>
    <p class="muted">Soft delete will remove payment rows from this file and reverse their impact on affected claims. This is logged for audit.</p>
    <form method="POST" action="/payment-batch/delete" onsubmit="return confirm('Delete this payment batch? This will reverse payment effects.');">
      <input type="hidden" name="file" value="${safeStr(safeFile)}"/>
      <label>Type DELETE to confirm</label>
      <input name="confirm" placeholder="DELETE" required />
      <div class="btnRow">
        <button class="btn danger" type="submit">Delete Payment Batch</button>
      </div>
    </form>
  `, navUser(), {showChat:true, orgName: org.org_name});

  return send(res, 200, html);
}

if (method === "POST" && pathname === "/payment-batch/delete") {
  const body = await parseBody(req);
  const params = new URLSearchParams(body);
  const file = String(params.get("file") || "").trim();
  const confirm = String(params.get("confirm") || "").trim();

  if (!file) return redirect(res, "/upload-payments");
  const safeFile = path.basename(file);
  if (safeFile !== file) return send(res, 400, "Invalid file", "text/plain");

  if (confirm !== "DELETE") return redirect(res, `/payment-batch-detail?file=${encodeURIComponent(safeFile)}`);

  const allPayments = readJSON(FILES.payments, []);
  const toDelete = allPayments.filter(p => p.org_id === org.org_id && String(p.source_file||"") === safeFile);
  if (!toDelete.length) return redirect(res, `/payment-batch-detail?file=${encodeURIComponent(safeFile)}`);

  const billedAll = readJSON(FILES.billed, []);
  const billedOrg = billedAll.filter(b => b.org_id === org.org_id);

  // Reverse: subtract each payment amount from the billed claim insurance_paid/paid_amount (best-effort)
  for (const p of toDelete){
    const b = findBilledByClaim(org.org_id, billedOrg, p.claim_number);
    if (!b) continue;
    const amt = num(p.amount_paid);
    const prior = num(b.insurance_paid || b.paid_amount);
    const newPaid = Math.max(0, prior - amt);
    b.insurance_paid = newPaid;
    b.paid_amount = newPaid;
    if (newPaid <= 0.0001) {
      b.paid_at = null;
      // do not force Denied; return to Pending and let user decide
      b.status = "Pending";
    } else {
      // recompute expected and status
      const billedAmt = num(b.amount_billed);
      const allowed = num(b.allowed_amount);
      const patientResp = num(b.patient_responsibility);
      const expectedInsurance = (b.expected_insurance != null && String(b.expected_insurance).trim() !== "")
        ? num(b.expected_insurance)
        : computeExpectedInsurance((allowed > 0 ? allowed : billedAmt), patientResp);

      const underpaid = Math.max(0, expectedInsurance - newPaid);
      b.underpaid_amount = underpaid;
      b.status = (underpaid <= 0.01) ? "Paid" : "Underpaid";
    }
  }

  // Write billed updates
  const billedOut = billedAll.map(b => {
    if (b.org_id !== org.org_id) return b;
    const updated = billedOrg.find(x => x.billed_id === b.billed_id);
    return updated || b;
  });
  writeJSON(FILES.billed, billedOut);

  // Remove payments
  const remaining = allPayments.filter(p => !(p.org_id === org.org_id && String(p.source_file||"") === safeFile));
  writeJSON(FILES.payments, remaining);

  // Log soft delete
  logDeletedPaymentBatch({
    deleted_id: uuid(),
    org_id: org.org_id,
    file: safeFile,
    deleted_at: nowISO(),
    deleted_by_user_id: user.user_id,
    payments_count: toDelete.length,
    total_paid: toDelete.reduce((s,p)=>s+num(p.amount_paid),0)
  });

  auditLog({ actor:"user", action:"payment_batch_deleted", org_id: org.org_id, file: safeFile, count: toDelete.length });

  return redirect(res, "/upload-payments");
}
if (method === "GET" && pathname === "/upload-denials") {
  const billedAll = readJSON(FILES.billed, []).filter(b => b.org_id === org.org_id);

  // show denial-type cases first (exclude underpayment negotiation cases)
  const allCasesForStatus = readJSON(FILES.cases, [])
    .filter(c => c.org_id === org.org_id && String(c.case_type || "denial").toLowerCase() !== "underpayment");
  allCasesForStatus.sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
  const recentCases = allCasesForStatus.slice(0, 15);

  const rows = recentCases.map(c => {
    // Link to billed claim if we can find it
    const linked = billedAll.find(b => b.denial_case_id === c.case_id) || null;
    const claimNo = linked ? (linked.claim_number || "") : "";
    const payer = linked ? (linked.payer || "") : "";
    const dos = linked ? (linked.dos || "") : "";
    const billedAmt = linked ? Number(linked.amount_billed || 0) : 0;

    const claimLink = linked
      ? `<a href="/claim-detail?billed_id=${encodeURIComponent(linked.billed_id)}">${safeStr(claimNo)}</a>`
      : `<span class="muted small">—</span>`;

    const openAppeal = `<a href="/appeal-detail?case_id=${encodeURIComponent(c.case_id)}">Open</a>`;

    return `<tr>
      <td>${claimLink}</td>
      <td>${safeStr(payer)}</td>
      <td>${safeStr(dos)}</td>
      <td>$${billedAmt.toFixed(2)}</td>
      <td class="muted small">${safeStr(c.case_id)}</td>
      <td>${safeStr(c.status)}</td>
      <td>${openAppeal}</td>
    </tr>`;
  }).join("");

  const html = renderPage("Upload Denials", `
    <h2>Upload Denials</h2>
    <p class="muted">Upload denial documents to generate appeal drafts. Each document becomes its own case.</p>

    <form method="POST" action="/upload-denials" enctype="multipart/form-data">
      <label>Denial Documents (up to 3)</label>
      <div id="case-dropzone" class="dropzone">Drop up to 3 documents here or click to select</div>
      <input id="case-files" type="file" name="files" multiple required accept=".pdf,.doc,.docx,.jpg,.png" style="display:none" />

      <label>Optional notes</label>
      <textarea name="notes" placeholder="Any context to help review (optional)" style="min-height:140px;"></textarea>

      <div class="btnRow" style="margin-top:16px;">
        <button class="btn" type="submit">Submit Denials</button>
        <a class="btn secondary" href="/claims">Back to Claims Lifecycle</a>
      </div>
    </form>

    <div class="hr"></div>
    <h3>Denial Case Queue</h3>
    ${
      recentCases.length === 0
        ? `<p class="muted">No denial cases yet.</p>`
        : `<div style="overflow:auto;">
            <table>
              <thead><tr><th>Claim #</th><th>Payer</th><th>DOS</th><th>Billed</th><th>Case ID</th><th>Status</th><th>Open</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
           </div>`
    }

    <script>
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
    </script>
  `, navUser(), {showChat:true, orgName: org.org_name});
  return send(res, 200, html);
}

// Negotiations upload / hub
if (method === "GET" && pathname === "/upload-negotiations") {
  const billedAll = readJSON(FILES.billed, []).filter(b => b.org_id === org.org_id);
  const negs = getNegotiations(org.org_id).map(n => normalizeNegotiation(n));
  const q = String(parsed.query.q || "").trim().toLowerCase();

  const filt = q ? negs.filter(n => {
    const blob = `${n.claim_number||""} ${n.payer||""} ${n.status||""}`.toLowerCase();
    return blob.includes(q);
  }) : negs;

  const rows = filt
    .sort((a,b)=> new Date(b.updated_at||b.created_at||0).getTime() - new Date(a.updated_at||a.created_at||0).getTime())
    .slice(0, 200)
    .map(n => `
      <tr>
        <td><a href="/negotiation-detail?negotiation_id=${encodeURIComponent(n.negotiation_id)}">${safeStr(n.claim_number||"")}</a></td>
        <td>${safeStr(n.payer||"")}</td>
        <td>${safeStr(n.status||"Open")}</td>
        <td>$${Number(n.requested_amount||0).toFixed(2)}</td>
        <td>$${Number(n.approved_amount||0).toFixed(2)}</td>
        <td>$${Number(n.collected_amount||0).toFixed(2)}</td>
        <td>${n.updated_at ? new Date(n.updated_at).toLocaleDateString() : "—"}</td>
      </tr>
    `).join("");

  const underpaidClaims = billedAll
    .filter(b => String(b.status||"") === "Underpaid")
    .slice(0, 150);

  const options = underpaidClaims.map(b => `<option value="${safeStr(b.billed_id)}">${safeStr(b.claim_number)} — ${safeStr(b.payer||"")}</option>`).join("");

  const html = renderPage("Upload Negotiations", `
    <h2>Negotiations</h2>
    <p class="muted">Create and manage negotiation cases. All negotiation links route to the negotiation detail page.</p>

    <div class="hr"></div>

    <h3>Start a Negotiation</h3>
    <form method="POST" action="/negotiations/create">
      <label>Select Underpaid Claim</label>
      <select name="billed_id" required>
        <option value="">Select a claim</option>
        ${options || ""}
      </select>

      <label>Requested Amount (optional)</label>
      <input name="requested_amount" placeholder="e.g. 250.00" />

      <div class="btnRow">
        <button class="btn" type="submit">Create Negotiation</button>
        <a class="btn secondary" href="/claims">Back to Claims Lifecycle</a>
      </div>
    </form>

    <div class="hr"></div>

    <h3>Search Negotiations</h3>
    <form method="GET" action="/upload-negotiations" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;">
      <div style="display:flex;flex-direction:column;min-width:260px;">
        <label>Search</label>
        <input name="q" value="${safeStr(parsed.query.q || "")}" placeholder="Claim #, payer, status..." />
      </div>
      <div>
        <button class="btn secondary" type="submit" style="margin-top:1.6em;">Apply</button>
        <a class="btn secondary" href="/upload-negotiations" style="margin-top:1.6em;">Reset</a>
      </div>
    </form>

    <div class="hr"></div>

    <h3>Negotiation Queue (showing up to 200)</h3>
    <div style="overflow:auto;">
      <table>
        <thead><tr><th>Claim #</th><th>Payer</th><th>Status</th><th>Requested</th><th>Approved</th><th>Collected</th><th>Updated</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="7" class="muted">No negotiations yet.</td></tr>`}</tbody>
      </table>
    </div>
  `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});

  return send(res, 200, html);
}


// Create negotiation from billed_id (always routes to negotiation-detail)
if (method === "POST" && pathname === "/negotiations/create") {
  const body = await parseBody(req);
  const params = new URLSearchParams(body);
  const billed_id = (params.get("billed_id") || "").trim();
  const requested_amount = params.get("requested_amount") || "";

  const billedAll = readJSON(FILES.billed, []);
  const b = billedAll.find(x => x.billed_id === billed_id && x.org_id === org.org_id);
  if (!b) return redirect(res, "/upload-negotiations");

  // If an open negotiation exists for this claim, go there
  const existing = getNegotiations(org.org_id)
    .filter(n => n.billed_id === billed_id)
    .sort((a,b)=> new Date(b.updated_at||b.created_at||0).getTime() - new Date(a.updated_at||a.created_at||0).getTime())[0];

  if (existing) return redirect(res, `/negotiation-detail?negotiation_id=${encodeURIComponent(existing.negotiation_id)}`);

  const negotiation_id = uuid();
  const rec = normalizeNegotiation({
    negotiation_id,
    org_id: org.org_id,
    billed_id: b.billed_id,
    claim_number: b.claim_number || "",
    payer: b.payer || "",
    dos: b.dos || "",
    amount_billed: num(b.amount_billed),
    amount_paid: num(b.insurance_paid || b.paid_amount),
    amount_underpaid: computeClaimAtRisk({ ...b, status: "Underpaid" }),
    requested_amount: requested_amount ? num(requested_amount) : 0,
    approved_amount: 0,
    collected_amount: 0,
    status: "Open",
    notes: "",
    documents: []
  });

  saveNegotiation(rec);

  // Link on billed record for quick access (non-breaking if field doesn't exist)
  try {
    updateBilledClaim(b.billed_id, (x)=>{
      x.negotiation_id = negotiation_id; // latest
    });
  } catch {}

  auditLog({ actor:"user", action:"negotiation_create", org_id: org.org_id, negotiation_id, billed_id });
  return redirect(res, `/negotiation-detail?negotiation_id=${encodeURIComponent(negotiation_id)}`);
}

// Negotiation detail (single source of truth)
if (method === "GET" && pathname === "/negotiation-detail") {
  const negotiation_id = String(parsed.query.negotiation_id || "").trim();
  if (!negotiation_id) return redirect(res, "/upload-negotiations");

  const n0 = getNegotiationById(org.org_id, negotiation_id);
  if (!n0) return redirect(res, "/upload-negotiations");
  const n = normalizeNegotiation({ ...n0 });

  const billedAll = readJSON(FILES.billed, []);
  const b = billedAll.find(x => x.billed_id === n.billed_id && x.org_id === org.org_id);

  const docList = (n.documents || []).map(d => {
    const link = d && d.filename ? `<a href="/file?name=${encodeURIComponent(d.filename)}" target="_blank">${safeStr(d.filename)}</a>` : "";
    return `<li>${link} <span class="muted small">${d.uploaded_at ? new Date(d.uploaded_at).toLocaleString() : ""}</span></li>`;
  }).join("");

  const applyHelp = `When a negotiation is approved, you can track approved vs collected. You may apply collected funds to the claim (manual control) even if approval differs from payment timing.`;

  const html = renderPage("Negotiation Detail", `
    <h2>Negotiation Detail</h2>
    <p class="muted">${safeStr(applyHelp)}</p>

    <div class="hr"></div>

    <h3>Claim</h3>
    <table>
      <tr><th>Claim #</th><td>${safeStr(n.claim_number)}</td></tr>
      <tr><th>Payer</th><td>${safeStr(n.payer)}</td></tr>
      <tr><th>DOS</th><td>${safeStr(n.dos)}</td></tr>
      <tr><th>Status</th><td>${safeStr(n.status)}</td></tr>
      <tr><th>Requested</th><td>$${Number(n.requested_amount||0).toFixed(2)}</td></tr>
      <tr><th>Approved</th><td>$${Number(n.approved_amount||0).toFixed(2)}</td></tr>
      <tr><th>Collected</th><td>$${Number(n.collected_amount||0).toFixed(2)}</td></tr>
      <tr><th>Updated</th><td>${n.updated_at ? new Date(n.updated_at).toLocaleString() : "—"}</td></tr>
    </table>

    <div class="hr"></div>

    <h3>Update Negotiation</h3>
    <form method="POST" action="/negotiations/update" style="display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;">
      <input type="hidden" name="negotiation_id" value="${safeStr(n.negotiation_id)}"/>
      <div style="min-width:260px;">
        <label>Status</label>
        <select name="status">
          ${NEGOTIATION_STATUSES.map(s => `<option value="${safeStr(s)}"${n.status===s?" selected":""}>${safeStr(s)}</option>`).join("")}
        </select>
      </div>
      <div style="min-width:200px;">
        <label>Requested Amount</label>
        <input name="requested_amount" value="${safeStr(String(n.requested_amount||""))}" />
      </div>
      <div style="min-width:200px;">
        <label>Approved Amount</label>
        <input name="approved_amount" value="${safeStr(String(n.approved_amount||""))}" />
      </div>
      <div style="min-width:200px;">
        <label>Collected Amount</label>
        <input name="collected_amount" value="${safeStr(String(n.collected_amount||""))}" />
      </div>
      <div style="min-width:260px;">
        <label>Notes</label>
        <input name="notes" value="${safeStr(n.notes||"")}" placeholder="Optional notes..." />
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <label style="display:flex;gap:8px;align-items:center;margin:0;">
          <input type="checkbox" name="apply_to_claim" value="1" style="width:auto;margin:0;">
          <span class="muted small">Apply collected to claim</span>
        </label>
        <button class="btn" type="submit">Save</button>
        ${b ? `<a class="btn secondary" href="/claim-detail?billed_id=${encodeURIComponent(b.billed_id)}">Back to Claim</a>` : `<a class="btn secondary" href="/claims?view=all">Back to Claims</a>`}
        <a class="btn secondary" href="/upload-negotiations">Negotiations Queue</a>
      </div>
    </form>

    <div class="hr"></div>

    <h3>Upload Negotiation Documents</h3>
    <form method="POST" action="/negotiations/upload" enctype="multipart/form-data">
      <input type="hidden" name="negotiation_id" value="${safeStr(n.negotiation_id)}"/>
      <input type="file" name="neg_docs" multiple />
      <div class="btnRow">
        <button class="btn secondary" type="submit">Upload</button>
      </div>
    </form>

    <h3>Documents</h3>
    ${docList ? `<ul class="muted small">${docList}</ul>` : `<p class="muted small">No documents uploaded.</p>`}
  `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
  return send(res, 200, html);
}

// Update negotiation; optional apply to claim (manual control)
if (method === "POST" && pathname === "/negotiations/update") {
  const body = await parseBody(req);
  const params = new URLSearchParams(body);
  const negotiation_id = (params.get("negotiation_id") || "").trim();
  if (!negotiation_id) return redirect(res, "/upload-negotiations");

  const rec0 = getNegotiationById(org.org_id, negotiation_id);
  if (!rec0) return redirect(res, "/upload-negotiations");

  const rec = normalizeNegotiation({ ...rec0 });
  rec.status = String(params.get("status") || rec.status || "Open");
  if (!NEGOTIATION_STATUSES.includes(rec.status)) rec.status = "Open";

  rec.requested_amount = num(params.get("requested_amount"));
  rec.approved_amount = num(params.get("approved_amount"));
  rec.collected_amount = num(params.get("collected_amount"));
  rec.notes = (params.get("notes") || "").trim();

  saveNegotiation(rec);

  // If user chooses to apply collected to claim, do it now.
    // Apply to claim rules:
// - If status is "Payment Received": apply collected automatically (unless collected is 0).
// - Otherwise: apply only when user explicitly checks "Apply collected to claim".
const explicitApply = params.get("apply_to_claim") === "1";
const autoApply = (rec.status === "Payment Received");
const apply = (explicitApply || autoApply);

if (apply && rec.billed_id) {
    const collected = num(rec.collected_amount);
    if (collected > 0) {
      updateBilledClaim(rec.billed_id, (b)=>{
        // apply as insurance paid increment and recalc status (keep manual override possible later)
        const priorPaid = num(b.insurance_paid || b.paid_amount);
        const billedAmt = num(b.amount_billed);
        const newPaid = priorPaid + collected;
        b.insurance_paid = newPaid;
        b.paid_amount = newPaid;
        b.paid_at = b.paid_at || new Date().toISOString().split("T")[0];

        // recompute expected
        const allowed = num(b.allowed_amount);
        const patientResp = num(b.patient_responsibility);
        const expectedInsurance = (b.expected_insurance != null && String(b.expected_insurance).trim() !== "")
          ? num(b.expected_insurance)
          : computeExpectedInsurance((allowed > 0 ? allowed : billedAmt), patientResp);

        const underpaid = Math.max(0, expectedInsurance - newPaid);
        b.underpaid_amount = underpaid;
        if (underpaid <= 0.01) b.status = "Paid";
        else b.status = "Underpaid";
      });

      auditLog({ actor:"user", action:"negotiation_apply_to_claim", org_id: org.org_id, negotiation_id, collected_applied: collected });
    }
  }

  auditLog({ actor:"user", action:"negotiation_update", org_id: org.org_id, negotiation_id, status: rec.status });
  return redirect(res, `/negotiation-detail?negotiation_id=${encodeURIComponent(negotiation_id)}`);
}

// Upload negotiation documents
if (method === "POST" && pathname === "/negotiations/upload") {
  const contentType = req.headers["content-type"] || "";
  if (!contentType.includes("multipart/form-data")) return redirect(res, "/upload-negotiations");
  const boundaryMatch = /boundary=([^;]+)/.exec(contentType);
  if (!boundaryMatch) return redirect(res, "/upload-negotiations");
  const boundary = boundaryMatch[1];

  const { files, fields } = await parseMultipart(req, boundary);
  const negotiation_id = (fields.negotiation_id || "").trim();
  if (!negotiation_id) return redirect(res, "/upload-negotiations");

  const rec0 = getNegotiationById(org.org_id, negotiation_id);
  if (!rec0) return redirect(res, "/upload-negotiations");

  const rec = normalizeNegotiation({ ...rec0 });

  const uploadFiles = files.filter(f => f.fieldName === "neg_docs");
  if (!uploadFiles.length) return redirect(res, `/negotiation-detail?negotiation_id=${encodeURIComponent(negotiation_id)}`);

  const dir = path.join(UPLOADS_DIR, org.org_id, "negotiations", negotiation_id);
  ensureDir(dir);

  for (const f of uploadFiles) {
    const safeName = (f.filename || "neg_doc").replace(/[^a-zA-Z0-9._-]/g, "_");
    const storedName = `${Date.now()}_${safeName}`;
    const storedPath = path.join(dir, storedName);
    fs.writeFileSync(storedPath, f.buffer);

    // Store by filename only; /file route searches org tree by basename
    rec.documents.push({ filename: storedName, uploaded_at: nowISO() });
  }

  saveNegotiation(rec);
  auditLog({ actor:"user", action:"negotiation_upload_docs", org_id: org.org_id, negotiation_id, count: uploadFiles.length });
  return redirect(res, `/negotiation-detail?negotiation_id=${encodeURIComponent(negotiation_id)}`);
}


// --------- BILLED CLAIMS UPLOAD (EMR/EHR EXPORT INTAKE) ----------
  // Submission-based view: each upload creates a submission batch. Click into a batch to manage individual claims.
    // --------- BILLED CLAIMS UPLOAD (EMR/EHR EXPORT INTAKE) ----------
  // Submission-based view: each upload creates a submission batch. Click into a batch to manage individual claims.
  if (method === "GET" && pathname === "/billed") {
    const submission_id = (parsed.query.submission_id || "").trim();

    const q = (parsed.query.q || "").trim().toLowerCase();
    const statusF = (parsed.query.status || "").trim();
    const payerF = (parsed.query.payer || "").trim();
    const start = (parsed.query.start || "").trim();
    const end = (parsed.query.end || "").trim();

    const billedAll = readJSON(FILES.billed, []).filter(b => b.org_id === org.org_id);
    const subsAll = readJSON(FILES.billed_submissions, []).filter(s => s.org_id === org.org_id);

    // ===== Submissions Overview =====
    if (!submission_id) {
      const rows = subsAll
        .sort((a,b)=> new Date(b.uploaded_at||0).getTime() - new Date(a.uploaded_at||0).getTime())
        .map(s => {
          const claims = billedAll.filter(b => b.submission_id === s.submission_id);

          const totalClaims = claims.length;
          const paidCount = claims.filter(b => (b.status||"Pending")==="Paid").length;
          const deniedCount = claims.filter(b => (b.status||"Pending")==="Denied").length;
          const underpaidCount = claims.filter(b => (b.status||"Pending")==="Underpaid").length;
          const pendingCount = claims.filter(b => (b.status||"Pending")==="Pending").length;

          const totalBilledAmt = claims.reduce((sum,b)=> sum + Number(b.amount_billed || 0), 0);
          const collectedAmt = claims.reduce((sum, b) => sum + Number(b.insurance_paid || b.paid_amount || 0), 0);
          const atRiskAmt = Math.max(0, totalBilledAmt - collectedAmt);
          const collectionRate = totalBilledAmt > 0 ? (collectedAmt / totalBilledAmt) * 100 : 0;
          const barColor = collectionRate >= 80 ? "#065f46" : (collectionRate >= 60 ? "#f59e0b" : "#b91c1c");

          return `
            <tr>
              <td><a href="/billed?submission_id=${encodeURIComponent(s.submission_id)}">${safeStr(s.original_filename || "billed_upload")}</a></td>
              <td class="muted small">${s.uploaded_at ? new Date(s.uploaded_at).toLocaleDateString() : "—"}</td>
              <td>${totalClaims}</td>
              <td>${paidCount}</td>
              <td>${deniedCount}</td>
              <td>${underpaidCount}</td>
              <td>${pendingCount}</td>
              <td>$${Number(totalBilledAmt||0).toFixed(2)}</td>
              <td>$${Number(collectedAmt||0).toFixed(2)}</td>
              <td>$${Number(atRiskAmt||0).toFixed(2)}</td>
              <td style="min-width:160px;">
                <div style="height:10px;background:#e5e7eb;border-radius:999px;overflow:hidden;">
                  <div style="width:${Math.min(100, Math.max(0, Math.round(collectionRate)))}%;height:100%;background:${barColor};"></div>
                </div>
                <div class="small muted">${collectionRate.toFixed(1)}%</div>
              </td>
              <td>
                <form method="POST" action="/delete-batch" onsubmit="return confirm('Delete this submission and all its claims?');" style="display:inline;">
                  <input type="hidden" name="submission_id" value="${safeStr(s.submission_id)}"/>
                  <button class="btn danger small" type="submit">Delete</button>
                </form>
              </td>
            </tr>
          `;
        }).join("");

      const html = renderPage("Billed Claims Upload", `
        <h2>Billed Claims Upload</h2>
        <p class="muted">Upload a billed claims CSV from your EMR/EHR. Each upload becomes a submission batch you can manage.</p>

        <form method="POST" action="/billed/upload" enctype="multipart/form-data">
          <label>Upload CSV/XLS/XLSX</label>
          <input type="file" name="billedfile" accept=".csv,.xls,.xlsx" required />
          <div class="btnRow">
            <button class="btn" type="submit">Upload Billed Claims</button>
            <a class="btn secondary" href="/dashboard">Back</a>
          </div>
        </form>

        <div class="hr"></div>
        <h3>Submissions</h3>
        <div style="overflow:auto;">
          <table>
            <thead>
              <tr>
                <th>File</th><th>Uploaded</th><th>Claims</th><th>Paid</th><th>Denied</th><th>Underpaid</th><th>Pending</th>
                <th>Total Billed</th><th>Collected</th><th>At Risk</th><th>Collection</th><th>Action</th>
              </tr>
            </thead>
            <tbody>${rows || `<tr><td colspan="12" class="muted">No submissions yet.</td></tr>`}</tbody>
          </table>
        </div>
      `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
      return send(res, 200, html);
    }

    // ===== Submission Detail =====
    const sub = subsAll.find(s => s.submission_id === submission_id);
    if (!sub) return redirect(res, "/billed");

    // Filters
    let billed = billedAll.filter(b => b.submission_id === submission_id);

    // payer options
    const payerOpts = Array.from(new Set(billed.map(b => (b.payer || "").trim()).filter(Boolean))).sort();

    // date range filter (DOS or created_at fallback)
    const fromDate = start ? new Date(start + "T00:00:00.000Z") : null;
    const toDate = end ? new Date(end + "T23:59:59.999Z") : null;

    billed = billed.filter(b => {
      // search
      if (q) {
        const blob = `${b.claim_number||""} ${b.payer||""} ${b.patient_name||""}`.toLowerCase();
        if (!blob.includes(q)) return false;
      }
      // status
      if (statusF && (b.status || "Pending") !== statusF) return false;
      // payer
      if (payerF && (b.payer || "") !== payerF) return false;
      // date window
      if (fromDate || toDate) {
        const dt = new Date((b.dos || b.created_at || b.paid_at || b.denied_at || nowISO()));
        if (fromDate && dt < fromDate) return false;
        if (toDate && dt > toDate) return false;
      }
      return true;
    });

    const totalClaims = billed.length;

    // Pagination
    const PER_PAGE_OPTIONS = [10, 25, 50, 100];
    const perPage = Math.max(10, Math.min(100, Number(parsed.query.per_page || 25) || 25));
    const pageNum = Math.max(1, Number(parsed.query.page || 1) || 1);
    const totalFiltered = billed.length;
    const totalPages = Math.max(1, Math.ceil(totalFiltered / perPage));
    const startIdx = (pageNum - 1) * perPage;
    const billedPage = billed.slice(startIdx, startIdx + perPage);

    // Summary metrics for this submission (all claims, not filtered page)
    const allInSub = billedAll.filter(b => b.submission_id === submission_id);
    const totalBilledAmt = allInSub.reduce((sum,b)=> sum + Number(b.amount_billed || 0), 0);
    const collectedAmt = allInSub.reduce((sum, b) => sum + Number(b.insurance_paid || b.paid_amount || 0), 0);
    const atRiskAmt = Math.max(0, totalBilledAmt - collectedAmt);
    const collectionRate = totalBilledAmt > 0 ? ((collectedAmt / totalBilledAmt) * 100) : 0;
    const barColor = collectionRate >= 80 ? "#065f46" : (collectionRate >= 60 ? "#f59e0b" : "#b91c1c");

    const rows = billedPage.map(b => {
      const st = (b.status || "Pending");
      const today = new Date().toISOString().split("T")[0];

      const action = (() => {
        const paidFullForm = `
          <form method="POST" action="/billed/resolve" style="display:inline-block;margin-right:6px;">
            <input type="hidden" name="billed_id" value="${safeStr(b.billed_id)}"/>
            <input type="hidden" name="submission_id" value="${safeStr(submission_id)}"/>
            <input type="hidden" name="action" value="paid_full"/>
            <input type="date" name="date" value="${today}" required style="width:155px;margin-bottom:6px;"/>
            <button class="btn success small" type="submit">Paid in Full</button>
          </form>`;

        const deniedForm = `
          <form method="POST" action="/billed/resolve" style="display:inline-block;">
            <input type="hidden" name="billed_id" value="${safeStr(b.billed_id)}"/>
            <input type="hidden" name="submission_id" value="${safeStr(submission_id)}"/>
            <input type="hidden" name="action" value="denied"/>
            <input type="date" name="date" value="${today}" required style="width:155px;margin-bottom:6px;"/>
            <button class="btn danger small" type="submit">Mark Denied</button>
          </form>`;

        const negotiateBtn = (st === "Underpaid")
          ? `<form method="POST" action="/billed/negotiate" style="margin-top:6px;">
               <input type="hidden" name="billed_id" value="${safeStr(b.billed_id)}"/>
               <input type="hidden" name="submission_id" value="${safeStr(submission_id)}"/>
               <button class="btn secondary small" type="submit">Negotiate Underpayment</button>
             </form>`
          : "";

        const dd = `
          <div style="margin-top:8px;">
            <label class="small muted">Insurance Status</label>
            <select name="insurance_mode" id="mode_${safeStr(b.billed_id)}" onchange="window.__tjhpModeChange('${safeStr(b.billed_id)}')" style="width:260px;">
              <option value="">Select</option>
              <option value="insurance_underpaid">Insurance Underpaid</option>
            </select>
          </div>

          <div id="fields_${safeStr(b.billed_id)}" style="display:none;margin-top:8px;border:1px solid #e5e7eb;border-radius:10px;padding:10px;">
            <form method="POST" action="/billed/resolve" id="form_${safeStr(b.billed_id)}" style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
              <input type="hidden" name="billed_id" value="${safeStr(b.billed_id)}"/>
              <input type="hidden" name="submission_id" value="${safeStr(submission_id)}"/>
              <input type="hidden" name="action" id="action_${safeStr(b.billed_id)}" value=""/>

              <div>
                <label>Date</label>
                <input type="date" name="date" value="${today}" required style="width:155px;"/>
              </div>

              <div>
                <label>Insurance Paid</label>
                <input type="text" name="insurance_paid" id="ip_${safeStr(b.billed_id)}" placeholder="0.00" style="width:140px;" oninput="window.__tjhpCalc('${safeStr(b.billed_id)}')"/>
              </div>

              <div>
                <label>Allowed Amount</label>
                <input type="text" name="allowed_amount" id="al_${safeStr(b.billed_id)}" placeholder="0.00" style="width:140px;" oninput="window.__tjhpCalc('${safeStr(b.billed_id)}')"/>
              </div>

              <div id="prwrap_${safeStr(b.billed_id)}" style="display:block;">
                <label>Patient Resp</label>
                <input type="text" name="patient_responsibility" id="pr_${safeStr(b.billed_id)}" placeholder="auto" style="width:140px;" oninput="window.__tjhpCalc('${safeStr(b.billed_id)}')"/>
              </div>

              <button class="btn small" type="submit">Save</button>
            </form>

            <div class="small muted" id="calc_${safeStr(b.billed_id)}" style="margin-top:8px;"></div>
          </div>

          <script>
            window.__tjhpModeChange = window.__tjhpModeChange || function(id){
              const mode = document.getElementById("mode_"+id).value;
              const box = document.getElementById("fields_"+id);
              const action = document.getElementById("action_"+id);
              if (!mode){ box.style.display="none"; return; }
              box.style.display="block";
              action.value = mode;
              window.__tjhpCalc(id);
            };

            window.__tjhpCalc = window.__tjhpCalc || function(id){
              const ip = document.getElementById("ip_"+id);
              const al = document.getElementById("al_"+id);
              const pr = document.getElementById("pr_"+id);
              const out = document.getElementById("calc_"+id);
              if (!ip || !al || !pr || !out) return;

              const ipn = Number(String(ip.value||"").replace(/[^0-9.\-]/g,"")) || 0;
              const aln = Number(String(al.value||"").replace(/[^0-9.\-]/g,"")) || 0;
              const computed = Math.max(0, aln - ipn);

              if (!String(pr.value||"").trim()){
                pr.value = computed ? computed.toFixed(2) : "";
              }

              const prn = Number(String(pr.value||"").replace(/[^0-9.\-]/g,"")) || computed;
              const expectedInsurance = Math.max(0, aln - prn);
              const underpaid = Math.max(0, expectedInsurance - ipn);

              out.textContent = "Computed → Expected Insurance: $" + expectedInsurance.toFixed(2) + " | Underpaid: $" + underpaid.toFixed(2);
            };
          </script>
        `;

        return `
          <div>
            ${paidFullForm}
            ${deniedForm}
            ${dd}
            ${negotiateBtn}
            ${(st === "Underpaid") ? `
              <form method="POST" action="/claim/resolve" style="margin-top:8px;display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
                <input type="hidden" name="billed_id" value="${safeStr(b.billed_id)}"/>
                <input type="hidden" name="submission_id" value="${safeStr(submission_id)}"/>
                <div style="display:flex;flex-direction:column;min-width:260px;">
                  <label class="small muted">Resolve Underpaid</label>
                  <select name="resolution" required style="width:260px;">
                    <option value="">Select</option>
                    <option value="Contractual">Contractual Agreement (Write-off)</option>
                    <option value="Patient Balance">Patient Responsibility Needed</option>
                    <option value="Appeal">Send to Appeal</option>
                  </select>
                </div>
                <button class="btn secondary small" type="submit">Apply</button>
              </form>
            ` : ``}
          </div>
        `;
      })();

const statusCell = (() => {

  const st2 = (b.status || "Pending");

  const billedAmt = Number(b.amount_billed || 0);
  const paidAmt = Number(b.insurance_paid || b.paid_amount || 0);
  const allowed = Number(b.allowed_amount || 0);
  const patientResp = Number(b.patient_responsibility || 0);
  const patientCollected = Number(b.patient_collected || 0);

  const expectedInsurance = (b.expected_insurance != null && String(b.expected_insurance).trim() !== "")
  ? Number(b.expected_insurance)
  : computeExpectedInsurance((allowed > 0 ? allowed : billedAmt), patientResp);

  const underpaid = Math.max(0, expectedInsurance - paidAmt);
  const contractualWriteOff = Math.max(0, billedAmt - (allowed || 0));

  if (st2 === "Denied") {
    return `
      <span class="badge err">Denied</span>
      <div class="small">Paid: $${paidAmt.toFixed(2)}</div>
      <div class="small">Expected: $${expectedInsurance.toFixed(2)}</div>
      ${b.denial_case_id ? `<div class="small">Appeal: <a href="/status?case_id=${encodeURIComponent(b.denial_case_id)}">${safeStr(b.denial_case_id)}</a></div>` : ``}
    `;
  }

  if (st2 === "Contractual") {
    return `
      <span class="badge writeoff">Write-Off</span>
      <div class="small">Paid: $${paidAmt.toFixed(2)}</div>
      <div class="small">Write-Off: $${contractualWriteOff.toFixed(2)}</div>
    `;
  }

  if (st2 === "Underpaid") {
    return `
      <span class="badge underpaid">Underpaid</span>
      <div class="small">Paid: $${paidAmt.toFixed(2)}</div>
      <div class="small">Expected: $${expectedInsurance.toFixed(2)}</div>
      <div class="small">Underpaid: $${underpaid.toFixed(2)}</div>
      ${b.suggested_action ? `<div class="small muted">Suggested: ${safeStr(b.suggested_action)}</div>` : ``}
    `;
  }

  if (st2 === "Patient Balance") {
    const remaining = Math.max(0, patientResp - patientCollected);
    return `
      <span class="badge warn">Patient Owes</span>
      <div class="small">Insurance Paid: $${paidAmt.toFixed(2)}</div>
      <div class="small">Patient Resp: $${patientResp.toFixed(2)}</div>
      <div class="small">Collected: $${patientCollected.toFixed(2)}</div>
      <div class="small">Remaining: $${remaining.toFixed(2)}</div>
    `;
  }

  if (st2 === "Paid") {
    return `
      <span class="badge ok">Paid</span>
      <div class="small">Insurance Paid: $${paidAmt.toFixed(2)}</div>
      ${patientResp > 0 ? `<div class="small">Patient: $${patientCollected.toFixed(2)} / $${patientResp.toFixed(2)}</div>` : ``}
    `;
  }

  if (st2 === "Appeal") {
    return `
      <span class="badge warn">Appeal</span>
      <div class="small">Paid: $${paidAmt.toFixed(2)}</div>
      <div class="small">Expected: $${expectedInsurance.toFixed(2)}</div>
    `;
  }

  return `
    <span class="badge">${safeStr(st2)}</span>
    <div class="small">Paid: $${paidAmt.toFixed(2)}</div>
  `;

})();

      return `<tr>
        <td><a href="/claim-detail?billed_id=${encodeURIComponent(safeStr(b.billed_id))}">${safeStr(b.claim_number || "")}</a></td>
        <td>${safeStr(b.dos || "")}</td>
        <td>${safeStr(b.payer || "")}</td>
        <td>$${Number(b.amount_billed || 0).toFixed(2)}</td>
        <td>${statusCell}</td>
        <td>${action}</td>
      </tr>`;
    }).join("");

    const html = renderPage("Billed Submission", `
      <h2>Billed Claims Submission</h2>
      <p class="muted"><strong>File:</strong> ${safeStr(sub.original_filename || "billed_upload")} · <strong>Uploaded:</strong> ${sub.uploaded_at ? new Date(sub.uploaded_at).toLocaleString() : "—"} · <strong>Total claims:</strong> ${allInSub.length}</p>

      <div class="hr"></div>
      <h3>Submission Financial Summary <span class="tooltip">ⓘ<span class="tooltiptext">Snapshot of billed revenue, collected revenue, and revenue at risk for this submission batch.</span></span></h3>
      <div class="row">
        <div class="col">
          <div class="kpi-card"><h4>Total Billed</h4><p>$${totalBilledAmt.toFixed(2)}</p></div>
          <div class="kpi-card"><h4>Revenue Collected</h4><p>$${collectedAmt.toFixed(2)}</p></div>
          <div class="kpi-card"><h4>Revenue At Risk</h4><p>$${atRiskAmt.toFixed(2)}</p></div>
        </div>
        <div class="col">
          <div class="kpi-card"><h4>Collection Rate</h4><p>${collectionRate.toFixed(1)}%</p></div>
          <div style="margin-top:20px;">
            <div style="height:22px;background:#e5e7eb;border-radius:12px;overflow:hidden;">
              <div style="width:${Math.min(100, Math.max(0, Math.round(collectionRate)))}%;height:100%;background:${barColor};transition:width 0.4s ease;"></div>
            </div>
            <div class="small muted" style="margin-top:6px;">${collectionRate.toFixed(1)}% of billed revenue has been collected</div>
          </div>
        </div>
      </div>

      <div class="hr"></div>
      <h3>Bulk Actions</h3>
      <form method="POST" action="/billed/bulk-update" style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;">
        <input type="hidden" name="submission_id" value="${safeStr(submission_id)}"/>
        <div style="display:flex;flex-direction:column;">
          <label>Action</label>
          <select name="action" required>
            <option value="paid">Mark All Paid</option>
            <option value="denied">Mark All Denied</option>
            <option value="reset">Reset All to Pending</option>
          </select>
        </div>
        <div style="display:flex;flex-direction:column;">
          <label>Date (paid/denied)</label>
          <input type="date" name="date" />
        </div>
        <button class="btn" type="submit">Apply</button>
        <a class="btn secondary" href="/billed">Back to Submissions</a>
      </form>

      <div class="hr"></div>
      <h3>Claims in this Submission</h3>

      <form method="GET" action="/billed" style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
        <input type="hidden" name="submission_id" value="${safeStr(submission_id)}"/>
        <div style="display:flex;flex-direction:column;min-width:220px;">
          <label>Search</label>
          <input name="q" value="${safeStr(parsed.query.q || "")}" placeholder="Claim/Payer/Patient..." />
        </div>
        <div style="display:flex;flex-direction:column;">
          <label>Status</label>
          <select name="status">
            <option value="">All</option>
            <option value="Pending"${statusF==="Pending"?" selected":""}>Pending</option>
            <option value="Paid"${statusF==="Paid"?" selected":""}>Paid</option>
            <option value="Denied"${statusF==="Denied"?" selected":""}>Denied</option>
            <option value="Underpaid"${statusF==="Underpaid"?" selected":""}>Underpaid</option>
            <option value="Contractual"${statusF==="Contractual"?" selected":""}>Contractual</option>
            <option value="Appeal"${statusF==="Appeal"?" selected":""}>Appeal</option>
            <option value="Patient Balance"${statusF==="Patient Balance"?" selected":""}>Patient Balance</option>
          </select>
        </div>
        <div style="display:flex;flex-direction:column;">
          <label>Payer</label>
          <select name="payer">
            <option value="">All</option>
            ${payerOpts.map(p => `<option value="${safeStr(p)}"${payerF===p?" selected":""}>${safeStr(p)}</option>`).join("")}
          </select>
        </div>
        <div style="display:flex;flex-direction:column;">
          <label>Start</label>
          <input type="date" name="start" value="${safeStr(start)}" />
        </div>
        <div style="display:flex;flex-direction:column;">
          <label>End</label>
          <input type="date" name="end" value="${safeStr(end)}" />
        </div>
        <div>
          <button class="btn" type="submit" style="margin-top:1.6em;">Filter</button>
          <a class="btn secondary" href="/billed?submission_id=${encodeURIComponent(submission_id)}" style="margin-top:1.6em;">Reset</a>
        </div>
      </form>

      <div class="hr"></div>
      <div style="overflow:auto;">
        <table>
          <thead><tr><th>Claim #</th><th>DOS</th><th>Payer</th><th>Billed</th><th>Status</th><th>Action</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="6" class="muted">No claims found for this filter.</td></tr>`}</tbody>
        </table>

        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px;flex-wrap:wrap;gap:10px;">
          <div class="muted small">Showing ${Math.min(perPage, billedPage.length)} of ${totalFiltered} filtered results (Page ${pageNum}/${totalPages}).</div>
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
            <label class="small muted">Claims per page</label>
            <select onchange="window.location=this.value">
              ${PER_PAGE_OPTIONS.map(n => {
                const qs = new URLSearchParams({
                  submission_id: submission_id,
                  q: q || "",
                  status: statusF || "",
                  payer: payerF || "",
                  start: start || "",
                  end: end || "",
                  page: "1",
                  per_page: String(n)
                }).toString();
                return `<option value="/billed?${qs}" ${n===perPage ? "selected":""}>${n}</option>`;
              }).join("")}
            </select>

            <div>
              ${Array.from({length: totalPages}, (_,i)=> {
                const pn = i+1;
                const qs = new URLSearchParams({
                  submission_id: submission_id,
                  q: q || "",
                  status: statusF || "",
                  payer: payerF || "",
                  start: start || "",
                  end: end || "",
                  page: String(pn),
                  per_page: String(perPage)
                }).toString();
                return `<a href="/billed?${qs}" style="margin:0 4px;${pn===pageNum ? "font-weight:900;":""}">${pn}</a>`;
              }).join("")}
            </div>
          </div>
        </div>
      </div>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
    return send(res, 200, html);
  }

  if (method === "POST" && pathname === "/billed/upload") {
    const contentType = req.headers["content-type"] || "";
    if (!contentType.includes("multipart/form-data")) return send(res, 400, "Invalid upload", "text/plain");
    const boundaryMatch = /boundary=([^;]+)/.exec(contentType);
    if (!boundaryMatch) return send(res, 400, "Missing boundary", "text/plain");
    const boundary = boundaryMatch[1];

    const { files } = await parseMultipart(req, boundary);
    const f = files.find(x => x.fieldName === "billedfile") || files[0];
    if (!f) return redirect(res, "/billed");

    const nameLower = (f.filename || "").toLowerCase();
    const isCSV = nameLower.endsWith(".csv");
    const isXLS = nameLower.endsWith(".xls") || nameLower.endsWith(".xlsx");
    if (!isCSV && !isXLS) {
      const html = renderPage("Billed Claims Upload", `
        <h2>Billed Claims Upload</h2>
        <p class="error">Only CSV or Excel files are allowed.</p>
        <div class="btnRow"><a class="btn secondary" href="/billed">Back</a></div>
      `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
      return send(res, 400, html);
    }

    // store raw file
    const dir = path.join(UPLOADS_DIR, org.org_id, "billed");
    ensureDir(dir);
    const stored = path.join(dir, `${Date.now()}_${(f.filename || "billed").replace(/[^a-zA-Z0-9._-]/g,"_")}`);
    fs.writeFileSync(stored, f.buffer);

    const submission_id = uuid();
    const uploaded_at = nowISO();
    const original_filename = f.filename || "billed_upload";

    // Create submission metadata now; update claim_count after parsing CSV
    const subs = readJSON(FILES.billed_submissions, []);
    subs.push({
      submission_id,
      org_id: org.org_id,
      uploaded_at,
      original_filename,
      claim_count: 0
    });
    writeJSON(FILES.billed_submissions, subs);

    let rowsAdded = 0;
    if (isCSV) {
      const text = f.buffer.toString("utf8");
      const parsedCSV = parseCSV(text);
      const rows = parsedCSV.rows;

      const billed = readJSON(FILES.billed, []);

      for (const r of rows) {
        const claim = (pickField(r, ["claim", "claim#", "claim number", "claimnumber", "clm"]) || "").trim();
        if (!claim) continue;

        // Avoid duplicates per org by claim number
        const exists = billed.find(b => b.org_id === org.org_id && String(b.claim_number || "") === claim);
        if (exists) continue;

        const payer = (pickField(r, ["payer", "insurance", "carrier", "plan"]) || "").trim();
        const amt = (pickField(r, ["billed", "charge", "amount billed", "total charge", "charges"]) || "").trim();
        const dos = (pickField(r, ["dos", "date of service", "service date"]) || "").trim();
        const patient = (pickField(r, ["patient", "member", "name"]) || "").trim();

        billed.push({
          billed_id: uuid(),
          org_id: org.org_id,
          submission_id,
          claim_number: claim,
          patient_name: patient || "",
          dos: dos || "",
          payer: payer || "",
          amount_billed: Number(amt || 0) || 0,
          status: "Pending",
          paid_amount: null,
          paid_at: null,
          denied_at: null,
          denial_case_id: null,
          source_file: path.basename(stored),
          created_at: uploaded_at
        });
        rowsAdded += 1;
      }

      writeJSON(FILES.billed, billed);

      // update submission claim_count
      const subs2 = readJSON(FILES.billed_submissions, []);
      const s = subs2.find(x => x.submission_id === submission_id && x.org_id === org.org_id);
      if (s) {
        s.claim_count = rowsAdded;
        writeJSON(FILES.billed_submissions, subs2);
      }
    }

    const html = renderPage("Billed Claims Upload", `
      <h2>Billed Claims File Received</h2>
      <p class="muted">Your billed claims file was uploaded successfully.</p>
      <ul class="muted">
        <li><strong>File:</strong> ${safeStr(f.filename)}</li>
        <li><strong>Submission created:</strong> ${safeStr(new Date(uploaded_at).toLocaleString())}</li>
        <li><strong>Claims added:</strong> ${isCSV ? rowsAdded : "File stored (Excel not parsed — export to CSV for import)"}</li>
      </ul>
      <div class="btnRow">
        <a class="btn" href="/billed?submission_id=${encodeURIComponent(submission_id)}">View This Submission</a>
        <a class="btn secondary" href="/billed">Back to Submissions</a>
      </div>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
    return send(res, 200, html);
  }

 
  // --------- BILLED CLAIMS: SIMPLE RESOLUTION (progressive UI) ----------
  if (method === "POST" && pathname === "/billed/resolve") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);

    const billed_id = (params.get("billed_id") || "").trim();
    const submission_id = (params.get("submission_id") || "").trim();
    const action = (params.get("action") || "").trim(); // paid_full | denied | insurance_underpaid
    const date = (params.get("date") || "").trim();

    const billedAll = readJSON(FILES.billed, []);
    const b = billedAll.find(x => x.billed_id === billed_id && x.org_id === org.org_id);
    if (!b) return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : "/billed");

    const today = new Date().toISOString().split("T")[0];
    const when = date || today;

    // Always store these financial fields (kept simple)
    b.insurance_paid = b.insurance_paid || 0;
    b.allowed_amount = b.allowed_amount || null;
    b.patient_responsibility = b.patient_responsibility || 0;
    b.patient_collected = b.patient_collected || 0;
    b.expected_insurance = b.expected_insurance || null;
    b.underpaid_amount = b.underpaid_amount || null;

    if (action === "paid_full") {
      // Minimal-click: treat billed as fully reimbursed by insurance (can be edited later by selecting partial/underpaid)
      const billedAmt = Number(b.amount_billed || 0);
      b.status = "Paid";
      b.paid_at = when;
      b.paid_amount = billedAmt;
      b.insurance_paid = billedAmt;
      b.allowed_amount = billedAmt;
      b.patient_responsibility = 0;
      b.patient_collected = 0;
      b.expected_insurance = billedAmt;
      b.underpaid_amount = 0;

      // Create payment row for analytics (manual-billed)
      const paymentsData = readJSON(FILES.payments, []);
      const existsPay = paymentsData.find(p => p.org_id === org.org_id && p.source_file === "manual-billed" && String(p.claim_number||"")===String(b.claim_number||"") && String(p.date_paid||"")===String(when||""));
      if (!existsPay) {
        paymentsData.push({
          payment_id: uuid(),
          org_id: org.org_id,
          claim_number: b.claim_number || "",
          payer: b.payer || "",
          amount_paid: Number(b.insurance_paid || 0),
          date_paid: when,
          source_file: "manual-billed",
          created_at: nowISO(),
          denied_approved: false
        });
        writeJSON(FILES.payments, paymentsData);
      }

      writeJSON(FILES.billed, billedAll);
      auditLog({ actor:"user", action:"billed_paid_full", org_id: org.org_id, billed_id, paid_at: when });
      return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : "/billed");
    }

    if (action === "denied") {
      // Reuse existing denied behavior by redirecting to /billed/mark-denied (keeps full denial workflow)
      // We implement inline here to preserve the clean UI buttons.
      const denied_at = when;

      let cid = b.denial_case_id || "";
      const cases = readJSON(FILES.cases, []);
      if (!cid) {
        cid = uuid();
        cases.push({
          case_id: cid,
          org_id: org.org_id,
          created_by_user_id: user.user_id,
          created_at: denied_at,
          status: "UPLOAD_RECEIVED",
          notes: `Auto-created from billed claims. Claim #: ${b.claim_number} | Payer: ${b.payer} | DOS: ${b.dos}`,
          case_type: "denial",
          files: [],
          template_id: "",
          paid: false,
          paid_at: null,
          paid_amount: null,
          ai_started_at: null,
          appeal_packet: appealPacketDefaults(org.org_name),
          appeal_attachments: [],
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

        // Start AI if capacity
        const cases2 = readJSON(FILES.cases, []);
        const cObj = cases2.find(x => x.case_id === cid && x.org_id === org.org_id);
        if (cObj) {
          const okAI = canStartAI(org.org_id);
          if (okAI.ok) {
            cObj.status = "ANALYZING";
            cObj.ai_started_at = nowISO();
            writeJSON(FILES.cases, cases2);
            recordAIJob(org.org_id);
          }
        }
      } else {
        writeJSON(FILES.cases, cases);
      }

      b.status = "Denied";
      b.denied_at = denied_at;
      b.denial_case_id = cid;
      writeJSON(FILES.billed, billedAll);

      auditLog({ actor:"user", action:"billed_mark_denied", org_id: org.org_id, billed_id, case_id: cid, denied_at });
      return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : `/status?case_id=${encodeURIComponent(cid)}`);
    }

    // Partial/Underpaid require amounts
    const insurancePaid = num(params.get("insurance_paid"));
    const allowedAmt = num(params.get("allowed_amount"));
    const patientResp = num(params.get("patient_responsibility")); // editable override
    const patientStatus = (params.get("patient_status") || "not_paid").trim(); // full | partial | not_paid
    const patientPaid = num(params.get("patient_paid"));

    b.paid_at = when;
    b.paid_amount = insurancePaid;
    b.insurance_paid = insurancePaid;
    b.allowed_amount = allowedAmt;

    // patient responsibility defaults to allowed - insurance, but user can override
    const computedPR = Math.max(0, allowedAmt - insurancePaid);
    b.patient_responsibility = patientResp > 0 ? patientResp : computedPR;

    // patient collected based on patient status
    if (patientStatus === "full") b.patient_collected = b.patient_responsibility;
    else if (patientStatus === "partial") b.patient_collected = Math.min(b.patient_responsibility, patientPaid);
    else b.patient_collected = 0;

    // expected insurance is allowed - patient responsibility (editable later in negotiate packet)
    b.expected_insurance = computeExpectedInsurance(b.allowed_amount, b.patient_responsibility);
    b.underpaid_amount = computeUnderpaidAmount(b.expected_insurance, b.insurance_paid);

    if (action === "insurance_underpaid") {
      b.status = "Underpaid";
    } else {
      // insurance_partial
      // if patient still owes, keep Patient Balance; otherwise Paid
      const remainingPatient = Math.max(0, b.patient_responsibility - b.patient_collected);
      b.status = (remainingPatient > 0) ? "Patient Balance" : "Paid";
      // If it looks like underpaid, prioritize Underpaid (A)
      if (b.underpaid_amount > 0.01) b.status = "Underpaid";
    }

    writeJSON(FILES.billed, billedAll);
    auditLog({ actor:"user", action:"billed_resolve", org_id: org.org_id, billed_id, action_type: action });

    return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : "/billed");
  }

  // --------- BILLED CLAIMS: NEGOTIATE UNDERPAYMENT (auto-create case) ----------
  if (method === "POST" && pathname === "/billed/negotiate") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);

    const billed_id = (params.get("billed_id") || "").trim();
    const submission_id = (params.get("submission_id") || "").trim();

    const billedAll = readJSON(FILES.billed, []);
    const b = billedAll.find(x => x.billed_id === billed_id && x.org_id === org.org_id);
    if (!b) return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : "/billed");

    // Create underpayment case and link it
    const cases = readJSON(FILES.cases, []);
    const cid = uuid();

    const expected = (b.expected_insurance != null) ? Number(b.expected_insurance) : computeExpectedInsurance(b.allowed_amount || 0, b.patient_responsibility || 0);
    const actual = Number(b.insurance_paid || 0);
    const underpaid = Math.max(0, expected - actual);

    const meta = {
      claim_number: b.claim_number || "",
      dos: b.dos || "",
      payer: b.payer || "",
      billed_amount: Number(b.amount_billed || 0),
      allowed_amount: Number(b.allowed_amount || 0),
      patient_responsibility: Number(b.patient_responsibility || 0),
      expected_insurance: expected,
      actual_paid: actual,
      underpaid_amount: underpaid
    };

    cases.push({
      case_id: cid,
      org_id: org.org_id,
      created_by_user_id: user.user_id,
      created_at: nowISO(),
      status: "UPLOAD_RECEIVED",
      notes: `Auto-created underpayment negotiation. Claim #: ${b.claim_number} | Payer: ${b.payer} | DOS: ${b.dos}`,
      case_type: "underpayment",
      underpayment_meta: meta,
      files: [],
      template_id: "",
      paid: false,
      paid_at: null,
      paid_amount: null,
      ai_started_at: null,
      appeal_packet: appealPacketDefaults(org.org_name),
      appeal_attachments: [],
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

    // Start AI if capacity
    const cases2 = readJSON(FILES.cases, []);
    const cObj = cases2.find(x => x.case_id === cid && x.org_id === org.org_id);
    if (cObj) {
      const okAI = canStartAI(org.org_id);
      if (okAI.ok) {
        cObj.status = "ANALYZING";
        cObj.ai_started_at = nowISO();
        writeJSON(FILES.cases, cases2);
        recordAIJob(org.org_id);
      }
    }

    // Link from billed claim
    b.negotiation_case_id = cid;
    writeJSON(FILES.billed, billedAll);

    auditLog({ actor:"user", action:"billed_negotiate_create_case", org_id: org.org_id, billed_id, case_id: cid });

    return redirect(res, `/status?case_id=${encodeURIComponent(cid)}`);
  }

if (method === "POST" && pathname === "/billed/mark-paid") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const billed_id = params.get("billed_id") || "";
    const submission_id = (params.get("submission_id") || "").trim();
    const paid_at = params.get("paid_at") || nowISO();
    const paid_amount_in = (params.get("paid_amount") || "").trim();

    const billed = readJSON(FILES.billed, []);
    const b = billed.find(x => x.billed_id === billed_id && x.org_id === org.org_id);
    if (!b) return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : "/billed");

    b.status = "Paid";
    b.paid_at = paid_at;
    b.paid_amount = paid_amount_in ? Number(paid_amount_in) : (b.amount_billed || 0);

    writeJSON(FILES.billed, billed);

    // Create payment row for analytics (avoid duplicate manual-billed for same claim+date)
    const paymentsData = readJSON(FILES.payments, []);
    const existsPay = paymentsData.find(p => p.org_id === org.org_id && p.source_file === "manual-billed" && String(p.claim_number||"")===String(b.claim_number||"") && String(p.date_paid||"")===String(paid_at||""));
    if (!existsPay) {
      paymentsData.push({
        payment_id: uuid(),
        org_id: org.org_id,
        claim_number: b.claim_number || "",
        payer: b.payer || "",
        amount_paid: b.paid_amount || 0,
        date_paid: paid_at,
        source_file: "manual-billed",
        created_at: nowISO(),
        denied_approved: false
      });
      writeJSON(FILES.payments, paymentsData);
    }

    auditLog({ actor:"user", action:"billed_mark_paid", org_id: org.org_id, billed_id, paid_at, paid_amount: b.paid_amount });
    return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : "/billed");
  }

  if (method === "POST" && pathname === "/billed/mark-denied") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const billed_id = params.get("billed_id") || "";
    const submission_id = (params.get("submission_id") || "").trim();
    const denied_at = params.get("denied_at") || nowISO();

    const billed = readJSON(FILES.billed, []);
    const b = billed.find(x => x.billed_id === billed_id && x.org_id === org.org_id);
    if (!b) return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : "/billed");

    // Create a denial case (no document yet, but it enters denial workflow) if not already created
    let cid = b.denial_case_id || "";
    const cases = readJSON(FILES.cases, []);

    if (!cid) {
      cid = uuid();
      cases.push({
        case_id: cid,
        org_id: org.org_id,
        created_by_user_id: user.user_id,
        created_at: denied_at,
        status: "UPLOAD_RECEIVED",
        notes: `Auto-created from billed claims. Claim #: ${b.claim_number} | Payer: ${b.payer} | DOS: ${b.dos}`,
        case_type: "denial",
        files: [],
        template_id: "",
        paid: false,
        paid_at: null,
        paid_amount: null,
        ai_started_at: null,
        appeal_packet: appealPacketDefaults(org.org_name),
        appeal_attachments: [],
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

      // Start AI if capacity
      const cases2 = readJSON(FILES.cases, []);
      const cObj = cases2.find(x => x.case_id === cid && x.org_id === org.org_id);
      if (cObj) {
        const okAI = canStartAI(org.org_id);
        if (okAI.ok) {
          cObj.status = "ANALYZING";
          cObj.ai_started_at = nowISO();
          writeJSON(FILES.cases, cases2);
          recordAIJob(org.org_id);
        }
      }
    } else {
      // ensure persisted cases
      writeJSON(FILES.cases, cases);
    }

    b.status = "Denied";
    b.denied_at = denied_at;
    b.denial_case_id = cid;
    writeJSON(FILES.billed, billed);

    auditLog({ actor:"user", action:"billed_mark_denied", org_id: org.org_id, billed_id, case_id: cid, denied_at });
    return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : `/status?case_id=${encodeURIComponent(cid)}`);
  }

  if (method === "POST" && pathname === "/billed/reset") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const billed_id = params.get("billed_id") || "";
    const submission_id = (params.get("submission_id") || "").trim();

    const billed = readJSON(FILES.billed, []);
    const b = billed.find(x => x.billed_id === billed_id && x.org_id === org.org_id);
    if (!b) return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : "/billed");

    // If previously paid, remove manual-billed payment rows for this claim (do not remove payment uploads from source files)
    if ((b.status || "Pending") === "Paid") {
      const paymentsData = readJSON(FILES.payments, []);
      const filtered = paymentsData.filter(p => !(p.org_id === org.org_id && p.source_file === "manual-billed" && String(p.claim_number||"") === String(b.claim_number||"")));
      writeJSON(FILES.payments, filtered);
    }

    // If previously denied, remove the auto-created denial case (only if it has no files to avoid deleting uploaded docs)
    if ((b.status || "Pending") === "Denied" && b.denial_case_id) {
      const cases = readJSON(FILES.cases, []);
      const filteredCases = cases.filter(c => !(c.org_id === org.org_id && c.case_id === b.denial_case_id && (!c.files || c.files.length === 0)));
      writeJSON(FILES.cases, filteredCases);
    }

    b.status = "Pending";
    b.paid_at = null;
    b.paid_amount = null;
    b.denied_at = null;
    b.denial_case_id = null;
    writeJSON(FILES.billed, billed);

    auditLog({ actor:"user", action:"billed_reset_pending", org_id: org.org_id, billed_id });
    return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : "/billed");
  }

  if (method === "POST" && pathname === "/billed/bulk-update") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const submission_id = (params.get("submission_id") || "").trim();
    const action = (params.get("action") || "").trim(); // paid|denied|reset
    const date = (params.get("date") || "").trim();

    if (!submission_id || !action) return redirect(res, "/billed");

    const billed = readJSON(FILES.billed, []).filter(b => b.org_id === org.org_id);
    const targetIds = billed.filter(b => b.submission_id === submission_id).map(b => b.billed_id);
    if (!targetIds.length) return redirect(res, `/billed?submission_id=${encodeURIComponent(submission_id)}`);

    const billedAll = readJSON(FILES.billed, []);
    let changed = 0;

    if (action === "paid") {
      const paid_at = date || nowISO();
      const paymentsData = readJSON(FILES.payments, []);
      for (const b of billedAll) {
        if (b.org_id !== org.org_id) continue;
        if (b.submission_id !== submission_id) continue;
        if ((b.status || "Pending") === "Paid") continue;

        b.status = "Paid";
        b.paid_at = paid_at;
        b.paid_amount = Number(b.amount_billed || 0);
        b.denied_at = b.denied_at || null;

        const existsPay = paymentsData.find(p => p.org_id === org.org_id && p.source_file === "manual-billed" && String(p.claim_number||"")===String(b.claim_number||"") && String(p.date_paid||"")===String(paid_at||""));
        if (!existsPay) {
          paymentsData.push({
            payment_id: uuid(),
            org_id: org.org_id,
            claim_number: b.claim_number || "",
            payer: b.payer || "",
            amount_paid: b.paid_amount || 0,
            date_paid: paid_at,
            source_file: "manual-billed",
            created_at: nowISO(),
            denied_approved: false
          });
        }
        changed++;
      }
      writeJSON(FILES.payments, paymentsData);
      writeJSON(FILES.billed, billedAll);
    } else if (action === "denied") {
      const denied_at = date || nowISO();
      const cases = readJSON(FILES.cases, []);
      for (const b of billedAll) {
        if (b.org_id !== org.org_id) continue;
        if (b.submission_id !== submission_id) continue;
        if ((b.status || "Pending") === "Denied") continue;

        // Create denial case if missing
        if (!b.denial_case_id) {
          const cid = uuid();
          cases.push({
            case_id: cid,
            org_id: org.org_id,
            created_by_user_id: user.user_id,
            created_at: denied_at,
            status: "UPLOAD_RECEIVED",
            notes: `Auto-created from billed claims (bulk). Claim #: ${b.claim_number} | Payer: ${b.payer} | DOS: ${b.dos}`,
            case_type: "denial",
            files: [],
            template_id: "",
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
          b.denial_case_id = cid;
        }

        b.status = "Denied";
        b.denied_at = denied_at;
        b.paid_at = null;
        b.paid_amount = null;
        changed++;
      }
      writeJSON(FILES.cases, cases);
      writeJSON(FILES.billed, billedAll);
    } else if (action === "reset") {
      // Remove manual-billed payments and empty-file denial cases for this submission
      const paymentsData = readJSON(FILES.payments, []);
      const cases = readJSON(FILES.cases, []);

      const claimNos = new Set(billedAll.filter(b => b.org_id === org.org_id && b.submission_id === submission_id).map(b => String(b.claim_number||"")));
      const denialCaseIds = new Set(billedAll.filter(b => b.org_id === org.org_id && b.submission_id === submission_id && b.denial_case_id).map(b => b.denial_case_id));

      const paymentsFiltered = paymentsData.filter(p => !(p.org_id === org.org_id && p.source_file === "manual-billed" && claimNos.has(String(p.claim_number||""))));
      writeJSON(FILES.payments, paymentsFiltered);

      const casesFiltered = cases.filter(c => !(c.org_id === org.org_id && denialCaseIds.has(c.case_id) && (!c.files || c.files.length === 0)));
      writeJSON(FILES.cases, casesFiltered);

      for (const b of billedAll) {
        if (b.org_id !== org.org_id) continue;
        if (b.submission_id !== submission_id) continue;
        b.status = "Pending";
        b.paid_at = null;
        b.paid_amount = null;
        b.denied_at = null;
        b.denial_case_id = null;
        changed++;
      }
      writeJSON(FILES.billed, billedAll);
    }

    auditLog({ actor:"user", action:"billed_bulk_update", org_id: org.org_id, submission_id, bulk_action: action, date });
    return redirect(res, `/billed?submission_id=${encodeURIComponent(submission_id)}`);
  }

  // --------- UNDERPAID RESOLUTION (Contractual / Appeal / Patient Balance) ----------
  if (method === "POST" && pathname === "/claim/resolve") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);

    const billed_id = (params.get("billed_id") || "").trim();
    const submission_id = (params.get("submission_id") || "").trim();
    const resolution = (params.get("resolution") || "").trim(); // Contractual | Appeal | Patient Balance

    const billedAll = readJSON(FILES.billed, []);
    const b = billedAll.find(x => x.billed_id === billed_id && x.org_id === org.org_id);
    if (!b) return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : "/billed");

    if (resolution === "Contractual") {
      b.status = "Contractual";
      b.contractual_adjustment = Math.max(0, num(b.amount_billed) - num(b.allowed_amount || b.amount_billed));
    } else if (resolution === "Appeal") {
      b.status = "Appeal";
      b.appeal_flag = true;
    } else if (resolution === "Patient Balance") {
      b.status = "Patient Balance";
      b.patient_balance = Math.max(0, num(b.patient_responsibility) - num(b.patient_collected));
    }

    writeJSON(FILES.billed, billedAll);
    auditLog({ actor:"user", action:"claim_resolve", org_id: org.org_id, billed_id, resolution });

    return redirect(res, submission_id ? `/billed?submission_id=${encodeURIComponent(submission_id)}` : "/billed");
  }

// --------- CASE UPLOAD ----------
  // Legacy combined uploads page: redirect to the new Denials uploader.
  if (method === "GET" && pathname === "/upload") {
    return redirect(res, "/upload-denials");
  }


  if (method === "POST" && (pathname === "/upload" || pathname === "/upload-denials")) {
    // limit: pilot cases
    const can = pilotCanCreateCase(org.org_id);
    if (!can.ok) {
      const html = renderPage("Limit", `
        <h2>Limit Reached</h2>
        <p class="error">${safeStr(can.reason)}</p>
        <div class="btnRow"><a class="btn secondary" href="/dashboard">Back</a></div>
      `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
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
    if (!files.length) return redirect(res, "/upload-denials");
    if (files.length > maxFiles) {
      const html = renderPage("Upload", `
        <h2>Upload</h2>
        <p class="error">Please upload no more than ${maxFiles} files per case.</p>
        <div class="btnRow"><a class="btn secondary" href="/upload">Back</a></div>
      `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
      return send(res, 400, html);
    }

    const maxBytes = limits.max_file_size_mb * 1024 * 1024;
    for (const f of files) {
      if (f.buffer.length > maxBytes) {
        const html = renderPage("Upload", `
          <h2>Upload</h2>
          <p class="error">File too large. Max size is ${limits.max_file_size_mb} MB.</p>
          <div class="btnRow"><a class="btn secondary" href="/upload">Back</a></div>
        `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
        return send(res, 400, html);
      }
    }

    // Handle template file upload and multiple document cases
    // Separate document files (named "files") and optional template upload
    const docFiles = files.filter(f => f.fieldName === "files");
    // Ensure at least one document file
    if (!docFiles.length) return redirect(res, "/upload-denials");
    // Determine selected template from dropdown
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
        template_id: "",
        // Track payment status for each case. A case is marked paid when appeals have resulted in payment.
        paid: false,
        paid_at: null,
        paid_amount: null,
        ai_started_at: null,
        appeal_packet: appealPacketDefaults(org.org_name),
        appeal_attachments: [],
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
      return redirect(res, "/upload-denials?submitted=1");
}
    // If no cases were created (limit reached), show limit message
    const html = renderPage("Limit", `
      <h2>Limit Reached</h2>
      <p class="error">${safeStr(limitReason || "Case limit reached")}</p>
      <div class="btnRow"><a class="btn secondary" href="/dashboard">Back</a></div>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
    return send(res, 403, html);
  }

  // status (poll)
  if (method === "GET" && pathname === "/status") {
    const case_id = parsed.query.case_id || "";
    const cases = readJSON(FILES.cases, []);
    const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
    if (!c) return redirect(res, "/dashboard");
    normalizeAppealPacket(c, org.org_name);
    // If LMN empty, seed template
    if (!c.appeal_packet.lmn_text) c.appeal_packet.lmn_text = appealPacketDefaults(org.org_name).lmn_text;

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

    const html = renderPage("Status", `
      <h2>Review in Progress</h2>
      <p class="muted">Our AI agent is analyzing your uploaded documents and preparing a draft. This is decision support only.</p>
      ${badge}
      <div class="hr"></div>
      <div class="muted small"><strong>Case ID:</strong> ${safeStr(case_id)}</div>
      <script>setTimeout(()=>window.location.reload(), 2500);</script>
      <div class="btnRow"><a class="btn secondary" href="/dashboard">Back</a></div>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});

    return send(res, 200, html);
  }

  
// ==============================
// APPEAL DETAIL (NEW) - Denial appeals workflow (separate from negotiation)
// ==============================
if (method === "GET" && pathname === "/appeal-detail") {
  const case_id = String(parsed.query.case_id || "").trim();
  if (!case_id) return redirect(res, "/upload-denials");

  const cases = readJSON(FILES.cases, []);
  const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
  if (!c) return redirect(res, "/upload-denials");

  // ensure AI completed if needed
  if (c.status === "ANALYZING") {
    maybeCompleteAI(c, org.org_name);
    writeJSON(FILES.cases, cases);
  }
  if (!c.ai) c.ai = {};
  normalizeAppealPacket(c, org.org_name);

  const billedAll = readJSON(FILES.billed, []).filter(b => b.org_id === org.org_id);
  const linked = billedAll.find(b => b.denial_case_id === c.case_id) || null;

  const claimSummary = linked ? `
    <table>
      <tr><th>Claim #</th><td><a href="/claim-detail?billed_id=${encodeURIComponent(linked.billed_id)}">${safeStr(linked.claim_number||"")}</a></td></tr>
      <tr><th>Payer</th><td>${safeStr(linked.payer||"")}</td></tr>
      <tr><th>DOS</th><td>${safeStr(linked.dos||"")}</td></tr>
      <tr><th>Billed</th><td>$${num(linked.amount_billed).toFixed(2)}</td></tr>
      <tr><th>Paid</th><td>$${num(linked.insurance_paid || linked.paid_amount).toFixed(2)}</td></tr>
      <tr><th>Status</th><td><span class="badge ${badgeClassForStatus(linked.status||"Denied")}">${safeStr(linked.status||"Denied")}</span></td></tr>
    </table>
  ` : `<p class="muted">No billed claim is linked to this denial case yet.</p>`;

  const statusLabel = safeStr(c.status || "");
  const draftText = (c.ai && c.ai.draft_text) ? c.ai.draft_text : "";
  const considerations = (c.ai && c.ai.appeal_considerations) ? c.ai.appeal_considerations : "";

  const html = renderPage("Appeal Detail", `
    <h2>Appeal Detail</h2>
    <p class="muted">Denial appeal workflow. Edit the appeal letter, get AI suggestions, upload attachments, and track submission/approval.</p>

    <div class="hr"></div>
    <h3>Case</h3>
    <div class="muted small"><strong>Case ID:</strong> ${safeStr(case_id)} · <strong>Status:</strong> ${statusLabel}</div>

    <div class="hr"></div>
    <h3>Denied Claim</h3>
    ${claimSummary}

    <div class="hr"></div>
    <h3>Appeal Letter</h3>
    <div class="muted small">${safeStr(considerations)}</div>

    <textarea id="appealDraft" style="min-height:240px;">${safeStr(draftText)}</textarea>

    <div class="btnRow">
      <button class="btn secondary" type="button" onclick="window.__tjhpAppealAI('Improve the tone and clarity. Keep it professional and concise.')">Improve Tone (AI)</button>
      <button class="btn secondary" type="button" onclick="window.__tjhpAppealAI('Add a short, stronger justification section. Do not invent clinical facts; use placeholders if needed.')">Strengthen Justification (AI)</button>
      <button class="btn secondary" type="button" onclick="window.__tjhpAppealAI('Rewrite into bullet-point structure suitable for payer review. Do not invent facts.')">Convert to Bullets (AI)</button>
      <button class="btn" type="button" onclick="window.__tjhpSaveAppeal()">Save Draft</button>
    </div>

    <div id="appealSaveMsg" class="muted small" style="margin-top:8px;"></div>

    <div class="hr"></div>
    <h3>Status Actions</h3>
    <div class="row">
      <div class="col">
        <form method="POST" action="/appeal/action">
          <input type="hidden" name="case_id" value="${safeStr(case_id)}"/>
          <input type="hidden" name="action" value="mark_submitted"/>
          <button class="btn secondary" type="submit">Mark Submitted</button>
        </form>
      </div>
      <div class="col">
        <form method="POST" action="/appeal/action">
          <input type="hidden" name="case_id" value="${safeStr(case_id)}"/>
          <input type="hidden" name="action" value="mark_denied"/>
          <button class="btn secondary" type="submit">Mark Denied</button>
        </form>
      </div>
      <div class="col">
        <form method="POST" action="/appeal/action">
          <input type="hidden" name="case_id" value="${safeStr(case_id)}"/>
          <input type="hidden" name="action" value="close"/>
          <button class="btn secondary" type="submit">Close Case</button>
        </form>
      </div>
    </div>

    <div class="hr"></div>
    <h3>Mark Approved (Option C)</h3>
    <p class="muted small">Enter the approved amount. You may optionally apply it to the claim now.</p>
    <form method="POST" action="/appeal/action" style="display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;">
      <input type="hidden" name="case_id" value="${safeStr(case_id)}"/>
      <input type="hidden" name="action" value="mark_approved"/>
      <div style="min-width:220px;">
        <label>Approved Amount</label>
        <input name="approved_amount" placeholder="e.g. 250.00" required />
      </div>
      <div style="min-width:220px;">
        <label>Paid Date (optional)</label>
        <input type="date" name="paid_at" />
      </div>
      <label style="display:flex;gap:8px;align-items:center;margin:0;">
        <input type="checkbox" name="apply_payment" value="1" style="width:auto;margin:0;">
        <span class="muted small">Apply payment to claim now</span>
      </label>
      <button class="btn" type="submit">Mark Approved</button>
    </form>

    <div class="hr"></div>
    <h3>Attachments</h3>
    <p class="muted small">Upload de-identified supporting documents (auto-delete in 60 minutes).</p>
    <form method="POST" action="/appeal/upload" enctype="multipart/form-data">
      <input type="hidden" name="case_id" value="${safeStr(case_id)}"/>
      <input type="file" name="appeal_docs" multiple />
      <div class="btnRow">
        <button class="btn secondary" type="submit">Upload Attachments</button>
      </div>
    </form>

    <div class="btnRow">
      <a class="btn secondary" href="/upload-denials">Back to Denial Queue</a>
      <a class="btn secondary" href="/claims">Claims Lifecycle</a>
    </div>

    <script>
      window.__tjhpAppealAI = async function(instruction){
        const ta = document.getElementById("appealDraft");
        const msg = "You are helping improve a denial appeal letter. " + instruction + "\\n\\nCURRENT DRAFT:\\n" + (ta ? ta.value : "");
        const r = await fetch("/ai/chat", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ message: msg }) });
        const data = await r.json();
        if (data && data.answer && ta) ta.value = data.answer;
      };

      window.__tjhpSaveAppeal = async function(){
        const ta = document.getElementById("appealDraft");
        const out = document.getElementById("appealSaveMsg");
        if (!ta) return;
        out.textContent = "Saving...";
        try{
          const r = await fetch("/appeal/save-draft", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ case_id: "${safeStr(case_id)}", draft_text: ta.value }) });
          const data = await r.json();
          out.textContent = (data && data.ok) ? "Saved." : "Could not save.";
        }catch(e){
          out.textContent = "Could not save.";
        }
      };
    </script>
  `, navUser(), {showChat:true, orgName: org.org_name});

  return send(res, 200, html);
}

if (method === "POST" && pathname === "/appeal/save-draft") {
  const body = await parseBody(req);
  let payload = {};
  try { payload = JSON.parse(body || "{}"); } catch { payload = {}; }
  const case_id = String(payload.case_id || "").trim();
  const draft_text = String(payload.draft_text || "");

  if (!case_id) return send(res, 200, JSON.stringify({ ok:false }), "application/json");

  const cases = readJSON(FILES.cases, []);
  const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
  if (!c) return send(res, 200, JSON.stringify({ ok:false }), "application/json");

  if (!c.ai) c.ai = {};
  c.ai.draft_text = draft_text;
  c.updated_at = nowISO();
  writeJSON(FILES.cases, cases);
  auditLog({ actor:"user", action:"appeal_save_draft", org_id: org.org_id, case_id });
  return send(res, 200, JSON.stringify({ ok:true }), "application/json");
}

if (method === "POST" && pathname === "/appeal/action") {
  const body = await parseBody(req);
  const params = new URLSearchParams(body);
  const case_id = String(params.get("case_id") || "").trim();
  const action = String(params.get("action") || "").trim();

  const cases = readJSON(FILES.cases, []);
  const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
  if (!c) return redirect(res, "/upload-denials");

  // status transitions
  if (action === "mark_submitted") c.status = "Submitted";
  if (action === "mark_denied") c.status = "Denied";
  if (action === "close") c.status = "Closed";

  if (action === "mark_approved") {
    c.status = "Approved (Pending Payment)";
    const approvedAmt = num(params.get("approved_amount"));
    const applyPay = params.get("apply_payment") === "1";
    const paidAt = (params.get("paid_at") || "").trim();

    // Link/update claim if available
    const billedAll = readJSON(FILES.billed, []);
    const b = billedAll.find(x => x.org_id === org.org_id && x.denial_case_id === case_id) || null;

    if (b) {
      b.appeal_approved_amount = approvedAmt;
      b.appeal_approved_at = nowISO();
      b.status = "Appeal";
      if (applyPay && approvedAmt > 0) {
        const prior = num(b.insurance_paid || b.paid_amount);
        const newPaid = prior + approvedAmt;
        b.insurance_paid = newPaid;
        b.paid_amount = newPaid;
        b.paid_at = paidAt || b.paid_at || new Date().toISOString().split("T")[0];

        const billedAmt = num(b.amount_billed);
        const allowed = num(b.allowed_amount);
        const patientResp = num(b.patient_responsibility);
        const expectedInsurance = (b.expected_insurance != null && String(b.expected_insurance).trim() !== "")
          ? num(b.expected_insurance)
          : computeExpectedInsurance((allowed > 0 ? allowed : billedAmt), patientResp);

        const underpaid = Math.max(0, expectedInsurance - newPaid);
        b.underpaid_amount = underpaid;
        b.status = (underpaid <= 0.01) ? "Paid" : "Underpaid";

        // log payment record
        const paymentsData = readJSON(FILES.payments, []);
        paymentsData.push({
          payment_id: uuid(),
          org_id: org.org_id,
          claim_number: b.claim_number || "",
          payer: b.payer || "Appeal Approved",
          amount_paid: approvedAmt,
          date_paid: paidAt || new Date().toISOString().split("T")[0],
          source_file: "appeal-approved",
          created_at: nowISO(),
          denied_approved: true
        });
        writeJSON(FILES.payments, paymentsData);
      }
      writeJSON(FILES.billed, billedAll);
    }
    c.approved_amount = approvedAmt;
    c.approved_at = nowISO();
  }

  c.updated_at = nowISO();
  writeJSON(FILES.cases, cases);
  auditLog({ actor:"user", action:"appeal_action", org_id: org.org_id, case_id, action_taken: action });

  return redirect(res, `/appeal-detail?case_id=${encodeURIComponent(case_id)}`);
}
// draft view + edit
  if (method === "GET" && pathname === "/draft") {
    const case_id = parsed.query.case_id || "";
    const cases = readJSON(FILES.cases, []);
    const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
    if (!c) return redirect(res, "/dashboard");
    normalizeAppealPacket(c, org.org_name);
    // If LMN empty, seed template
    if (!c.appeal_packet.lmn_text) c.appeal_packet.lmn_text = appealPacketDefaults(org.org_name).lmn_text;

    const html = renderPage("Appeal Packet Builder", `
      <h2>${safeStr(((c.case_type||"").toLowerCase()==="underpayment") ? "Underpayment Negotiation Packet (De‑Identified)" : "Appeal Packet Builder (De‑Identified)")}</h2>
      <p class="muted">Build a complete appeal packet without storing patient identifiers. Do not upload or enter patient name, DOB, or member ID.</p>
      <div class="badge warn">DE‑IDENTIFIED MODE · No PHI · Human review required</div>
      <div class="hr"></div>

      <form method="POST" action="/appeal/save">
        <input type="hidden" name="case_id" value="${safeStr(case_id)}"/>

        <h3>De‑Identified Confirmation</h3>
        <label style="display:flex;gap:10px;align-items:flex-start;margin-top:8px;">
          <input type="checkbox" name="deid_confirmed" value="1" ${c.appeal_packet && c.appeal_packet.deid_confirmed ? "checked" : ""} style="width:auto;margin:0;margin-top:2px;">
          <span class="muted">I confirm this case is de‑identified (no patient identifiers in text or uploads).</span>
        </label>

        <div class="hr"></div>
        <h3>1) Appeal Letter</h3>
        <textarea name="draft_text">${safeStr((c.ai && c.ai.draft_text) || "")}</textarea>

        <div class="hr"></div>
        <h3>2) Letter of Medical Necessity (LMN)</h3>
        <textarea name="lmn_text">${safeStr((c.appeal_packet && c.appeal_packet.lmn_text) || "")}</textarea>

        <div class="hr"></div>
        <h3>3) Admin + Coding Summary (No PHI)</h3>
        <div class="row">
          <div class="col">
            <label>Claim #</label>
            <input name="claim_number" value="${safeStr(c.appeal_packet?.claim_number || "")}" placeholder="Claim number (no patient identifiers)" />
            <label>Payer</label>
            <input name="payer" value="${safeStr(c.appeal_packet?.payer || "")}" placeholder="Payer name" />
            <label>Date of Service (DOS)</label>
            <input name="dos" value="${safeStr(c.appeal_packet?.dos || "")}" placeholder="YYYY-MM-DD or payer format" />
            <label>Authorization #</label>
            <input name="authorization_number" value="${safeStr(c.appeal_packet?.authorization_number || "")}" placeholder="Authorization number (if applicable)" />
          </div>
          <div class="col">
            <label>CPT/HCPCS codes</label>
            <input name="cpt_hcpcs_codes" value="${safeStr(c.appeal_packet?.cpt_hcpcs_codes || "")}" placeholder="e.g., 99214, 27447" />
            <label>ICD‑10 codes</label>
            <input name="icd10_codes" value="${safeStr(c.appeal_packet?.icd10_codes || "")}" placeholder="e.g., M17.11" />
            <label>Provider NPI</label>
            <input name="provider_npi" value="${safeStr(c.appeal_packet?.provider_npi || "")}" placeholder="NPI" />
            <label>Provider Tax ID</label>
            <input name="provider_tax_id" value="${safeStr(c.appeal_packet?.provider_tax_id || "")}" placeholder="Tax ID" />
            <label>Provider Address</label>
            <input name="provider_address" value="${safeStr(c.appeal_packet?.provider_address || "")}" placeholder="Practice address" />
          </div>
        </div>

        <div class="hr"></div>
        <h3>4) Interaction Log (No PHI)</h3>
        <textarea name="contact_log" style="min-height:140px;">${safeStr(c.appeal_packet?.contact_log || "")}</textarea>

        <div class="hr"></div>
        <h3>5) Checklist (editable)</h3>
        <textarea name="checklist_notes" style="min-height:180px;">${safeStr(c.appeal_packet?.checklist_notes || "")}</textarea>

        <div class="btnRow">
          <button class="btn" type="submit">Save Packet Inputs</button>
          <a class="btn secondary" href="/status?case_id=${encodeURIComponent(case_id)}">Back to Status</a>
          <a class="btn secondary" href="/dashboard">Dashboard</a>
        </div>
      </form>

      <div class="hr"></div>
      <h3>6) Attachments (De‑Identified Only · Auto‑Delete in 60 minutes)</h3>
      <p class="muted small">Upload de‑identified documents only. Files are stored temporarily and automatically deleted.</p>
      <form method="POST" action="/appeal/upload" enctype="multipart/form-data">
        <input type="hidden" name="case_id" value="${safeStr(case_id)}"/>
        <label>Upload attachments (multiple)</label>
        <input type="file" name="appeal_docs" multiple />
        <div class="btnRow">
          <button class="btn secondary" type="submit">Upload Attachments</button>
        </div>
      </form>

      <div class="hr"></div>
      <h3>Current Attachments</h3>
      ${
        (c.appeal_attachments && c.appeal_attachments.length)
          ? `<ul class="muted small">${
              c.appeal_attachments.map(a => {
                const exp = a.expires_at ? new Date(a.expires_at).toLocaleString() : "—";
                return `<li>${safeStr(a.filename)} <span class="muted">(expires: ${safeStr(exp)})</span></li>`;
              }).join("")
            }</ul>`
          : `<p class="muted small">No attachments uploaded.</p>`
      }

      <div class="hr"></div>
      <h3>7) Compile + Export</h3>
      <form method="POST" action="/appeal/compile">
        <input type="hidden" name="case_id" value="${safeStr(case_id)}"/>
        <div class="btnRow">
          <button class="btn" type="submit">Generate Full Appeal Packet</button>
          <a class="btn secondary" href="/appeal/export?case_id=${encodeURIComponent(case_id)}&fmt=txt">Download TXT</a>
          <a class="btn secondary" href="/appeal/export?case_id=${encodeURIComponent(case_id)}&fmt=doc">Download Word</a>
          <a class="btn secondary" href="/appeal/export?case_id=${encodeURIComponent(case_id)}&fmt=pdf">Open Printable (Save as PDF)</a>
        </div>
      </form>
`, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
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
    normalizeAppealPacket(c, org.org_name);
    // If LMN empty, seed template
    if (!c.appeal_packet.lmn_text) c.appeal_packet.lmn_text = appealPacketDefaults(org.org_name).lmn_text;
    c.ai.draft_text = draft;
    writeJSON(FILES.cases, cases);
    return redirect(res, `/draft?case_id=${encodeURIComponent(case_id)}`);
  }

// Apply/revert templates from within the draft review page
if (method === "POST" && pathname === "/draft-template") {
  const contentType = req.headers["content-type"] || "";
  if (!contentType.includes("multipart/form-data")) return redirect(res, "/dashboard");
  const boundaryMatch = /boundary=([^;]+)/.exec(contentType);
  if (!boundaryMatch) return redirect(res, "/dashboard");
  const boundary = boundaryMatch[1];

  const { files, fields } = await parseMultipart(req, boundary);

  const case_id = (fields.case_id || "").trim();
  if (!case_id) return redirect(res, "/dashboard");

  const cases = readJSON(FILES.cases, []);
  const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
  if (!c) return redirect(res, "/dashboard");

  let selectedTemplateId = (fields.template_id || "").trim();

  // Upload new template (optional)
  const templateUpload = files.find(f => f.fieldName === "templateFile");
  if (templateUpload && templateUpload.filename) {
    const safeName = (templateUpload.filename || "template").replace(/[^a-zA-Z0-9._-]/g, "_");
    const newId = uuid();
    const storedPath = path.join(TEMPLATES_DIR, `${newId}_${safeName}`);
    fs.writeFileSync(storedPath, templateUpload.buffer);

    const templates = readJSON(FILES.templates, []);
    templates.push({
      template_id: newId,
      org_id: org.org_id,
      filename: safeName,
      stored_path: storedPath,
      uploaded_at: nowISO()
    });
    writeJSON(FILES.templates, templates);

    selectedTemplateId = newId;
  }

  if (selectedTemplateId) {
    const templates = readJSON(FILES.templates, []);
    const tpl = templates.find(t => t.template_id === selectedTemplateId && t.org_id === org.org_id);
    if (tpl && tpl.stored_path && fs.existsSync(tpl.stored_path)) {
      c.ai.draft_text = fs.readFileSync(tpl.stored_path, "utf8");
      c.template_id = selectedTemplateId;
    }
  } else {
    // revert to AI draft
    const out = aiGenerate(org.org_name);
    c.ai.draft_text = out.draft_text;
    c.template_id = "";
  }

  writeJSON(FILES.cases, cases);
  return redirect(res, `/draft?case_id=${encodeURIComponent(case_id)}`);
}



  // ===== Appeal Packet Builder Routes (De‑Identified / Non‑PHI) =====
  if (method === "POST" && pathname === "/appeal/save") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const case_id = (params.get("case_id") || "").trim();
    const cases = readJSON(FILES.cases, []);
    const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
    if (!c) return redirect(res, "/dashboard");
    normalizeAppealPacket(c, org.org_name);
    // If LMN empty, seed template
    if (!c.appeal_packet.lmn_text) c.appeal_packet.lmn_text = appealPacketDefaults(org.org_name).lmn_text;

    normalizeAppealPacket(c, org.org_name);

    // Save non‑PHI fields
    c.appeal_packet.deid_confirmed = params.get("deid_confirmed") === "1";
    c.appeal_packet.claim_number = (params.get("claim_number") || "").trim();
    c.appeal_packet.payer = (params.get("payer") || "").trim();
    c.appeal_packet.dos = (params.get("dos") || "").trim();
    c.appeal_packet.cpt_hcpcs_codes = (params.get("cpt_hcpcs_codes") || "").trim();
    c.appeal_packet.icd10_codes = (params.get("icd10_codes") || "").trim();
    c.appeal_packet.authorization_number = (params.get("authorization_number") || "").trim();
    c.appeal_packet.provider_npi = (params.get("provider_npi") || "").trim();
    c.appeal_packet.provider_tax_id = (params.get("provider_tax_id") || "").trim();
    c.appeal_packet.provider_address = (params.get("provider_address") || "").trim();
    c.appeal_packet.contact_log = (params.get("contact_log") || "").trim();
    c.appeal_packet.checklist_notes = (params.get("checklist_notes") || "").trim();

    // Save AI texts (editable)
    const draft_text = params.get("draft_text") || "";
    const lmn_text = params.get("lmn_text") || "";
    if (!c.ai) c.ai = {};
    c.ai.draft_text = draft_text;
    c.appeal_packet.lmn_text = lmn_text;

    writeJSON(FILES.cases, cases);
    auditLog({ actor:"user", action:"appeal_save", org_id: org.org_id, case_id });
    return redirect(res, `/draft?case_id=${encodeURIComponent(case_id)}`);
  }

  if (method === "POST" && pathname === "/appeal/upload") {
    const contentType = req.headers["content-type"] || "";
    if (!contentType.includes("multipart/form-data")) return redirect(res, "/dashboard");
    const boundaryMatch = /boundary=([^;]+)/.exec(contentType);
    if (!boundaryMatch) return redirect(res, "/dashboard");
    const boundary = boundaryMatch[1];

    const { files, fields } = await parseMultipart(req, boundary);
    const case_id = (fields.case_id || "").trim();
    if (!case_id) return redirect(res, "/dashboard");

    const cases = readJSON(FILES.cases, []);
    const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
    if (!c) return redirect(res, "/dashboard");
    normalizeAppealPacket(c, org.org_name);
    // If LMN empty, seed template
    if (!c.appeal_packet.lmn_text) c.appeal_packet.lmn_text = appealPacketDefaults(org.org_name).lmn_text;

    normalizeAppealPacket(c, org.org_name);

    const uploadFiles = files.filter(f => f.fieldName === "appeal_docs");
    if (!uploadFiles.length) return redirect(res, `/draft?case_id=${encodeURIComponent(case_id)}`);

    const caseDir = path.join(UPLOADS_DIR, org.org_id, case_id, "appeal_docs");
    ensureDir(caseDir);

    for (const f of uploadFiles) {
      const safeName = (f.filename || "attachment").replace(/[^a-zA-Z0-9._-]/g, "_");
      const file_id = uuid();
      const stored_path = path.join(caseDir, `${file_id}_${safeName}`);
      fs.writeFileSync(stored_path, f.buffer);

      c.appeal_attachments.push({
        file_id,
        filename: safeName,
        stored_path,
        uploaded_at: nowISO(),
        expires_at: new Date(Date.now() + APPEAL_ATTACHMENT_TTL_MS).toISOString()
      });
    }

    writeJSON(FILES.cases, cases);
    auditLog({ actor:"user", action:"appeal_upload", org_id: org.org_id, case_id, count: uploadFiles.length });
    return redirect(res, `/draft?case_id=${encodeURIComponent(case_id)}`);
  }

  if (method === "POST" && pathname === "/appeal/compile") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const case_id = (params.get("case_id") || "").trim();

    const cases = readJSON(FILES.cases, []);
    const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
    if (!c) return redirect(res, "/dashboard");
    normalizeAppealPacket(c, org.org_name);
    // If LMN empty, seed template
    if (!c.appeal_packet.lmn_text) c.appeal_packet.lmn_text = appealPacketDefaults(org.org_name).lmn_text;

    normalizeAppealPacket(c, org.org_name);

    if (!c.appeal_packet.deid_confirmed) {
      const html = renderPage("Appeal Packet", `
        <h2>De‑Identified Confirmation Required</h2>
        <p class="error">Please confirm this case is de‑identified before compiling the packet.</p>
        <div class="btnRow"><a class="btn" href="/draft?case_id=${encodeURIComponent(case_id)}">Back</a></div>
      `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
      return send(res, 400, html);
    }

    compileAppealPacketText(c, org.org_name);
    writeJSON(FILES.cases, cases);

    auditLog({ actor:"user", action:"appeal_compile", org_id: org.org_id, case_id });
    return redirect(res, `/draft?case_id=${encodeURIComponent(case_id)}`);
  }

  if (method === "GET" && pathname === "/appeal/export") {
    const case_id = (parsed.query.case_id || "").trim();
    const fmt = (parsed.query.fmt || "txt").toLowerCase();

    const cases = readJSON(FILES.cases, []);
    const c = cases.find(x => x.case_id === case_id && x.org_id === org.org_id);
    if (!c) return redirect(res, "/dashboard");
    normalizeAppealPacket(c, org.org_name);
    // If LMN empty, seed template
    if (!c.appeal_packet.lmn_text) c.appeal_packet.lmn_text = appealPacketDefaults(org.org_name).lmn_text;

    normalizeAppealPacket(c, org.org_name);
    const text = (c.appeal_packet && c.appeal_packet.compiled_packet_text) ? c.appeal_packet.compiled_packet_text : "";
    const packet = text || "(Packet not compiled yet. Click 'Generate Full Appeal Packet' first.)";

    if (fmt === "doc") {
      // Serve a simple Word-compatible HTML document
      const htmlDoc = `<!doctype html><html><head><meta charset="utf-8"/><title>Appeal Packet</title></head>
        <body><pre style="white-space:pre-wrap;font-family:Arial, sans-serif;">${safeStr(packet)}</pre></body></html>`;
      res.writeHead(200, {
        "Content-Type": "application/msword",
        "Content-Disposition": `attachment; filename=appeal_packet_${case_id}.doc`
      });
      return res.end(htmlDoc);
    }

    if (fmt === "pdf") {
      // Printable HTML (user can Save as PDF in browser)
      const htmlPrint = renderPage("Appeal Packet (Printable)", `
        <h2>Appeal Packet (Printable)</h2>
        <p class="muted">Use your browser to Print → Save as PDF.</p>
        <div class="btnRow"><button class="btn secondary" onclick="window.print()">Print / Save as PDF</button></div>
        <div class="hr"></div>
        <pre style="white-space:pre-wrap;">${safeStr(packet)}</pre>
      `, navUser(), {showChat:false});
      return send(res, 200, htmlPrint);
    }

    // default txt
    res.writeHead(200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": `attachment; filename=appeal_packet_${case_id}.txt`
    });
    return res.end(packet);
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

      // Auto-match: mark billed claim as Paid when claim number matches this case_id
      try {
        const billedAll = readJSON(FILES.billed, []);
        const claimNo = String(c.case_id || "").trim();
        const b = billedAll.find(x => x.org_id === org.org_id && String(x.claim_number || "").trim() === claimNo);
        if (b && (b.status || "Pending") !== "Paid") {
          b.status = "Paid";
          b.paid_amount = paid_amount || b.paid_amount || null;
          b.paid_at = paid_at || b.paid_at || nowISO();
          writeJSON(FILES.billed, billedAll);
        }
      } catch {}
}

    auditLog({ actor: "user", action: "mark_paid", case_id, org_id: org.org_id, paid_at, paid_amount });
  }
  return redirect(res, "/dashboard");
}

  // -------- PAYMENT DETAILS LIST (moved into Reports) --------
  if (method === "GET" && pathname === "/payments/list") {
    return redirect(res, "/report?type=payment_detail");
  }

  // (legacy payment details page retained but disabled)
  if (false && method === "GET" && pathname === "/payments/list") {
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
    const html = renderPage("Payment Details", `
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
      <h3>Payments (${paymentsFiltered.length} rows${payments.length > 500 ? ', showing first 500' : ''})</h3>
      ${detailTable}
      <div class="hr"></div>
      <div class="btnRow"><a class="btn secondary" href="/dashboard">Back to Dashboard</a></div>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
    return send(res, 200, html);
  }

  // -------- PAYMENT TRACKING (CSV/XLS allowed; CSV parsed) --------
  if (method === "GET" && pathname === "/payments") {
    return redirect(res, "/upload-payments");
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
    const isPDF = nameLower.endsWith(".pdf");
    const isDOC = nameLower.endsWith(".doc") || nameLower.endsWith(".docx");

    if (!isCSV && !isXLS && !isPDF && !isDOC) {
      const html = renderPage("Revenue Management", `
        <h2>Revenue Management</h2>
        <p class="error">Allowed file types: CSV, Excel (.xls/.xlsx), PDF, Word (.doc/.docx).</p>
        <div class="btnRow"><a class="btn secondary" href="/payments">Back</a></div>
      `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
      return send(res, 400, html);
    }

    // file size cap (use same as plan)
    const limits = getLimitProfile(org.org_id);
    const maxBytes = limits.max_file_size_mb * 1024 * 1024;
    if (f.buffer.length > maxBytes) {
      const html = renderPage("Revenue Management", `
        <h2>Revenue Management</h2>
        <p class="error">File too large. Max size is ${limits.max_file_size_mb} MB.</p>
        <div class="btnRow"><a class="btn secondary" href="/payments">Back</a></div>
      `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
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

      const addedPayments = [];

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
        addedPayments.push(paymentsData[paymentsData.length-1]);
      }
      writeJSON(FILES.payments, paymentsData);

// ======= SMART CLAIM RECONCILIATION (Paid / Underpaid / Pending) =======

let billedAll_sync = readJSON(FILES.billed, []);
let subsAll_sync = readJSON(FILES.billed_submissions, []);

function normalizeClaimNum(x) { return String(x || "").replace(/[^0-9]/g, ""); }

let changed_sync = false;

for (const ap of addedPayments) {

  const normalizedClaim = normalizeClaimNum(ap.claim_number);
  if (!normalizedClaim) continue;

  const billedClaim = billedAll_sync.find(b =>
    b.org_id === org.org_id &&
    normalizeClaimNum(b.claim_number) === normalizedClaim
  );

  if (!billedClaim) continue;

  const paid = num(ap.amount_paid);
  billedClaim.paid_amount = paid;
  billedClaim.paid_at = (ap.date_paid || "").trim() || nowISO();
  billedClaim.insurance_paid = paid;

  const billedAmt = num(billedClaim.amount_billed);
  const expected = (billedClaim.expected_insurance != null && String(billedClaim.expected_insurance).trim() !== "")
    ? num(billedClaim.expected_insurance)
    : billedAmt;

  if (paid <= 0) {
    billedClaim.status = "Denied";
    billedClaim.suggested_action = "";
    billedClaim.underpaid_amount = null;
  } else if (paid + 0.01 >= expected) {
    billedClaim.status = "Paid";
    billedClaim.suggested_action = "";
    billedClaim.underpaid_amount = 0;
  } else {
    billedClaim.status = "Underpaid";
    billedClaim.underpaid_amount = Math.max(0, num(billedClaim.amount_billed) - paid - num(billedClaim.patient_collected));

    const gap = Math.max(0, num(billedClaim.amount_billed) - paid - num(billedClaim.patient_collected));
    const diffPct = num(billedClaim.amount_billed) > 0 ? (gap / num(billedClaim.amount_billed)) * 100 : 100;
    if (diffPct <= 5) billedClaim.suggested_action = "Contractual";
    else if (diffPct <= 20) billedClaim.suggested_action = "Patient Balance";
    else billedClaim.suggested_action = "Appeal";
  }

  changed_sync = true;
}

if (changed_sync) {

  writeJSON(FILES.billed, billedAll_sync);

  subsAll_sync.forEach(s => {

    if (s.org_id !== org.org_id) return;

    const claims = billedAll_sync.filter(b => b.submission_id === s.submission_id);

    s.paid = claims.filter(c => (c.status || "Pending") === "Paid").length;
    s.denied = claims.filter(c => (c.status || "Pending") === "Denied").length;
    s.pending = claims.filter(c => (c.status || "Pending") === "Pending").length;

    s.underpaid = claims.filter(c => (c.status || "Pending") === "Underpaid").length;
    s.contractual = claims.filter(c => (c.status || "Pending") === "Contractual").length;
    s.appeal = claims.filter(c => (c.status || "Pending") === "Appeal").length;
    s.patient_balance = claims.filter(c => (c.status || "Pending") === "Patient Balance").length;

    s.revenue_collected = claims
      .filter(c => (c.status || "Pending") === "Paid")
      .reduce((sum, c) => sum + num(c.paid_amount), 0);

    // Revenue at risk counts: Pending + Denied + Underpaid + Appeal (NOT Contractual, NOT Patient Balance)
    s.revenue_at_risk = claims
      .filter(c => ["Pending","Denied","Underpaid","Appeal"].includes((c.status || "Pending")))
      .reduce((sum, c) => {
        const billedAmt = num(c.amount_billed);
        const paidAmt = num(c.paid_amount);
        const exp = (c.expected_insurance != null && String(c.expected_insurance).trim() !== "") ? num(c.expected_insurance) : billedAmt;

        if ((c.status || "Pending") === "Underpaid" || (c.status || "Pending") === "Appeal") {
          return sum + Math.max(0, exp - paidAmt);
        }
        return sum + Math.max(0, billedAmt - paidAmt);
      }, 0);

  });

  writeJSON(FILES.billed_submissions, subsAll_sync);
}

rowsAdded = toUse;
      consumePaymentRows(org.org_id, rowsAdded);
    } else {
      // Excel stored but not parsed in v1 (still counts as 0 rows until CSV provided)
      rowsAdded = 0;
    }

    const html = renderPage("Revenue Management", `
      <h2>Payment File Received</h2>
      <p class="muted">Your file was uploaded successfully.</p>
      <ul class="muted">
        <li><strong>File:</strong> ${safeStr(f.filename)}</li>
        <li><strong>Rows processed:</strong> ${isCSV ? rowsAdded : "File stored (not parsed — upload CSV for analytics extraction)"}</li>
      </ul>
      <div class="btnRow">
        <a class="btn" href="/payment-batch-detail?file=${encodeURIComponent(path.basename(stored))}">View Payment Batch</a>
        <a class="btn secondary" href="/upload-payments">Upload more</a>
      </div>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
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

    const planName = (sub && sub.status === "active") ? "Monthly" : (pilot && pilot.status === "active" ? "Free Trial" : "Expired");
    const planEnds = (sub && sub.status === "active") ? "—" : (pilot?.ends_at ? new Date(pilot.ends_at).toLocaleDateString() : "—");

    const html = renderPage("Account", `
      <h2>Account</h2>
      <p class="muted"><strong>Email:</strong> ${safeStr(user.email || "")}</p>
      <p class="muted"><strong>Organization:</strong> ${safeStr(org.org_name)}</p>
      <form method="POST" action="/account/org-name" style="margin-top:8px;">
        <label>Update Organization Name</label>
        <input name="org_name" value="${safeStr(org.org_name)}" required />
        <div class="btnRow">
          <button class="btn secondary" type="submit">Save Organization Name</button>
        </div>
      </form>

      <div class="hr"></div>
      <h3>Plan</h3>
      <table>
        <tr><th>Current Plan</th><td>${safeStr(planName)}</td></tr>
        <tr><th>Trial Ends</th><td>${safeStr(planEnds)}</td></tr>
        <tr><th>Access Mode</th><td>${safeStr(limits.mode==="pilot" ? "trial" : limits.mode)}</td></tr>
        <tr><th>AI Questions Used</th><td>${safeStr(String(getUsage(org.org_id).ai_chat_used || 0))}</td></tr>
        <tr><th>AI Questions Limit</th><td>${safeStr(String(getAIChatLimit(org.org_id)))}</td></tr>
        <tr><th>AI Questions Remaining</th><td>${safeStr(String(Math.max(0, getAIChatLimit(org.org_id) - (getUsage(org.org_id).ai_chat_used || 0))))}</td></tr>
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
        <a class="btn secondary" href="${safeStr(process.env.SHOPIFY_UPGRADE_URL || "https://tjhealthpro.com")}">Upgrade / Manage Plan</a>
      </div>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
    return send(res, 200, html);
  }

  
  // Update organization name
  if (method === "POST" && pathname === "/account/org-name") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const newName = (params.get("org_name") || "").trim();
    if (!newName) return redirect(res, "/account");

    const orgs = readJSON(FILES.orgs, []);
    const oidx = orgs.findIndex(o => o.org_id === org.org_id);
    if (oidx >= 0) {
      orgs[oidx].org_name = newName;
      orgs[oidx].updated_at = nowISO();
      writeJSON(FILES.orgs, orgs);
      auditLog({ actor:"user", action:"update_org_name", org_id: org.org_id, user_id: user.user_id });
    }
    return redirect(res, "/account");
  }

if (method === "POST" && pathname === "/account/password") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const current = params.get("current_password") || "";
    const p1 = params.get("new_password") || "";
    const p2 = params.get("new_password2") || "";

    if (p1.length < 8 || p1 !== p2) {
      const html = renderPage("Account", `
        <h2>Account</h2>
        <p class="error">New passwords must match and be at least 8 characters.</p>
        <div class="btnRow"><a class="btn secondary" href="/account">Back</a></div>
      `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
      return send(res, 400, html);
    }

    const users = readJSON(FILES.users, []);
    const uidx = users.findIndex(u => u.user_id === user.user_id);
    if (uidx < 0) return redirect(res, "/logout");

    if (!bcrypt.compareSync(current, users[uidx].password_hash)) {
      const html = renderPage("Account", `
        <h2>Account</h2>
        <p class="error">Current password is incorrect.</p>
        <div class="btnRow"><a class="btn secondary" href="/account">Back</a></div>
      `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
      return send(res, 401, html);
    }

    users[uidx].password_hash = bcrypt.hashSync(p1, 10);
    writeJSON(FILES.users, users);
    auditLog({ actor:"user", action:"change_password", org_id: org.org_id, user_id: user.user_id });

    const html = renderPage("Account", `
      <h2>Account</h2>
      <p class="muted">Password updated successfully.</p>
      <div class="btnRow"><a class="btn" href="/dashboard">Back to Dashboard</a></div>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
    return send(res, 200, html);
  }


 
  // Report export (CSV) — used by Payment Detail Report
  if (method === "GET" && pathname === "/report/export") {
    const start = parsed.query.start || "";
    const end = parsed.query.end || "";
    const type = (parsed.query.type || "").trim();
    const payerFilter = (parsed.query.payer || "").trim();
    const deniedFilter = (parsed.query.denied || "").trim();

    if (!start || !end || type !== "payment_detail") return redirect(res, "/report");

    const startDate = new Date(start);
    const endDate = new Date(end);
    endDate.setHours(23,59,59,999);

    let payments = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id);
    payments = payments.filter(p => {
      const d = new Date(p.date_paid || p.created_at);
      return d >= startDate && d <= endDate;
    });
    if (payerFilter) payments = payments.filter(p => String((p.payer || "Unknown").trim() || "Unknown") === payerFilter);
    if (deniedFilter === "1") payments = payments.filter(p => p.denied_approved);

    const header = ["claim_number","payer","amount_paid","date_paid","denied_approved","source_file","created_at"].join(",");
    const rows = payments.map(p => [
      p.claim_number || "",
      (p.payer || "").trim(),
      p.amount_paid || "",
      p.date_paid || "",
      p.denied_approved ? "Yes" : "",
      p.source_file || "",
      p.created_at || ""
    ].map(x => `"${String(x).replace(/"/g,'""')}"`).join(","));

    const csv = [header, ...rows].join("\n");
    res.writeHead(200, { "Content-Type":"text/csv", "Content-Disposition":"attachment; filename=payment_detail_report.csv" });
    return res.end(csv);
  }

// exports hub
  if (method === "GET" && pathname === "/exports") {
    const html = renderPage("Exports", `
      <h2>Exports</h2>
      <p class="muted">Download exports for leadership and operations review.</p>
      <div class="btnRow">
        <a class="btn secondary" href="/export/cases.csv">Cases CSV</a>
        <a class="btn secondary" href="/export/payments.csv">Payments CSV</a>
        <a class="btn secondary" href="/export/analytics.csv">Analytics CSV</a>
        <a class="btn secondary" href="/report">Printable Summary</a>
      </div>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
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
    const start = parsed.query.start || "";
    const end = parsed.query.end || "";
    const type = (parsed.query.type || "").trim() || "executive";
    const payerFilter = (parsed.query.payer || "").trim();
    const deniedFilter = (parsed.query.denied || "").trim();

    // If no date range chosen yet, show generator form
    if (!start || !end) {
      const html = renderPage("Reports", `
        <h2>Generate Report</h2>
        <p class="muted">Choose a date range and report type. Reports are based only on data uploaded into the app.</p>

        <form method="GET" action="/report">
          <label>Start Date</label>
          <input type="date" name="start" required />

          <label>End Date</label>
          <input type="date" name="end" required />

          <label>Report Type</label>
          <select name="type">
            <option value="executive">Executive Summary</option>
            <option value="denials">Denial Summary</option>
            <option value="payments">Payment Summary</option>
            <option value="recovery">Recovery Analysis</option>
            <option value="payers">Payer Breakdown</option>
            <option value="payment_detail">Payment Detail Report</option>
            <option value="kpi_payment_speed">Average Days to Payment</option>
            <option value="kpi_denial_turnaround">Denial Turnaround Time</option>
            <option value="kpi_resolution_time">Time to Resolution</option>
            <option value="kpi_denial_aging">Denial Aging (From Denial Date)</option>
          </select>

          <label>Optional Payer Filter</label>
          <input name="payer" placeholder="Exact payer name (optional)" />

          <label>Denied Recovery Only</label>
          <select name="denied">
            <option value="">All</option>
            <option value="1">Denied → Approved Only</option>
          </select>

          <div class="btnRow">
            <button class="btn" type="submit">Generate</button>
            <a class="btn secondary" href="/dashboard">Back</a>
          </div>
        </form>
      `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
      return send(res, 200, html);
    }

    const startDate = new Date(start);
    const endDate = new Date(end);
    endDate.setHours(23,59,59,999);

    const casesAll = readJSON(FILES.cases, []).filter(c => c.org_id === org.org_id);
    const payAll = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id);

    const cases = casesAll.filter(c => {
      const d = new Date(c.created_at);
      return d >= startDate && d <= endDate;
    });

    const payments = payAll.filter(p => {
      const d = new Date(p.date_paid || p.created_at);
      return d >= startDate && d <= endDate;
    });
    // Apply optional report filters (payer / denied-only)
    let paymentsFiltered = payments.slice();
    if (payerFilter) {
      paymentsFiltered = paymentsFiltered.filter(p => String((p.payer || "Unknown").trim() || "Unknown") === payerFilter);
    }
    if (deniedFilter === "1") {
      paymentsFiltered = paymentsFiltered.filter(p => p.denied_approved);
    }


    const deniedRecovered = paymentsFiltered.filter(p => p.denied_approved);
    const recoveredDollars = deniedRecovered.reduce((s,p)=>s + Number(p.amount_paid || 0), 0);

    const paidCases = cases.filter(c => c.paid).length;
    const recoveryRate = cases.length ? ((paidCases / cases.length) * 100).toFixed(1) : "0.0";

    const payByPayer = {};
    paymentsFiltered.forEach(p => {
      const payer = (p.payer || "Unknown").trim() || "Unknown";
      if (!payByPayer[payer]) payByPayer[payer] = { total: 0, count: 0, deniedWins: 0 };
      payByPayer[payer].total += Number(p.amount_paid || 0);
      payByPayer[payer].count += 1;
      if (p.denied_approved) payByPayer[payer].deniedWins += 1;
    });

    const topPayers = Object.entries(payByPayer)
      .sort((a,b)=>b[1].total - a[1].total)
      .slice(0, 8)
      .map(([payer, info]) => ({ payer, ...info }));

    let body = `<h2>Report</h2>
      <p class="muted"><strong>Organization:</strong> ${safeStr(org.org_name)}</p>
      <p class="muted"><strong>Date range:</strong> ${safeStr(start)} to ${safeStr(end)}</p>
      <div class="hr"></div>`;

    if (type === "executive") {
      body += `
        <h3>Executive Summary <span class="tooltip">ⓘ<span class="tooltiptext">High-level summary for the selected date range.</span></span></h3>
        <ul class="muted">
          <li><strong>Denied cases in range:</strong> ${cases.length}</li>
          <li><strong>Payments logged in range:</strong> ${paymentsFiltered.length}</li>
          <li><strong>Denied → Approved wins:</strong> ${deniedRecovered.length}</li>
          <li><strong>Recovered dollars (denials):</strong> $${Number(recoveredDollars).toFixed(2)}</li>
          <li><strong>Recovery rate (cases paid):</strong> ${recoveryRate}%</li>
        </ul>
      `;
    } else if (type === "denials") {
      const cats = {};
      cases.forEach(c => {
        const cat = (c.ai && c.ai.denial_reason_category) ? c.ai.denial_reason_category : "Unknown";
        cats[cat] = (cats[cat] || 0) + 1;
      });
      body += `
        <h3>Denial Summary</h3>
        <ul class="muted">
          <li><strong>Total denial cases:</strong> ${cases.length}</li>
          <li><strong>Drafts generated:</strong> ${cases.filter(c => c.status === "DRAFT_READY" || (c.ai && c.ai.draft_text)).length}</li>
          <li><strong>Paid (marked):</strong> ${paidCases}</li>
        </ul>
        <div class="hr"></div>
        <h3>Denial Categories</h3>
        ${
          Object.keys(cats).length
            ? `<table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>${
                Object.entries(cats).sort((a,b)=>b[1]-a[1]).map(([k,v]) => `<tr><td>${safeStr(k)}</td><td>${v}</td></tr>`).join("")
              }</tbody></table>`
            : `<p class="muted">No denial category data available in this date range.</p>`
        }
      `;
    } else if (type === "payments") {
      body += `
        <h3>Payment Summary</h3>
        <ul class="muted">
          <li><strong>Total payments:</strong> ${paymentsFiltered.length}</li>
          <li><strong>Total dollars paid:</strong> $${Number(payments.reduce((s,p)=>s+Number(p.amount_paid||0),0)).toFixed(2)}</li>
          <li><strong>Denied → Approved dollars:</strong> $${Number(recoveredDollars).toFixed(2)}</li>
        </ul>
      `;
    } else if (type === "recovery") {
      body += `
        <h3>Recovery Analysis</h3>
        <ul class="muted">
          <li><strong>Denied cases:</strong> ${cases.length}</li>
          <li><strong>Paid (marked):</strong> ${paidCases}</li>
          <li><strong>Recovery rate:</strong> ${recoveryRate}%</li>
          <li><strong>Denied → Approved wins (payments):</strong> ${deniedRecovered.length}</li>
          <li><strong>Denied → Approved dollars:</strong> $${Number(recoveredDollars).toFixed(2)}</li>
        </ul>
      `;
    } else if (type === "payment_detail") {
      body += `
        <h3>Payment Detail Report</h3>
        <p class="muted">Showing payments in date range${payerFilter ? ` for payer <strong>${safeStr(payerFilter)}</strong>` : ""}${deniedFilter==="1" ? " (Denied → Approved only)" : ""}.</p>

        <div class="btnRow">
          <a class="btn secondary" href="/report/export?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}&type=payment_detail&payer=${encodeURIComponent(payerFilter||"")}&denied=${encodeURIComponent(deniedFilter||"")}">Export CSV</a>
        </div>

        <div class="hr"></div>
        ${
          paymentsFiltered.length
            ? `<table><thead><tr><th>Claim #</th><th>Payer</th><th>Amount</th><th>Date</th><th>Denied?</th></tr></thead><tbody>${
                paymentsFiltered.slice(0, 500).map(p => {
                  const dt = new Date(p.date_paid || p.created_at);
                  return `<tr>
                    <td>${safeStr(p.claim_number || "")}</td>
                    <td>${safeStr((p.payer || "Unknown").trim() || "Unknown")}</td>
                    <td>$${Number(p.amount_paid || 0).toFixed(2)}</td>
                    <td>${dt.toLocaleDateString()}</td>
                    <td>${p.denied_approved ? "Yes" : ""}</td>
                  </tr>`;
                }).join("")
              }</tbody></table>`
            : `<p class="muted">No payments found for this filter.</p>`
        }
        <p class="muted small">${paymentsFiltered.length > 500 ? "Showing first 500 rows." : ""}</p>
      `;
    }

   
    else if (type === "kpi_payment_speed") {
      const a2 = computeAnalytics(org.org_id);
      body += `
        <h3>Average Days to Payment <span class="tooltip">ⓘ<span class="tooltiptext">Average days from denial date (or billed date) to payment date for paid billed claims.</span></span></h3>
        <div class="kpi-card"><h4>Avg Days to Payment <span class="tooltip">ⓘ<span class="tooltiptext">Lower is better. Indicates faster revenue recovery.</span></span></h4><p>${a2.avgDaysToPayment !== null ? a2.avgDaysToPayment + " days" : "—"}</p></div>
      `;
    }
    else if (type === "kpi_denial_turnaround") {
      const a2 = computeAnalytics(org.org_id);
      body += `
        <h3>Denial Turnaround Time <span class="tooltip">ⓘ<span class="tooltiptext">Average days between denial date and denial case creation (work start).</span></span></h3>
        <div class="kpi-card"><h4>Avg Denial Turnaround <span class="tooltip">ⓘ<span class="tooltiptext">Lower is better. Measures how quickly denials enter the appeal workflow.</span></span></h4><p>${a2.avgDenialTurnaround !== null ? a2.avgDenialTurnaround + " days" : "—"}</p></div>
      `;
    }
    else if (type === "kpi_resolution_time") {
      const a2 = computeAnalytics(org.org_id);
      body += `
        <h3>Time to Resolution <span class="tooltip">ⓘ<span class="tooltiptext">Average days between billed date and payment date for paid billed claims.</span></span></h3>
        <div class="kpi-card"><h4>Avg Time to Resolution <span class="tooltip">ⓘ<span class="tooltiptext">Lower is better. Measures billing-to-cash cycle time.</span></span></h4><p>${a2.avgTimeToResolution !== null ? a2.avgTimeToResolution + " days" : "—"}</p></div>
      `;
    }
    else if (type === "kpi_denial_aging") {
      const a2 = computeAnalytics(org.org_id);
      const ag = a2.agingFromDenial || { over30: 0, over60: 0, over90: 0 };
      body += `
        <h3>Denial Aging (From Denial Date) <span class="tooltip">ⓘ<span class="tooltiptext">Counts of denied/unpaid claims grouped by how long since denial date.</span></span></h3>
        <ul class="muted">
          <li>30+ Days <span class="tooltip">ⓘ<span class="tooltiptext">Denied/unpaid claims older than 30 days since denial date.</span></span>: ${ag.over30}</li>
          <li>60+ Days <span class="tooltip">ⓘ<span class="tooltiptext">Denied/unpaid claims older than 60 days since denial date.</span></span>: ${ag.over60}</li>
          <li>90+ Days <span class="tooltip">ⓘ<span class="tooltiptext">Denied/unpaid claims older than 90 days since denial date.</span></span>: ${ag.over90}</li>
        </ul>
      `;
    }

else if (type === "payers") {
      body += `
        <h3>Payer Breakdown</h3>
        ${
          topPayers.length
            ? `<table><thead><tr><th>Payer</th><th># Payments</th><th>Total Paid</th><th>Denied Wins</th></tr></thead><tbody>${
                topPayers.map(x => `<tr><td><a href="/payer-claims?payer=${encodeURIComponent(x.payer)}">${safeStr(x.payer)}</a></td><td>${x.count}</td><td>$${Number(x.total).toFixed(2)}</td><td>${x.deniedWins}</td></tr>`).join("")
              }</tbody></table>`
            : `<p class="muted">No payer data available in this date range.</p>`
        }
      `;
    }

    body += `
      <div class="hr"></div>
      <div class="btnRow">
        <button class="btn secondary" onclick="window.print()">Print / Save as PDF</button>
        <a class="btn secondary" href="/report">New Report</a>
        <a class="btn secondary" href="/dashboard">Back</a>
      </div>
    `;

    const html = renderPage("Report", body, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
    return send(res, 200, html);
  }

  // pilot complete page
  if (method === "GET" && pathname === "/pilot-complete") {
    const pilotEnd = getPilot(org.org_id) || ensurePilot(org.org_id);
    if (new Date(pilotEnd.ends_at).getTime() < Date.now() && pilotEnd.status !== "complete") markPilotComplete(org.org_id);
    const p2 = getPilot(org.org_id);
    const html = renderPage("Free Trial Complete", `
      <h2>Free Trial Complete</h2>
      <p>Your free trial has ended. Existing work remains available during the retention period.</p>
      <div class="hr"></div>
      <p class="muted">
        To limit unnecessary data retention, documents and analytics from this trial will be securely deleted
        <strong>14 days after the trial end date</strong> unless you continue monthly access.
      </p>
      <ul class="muted">
        <li>Trial end date: ${new Date(p2.ends_at).toLocaleDateString()}</li>
        <li>Scheduled deletion date: ${p2.retention_delete_at ? new Date(p2.retention_delete_at).toLocaleDateString() : "—"}</li>
      </ul>
      <div class="btnRow">
        <a class="btn" href="${safeStr(process.env.SHOPIFY_UPGRADE_URL || "https://tjhealthpro.com")}">Continue Monthly Access (via Shopify)</a>
        <a class="btn secondary" href="/exports">Download Exports</a>
        <a class="btn secondary" href="/logout">Logout</a>
      </div>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
    return send(res, 200, html);
  }

 
  // Delete claim batch route
  if (method === "POST" && pathname === "/delete-batch") {
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      const params = new URLSearchParams(body);
      const submissionId = (params.get("submission_id") || "").trim();
      let billedAll = readJSON(FILES.billed, []);
      let subsAll = readJSON(FILES.billed_submissions, []);
      // Remove claims for this submission
      billedAll = billedAll.filter(b => !(b.org_id === org.org_id && b.submission_id === submissionId));
      subsAll = subsAll.filter(s => !(s.org_id === org.org_id && s.submission_id === submissionId));
      writeJSON(FILES.billed, billedAll);
      writeJSON(FILES.billed_submissions, subsAll);
      return redirect(res, "/billed");
    });
    return;
  }

  // Payer Claims drill-down route
  if (method === "GET" && pathname === "/payer-claims") {
    const payer = (parsed.query.payer || "").trim();
    const from = (parsed.query.from || "").trim();
    const to = (parsed.query.to || "").trim();
    const status = (parsed.query.status || "").trim();
    let claims = readJSON(FILES.billed, []).filter(b => b.org_id === org.org_id);
    if (payer) {
      const lp = payer.toLowerCase();
      claims = claims.filter(b => ((b.payer || "").trim().toLowerCase() === lp));
    }
    if (from) {
      const d = new Date(from);
      claims = claims.filter(b => {
        const dt = new Date(b.date_of_service || b.created_at || b.paid_at || b.denied_at || 0);
        return dt.getTime() >= d.getTime();
      });
    }
    if (to) {
      const d2 = new Date(to);
      claims = claims.filter(b => {
        const dt = new Date(b.date_of_service || b.created_at || b.paid_at || b.denied_at || 0);
        return dt.getTime() <= d2.getTime();
      });
    }
    if (status === "paid") {
      claims = claims.filter(b => (b.status || "").toLowerCase() === "paid");
    } else if (status === "unpaid") {
      claims = claims.filter(b => (b.status || "").toLowerCase() !== "paid");
    } else if (status === "underpaid") {
      claims = claims.filter(b => Number(b.paid_amount || 0) < Number(b.expected_amount || b.amount_billed || 0));
    }
    const rows = claims.slice(0, 500).map(c => {
      const exp = Number(c.amount_billed || 0);
      const paidAmt = Number(c.paid_amount || 0);
      return `<tr>
        <td><a href="/claim-detail?billed_id=${encodeURIComponent(safeStr(c.billed_id||""))}">${safeStr(c.claim_number || "")}</a></td>
        <td>${safeStr(c.patient_name || "")}</td>
        <td>${safeStr(c.dos || c.date_of_service || "")}</td>
        <td>${safeStr(c.status || "Pending")}</td>
        <td>$${exp.toFixed(2)}</td>
        <td>$${paidAmt.toFixed(2)}</td>
        <td><a href="/billed?submission_id=${encodeURIComponent(c.submission_id || "")}">${safeStr(c.submission_id || "View Batch")}</a></td>
      </tr>`;
    }).join("");
    const html = renderPage(`${safeStr(payer)} Claims`, `
      <h2>${safeStr(payer)} Claims</h2>
      <form method="GET" action="/payer-claims">
        <input type="hidden" name="payer" value="${safeStr(payer)}"/>
        <label>From:</label><input type="date" name="from" value="${safeStr(from)}"/>
        <label>To:</label><input type="date" name="to" value="${safeStr(to)}"/>
        <label>Status:</label>
        <select name="status">
          <option value="" ${!status ? "selected" : ""}>All</option>
          <option value="paid" ${status==="paid" ? "selected" : ""}>Paid</option>
          <option value="unpaid" ${status==="unpaid" ? "selected" : ""}>Unpaid</option>
          <option value="underpaid" ${status==="underpaid" ? "selected" : ""}>Underpaid</option>
        </select>
        <button class="btn secondary" type="submit">Filter</button>
      </form>
      <table>
        <thead><tr><th>Claim #</th><th>Patient</th><th>Date of Service</th><th>Status</th><th>Billed</th><th>Paid</th><th>Submission</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="7" class="muted">No claims found.</td></tr>`}</tbody>
      </table>
      <p class="muted small">${claims.length > 500 ? "Showing first 500 results." : ""}</p>
      <div class="btnRow"><a class="btn secondary" href="/dashboard">Back</a></div>
      <br><form method="GET" action="/analyze-payer" style="margin-top:10px;"><input type="hidden" name="payer" value="${safeStr(payer)}"/><button class="btn" type="submit">AI Analyze This Payer</button></form>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
    return send(res, 200, html);
  }

  // AI Analyze Payer route
  if (method === "GET" && pathname === "/analyze-payer") {
    const payer = (parsed.query.payer || "").trim();
    let claims = readJSON(FILES.billed, []).filter(b => b.org_id === org.org_id && ((b.payer || "").trim().toLowerCase() === payer.toLowerCase()));
    const totalExpected = claims.reduce((sum, c) => sum + Number(c.expected_amount || c.amount_billed || 0), 0);
    const totalPaid = claims.reduce((sum, c) => sum + Number(c.paid_amount || 0), 0);
    const underpaidClaims = claims.filter(c => Number(c.paid_amount || 0) < Number(c.expected_amount || c.amount_billed || 0));
    const deniedClaims = claims.filter(c => (c.status || "").toLowerCase() === "denied");
    const appealedClaims = claims.filter(c => c.appealed === true);
    const recoveredClaims = appealedClaims.filter(c => Number(c.paid_amount || 0) > 0);
    const recoveryRate = appealedClaims.length ? (recoveredClaims.length / appealedClaims.length) * 100 : 0;
    const denialRate = claims.length ? (deniedClaims.length / claims.length) * 100 : 0;
    const denialReasons = {};
    deniedClaims.forEach(c => {
      const reason = c.denial_reason || (c.ai && c.ai.denial_reason_category) || "Unknown";
      denialReasons[reason] = (denialReasons[reason] || 0) + 1;
    });
    const topDenials = Object.entries(denialReasons).sort((a,b) => b[1] - a[1]).slice(0,5);
    const cptUnderpaid = {};
    underpaidClaims.forEach(c => {
      const code = c.cpt_code || c.cpt || "Unknown";
      const diff = Number(c.expected_amount || c.amount_billed || 0) - Number(c.paid_amount || 0);
      cptUnderpaid[code] = (cptUnderpaid[code] || 0) + diff;
    });
    const topUnderpaidCPT = Object.entries(cptUnderpaid).sort((a,b) => b[1] - a[1]).slice(0,5);
    const paidClaims = claims.filter(c => c.paid_date || c.paid_at);
    const avgDaysToPay = paidClaims.length ? (paidClaims.reduce((sum, c) => {
      const dos = new Date(c.date_of_service || c.denied_at || c.created_at || 0);
      const pd = new Date(c.paid_date || c.paid_at || 0);
      return sum + ((pd - dos) / (1000 * 60 * 60 * 24));
    }, 0) / paidClaims.length).toFixed(1) : 0;
    let suggestions = [];
    if (denialRate > 15) suggestions.push("High denial rate. Audit front-end eligibility & coding.");
    if (recoveryRate < 50 && appealedClaims.length > 0) suggestions.push("Low appeal recovery rate. Review appeal templates.");
    if (avgDaysToPay > 45) suggestions.push("Slow payment turnaround. Consider follow-up at 30 days.");
    if (underpaidClaims.length > 0) suggestions.push("Underpayments detected. Audit contract reimbursement rates.");
    if (!suggestions.length) suggestions.push("Payer performance within expected range.");
    let grade = "A";
    if (denialRate > 20 || recoveryRate < 40) grade = "D";
    else if (denialRate > 15 || recoveryRate < 50) grade = "C";
    else if (denialRate > 10 || recoveryRate < 60) grade = "B";
    const underpayPercent = totalExpected > 0 ? ((totalExpected - totalPaid) / totalExpected * 100) : 0;
    const html = renderPage(`AI Payer Intelligence: ${safeStr(payer)}`, `
      <h2>AI Payer Intelligence: ${safeStr(payer)}</h2>
      <p><strong>Total Claims:</strong> ${claims.length}</p>
      <p><strong>Denial Rate:</strong> ${denialRate.toFixed(1)}%</p>
      <p><strong>Recovery Rate on Appeals:</strong> ${recoveryRate.toFixed(1)}%</p>
      <p><strong>Average Days to Pay:</strong> ${avgDaysToPay}</p>
      <p><strong>Total Underpaid:</strong> $${(totalExpected - totalPaid).toFixed(2)}</p>
      <style>
        .bar-container{background:#eee;border-radius:6px;margin-bottom:12px;}
        .bar{height:20px;border-radius:6px;color:white;text-align:right;padding-right:5px;font-size:12px;}
        .denial-bar{background:#d9534f;}
        .recovery-bar{background:#5cb85c;}
        .underpay-bar{background:#f0ad4e;}
      </style>
      <h3>Payer Performance Visual</h3>
      <div class="bar-container"><div class="bar denial-bar" style="width:${Math.min(denialRate,100)}%">Denial ${denialRate.toFixed(1)}%</div></div>
      <div class="bar-container"><div class="bar recovery-bar" style="width:${Math.min(recoveryRate,100)}%">Recovery ${recoveryRate.toFixed(1)}%</div></div>
      <div class="bar-container"><div class="bar underpay-bar" style="width:${Math.min(underpayPercent,100)}%">Underpayment %</div></div>
      <h3>Payer Scorecard</h3>
      <p style="font-size:24px;">Grade: <strong>${grade}</strong></p>
      <h3>Top Denial Reasons</h3>
      <ul>
        ${topDenials.map(d => `<li>${safeStr(d[0])} (${d[1]})</li>`).join("")}
      </ul>
      <h3>Most Underpaid CPT Codes</h3>
      <ul>
        ${topUnderpaidCPT.map(c => `<li>${safeStr(c[0])} — $${c[1].toFixed(2)}</li>`).join("")}
      </ul>
      <h3>AI Suggested Actions</h3>
      <ul>
        ${suggestions.map(s => `<li>${safeStr(s)}</li>`).join("")}
      </ul>
      <form method="POST" action="/bulk-appeal" style="margin-top:10px;">
        <input type="hidden" name="payer" value="${safeStr(payer)}"/>
        <button class="btn" type="submit">Send All Underpaid Claims to Appeals</button>
      </form>
      <div class="btnRow" style="margin-top:12px;"><a class="btn secondary" href="/dashboard">Back</a> <a class="btn secondary" href="/payer-claims?payer=${encodeURIComponent(payer)}">Back to Claims</a></div>
    `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});
    return send(res, 200, html);
  }

  // Bulk appeal route
  if (method === "POST" && pathname === "/bulk-appeal") {
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      const params = new URLSearchParams(body);
      const payer = (params.get("payer") || "").trim();
      let billedAll = readJSON(FILES.billed, []);
      billedAll.forEach(c => {
        if (c.org_id === org.org_id && ((c.payer || "").trim().toLowerCase() === payer.toLowerCase()) && Number(c.paid_amount || 0) < Number(c.expected_amount || c.amount_billed || 0)) {
          c.appealed = true;
          c.appeal_date = new Date().toISOString();
        }
      });
      writeJSON(FILES.billed, billedAll);
      return redirect(res, `/analyze-payer?payer=${encodeURIComponent(payer)}`);
    });
    return;
  }


  // --------- CLAIM DETAIL VIEW ----------
 
if (method === "GET" && pathname === "/claim-detail") {

  const billed_id = (parsed.query.billed_id || "").trim();
  const billedAll = readJSON(FILES.billed, []);
  const paymentsAll = readJSON(FILES.payments, []);

  function normalizeClaimNum(x) {
    return String(x || "").replace(/[^0-9]/g, "");
  }

  const b = billedAll.find(x =>
    x.billed_id === billed_id &&
    x.org_id === org.org_id
  );

  if (!b) return redirect(res, "/billed");

  const relatedPayments = paymentsAll.filter(p =>
  p.org_id === org.org_id &&
  normalizeClaimNum(p.claim_number) === normalizeClaimNum(b.claim_number)
);

const negHistory = getNegotiationsByBilled(org.org_id, b.billed_id)
  .map(n => normalizeNegotiation(n))
  .sort((a,b)=> new Date(b.updated_at||b.created_at||0).getTime() - new Date(a.updated_at||a.created_at||0).getTime());

const negHistoryHtml = negHistory.length
  ? `<table>
       <thead><tr><th>Negotiation</th><th>Status</th><th>Requested</th><th>Approved</th><th>Collected</th><th>Updated</th></tr></thead>
       <tbody>${
         negHistory.map(n => `
           <tr>
             <td><a href="/negotiation-detail?negotiation_id=${encodeURIComponent(n.negotiation_id)}">${safeStr(n.negotiation_id)}</a></td>
             <td>${safeStr(n.status)}</td>
             <td>$${Number(n.requested_amount||0).toFixed(2)}</td>
             <td>$${Number(n.approved_amount||0).toFixed(2)}</td>
             <td>$${Number(n.collected_amount||0).toFixed(2)}</td>
             <td>${n.updated_at ? new Date(n.updated_at).toLocaleDateString() : "—"}</td>
           </tr>
         `).join("")
       }</tbody>
     </table>`
  : `<p class="muted">No negotiation cases for this claim yet.</p>`;


  const claimRows = Object.keys(b).sort().map(k => {
    const v = (typeof b[k] === "object") ? JSON.stringify(b[k]) : String(b[k] ?? "");
    return `<tr><th style="width:240px;">${safeStr(k)}</th><td>${safeStr(v)}</td></tr>`;
  }).join("");

  const paymentTable = relatedPayments.length === 0
    ? `<p class="muted">No payment records found for this claim.</p>`
    : `
      <table>
        <thead>
          <tr>
            <th>Date Paid</th><th>Amount</th><th>Payer</th><th>Allowed</th><th>Patient Resp</th><th>Expected Ins</th><th>Underpaid</th><th>Source File</th><th>Notes</th>
          </tr>
        </thead>
        <tbody>
          ${relatedPayments.map(p => `
            <tr>
              <td>${safeStr(p.date_paid || "")}</td>
              <td>$${num(p.amount_paid).toFixed(2)}</td>
              <td>${safeStr(p.payer || "")}</td>
              <td>$${num(b.allowed_amount || 0).toFixed(2)}</td><td>$${num(b.patient_responsibility || 0).toFixed(2)}</td><td>$${num(b.expected_insurance || 0).toFixed(2)}</td><td>$${Math.max(0, num(b.amount_billed||0) - num(b.insurance_paid||b.paid_amount||0) - num(b.patient_collected||0)).toFixed(2)}</td><td class="muted small">${p.source_file ? '<a href="/file?name=' + encodeURIComponent(p.source_file) + '" target="_blank">' + safeStr(p.source_file) + '</a>' : ""}</td><td class="muted small">${safeStr(p.notes || "")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;

  const html = renderPage("Claim Detail", `
    <h2>Claim Detail</h2>
    <div class="hr"></div>
    <table>
      <tbody>${claimRows}</tbody>
    </table>

    <div class="hr"></div>
    <h3>Payment History</h3>
    ${paymentTable}

    <div class="hr"></div>
    <h3>Denial History</h3>
    ${
      b.denial_case_id
        ? `<div class="muted small">Case: <a href="/appeal-detail?case_id=${encodeURIComponent(b.denial_case_id)}">${safeStr(b.denial_case_id)}</a></div>`
        : `<p class="muted">No denial case linked to this claim.</p>`
    }

    <div class="hr"></div>
<h3>Negotiation History</h3>
${negHistoryHtml}

<div class="hr"></div>
<h3>Timeline</h3>
<ul class="muted">
  ${b.created_at ? `<li><strong>Claim created:</strong> ${safeStr(b.created_at)}</li>` : ``}
  ${b.denied_at ? `<li><strong>Denied:</strong> ${safeStr(b.denied_at)}</li>` : ``}
  ${b.paid_at ? `<li><strong>Paid/Posted:</strong> ${safeStr(b.paid_at)}</li>` : ``}
  ${b.denial_case_id ? `<li><strong>Denial case:</strong> <a href="/appeal-detail?case_id=${encodeURIComponent(b.denial_case_id)}">${safeStr(b.denial_case_id)}</a></li>` : ``}
  ${b.negotiation_id ? `<li><strong>Negotiation:</strong> <a href="/negotiation-detail?negotiation_id=${encodeURIComponent(b.negotiation_id)}">${safeStr(b.negotiation_id)}</a></li>` : ``}
</ul>

<div class="hr"></div>
<h3>Actions</h3>
<div class="btnRow">
  <a class="btn secondary" href="/appeal-workspace?billed_id=${encodeURIComponent(b.billed_id)}">Appeal Workspace</a>
  <form method="POST" action="/negotiations/create" style="display:inline;">
    <input type="hidden" name="billed_id" value="${safeStr(b.billed_id)}"/>
    <button class="btn secondary" type="submit">Start Negotiation</button>
  </form>
  <a class="btn secondary" href="/upload-negotiations">Negotiations Queue</a>
</div>

<div class="hr"></div>
<h3>Quick Status Updates</h3>
<div class="row">
  <div class="col">
    <form method="POST" action="/claim/resolve">
      <input type="hidden" name="billed_id" value="${safeStr(b.billed_id)}"/>
      <input type="hidden" name="submission_id" value="${safeStr(b.submission_id || "")}"/>
      <input type="hidden" name="resolution" value="Contractual"/>
      <button class="btn secondary" type="submit">Write Off</button>
    </form>
  </div>
  <div class="col">
    <form method="POST" action="/claim/resolve">
      <input type="hidden" name="billed_id" value="${safeStr(b.billed_id)}"/>
      <input type="hidden" name="submission_id" value="${safeStr(b.submission_id || "")}"/>
      <input type="hidden" name="resolution" value="Patient Balance"/>
      <button class="btn secondary" type="submit">Add Patient Responsibility</button>
    </form>
  </div>
  <div class="col">
    <form method="POST" action="/billed/mark-paid">
      <input type="hidden" name="billed_id" value="${safeStr(b.billed_id)}"/>
      <input type="hidden" name="submission_id" value="${safeStr(b.submission_id || "")}"/>
      <input type="hidden" name="paid_at" value="${new Date().toISOString().split("T")[0]}"/>
      <button class="btn success" type="submit">Mark Paid</button>
    </form>
  </div>
</div>

<div class="hr"></div>
<div class="btnRow">
      <a class="btn secondary" href="javascript:history.back()">Back</a>
      ${b.submission_id ? `<a class="btn secondary" href="/billed?submission_id=${encodeURIComponent(b.submission_id)}">View in Lifecycle</a>` : `<a class="btn secondary" href="/claims?view=all&q=${encodeURIComponent(b.claim_number||"")}">View in Lifecycle</a>`}
      <a class="btn secondary" href="/billed">Billed Submissions</a>
    </div>
  `, navUser(), {showChat:true, orgName: (typeof org!=="undefined" && org ? org.org_name : "")});

  return send(res, 200, html);
}


// fallback
  return redirect(res, "/dashboard");
});

server.listen(PORT, HOST, () => {
  console.log(`TJHP server listening on ${HOST}:${PORT}`);
});

