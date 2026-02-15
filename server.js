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
function page(title, content, navHtml="", opts={}) {
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
  return `<a href="/dashboard">Dashboard &amp; Analytics</a><a href="/billed">Billed Claims Upload</a><a href="/upload">Denial &amp; Payment Upload</a><a href="/report">Reports</a><a href="/account">Account</a><a href="/logout">Logout</a>`;
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

  const totalBilled = billed.reduce((s,b)=>s + safeNum(b.amount_billed), 0);
  const insuranceCollected = billed.reduce((s,b)=>s + safeNum(b.insurance_paid || b.paid_amount), 0);
  const patientRespTotal = billed.reduce((s,b)=>s + safeNum(b.patient_responsibility), 0);
  const patientCollected = billed.reduce((s,b)=>s + safeNum(b.patient_collected), 0);
  const patientOutstanding = Math.max(0, patientRespTotal - patientCollected);

  const allowedTotal = billed.reduce((s,b)=>s + safeNum(b.allowed_amount), 0);
  const contractualTotal = billed.reduce((s,b)=>s + Math.max(0, safeNum(b.amount_billed) - safeNum(b.allowed_amount)), 0);

  const underpaidAmt = billed.reduce((s,b)=>s + safeNum(b.underpaid_amount), 0);
  const underpaidCount = billed.filter(b => (b.status||"").toLowerCase()==="underpaid").length;

  const collectedTotal = insuranceCollected + patientCollected;
  const grossCollectionRate = totalBilled > 0 ? (collectedTotal/totalBilled)*100 : 0;
  const netCollectionRate = allowedTotal > 0 ? (collectedTotal/allowedTotal)*100 : 0;

  const revenueAtRisk = Math.max(0, totalBilled - collectedTotal);

  const statusCounts = { Paid:0, "Patient Balance":0, Underpaid:0, Denied:0, Pending:0 };
  billed.forEach(b=>{
    const st = (b.status || "Pending");
    if (st === "Paid") statusCounts.Paid++;
    else if (st === "Denied") statusCounts.Denied++;
    else if (st === "Underpaid") statusCounts.Underpaid++;
    else if (st === "Patient Balance") statusCounts["Patient Balance"]++;
    else statusCounts.Pending++;
  });

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
    atRiskSeries[k] = Math.max(0, bsum - csum);
  });

  const payerAgg = {};
  billed.forEach(b=>{
    const payer = (b.payer || "Unknown").trim() || "Unknown";
    payerAgg[payer] = payerAgg[payer] || { underpaid:0, expected:0, paid:0, count:0 };
    payerAgg[payer].underpaid += safeNum(b.underpaid_amount);
    payerAgg[payer].expected += safeNum(b.expected_insurance);
    payerAgg[payer].paid += safeNum(b.insurance_paid || b.paid_amount);
    payerAgg[payer].count += 1;
  });
  const payerTop = Object.entries(payerAgg)
    .sort((a,b)=>b[1].underpaid - a[1].underpaid)
    .slice(0,8)
    .map(([payer,v])=>({ payer, ...v }));

  return {
    kpis: {
      totalBilled, collectedTotal, revenueAtRisk,
      grossCollectionRate, netCollectionRate,
      underpaidAmt, underpaidCount,
      patientRespTotal, patientCollected, patientOutstanding,
      allowedTotal, contractualTotal,
      negotiationCases: underpayCases.length
    },
    statusCounts,
    series: { gran, keys, billed: keys.map(k=>safeNum(billedSeries[k])), collected: keys.map(k=>safeNum(collectedSeries[k])), atRisk: keys.map(k=>safeNum(atRiskSeries[k])) },
    payerTop
  };
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
  // Clean up expired de‑identified appeal attachments (non‑PHI mode)
  cleanupExpiredAppealAttachments(org.org_id);

  if (!isAccessEnabled(org.org_id)) return redirect(res, "/pilot-complete");
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


  // lock screen
  if (method === "GET" && pathname === "/lock") {
    const html = page("Starting", `
      <h2 class="center">Pilot Started</h2>
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
    `, navUser(), {showChat:true});
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
    (st["Pending"]||0);

  if (sumStatus > 0) {
    new Chart(statusEl, {
      type: "doughnut",
      data: {
        labels: ["Paid","Patient Balance","Underpaid","Denied","Pending"],
        datasets: [{
          data: [
            st["Paid"]||0,
            st["Patient Balance"]||0,
            st["Underpaid"]||0,
            st["Denied"]||0,
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


    <div class="btnRow">
      <a class="btn secondary" href="/weekly-summary">Weekly Summary</a>
      <a class="btn secondary" href="/analytics">Analytics</a>
      <a class="btn secondary" href="/dashboard">Back</a>
    </div>
  `, navUser(), {showChat:true});
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
  `, navUser(), {showChat:true});
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
      : `<span class="badge warn">Pilot Active</span>`;

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
        <td>$${Number(x.paid||0).toFixed(2)}</td>
        <td>$${Number(x.expected||0).toFixed(2)}</td>
        <td>$${Number(x.underpaid||0).toFixed(2)}</td>
      </tr>
    `).join("");

    const html = page("Dashboard", `
      <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-end;">
        <div>
          <h2 style="margin-bottom:4px;">Dashboard</h2>
          <p class="muted" style="margin-top:0;">Organization: ${safeStr(org.org_name)} · Pilot ends: ${new Date(pilot.ends_at).toLocaleDateString()}</p>
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
              <thead><tr><th>Payer</th><th>Paid</th><th>Expected</th><th>Underpaid</th></tr></thead>
              <tbody>${payerRows || `<tr><td colspan="4" class="muted">No payer data in this range.</td></tr>`}</tbody>
            </table>
          </div>
        </div>
        <div class="col">
          <h3>Patient Revenue <span class="tooltip">ⓘ<span class="tooltiptext">Patient responsibility vs collected and outstanding.</span></span></h3>
          <canvas id="patientRev" height="160"></canvas>

          <div class="btnRow" style="margin-top:10px;">
            <a class="btn" href="/billed">Billed Claims</a>
            <a class="btn secondary" href="/upload">Denial &amp; Payment Upload</a>
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
    (st["Pending"]||0);

  if (sumStatus > 0) {
    new Chart(statusEl, {
      type: "doughnut",
      data: {
        labels: ["Paid","Patient Balance","Underpaid","Denied","Pending"],
        datasets: [{
          data: [
            st["Paid"]||0,
            st["Patient Balance"]||0,
            st["Underpaid"]||0,
            st["Denied"]||0,
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


    `, navUser(), {showChat:true});

    return send(res, 200, html);
  }

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

    // Submission overview (default)
    if (!submission_id) {
      // Build submission summary rows
      const subsRows = subsAll
        .sort((a,b)=> new Date(b.uploaded_at||0).getTime() - new Date(a.uploaded_at||0).getTime())
        .map(s => {
          const claims = billedAll.filter(b => b.submission_id === s.submission_id);
          const totalClaims = claims.length;
          const paidCount = claims.filter(b => (b.status||"Pending")==="Paid").length;
          const deniedCount = claims.filter(b => (b.status||"Pending")==="Denied").length;
          const pendingCount = claims.filter(b => (b.status||"Pending")==="Pending").length;

          const totalBilledAmt = claims.reduce((sum,b)=> sum + Number(b.amount_billed||0), 0);
          const collectedAmt = claims
            .filter(b => (b.status||"Pending")==="Paid")
            .reduce((sum,b)=> sum + Number(b.paid_amount || b.amount_billed || 0), 0);
          const atRiskAmt = Math.max(0, totalBilledAmt - collectedAmt);

          const dt = s.uploaded_at ? new Date(s.uploaded_at) : null;
          const dtStr = dt ? dt.toLocaleString() : "—";

          return `<tr>
            <td>${safeStr(dtStr)}</td>
            <td>${safeStr(s.original_filename || "billed_upload")}</td>
            <td>${totalClaims}</td>
            <td>$${totalBilledAmt.toFixed(2)}</td>
            <td>${paidCount}</td>
            <td>${deniedCount}</td>
            <td>${pendingCount}</td>
            <td>$${collectedAmt.toFixed(2)}</td>
            <td>$${atRiskAmt.toFixed(2)}</td>
            <td><a href="/billed?submission_id=${encodeURIComponent(s.submission_id)}">View</a><form method="POST" action="/delete-batch" style="display:inline" onsubmit="return confirm('Delete this batch and all associated claims?')">  <input type="hidden" name="submission_id" value="${safeStr(s.submission_id)}"/>  <button type="submit" style="border:none;background:none;color:#b91c1c;cursor:pointer;margin-left:6px;">Delete</button></form></td>
          </tr>`;
        }).join("");

      const html = page("Billed Claims Upload", `
        <h2>Billed Claims Upload</h2>
        <p class="muted">
          Upload billed claims exported from your EMR/EHR. Each upload is stored as a <strong>submission batch</strong>.
          Click <strong>View</strong> to manage individual claims in that batch. Uploading payments later under
          <strong>Denial &amp; Payment Upload</strong> will auto-match by claim number and mark billed claims as <strong>Paid</strong>.
        </p>

        <div class="hr"></div>
        <h3>Upload Billed Claims <span class="tooltip">ⓘ<span class="tooltiptext">Upload a billed claims CSV from your EMR/EHR. This creates a submission batch you can manage.</span></span></h3>
        <p class="muted small">Upload CSV (recommended). Excel files are stored but not parsed in v1.</p>
        <form method="POST" action="/billed/upload" enctype="multipart/form-data">
          <label>Upload CSV/XLS/XLSX</label>
          <input type="file" name="billedfile" accept=".csv,.xls,.xlsx" required />
          <div class="btnRow">
            <button class="btn" type="submit">Upload Billed Claims</button>
            <a class="btn secondary" href="/dashboard">Back</a>
          </div>
        </form>

        <div class="hr"></div>
        <h3>Submission Batches <span class="tooltip">ⓘ<span class="tooltiptext">Each billed claims upload is stored as a batch. Use this table to track progress by batch and open the batch to manage individual claims.</span></span></h3>
        <div style="overflow:auto;">
          <table>
            <thead>
              <tr>
                <th>Submission Date/Time</th>
                <th>File Name</th>
                <th>Total Claims</th>
                <th>Total Billed Amount</th>
                <th>Paid</th>
                <th>Denied</th>
                <th>Pending</th>
                <th>Revenue Collected</th>
                <th>Revenue At Risk</th>
                <th>View</th>
              </tr>
            </thead>
            <tbody>${subsRows || `<tr><td colspan="10" class="muted">No submissions yet. Upload a billed claims file above.</td></tr>`}</tbody>
          </table>
        </div>
      `, navUser(), {showChat:true});
      return send(res, 200, html);
    }

    // Submission detail view
    const sub = subsAll.find(s => s.submission_id === submission_id);
    if (!sub) return redirect(res, "/billed");

    const startDt = start ? new Date(start + "T00:00:00.000Z") : null;
    const endDt = end ? new Date(end + "T23:59:59.999Z") : null;

    let billed = billedAll.filter(b => b.submission_id === submission_id);

    billed = billed.filter(b => {
      const created = b.created_at ? new Date(b.created_at) : new Date(0);
      if (startDt && created < startDt) return false;
      if (endDt && created > endDt) return false;
      if (statusF && (b.status || "Pending") !== statusF) return false;
      if (payerF && String(b.payer || "").trim() !== payerF) return false;
      if (q) {
        const hay = `${b.claim_number || ""} ${b.patient_name || ""} ${b.payer || ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const payerOpts = Array.from(new Set(billedAll.filter(b=>b.submission_id===submission_id).map(b => (b.payer || "").trim()).filter(Boolean))).sort();

    // Summary metrics for this submission
    const claimsAll = billedAll.filter(b => b.submission_id === submission_id);
    const totalClaims = claimsAll.length;
    const paidClaims = claimsAll.filter(b => (b.status||"Pending")==="Paid");
    const deniedClaims = claimsAll.filter(b => (b.status||"Pending")==="Denied");
    const pendingClaims = claimsAll.filter(b => (b.status||"Pending")==="Pending");

    const totalBilledAmount = claimsAll.reduce((sum, b) => sum + Number(b.amount_billed || 0), 0);
    const revenueCollected = paidClaims.reduce((sum, b) => sum + Number(b.paid_amount || b.amount_billed || 0), 0);
    const revenueAtRisk = Math.max(0, totalBilledAmount - revenueCollected);
    const collectionRate = totalBilledAmount > 0 ? Math.round((revenueCollected / totalBilledAmount) * 100) : 0;

    const barColor = collectionRate >= 80 ? "#065f46" : (collectionRate >= 60 ? "#f59e0b" : "#b91c1c");

    const rows = billed.slice(0, 500).map(b => {
      const st = (b.status || "Pending");
      const today = new Date().toISOString().split("T")[0];

      const action = (() => {
        const st = (b.status || "Pending");
        const today = new Date().toISOString().split("T")[0];

        const paidFullForm = `
          <form method="POST" action="/billed/resolve" style="display:inline-block;margin-right:6px;">
            <input type="hidden" name="billed_id" value="${safeStr(b.billed_id)}"/>
            <input type="hidden" name="submission_id" value="${safeStr(submission_id)}"/>
            <input type="hidden" name="action" value="paid_full"/>
            <input type="date" name="date" value="${today}" required style="width:155px;margin-bottom:6px;"/>
            <button class="btn small" type="submit">Paid in Full</button>
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

        // Progressive insurance dropdown
        const dd = `
          <div style="margin-top:8px;">
            <label class="small muted">Insurance Status</label>
            <select name="insurance_mode" id="mode_${safeStr(b.billed_id)}" onchange="window.__tjhpModeChange('${safeStr(b.billed_id)}')" style="width:260px;">
              <option value="">Select</option>
              <option value="insurance_partial">Insurance Partially Paid</option>
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

              <div id="prwrap_${safeStr(b.billed_id)}" style="display:none;">
                <label>Patient Resp</label>
                <input type="text" name="patient_responsibility" id="pr_${safeStr(b.billed_id)}" placeholder="auto" style="width:140px;" oninput="window.__tjhpCalc('${safeStr(b.billed_id)}')"/>
              </div>

              <div id="pstatuswrap_${safeStr(b.billed_id)}" style="display:none;">
                <label>Patient Status</label>
                <select name="patient_status" id="ps_${safeStr(b.billed_id)}" style="width:170px;" onchange="window.__tjhpPatientChange('${safeStr(b.billed_id)}')">
                  <option value="not_paid">Patient Not Paid</option>
                  <option value="full">Patient Paid in Full</option>
                  <option value="partial">Patient Paid Partial</option>
                </select>
              </div>

              <div id="ppaidwrap_${safeStr(b.billed_id)}" style="display:none;">
                <label>Patient Paid</label>
                <input type="text" name="patient_paid" id="pp_${safeStr(b.billed_id)}" placeholder="0.00" style="width:140px;"/>
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
              const prw = document.getElementById("prwrap_"+id);
              const psw = document.getElementById("pstatuswrap_"+id);
              const ppw = document.getElementById("ppaidwrap_"+id);

              if (!mode){ box.style.display="none"; return; }
              box.style.display="block";
              action.value = mode;

              // For both partial and underpaid show Patient Resp (auto, but editable)
              prw.style.display = "block";

              // Patient status shown only for insurance_partial
              if (mode === "insurance_partial"){
                psw.style.display = "block";
              } else {
                psw.style.display = "none";
                ppw.style.display = "none";
              }
              window.__tjhpCalc(id);
            };

            window.__tjhpPatientChange = window.__tjhpPatientChange || function(id){
              const v = document.getElementById("ps_"+id).value;
              const ppw = document.getElementById("ppaidwrap_"+id);
              ppw.style.display = (v === "partial") ? "block" : "none";
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

              // If patient resp is empty, auto-fill with computed
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
          </div>
        `;
      })();

      
const statusCell = (() => {

  const st = (b.status || "Pending");
  const ip = Number(b.insurance_paid || b.paid_amount || 0);
  const allowed = Number(b.allowed_amount || 0);
  const pr = Number(b.patient_responsibility || 0);
  const pc = Number(b.patient_collected || 0);
  const expectedInsurance = (b.expected_insurance != null) ? Number(b.expected_insurance) : Math.max(0, allowed - pr);
  const underpaid = Math.max(0, expectedInsurance - ip);
  const remainingPatient = Math.max(0, pr - pc);

  if (st === "Denied" && b.denial_case_id) {
    return `
      <span class="badge err">Denied</span>
      <div class="small muted">${b.denied_at ? new Date(b.denied_at).toLocaleDateString() : ""}</div>
      <div class="small">Appeal: <a href="/status?case_id=${encodeURIComponent(b.denial_case_id)}">${safeStr(b.denial_case_id)}</a></div>
    `;
  }

  if (st === "Underpaid") {
    return `
      <span class="badge err">Underpaid</span>
      <div class="small">Paid: $${ip.toFixed(2)}</div>
      <div class="small">Expected: $${expectedInsurance.toFixed(2)}</div>
      <div class="small">Underpaid: $${underpaid.toFixed(2)}</div>
    `;
  }

  if (st === "Patient Balance") {
    return `
      <span class="badge warn">Patient Owes</span>
      <div class="small">Insurance: $${ip.toFixed(2)}</div>
      <div class="small">Patient Resp: $${pr.toFixed(2)}</div>
      <div class="small">Collected: $${pc.toFixed(2)}</div>
      <div class="small">Remaining: $${remainingPatient.toFixed(2)}</div>
    `;
  }

  if (st === "Paid") {
    return `
      <span class="badge ok">Paid</span>
      <div class="small">Insurance: $${ip.toFixed(2)}</div>
      ${pr > 0 ? `<div class="small">Patient: $${pc.toFixed(2)} / $${pr.toFixed(2)}</div>` : ``}
    `;
  }

  return `<span class="badge">${safeStr(st)}</span>`;
})();


return `<tr>
        <td>${safeStr(b.claim_number || "")}</td>
        <td>${safeStr(b.dos || "")}</td>
        <td>${safeStr(b.payer || "")}</td>
        <td>$${Number(b.amount_billed || 0).toFixed(2)}</td>
        <td>${statusCell}</td>
        <td>${action}</td>
      </tr>`;
    }).join("");

    const html = page("Billed Submission", `
      <h2>Billed Claims Submission</h2>
      <p class="muted"><strong>File:</strong> ${safeStr(sub.original_filename || "billed_upload")} · <strong>Uploaded:</strong> ${sub.uploaded_at ? new Date(sub.uploaded_at).toLocaleString() : "—"} · <strong>Total claims:</strong> ${totalClaims}</p>

      <div class="hr"></div>
      <h3>Submission Financial Summary <span class="tooltip">ⓘ<span class="tooltiptext">Snapshot of billed revenue, collected revenue, and revenue at risk for this submission batch.</span></span></h3>
      <div class="row">
        <div class="col">
          <div class="kpi-card"><h4>Total Billed <span class="tooltip">ⓘ<span class="tooltiptext">Sum of billed amounts for all claims in this submission.</span></span></h4><p>$${totalBilledAmount.toFixed(2)}</p></div>
          <div class="kpi-card"><h4>Revenue Collected <span class="tooltip">ⓘ<span class="tooltiptext">Sum of paid amounts for claims marked Paid in this submission.</span></span></h4><p>$${revenueCollected.toFixed(2)}</p></div>
          <div class="kpi-card"><h4>Revenue At Risk <span class="tooltip">ⓘ<span class="tooltiptext">Total billed minus collected. Includes Pending + Denied amounts.</span></span></h4><p>$${revenueAtRisk.toFixed(2)}</p></div>
        </div>
        <div class="col">
          <div class="kpi-card"><h4>Collection Rate <span class="tooltip">ⓘ<span class="tooltiptext">Percent of billed dollars collected in this submission.</span></span></h4><p>${collectionRate}%</p></div>
          <div style="margin-top:20px;">
            <div style="height:22px;background:#e5e7eb;border-radius:12px;overflow:hidden;">
              <div style="width:${collectionRate}%;height:100%;background:${barColor};transition:width 0.4s ease;"></div>
            </div>
            <div class="small muted" style="margin-top:6px;">${collectionRate}% of billed revenue has been collected</div>
          </div>
        </div>
      </div>

      <div class="hr"></div>
      <h3>Bulk Actions <span class="tooltip">ⓘ<span class="tooltiptext">Apply a status to all claims in this submission batch. Use Reset to fix mistakes.</span></span></h3>
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
      <h3>Claims in this Submission <span class="tooltip">ⓘ<span class="tooltiptext">Filter and manage individual claims. Mark Paid/Denied or Reset to Pending.</span></span></h3>
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
        <p class="muted small">Showing ${Math.min(500, billed.length)} of ${billed.length} filtered results in this submission.</p>
      </div>
    `, navUser(), {showChat:true});
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
      const html = page("Billed Claims Upload", `
        <h2>Billed Claims Upload</h2>
        <p class="error">Only CSV or Excel files are allowed.</p>
        <div class="btnRow"><a class="btn secondary" href="/billed">Back</a></div>
      `, navUser(), {showChat:true});
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

    const html = page("Billed Claims Upload", `
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
    `, navUser(), {showChat:true});
    return send(res, 200, html);
  }

  
  // --------- BILLED CLAIMS: SIMPLE RESOLUTION (progressive UI) ----------
  if (method === "POST" && pathname === "/billed/resolve") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);

    const billed_id = (params.get("billed_id") || "").trim();
    const submission_id = (params.get("submission_id") || "").trim();
    const action = (params.get("action") || "").trim(); // paid_full | denied | insurance_partial | insurance_underpaid
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
// --------- CASE UPLOAD ----------
  if (method === "GET" && pathname === "/upload") {
    const allTemplates = readJSON(FILES.templates, []).filter(t => t.org_id === org.org_id);
    const templateOptions = allTemplates.map(t => `<option value="${safeStr(t.template_id)}">${safeStr(t.filename)}</option>`).join("");

    // Recent case status for inline processing display
    const allCasesForStatus = readJSON(FILES.cases, []).filter(c => c.org_id === org.org_id);
    allCasesForStatus.sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
    const recentCases = allCasesForStatus.slice(0, 8);

    
const allow = paymentRowsAllowance(org.org_id);
const paymentCount = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id).length;

// Build payment upload queue (grouped by source_file)
const allPay = readJSON(FILES.payments, []).filter(p => p.org_id === org.org_id);
const paymentFilesMap = {};
allPay.forEach(p => {
  const sf = (p.source_file || "").trim();
  if (!sf) return;
  if (!paymentFilesMap[sf]) {
    paymentFilesMap[sf] = {
      source_file: sf,
      count: 0,
      latest: p.created_at || p.date_paid || nowISO()
    };
  }
  paymentFilesMap[sf].count += 1;

  const dt = new Date(p.created_at || p.date_paid || Date.now()).getTime();
  const cur = new Date(paymentFilesMap[sf].latest || 0).getTime();
  if (dt > cur) {
    paymentFilesMap[sf].latest = p.created_at || p.date_paid || nowISO();
  }
});

const paymentQueue = Object.values(paymentFilesMap)
  .sort((a,b) => new Date(b.latest).getTime() - new Date(a.latest).getTime())
  .slice(0, 8);


const html = page("Denial & Payment Upload", `
      <h2>Uploads</h2>
      <p class="muted">Upload denial documents to generate appeal drafts, and upload payment files to power revenue analytics. All results appear on your Dashboard.</p>

      <div class="hr"></div>
      <h3>Denial &amp; Appeal Upload</h3>
      <p class="muted">Upload up to <strong>3 denial documents</strong>. Each document becomes its own case. Apply templates when reviewing the draft.</p>

      <form method="POST" action="/upload" enctype="multipart/form-data">
        <label>Denial Documents (up to 3)</label>
        <div id="case-dropzone" class="dropzone">Drop up to 3 documents here or click to select</div>
        <input id="case-files" type="file" name="files" multiple required accept=".pdf,.doc,.docx,.jpg,.png" style="display:none" />

        <label>Optional notes</label>
        <textarea name="notes" placeholder="Any context to help review (optional)"></textarea>

        

        <div class="btnRow" style="margin-top:16px;">
          <button class="btn" type="submit">Submit Denials</button>
          <a class="btn secondary" href="/dashboard">Back</a>
        </div>
      </form>

      <div class="hr"></div>
      <h3>Denial Case Queue</h3>
      ${
        recentCases.length === 0
          ? `<p class="muted">No denial cases yet.</p>`
          : `<table>
              <thead><tr><th>Case ID</th><th>Status</th><th>Open</th></tr></thead>
              <tbody>${
                recentCases.map(c => {
                  const openLink = (c.status === "DRAFT_READY")
                    ? `/draft?case_id=${encodeURIComponent(c.case_id)}`
                    : `/status?case_id=${encodeURIComponent(c.case_id)}`;
                  return `<tr>
                    <td>${safeStr(c.case_id)}</td>
                    <td>${safeStr(c.status)}</td>
                    <td><a href="${openLink}">Open</a></td>
                  </tr>`;
                }).join("")
              }</tbody>
            </table>`
      }

      <div class="hr"></div>
      <h3 id="payments">Payment Upload</h3>
      <p class="muted">Upload bulk payment files in CSV or Excel format. CSV drives analytics.</p>
      <p class="muted small"><strong>Rows remaining:</strong> ${allow.remaining}</p>

      <form method="POST" action="/payments" enctype="multipart/form-data">
        <label>Upload CSV/XLS/XLSX</label>
        <div id="pay-dropzone" class="dropzone">Drop a CSV/XLS/XLSX file here or click to select</div>
        <input id="pay-file" type="file" name="payfile" accept=".csv,.xls,.xlsx,.pdf,.doc,.docx" required style="display:none" />
        <div class="btnRow">
          <button class="btn" type="submit">Upload Payments</button>
          <a class="btn secondary" href="/report?type=payment_detail">View Payment Details</a>
        </div>
      </form>

      <div class="hr"></div>
      <h3>Payment Queue</h3>
      ${
        paymentQueue.length === 0
          ? `<p class="muted">No payment uploads yet.</p>`
          : `<table>
              <thead><tr><th>Source File</th><th>Records</th><th>Last Upload</th><th>Open</th></tr></thead>
              <tbody>${
                paymentQueue.map(x => {
                  return `<tr>
                    <td>${safeStr(x.source_file)}</td>
                    <td>${x.count}</td>
                    <td>${new Date(x.latest).toLocaleDateString()}</td>
                    <td><a href="/report?type=payment_detail">Open</a></td>
                  </tr>`;
                }).join("")
              }</tbody>
            </table>`
      }

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
    `, navUser(), {showChat:true});
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
      `, navUser(), {showChat:true});
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
      `, navUser(), {showChat:true});
      return send(res, 400, html);
    }

    const maxBytes = limits.max_file_size_mb * 1024 * 1024;
    for (const f of files) {
      if (f.buffer.length > maxBytes) {
        const html = page("Upload", `
          <h2>Upload</h2>
          <p class="error">File too large. Max size is ${limits.max_file_size_mb} MB.</p>
          <div class="btnRow"><a class="btn secondary" href="/upload">Back</a></div>
        `, navUser(), {showChat:true});
        return send(res, 400, html);
      }
    }

    // Handle template file upload and multiple document cases
    // Separate document files (named "files") and optional template upload
    const docFiles = files.filter(f => f.fieldName === "files");
    // Ensure at least one document file
    if (!docFiles.length) return redirect(res, "/upload");
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
      return redirect(res, "/upload?submitted=1");
}
    // If no cases were created (limit reached), show limit message
    const html = page("Limit", `
      <h2>Limit Reached</h2>
      <p class="error">${safeStr(limitReason || "Case limit reached")}</p>
      <div class="btnRow"><a class="btn secondary" href="/dashboard">Back</a></div>
    `, navUser(), {showChat:true});
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

    const html = page("Status", `
      <h2>Review in Progress</h2>
      <p class="muted">Our AI agent is analyzing your uploaded documents and preparing a draft. This is decision support only.</p>
      ${badge}
      <div class="hr"></div>
      <div class="muted small"><strong>Case ID:</strong> ${safeStr(case_id)}</div>
      <script>setTimeout(()=>window.location.reload(), 2500);</script>
      <div class="btnRow"><a class="btn secondary" href="/dashboard">Back</a></div>
    `, navUser(), {showChat:true});

    return send(res, 200, html);
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

    const html = page("Appeal Packet Builder", `
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
`, navUser(), {showChat:true});
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
      const html = page("Appeal Packet", `
        <h2>De‑Identified Confirmation Required</h2>
        <p class="error">Please confirm this case is de‑identified before compiling the packet.</p>
        <div class="btnRow"><a class="btn" href="/draft?case_id=${encodeURIComponent(case_id)}">Back</a></div>
      `, navUser(), {showChat:true});
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
      const htmlPrint = page("Appeal Packet (Printable)", `
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
      <h3>Payments (${paymentsFiltered.length} rows${payments.length > 500 ? ', showing first 500' : ''})</h3>
      ${detailTable}
      <div class="hr"></div>
      <div class="btnRow"><a class="btn secondary" href="/dashboard">Back to Dashboard</a></div>
    `, navUser(), {showChat:true});
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
    const isPDF = nameLower.endsWith(".pdf");
    const isDOC = nameLower.endsWith(".doc") || nameLower.endsWith(".docx");

    if (!isCSV && !isXLS && !isPDF && !isDOC) {
      const html = page("Revenue Management", `
        <h2>Revenue Management</h2>
        <p class="error">Allowed file types: CSV, Excel (.xls/.xlsx), PDF, Word (.doc/.docx).</p>
        <div class="btnRow"><a class="btn secondary" href="/payments">Back</a></div>
      `, navUser(), {showChat:true});
      return send(res, 400, html);
    }

    // file size cap (use same as plan)
    const limits = getLimitProfile(org.org_id);
    const maxBytes = limits.max_file_size_mb * 1024 * 1024;
    if (f.buffer.length > maxBytes) {
      const html = page("Revenue Management", `
        <h2>Revenue Management</h2>
        <p class="error">File too large. Max size is ${limits.max_file_size_mb} MB.</p>
        <div class="btnRow"><a class="btn secondary" href="/payments">Back</a></div>
      `, navUser(), {showChat:true});
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
      writeJSON(FILES.payments, paymentsData);// ======= CLAIM RECONCILIATION =======

let billedAll = readJSON(FILES.billed, []);
let subsAll = readJSON(FILES.billed_submissions, []);

function normalizeClaim(x) {
  return String(x || "").replace(/[^0-9]/g, "");
}

let changed = false;

for (const ap of addedPayments) {

  const normalizedClaim = normalizeClaim(ap.claim_number);
  if (!normalizedClaim) continue;

  const billedClaim = billedAll.find(b =>
    b.org_id === org.org_id &&
    normalizeClaim(b.claim_number) === normalizedClaim
  );

  if (!billedClaim) continue;

  // THIS LINE WAS MISSING BEFORE:
  billedClaim.status = "Paid";

  billedClaim.paid_amount = ap.amount_paid;
  billedClaim.paid_at = ap.date_paid || nowISO();

  changed = true;
}

if (changed) {

  writeJSON(FILES.billed, billedAll);

  // ===== Recalculate submission summaries =====

  subsAll.forEach(s => {

    if (s.org_id !== org.org_id) return;

    const claims = billedAll.filter(b =>
      b.submission_id === s.submission_id
    );

    s.paid = claims.filter(c => c.status === "Paid").length;
    s.denied = claims.filter(c => c.status === "Denied").length;
    s.pending = claims.filter(c => c.status === "Pending").length;

    s.revenue_collected = claims
      .filter(c => c.status === "Paid")
      .reduce((sum, c) => sum + Number(c.paid_amount || 0), 0);

    s.revenue_at_risk = claims
      .reduce((sum, c) =>
        sum + (Number(c.amount_billed || 0) - Number(c.paid_amount || 0)), 0);

  });

  writeJSON(FILES.billed_submissions, subsAll);
}

      // Auto-match billed claims from payment upload (claim_number)
      try {
        const billedAll = readJSON(FILES.billed, []);
        let changed = false;
        for (const ap of addedPayments) {
          const claimNo = String(ap.claim_number || '').trim();
          if (!claimNo) continue;
          const b = billedAll.find(x => x.org_id === org.org_id && String(x.claim_number || '').trim() === claimNo);
          if (!b) continue;
          if ((b.status || 'Pending') !== 'Paid') {
            /* status will be recalculated by simple rules below */
            b.paid_amount = ap.amount_paid || b.paid_amount || null;
            b.paid_at = ap.date_paid || b.paid_at || nowISO();
            changed = true;
          }
        }
        if (changed) writeJSON(FILES.billed, billedAll);
      } catch {}

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
        <li><strong>Rows processed:</strong> ${isCSV ? rowsAdded : "File stored (not parsed — upload CSV for analytics extraction)"}</li>
      </ul>
      <div class="btnRow">
        <a class="btn" href="/analytics">View Analytics</a>
        <a class="btn secondary" href="/payments">Upload more</a>
      </div>
    `, navUser(), {showChat:true});
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
    `, navUser(), {showChat:true});
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
      `, navUser(), {showChat:true});
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
      `, navUser(), {showChat:true});
      return send(res, 401, html);
    }

    users[uidx].password_hash = bcrypt.hashSync(p1, 10);
    writeJSON(FILES.users, users);
    auditLog({ actor:"user", action:"change_password", org_id: org.org_id, user_id: user.user_id });

    const html = page("Account", `
      <h2>Account</h2>
      <p class="muted">Password updated successfully.</p>
      <div class="btnRow"><a class="btn" href="/dashboard">Back to Dashboard</a></div>
    `, navUser(), {showChat:true});
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
    const html = page("Exports", `
      <h2>Exports</h2>
      <p class="muted">Download pilot outputs for leadership and operations review.</p>
      <div class="btnRow">
        <a class="btn secondary" href="/export/cases.csv">Cases CSV</a>
        <a class="btn secondary" href="/export/payments.csv">Payments CSV</a>
        <a class="btn secondary" href="/export/analytics.csv">Analytics CSV</a>
        <a class="btn secondary" href="/report">Printable Pilot Summary</a>
      </div>
    `, navUser(), {showChat:true});
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
      const html = page("Reports", `
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
      `, navUser(), {showChat:true});
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

    const html = page("Report", body, navUser(), {showChat:true});
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
        <a class="btn" href="${safeStr(process.env.SHOPIFY_UPGRADE_URL || "https://tjhealthpro.com")}">Continue Monthly Access (via Shopify)</a>
        <a class="btn secondary" href="/exports">Download Exports</a>
        <a class="btn secondary" href="/logout">Logout</a>
      </div>
    `, navUser(), {showChat:true});
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
      const exp = Number(c.expected_amount || c.amount_billed || 0);
      const paidAmt = Number(c.paid_amount || 0);
      return `<tr>
        <td>${safeStr(c.claim_number || "")}</td>
        <td>${safeStr(c.patient_name || "")}</td>
        <td>${safeStr(c.date_of_service || "")}</td>
        <td>${safeStr(c.status || "Pending")}</td>
        <td>$${exp.toFixed(2)}</td>
        <td>$${paidAmt.toFixed(2)}</td>
        <td><a href="/billed?submission_id=${encodeURIComponent(c.submission_id || "")}">${safeStr(c.submission_id || "View Batch")}</a></td>
      </tr>`;
    }).join("");
    const html = page(`${safeStr(payer)} Claims`, `
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
        <thead><tr><th>Claim #</th><th>Patient</th><th>Date of Service</th><th>Status</th><th>Expected</th><th>Paid</th><th>Submission</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="7" class="muted">No claims found.</td></tr>`}</tbody>
      </table>
      <p class="muted small">${claims.length > 500 ? "Showing first 500 results." : ""}</p>
      <div class="btnRow"><a class="btn secondary" href="/dashboard">Back</a></div>
      <br><form method="GET" action="/analyze-payer" style="margin-top:10px;"><input type="hidden" name="payer" value="${safeStr(payer)}"/><button class="btn" type="submit">AI Analyze This Payer</button></form>
    `, navUser(), {showChat:true});
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
    const html = page(`AI Payer Intelligence: ${safeStr(payer)}`, `
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
    `, navUser(), {showChat:true});
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

// fallback
  return redirect(res, "/dashboard");
});

server.listen(PORT, HOST, () => {
  console.log(`TJHP server listening on ${HOST}:${PORT}`);
});



// ============================================================
// ================== 3.0 FINAL STABLE BUILD ==================
// ============================================================
// This section replaces:
// 1) Payment reconciliation logic
// 2) Adds Underpaid smart engine
// 3) Adds manual resolution route
// 4) Makes Claim # clickable
// 5) Adds claim detail route
// 6) Removes Insurance Partially Paid
// 7) Adds pagination
// ============================================================



// ================= SMART PAYMENT RECONCILIATION =================

function normalizeClaim(x) {
  return String(x || "").replace(/[^0-9]/g, "");
}


// REPLACE YOUR EXISTING RECONCILIATION BLOCK WITH THIS:

// ======= SMART CLAIM RECONCILIATION =======

let billedAll = readJSON(FILES.billed, []);
let subsAll = readJSON(FILES.billed_submissions, []);

let changed = false;

for (const ap of addedPayments) {

  const normalizedClaim = normalizeClaim(ap.claim_number);
  if (!normalizedClaim) continue;

  const billedClaim = billedAll.find(b =>
    b.org_id === org.org_id &&
    normalizeClaim(b.claim_number) === normalizedClaim
  );

  if (!billedClaim) continue;

  const paid = num(ap.amount_paid);
  billedClaim.paid_amount = paid;
  billedClaim.paid_at = ap.date_paid || nowISO();

  const billedAmt = num(billedClaim.amount_billed);
  const expected = billedAmt;

  if (paid <= 0) {
    billedClaim.status = "Pending";
  } else if (paid >= expected) {
    billedClaim.status = "Paid";
  } else {
    billedClaim.status = "Underpaid";
    billedClaim.underpaid_amount = expected - paid;
  }

  changed = true;
}

if (changed) {

  writeJSON(FILES.billed, billedAll);

  subsAll.forEach(s => {

    if (s.org_id !== org.org_id) return;

    const claims = billedAll.filter(b => b.submission_id === s.submission_id);

    s.paid = claims.filter(c => c.status === "Paid").length;
    s.denied = claims.filter(c => c.status === "Denied").length;
    s.pending = claims.filter(c => c.status === "Pending").length;
    s.underpaid = claims.filter(c => c.status === "Underpaid").length;

    s.revenue_collected = claims
      .filter(c => c.status === "Paid")
      .reduce((sum, c) => sum + num(c.paid_amount), 0);

    s.revenue_at_risk = claims
      .filter(c => ["Pending","Denied","Underpaid"].includes(c.status))
      .reduce((sum, c) =>
        sum + (num(c.amount_billed) - num(c.paid_amount)), 0);

  });

  writeJSON(FILES.billed_submissions, subsAll);
}



// ================= CLAIM DETAIL ROUTE =================

// Add inside router before fallback:

if (method === "GET" && pathname === "/claim-detail") {

  const billed_id = (parsed.query.billed_id || "").trim();
  const billedAll = readJSON(FILES.billed, []);
  const claim = billedAll.find(x => x.billed_id === billed_id && x.org_id === org.org_id);
  if (!claim) return redirect(res, "/billed");

  const rows = Object.keys(claim).map(k =>
    `<tr><th>${k}</th><td>${claim[k]}</td></tr>`
  ).join("");

  const html = page("Claim Detail", `
    <h2>Claim Detail</h2>
    <table><tbody>${rows}</tbody></table>
    <a class="btn secondary" href="javascript:history.back()">Back</a>
  `, navUser(), {showChat:true});

  return send(res, 200, html);
}



// ================= PAGINATION LOGIC =================

// Insert after filtering billed claims in submission view:

const pageParam = Number(parsed.query.page || 1);
const perPageParam = Number(parsed.query.per_page || 50);
const perPage = [30,50,100].includes(perPageParam) ? perPageParam : 50;

const totalPages = Math.ceil(billed.length / perPage);
const startIdx = (pageParam - 1) * perPage;
const billedPage = billed.slice(startIdx, startIdx + perPage);

// Replace billed.map(...) with billedPage.map(...)



// ================= REMOVE PARTIAL PAID =================

// Remove this dropdown option from submission UI:

// <option value="insurance_partial">Insurance Partially Paid</option>

// Keep only:
// <option value="insurance_underpaid">Insurance Underpaid</option>



// ================= END 3.0 FINAL BUILD =================

