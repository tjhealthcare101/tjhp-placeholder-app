const http = require("http");
const bcrypt = require("bcrypt");

// TEMP in-memory user store (replace with DB later)
const users = {
  "admin@tjhealthpro.com": {
    passwordHash: bcrypt.hashSync("password123", 10),
  },
};

const PORT = process.env.PORT || 8080;

function send(res, status, body, type = "text/html") {
  res.writeHead(status, { "Content-Type": type });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const { url, method } = req;
  const pathname = url.split("?")[0];

  /* ---------------- LOGIN PAGE ---------------- */
  if (pathname === "/" && method === "GET") {
    return send(
      res,
      200,
      `
      <h2>Login</h2>
      <form method="POST" action="/login">
        <input name="email" placeholder="Email" required /><br/><br/>
        <input name="password" type="password" placeholder="Password" required /><br/><br/>
        <button>Login</button>
      </form>
      `
    );
  }

  /* ---------------- LOGIN SUBMIT ---------------- */
  if (pathname === "/login" && method === "POST") {
    let body = "";
    req.on("data", chunk => (body += chunk));
    req.on("end", async () => {
      const params = new URLSearchParams(body);
      const email = params.get("email");
      const password = params.get("password");

      const user = users[email];
      if (!user) return send(res, 401, "Invalid login");

      const ok = await bcrypt.compare(password, user.passwordHash);
      if (!ok) return send(res, 401, "Invalid login");

      // Redirect to lock screen
      res.writeHead(302, { Location: "/lock" });
      res.end();
    });
    return;
  }

  /* ---------------- LOCK SCREEN (5s) ---------------- */
  if (pathname === "/lock") {
    return send(
      res,
      200,
      `
      <html>
        <head>
          <meta http-equiv="refresh" content="5;url=/dashboard" />
        </head>
        <body style="font-family:system-ui;text-align:center;padding-top:80px;">
          <h2>TJ Healthcare Pro</h2>
          <p><strong>AI Review In Progress</strong></p>
          <p>Your data is being analyzed.<br/>This typically takes moments.</p>
          <p style="font-size:13px;color:#666;">
            No EMR access · No payer portals · No automated submissions · Human review required
          </p>
        </body>
      </html>
      `
    );
  }

  /* ---------------- DASHBOARD ---------------- */
  if (pathname === "/dashboard") {
    return send(
      res,
      200,
      `
      <h2>Dashboard</h2>

      <h3>Upload Data</h3>
      <ul>
        <li>Denial letters</li>
        <li>Payment remittances</li>
        <li>Claim/billing reports</li>
      </ul>

      <h3>AI Draft (Editable)</h3>
      <textarea style="width:90%;height:120px;">
This is a draft appeal generated from your uploaded documents.
You may edit, reorder, or rewrite before final submission.
      </textarea>

      <h3>Analytics (Preview)</h3>
      <ul>
        <li>Denials by payer</li>
        <li>Paid vs unpaid claims</li>
        <li>Underpaid amounts vs expected</li>
        <li>Average payment timelines</li>
      </ul>

      <h3>Exports</h3>
      <ul>
        <li>CSV – Denials</li>
        <li>CSV – Payments</li>
        <li>CSV – Appeals</li>
      </ul>

      <p style="font-size:13px;color:#666;">
        All outputs are drafts. Final review and submission is performed by your team.
      </p>
      `
    );
  }

  /* ---------------- FALLBACK ---------------- */
  send(res, 404, "Not found");
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
