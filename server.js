const http = require("http");

const PORT = process.env.PORT || 8080;
const HOST = "0.0.0.0";

const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>TJ Healthcare Pro</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body {
      background:#f9fafb;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      margin:0;
      padding:0;
    }
    .card {
      max-width:720px;
      margin:60px auto;
      padding:24px;
      background:#ffffff;
      border:1px solid #e5e7eb;
      border-radius:12px;
      text-align:center;
    }
    h1 {
      margin-bottom:8px;
    }
    hr {
      margin:24px 0;
      border:none;
      border-top:1px solid #e5e7eb;
    }
    .muted {
      color:#6b7280;
      font-size:14px;
    }
    a {
      color:#2563eb;
      text-decoration:none;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>TJ Healthcare Pro</h1>
    <p><strong>Your 30-Day Claim Denial Review Pilot</strong> access is being prepared.</p>

    <hr />

    <p>
      Please check your email for secure upload instructions.<br />
      If you do not receive them shortly, contact us at
      <a href="mailto:tjhealthcare101@gmail.com">tjhealthcare101@gmail.com</a>.
    </p>

    <p class="muted">
      No EMR access. No payer portal access. No automated submissions.<br />
      All outputs require human review.
    </p>
  </div>
</body>
</html>
`;

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(html);
});

server.listen(PORT, HOST, () => {
  console.log(`Server running on ${HOST}:${PORT}`);
});
