const http = require("http");

const PORT = process.env.PORT || 8080;
const HOST = "0.0.0.0";

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(`
    <div style="max-width:720px;margin:60px auto;padding:24px;border:1px solid #e5e7eb;border-radius:12px;font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
      <h1 style="text-align:center;">TJ Healthcare Pro</h1>
      <p style="text-align:center;margin-top:12px;">
        Your <strong>30-Day Claim Denial Review Pilot</strong> access is being prepared.
      </p>
      <hr style="margin:24px 0;" />
      <p>
        Please check your email for secure upload instructions.<br/>
        If you do not receive them shortly, contact us at
        <a href="mailto:tjhealthcare101@gmail.com">tjhealthcare101@gmail.com</a>.
      </p>
      <p style="font-size:14px;color:#6b7280;margin-top:16px;">
        No EMR access. No payer portal access. No automated submissions.<br/>
        All outputs require human review.
      </p>
    </div>
  `);
});

server.listen(PORT, HOST, () => {
  console.log(`Server listening on ${HOST}:${PORT}`);
});
