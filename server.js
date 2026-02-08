const http = require("http");
const bcrypt = require("bcryptjs");
const url = require("url");

const users = {}; // TEMP storage (email -> user object)

const PORT = process.env.PORT || 8080;

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "text/html" });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const { pathname, query } = parsed;

  // HOME
  if (pathname === "/") {
    return send(
      res,
      200,
      `<h2>TJ Healthcare Pro</h2>
       <p>30-Day Claim Denial Review Pilot</p>
       <a href="/signup">Create Account</a> | <a href="/login">Login</a>`
    );
  }

  // SIGNUP FORM
  if (pathname === "/signup" && req.method === "GET") {
    return send(
      res,
      200,
      `<h3>Create Account</h3>
       <form method="POST">
         <input name="email" placeholder="Email" required /><br/>
         <input name="password" type="password" placeholder="Password" required /><br/>
         <button>Create Account</button>
       </form>`
    );
  }

  // SIGNUP SUBMIT
  if (pathname === "/signup" && req.method === "POST") {
    let body = "";
    req.on("data", chunk => (body += chunk));
    req.on("end", async () => {
      const params = new URLSearchParams(body);
      const email = params.get("email");
      const password = params.get("password");

      if (users[email]) {
        return send(res, 400, "User already exists");
      }

      const hash = await bcrypt.hash(password, 10);
      users[email] = { email, passwordHash: hash };

      return send(res, 200, "Account created. <a href='/login'>Login</a>");
    });
    return;
  }

  // LOGIN FORM
  if (pathname === "/login" && req.method === "GET") {
    return send(
      res,
      200,
      `<h3>Login</h3>
       <form method="POST">
         <input name="email" placeholder="Email" required /><br/>
         <input name="password" type="password" required /><br/>
         <button>Login</button>
       </form>`
    );
  }

  // LOGIN SUBMIT
  if (pathname === "/login" && req.method === "POST") {
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

      return send(res, 200, "Logged in. Dashboard coming next.");
    });
    return;
  }

  send(res, 404, "Not found");
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
