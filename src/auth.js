const crypto = require("crypto");

const SESSION_TTL_MS = 8 * 3600 * 1000;               // matches the frontend (8h)
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

// ---------- password hashing (scrypt, per-user salt) ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(pw, salt, 64);
  return `scrypt$${salt.toString("hex")}$${key.toString("hex")}`;
}
function verifyPassword(pw, stored) {
  const [alg, saltHex, keyHex] = String(stored).split("$");
  if (alg !== "scrypt") return false;
  const key = crypto.scryptSync(pw, Buffer.from(saltHex, "hex"), 64);
  const want = Buffer.from(keyHex, "hex");
  return key.length === want.length && crypto.timingSafeEqual(key, want);
}

// ---------- auth service ----------
function makeAuth(db) {
  const q = {
    byEmail: db.prepare("SELECT * FROM users WHERE email = ?"),
    byId: db.prepare("SELECT * FROM users WHERE id = ?"),
    insert: db.prepare("INSERT INTO users (name,email,pw_hash,role,fingerprint,signup_ip,created_at) VALUES (?,?,?,?,?,?,?)"),
    touch: db.prepare("UPDATE users SET last_login_at = ? WHERE id = ?"),
    newSession: db.prepare("INSERT INTO sessions (token_hash,user_id,ip,user_agent,created_at,expires_at) VALUES (?,?,?,?,?,?)"),
    getSession: db.prepare(`SELECT s.expires_at, u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`),
    delSession: db.prepare("DELETE FROM sessions WHERE token_hash = ?"),
    delUserSessions: db.prepare("DELETE FROM sessions WHERE user_id = ?"),
    purge: db.prepare("DELETE FROM sessions WHERE expires_at < ?"),
  };
  const pub = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role });

  return {
    pub,
    getUserByEmail: (e) => q.byEmail.get(e),
    getUserById: (id) => q.byId.get(id),

    register({ name, email, password, role = "user", fingerprint = null, ip = null }) {
      name = String(name || "").trim(); email = String(email || "").trim().toLowerCase();
      if (name.length < 2) throw httpErr(400, "Please enter your name.");
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw httpErr(400, "Enter a valid email address.");
      if (String(password || "").length < 6) throw httpErr(400, "Password must be at least 6 characters.");
      if (q.byEmail.get(email)) throw httpErr(409, "An account with this email already exists.");
      const r = q.insert.run(name, email, hashPassword(password), role, fingerprint, ip, Date.now());
      return pub(q.byId.get(Number(r.lastInsertRowid)));
    },

    login({ email, password, role, ip, userAgent }) {
      email = String(email || "").trim().toLowerCase();
      const u = q.byEmail.get(email);
      // always run a hash so timing doesn't reveal whether the email exists
      const ok = u ? verifyPassword(String(password || ""), u.pw_hash)
                   : (verifyPassword("x", hashPassword("y")), false);
      if (!ok) throw httpErr(401, "Invalid email or password.");
      if (u.status === "banned") throw httpErr(403, "This account has been blocked for automated activity.");
      if (role && u.role !== role)
        throw httpErr(403, role === "admin" ? "This account does not have admin access."
                                            : "Admin accounts must sign in from the Admin tab.");
      const token = crypto.randomBytes(32).toString("hex");
      const now = Date.now();
      q.purge.run(now);
      q.newSession.run(sha256(token), u.id, ip, String(userAgent || "").slice(0, 200), now, now + SESSION_TTL_MS);
      q.touch.run(now, u.id);
      // same shape the frontend already expects: { token, name, email, role, exp }
      return { token, name: u.name, email: u.email, role: u.role, exp: now + SESSION_TTL_MS, userId: u.id };
    },

    // returns the user row or null (expired / unknown / banned)
    authenticate(token) {
      if (!token) return null;
      const row = q.getSession.get(sha256(token));
      if (!row || row.expires_at < Date.now() || row.status === "banned") return null;
      return row;
    },
    logout(token) { q.delSession.run(sha256(token)); },
    killSessions(userId) { q.delUserSessions.run(userId); },
  };
}

function httpErr(status, message) { const e = new Error(message); e.status = status; return e; }

// Express middleware helpers
const bearer = (req) => (req.headers.authorization || "").replace(/^Bearer\s+/i, "") || null;
function requireAuth(auth, role) {
  return (req, res, next) => {
    const token = bearer(req);
    const user = auth.authenticate(token);
    if (!user) return res.status(401).json({ error: "Not signed in." });
    if (role && user.role !== role) return res.status(403).json({ error: "Forbidden." });
    req.user = user; req.token = token; next();
  };
}

module.exports = { makeAuth, requireAuth, bearer, httpErr, hashPassword, sha256 };
