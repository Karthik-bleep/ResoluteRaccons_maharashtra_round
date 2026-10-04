require("dotenv").config();
const http = require("http");
const express = require("express");
const cors = require("cors");
const { Server } = require("socket.io");

const { openDb } = require("./src/db");
const { makeCore } = require("./src/core");
const { makeAuth, requireAuth, bearer } = require("./src/auth");
const { makeGuard } = require("./src/botguard");
const { makeDrop } = require("./src/drop");
const { makeService } = require("./src/service");

const PORT = process.env.PORT || 3000;
const TOTAL_SEATS = Number(process.env.TOTAL_SEATS || 500);

const db = openDb();
const core = makeCore(db);
const { bus, audit } = core;
const auth = makeAuth(db);
const guard = makeGuard({ db, audit });
const drop = makeDrop({ db, core, totalSeats: TOTAL_SEATS });
const svc = makeService({ db, core, auth, guard, drop });

// ---- seed the same test accounts your frontend already shows ----
for (const u of [
  { name: "Demo User", email: "user@fairdrop.test", password: "User@123", role: "user" },
  { name: "Security Admin", email: process.env.ADMIN_EMAIL || "admin@fairdrop.test", password: process.env.ADMIN_PASSWORD || "Admin@123", role: "admin" },
]) if (!auth.getUserByEmail(u.email)) auth.register(u);

const app = express();
app.set("trust proxy", process.env.TRUST_PROXY === "1");   // only then is X-Forwarded-For believed
app.use(cors());
app.use(express.json({ limit: "10kb" }));
app.use(express.static("public"));

// ---------- traffic metrics for the admin charts ----------
const traffic = { total: 0, perSec: 0, _last: 0, latencyMs: 0 };
app.use((req, res, next) => {
  const t0 = process.hrtime.bigint(); traffic.total++;
  res.on("finish", () => { const ms = Number(process.hrtime.bigint() - t0) / 1e6; traffic.latencyMs = traffic.latencyMs * 0.9 + ms * 0.1; });
  next();
});

const ipOf = (req) => req.ip || req.socket.remoteAddress || "unknown";

const send = (res, r) => res.status(r.status).json(r.body);
const ctx = (req) => ({ ip: ipOf(req), ua: req.headers["user-agent"] || "", body: req.body || {} });

// ================= health / public =================
app.get("/", (req, res) => res.json({ message: "Fair Drop backend is running!" }));
app.get("/api/auth/form-token", (req, res) => res.json({ token: guard.issueFormToken() }));
app.get("/api/drop/state", (req, res) => res.json(drop.publicState()));
app.get("/api/stats", (req, res) => {
  const c = drop.counts();
  res.json({ totalSeats: TOTAL_SEATS, remainingSeats: c.seats.available, totalUsers: db.prepare("SELECT COUNT(*) c FROM users").get().c,
             queueLength: c.entries, allocations: c.seats.sold + c.seats.held });
});

// ================= auth =================
app.post("/api/auth/register", (req, res) => send(res, svc.register(ctx(req))));

app.post("/api/auth/login", (req, res) => {
  const r = svc.login(ctx(req));
  if (r.status === 200) emitOnline();
  send(res, r);
});

app.post("/api/auth/logout", requireAuth(auth), (req, res) => {
  const r = svc.logout({ user: req.user, token: req.token, ip: ipOf(req) });
  for (const s of io.sockets.sockets.values()) if (s.data.token === req.token) s.disconnect(true);   // kill live admin/user socket too
  emitOnline();
  send(res, r);
});

app.get("/api/auth/me", requireAuth(auth), (req, res) => res.json(auth.pub(req.user)));

// ================= the drop (user side) =================
// Client flow: POST /join -> 428 + challenge -> solve PoW -> POST /join again with {powId, powNonce}
app.post("/api/drop/join", requireAuth(auth, "user"), (req, res) => send(res, svc.join({ user: req.user, ...ctx(req) })));
app.get("/api/drop/me", requireAuth(auth), (req, res) => res.json(drop.queueStatus(req.user.id)));
app.post("/api/drop/confirm", requireAuth(auth, "user"), (req, res) => send(res, svc.confirm({ user: req.user, ...ctx(req) })));

// ================= admin =================
const adminOnly = requireAuth(auth, "admin");
const buildStats = () => {
  const g = guard.snapshot(), c = drop.counts();
  return {
    totalRequests: traffic.total, reqPerSec: traffic.perSec, blockedBots: g.blocked, blockedPerSec: g.blockedPerSec,
    challenged: g.challenged, legitimateClaims: c.seats.sold, unsoldSeats: c.seats.available, held: c.seats.held,
    entries: c.entries, waitlist: c.waitlist, latencyMs: Math.round(traffic.latencyMs), online: onlineList().length,
    totalUsers: db.prepare("SELECT COUNT(*) c FROM users").get().c, drop: drop.publicState(),
  };
};
const recentAudit = (n = 50) => db.prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?").all(n);

app.get("/api/admin/stats", adminOnly, (req, res) => res.json(buildStats()));
app.get("/api/admin/audit", adminOnly, (req, res) => res.json(recentAudit(Math.min(Number(req.query.limit) || 100, 500))));
app.get("/api/admin/users", adminOnly, (req, res) => {
  const on = new Set(onlineList().map((u) => u.id));
  res.json(db.prepare("SELECT id,name,email,role,status,strikes,signup_ip,created_at,last_login_at FROM users ORDER BY id DESC LIMIT 500")
    .all().map((u) => ({ ...u, online: on.has(u.id) })));
});
app.post("/api/admin/drop/open", adminOnly, (req, res) => {
  const secs = Math.min(Math.max(Number(req.body?.windowSeconds) || 60, 5), 3600);
  res.json(drop.open(secs * 1000));
});
app.post("/api/admin/users/:id/ban", adminOnly, (req, res) => banUser(Number(req.params.id), req, res, true));
app.post("/api/admin/users/:id/unban", adminOnly, (req, res) => banUser(Number(req.params.id), req, res, false));
function banUser(id, req, res, ban) {
  const u = auth.getUserById(id);
  if (!u || u.role === "admin") return res.status(404).json({ error: "User not found." });
  db.prepare("UPDATE users SET status = ?, strikes = ? WHERE id = ?").run(ban ? "banned" : "active", ban ? u.strikes : 0, id);
  audit(ban ? "ADMIN_BAN" : "ADMIN_UNBAN", { userId: id, ip: ipOf(req), detail: `by ${req.user.email}` });
  if (ban) guard.hooks.onBan(id);
  res.json({ ok: true });
}

// ---------- errors ----------
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Bad JSON" });
  if (!err.status) console.error(err);
  res.status(err.status || 500).json({ error: err.status ? err.message : "Server error" });
});

// ================= live updates (socket.io) =================
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// Handshake: io(URL, { auth: { token } }) — same bearer token as REST.
io.use((socket, next) => {
  const user = auth.authenticate(socket.handshake.auth?.token);
  if (!user) return next(new Error("unauthorized"));
  socket.data.user = user; socket.data.token = socket.handshake.auth.token; next();
});

function onlineList() {
  const seen = new Map();
  for (const s of io.sockets.sockets.values()) { const u = s.data.user; if (u) seen.set(u.id, { id: u.id, name: u.name, email: u.email, role: u.role }); }
  return [...seen.values()];
}
const emitOnline = () => io.to("admins").emit("admin:online", onlineList());

io.on("connection", (socket) => {
  const u = socket.data.user;
  socket.join("user:" + u.id);
  socket.emit("drop:state", drop.publicState());
  socket.emit("seats", drop.seatMap());
  socket.emit("queue:update", drop.queueStatus(u.id));
  if (u.role === "admin") {
    socket.join("admins");
    socket.emit("admin:snapshot", { stats: buildStats(), audit: recentAudit(50), online: onlineList() });
  }
  emitOnline();
  socket.on("disconnect", () => setTimeout(emitOnline, 50));
});

// bus -> sockets
bus.on("audit", (row) => io.to("admins").emit("admin:event", row));
bus.on("drop", (s) => io.emit("drop:state", s));
bus.on("seats", (m) => io.emit("seats", m));
bus.on("seat", (s) => io.emit("seat:update", s));
bus.on("queue", (q) => io.to("user:" + q.userId).emit("queue:update", q));

// a banned bot loses its sessions, its sockets and its place in the drop
guard.hooks.onBan = (userId) => {
  auth.killSessions(userId); drop.removeUser(userId);
  for (const s of io.sockets.sockets.values()) if (s.data.user?.id === userId) s.disconnect(true);
  emitOnline();
};

setInterval(() => {
  traffic.perSec = traffic.total - traffic._last; traffic._last = traffic.total;
  guard.tick(); drop.expireHolds();
  io.to("admins").emit("admin:stats", buildStats());
}, 1000).unref();

server.listen(PORT, () => console.log(`Fair Drop server running on http://localhost:${PORT}`));
