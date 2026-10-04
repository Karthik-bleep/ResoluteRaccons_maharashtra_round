/* Drop-in replacement for the mock `API` object in your sign-in <script>.
   Same shape as before (register / login / session / logout) but talks to the real server.
   Also: PoW solver + live socket helper.
   In your HTML:  <script src="/socket.io/socket.io.js"></script>  then  <script src="/fairdrop-client.js"></script>
   Serve the HTML from the backend (put it in /public) so BASE can stay ''. */
const FD_BASE = window.FAIRDROP_API || "";                       // e.g. "http://localhost:3000" if the HTML is opened from elsewhere
const FD_STORE = { get: (k) => localStorage.getItem(k), set: (k, v) => localStorage.setItem(k, v), del: (k) => localStorage.removeItem(k) };

async function fdRequest(path, { method = "GET", body, auth = true } = {}) {
  const s = FD_API.session();
  const res = await fetch(FD_BASE + path, {
    method, headers: { "Content-Type": "application/json", ...(auth && s ? { Authorization: "Bearer " + s.token } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

// find nonce so sha256(prefix+nonce) has `bits` leading zero bits (server asks for this when traffic looks automated, and always before joining a drop)
async function fdSolvePow({ prefix, bits }) {
  const enc = new TextEncoder();
  for (let n = 0; ; n++) {
    const h = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(prefix + n)));
    let z = 0; for (const b of h) { if (b === 0) { z += 8; continue; } z += Math.clz32(b) - 24; break; }
    if (z >= bits) return n;
  }
}
// call an endpoint; if the server answers 428 (proof of work required) solve it and retry once
async function fdWithPow(path, opts = {}) {
  let r = await fdRequest(path, opts);
  if (r.status === 428) {
    const c = r.data.challenge, nonce = await fdSolvePow(c);
    r = await fdRequest(path, { ...opts, body: { ...(opts.body || {}), powId: c.id, powNonce: nonce } });
  }
  return r;
}

const FD_API = {
  _formToken: null, _formFetchedAt: 0,
  async prepareForm() { const r = await fdRequest("/api/auth/form-token", { auth: false }); this._formToken = r.data.token; },   // call when the sign-up form is shown
  async register({ name, email, password, website = "" }) {          // `website` = hidden honeypot input (leave empty, bots fill it)
    const r = await fdWithPow("/api/auth/register", { method: "POST", auth: false, body: { name, email, password, website, formToken: this._formToken, fingerprint: window.clientFingerprint } });
    if (r.status !== 201) throw new Error(r.data.error || "Sign-up failed.");
    return { email: r.data.email };
  },
  async login({ email, password, role }) {
    const r = await fdWithPow("/api/auth/login", { method: "POST", auth: false, body: { email, password, role } });
    if (r.status !== 200) throw new Error(r.data.error || "Sign-in failed.");
    FD_STORE.set("fd_session", JSON.stringify(r.data));              // { token, name, email, role, exp }
    return r.data;
  },
  session() { try { const s = JSON.parse(FD_STORE.get("fd_session") || "null"); return s && s.exp > Date.now() ? s : null; } catch { return null; } },
  logout() { fdRequest("/api/auth/logout", { method: "POST" }).catch(() => {}); FD_STORE.del("fd_session"); if (window.fdSocket) window.fdSocket.disconnect(); },
  joinDrop: () => fdWithPow("/api/drop/join", { method: "POST" }),
  confirmPurchase: () => fdRequest("/api/drop/confirm", { method: "POST" }),
};

/* Live connection. Everyone gets drop/seat/queue events; admins additionally get admin:* events.
   FD_LIVE({
     "admin:snapshot": ({stats, audit, online}) => ...,   // once, on connect
     "admin:stats":    (stats) => ...,                    // every second -> your two charts + counters
     "admin:event":    (row) => ...,                      // every audit event, instantly -> live feed
     "admin:online":   (users) => ...,
     "seats":          (list) => ..., "seat:update": ({id,status}) => ...,
     "queue:update":   (q) => ..., "drop:state": (s) => ...
   }) */
function FD_LIVE(handlers = {}) {
  const s = FD_API.session(); if (!s) return null;
  const sock = io(FD_BASE || undefined, { auth: { token: s.token } });
  for (const [ev, fn] of Object.entries(handlers)) sock.on(ev, fn);
  sock.on("connect_error", (e) => { if (e.message === "unauthorized") { FD_STORE.del("fd_session"); location.reload(); } });
  window.fdSocket = sock; return sock;
}
