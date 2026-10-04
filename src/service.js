// Request-level business logic, independent of Express so it can be tested directly.
// Every method returns { status, body }.
function makeService({ db, core, auth, guard, drop }) {
  const { audit } = core;
  const safe = (fn) => (...a) => {
    try { return fn(...a); }
    catch (e) { if (e.status) return { status: e.status, body: { error: e.message } }; throw e; }
  };

  return {
    register: safe(({ ip, ua, body = {} }) => {
      const { name, email, password, website, formToken, fingerprint } = body;
      const g = guard.gate({ ip, ua, action: "register", honeypot: website, formAgeMs: guard.formAge(formToken), fingerprint }, body);
      if (!g.pass) return g;
      const user = auth.register({ name, email, password, fingerprint, ip });
      guard.noteRegistration(ip);
      audit("USER_REGISTERED", { userId: user.id, ip, risk: g.risk.score, detail: user.email });
      return { status: 201, body: { email: user.email } };
    }),

    login: safe(({ ip, ua, body = {} }) => {
      const { email, password, role } = body;
      if (guard.loginLocked(ip, email)) return { status: 429, body: { error: "Too many failed attempts. Try again in a few minutes." } };
      const g = guard.gate({ ip, ua, action: "login" }, body);
      if (!g.pass) return g;
      try {
        const { userId, ...session } = auth.login({ email, password, role, ip, userAgent: ua });
        guard.loginOk(ip, email);
        audit("LOGIN", { userId, ip, risk: g.risk.score, detail: session.role });
        return { status: 200, body: session };            // { token, name, email, role, exp }
      } catch (e) {
        if (e.status === 401) { guard.loginFailed(ip, email); audit("LOGIN_FAILED", { ip, risk: g.risk.score, detail: String(email).slice(0, 80) }); }
        throw e;
      }
    }),

    logout({ user, token, ip }) {
      auth.logout(token);
      audit("LOGOUT", { userId: user.id, ip, detail: user.email });
      return { status: 200, body: { ok: true } };
    },

    join: safe(({ user, ip, ua, body = {} }) => {
      const g = guard.gate({ ip, ua, userId: user.id, action: "join", accountAgeMs: Date.now() - user.created_at }, body, { alwaysPow: true });
      if (!g.pass) return g;
      return { status: 200, body: drop.join(user.id, ip) };
    }),

    confirm: safe(({ user, ip, ua }) => {
      const g = guard.gate({ ip, ua, userId: user.id, action: "confirm" });
      if (!g.pass) return g;
      return { status: 200, body: drop.confirm(user.id, ip) };
    }),
  };
}
module.exports = { makeService };
