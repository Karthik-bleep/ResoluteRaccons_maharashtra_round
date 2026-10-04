const crypto = require("crypto");

const AUTOMATION_UA = /curl|wget|python|requests|aiohttp|httpx|go-http|okhttp|java\/|axios|node-fetch|undici|headless|phantom|selenium|puppeteer|playwright|scrapy|spider|crawler|\bbot\b/i;
const sha256buf = (s) => crypto.createHash("sha256").update(s).digest();

function leadingZeroBits(buf) {
  let n = 0;
  for (const byte of buf) {
    if (byte === 0) { n += 8; continue; }
    n += Math.clz32(byte) - 24; break;
  }
  return n;
}

/**
 * Bot guard = a RISK SCORE built from many weak signals (any single one is easy to fake;
 * together they are expensive to fake), plus a real proof-of-work gate, plus a fair lottery
 * (see drop.js) that removes the reward for being fast in the first place.
 */
function makeGuard({ db, audit, cfg = {} }) {
  const C = {
    blockAt: 60, challengeAt: 30,
    powBitsNormal: 16, powBitsHard: 20, powTtlMs: 60_000,
    minFormMs: 1500, blockMs: 5 * 60_000, ipBlockMs: 60_000, strikesToBan: 3,
    secret: process.env.HMAC_SECRET || crypto.randomBytes(32).toString("hex"),
    ...cfg,
  };

  const hits = new Map();       // key -> timestamps inside 10s window (rate)
  const cadence = new Map();    // key -> last 12 timestamps (rhythm)
  const regsByIp = new Map();   // ip -> signup timestamps (10 min)
  const blocked = new Map();    // key -> blockedUntil
  const powFails = new Map();   // userId -> {n, ts}
  const loginFails = new Map(); // ip|email -> {n, first}
  const challenges = new Map(); // id -> {userId, prefix, bits, exp}
  const metrics = { total: 0, blocked: 0, challenged: 0, allowed: 0 };
  let last = { total: 0, blocked: 0 }, rates = { reqPerSec: 0, blockedPerSec: 0 };
  const hooks = { onBan: () => {} };

  const slide = (map, key, now, windowMs, keep = Infinity) => {
    const a = map.get(key) || []; a.push(now);
    const cut = now - windowMs; while (a.length && a[0] < cut) a.shift();
    while (a.length > keep) a.shift();
    map.set(key, a); return a;
  };

  function assess({ ip, ua, userId = null, fingerprint = null, action, honeypot, formAgeMs = null, accountAgeMs = null }) {
    const now = Date.now(); metrics.total++;
    const key = userId ? "u:" + userId : "ip:" + ip;
    if ((blocked.get(key) || 0) > now) {
      metrics.blocked++;
      return { score: 100, decision: "block", signals: ["temporarily blocked"] };
    }
    let score = 0; const signals = [];
    const add = (n, why) => { score += n; signals.push(`${why} (+${n})`); };

    // 1. trap + basic client hygiene
    if (honeypot) add(100, "honeypot field filled");
    if (!ua) add(40, "no user-agent"); else if (AUTOMATION_UA.test(ua)) add(45, "automation user-agent");

    // 2. human timing on forms (server-signed timestamp, so it can't be faked client-side)
    if (formAgeMs !== null && formAgeMs < C.minFormMs) add(45, `form submitted in ${formAgeMs}ms`);
    if (action === "register" && formAgeMs === null) add(20, "no form token");

    // 3. rate (IP limit is lenient: campus/office NATs share one IP)
    const ipN = slide(hits, "ip:" + ip, now, 10_000).length;
    if (ipN > 120) add(65, `${ipN} req/10s from one IP`); else if (ipN > 40) add(35, `${ipN} req/10s from one IP`);
    if (userId) {
      const uN = slide(hits, "u:" + userId, now, 10_000).length;
      if (uN > 20) add(70, `${uN} req/10s from one account`); else if (uN > 8) add(40, `${uN} req/10s from one account`);
    }

    // 4. machine-like rhythm: humans are irregular, scripts are metronomes
    const ts = slide(cadence, key, now, 120_000, 12);
    if (ts.length >= 9) {
      const iv = ts.slice(1).map((t, i) => t - ts[i]);
      const mean = iv.reduce((a, b) => a + b, 0) / iv.length;
      const sd = Math.sqrt(iv.reduce((a, b) => a + (b - mean) ** 2, 0) / iv.length);
      if (mean < 1500 && sd / Math.max(mean, 1) < 0.12) add(35, `robotic cadence (${Math.round(mean)}ms ±${Math.round(sd)})`);
    }

    // 5. sign-up farming
    if (action === "register") {
      const regs = (regsByIp.get(ip) || []).filter((t) => t > now - 600_000);
      if (regs.length > 12) add(60, `${regs.length} sign-ups from this IP in 10 min`);
      else if (regs.length > 5) add(30, `${regs.length} sign-ups from this IP in 10 min`);
      if (fingerprint) {
        const n = db.prepare("SELECT COUNT(*) c FROM users WHERE fingerprint = ?").get(fingerprint).c;
        if (n > 3) add(40, `device fingerprint already on ${n} accounts`);
      }
    }
    if (action === "join" && accountAgeMs !== null && accountAgeMs < 5000) add(25, "account created seconds ago");

    // 6. failed proof-of-work attempts
    const pf = userId ? powFails.get(userId) : null;
    if (pf && pf.ts > now - 600_000) add(Math.min(pf.n, 3) * 20, `${pf.n} failed PoW attempts`);

    score = Math.min(100, score);
    const decision = score >= C.blockAt ? "block" : score >= C.challengeAt ? "challenge" : "allow";
    if (decision === "block") {
      metrics.blocked++;
      blocked.set(key, now + (userId ? C.blockMs : C.ipBlockMs));
      audit("BOT_BLOCKED", { userId, ip, risk: score, detail: `${action}: ${signals.join("; ")}` });
      if (userId) strike(userId, ip);
    } else if (decision === "challenge") { metrics.challenged++; metrics.allowed++; }
    else metrics.allowed++;
    return { score, decision, signals };
  }

  function strike(userId, ip) {
    db.prepare("UPDATE users SET strikes = strikes + 1 WHERE id = ?").run(userId);
    const u = db.prepare("SELECT strikes, role FROM users WHERE id = ?").get(userId);
    if (u && u.role !== "admin" && u.strikes >= C.strikesToBan) {
      db.prepare("UPDATE users SET status = 'banned' WHERE id = ?").run(userId);
      audit("USER_BANNED", { userId, ip, detail: `${u.strikes} strikes` });
      hooks.onBan(userId);
    }
  }

  // ---- proof of work: find nonce so sha256(prefix+nonce) has `bits` leading zero bits ----
  function issueChallenge({ userId, risk }) {
    const bits = risk >= C.challengeAt ? C.powBitsHard : C.powBitsNormal;   // suspicious => ~16x more work
    const id = crypto.randomBytes(8).toString("hex"), prefix = crypto.randomBytes(12).toString("hex");
    challenges.set(id, { userId, prefix, bits, exp: Date.now() + C.powTtlMs });
    return { id, prefix, bits, expiresAt: Date.now() + C.powTtlMs };
  }
  function verifyChallenge({ userId, id, nonce }) {
    const c = challenges.get(id); challenges.delete(id);               // single use
    const fail = (reason) => {
      if (userId) { const p = powFails.get(userId) || { n: 0 }; powFails.set(userId, { n: p.n + 1, ts: Date.now() }); }
      return { ok: false, reason };
    };
    if (!c || c.exp < Date.now()) return fail("challenge expired or unknown");
    if (c.userId !== userId) return fail("challenge belongs to someone else");
    if (leadingZeroBits(sha256buf(c.prefix + String(nonce))) < c.bits) return fail("wrong proof of work");
    powFails.delete(userId); return { ok: true };
  }

  // ---- signed form token (render time) ----
  const mac = (s) => crypto.createHmac("sha256", C.secret).update(s).digest("base64url");
  const issueFormToken = () => { const t = String(Date.now()); return `${t}.${mac(t)}`; };
  function formAge(token) {
    if (typeof token !== "string") return null;
    const [t, m] = token.split(".");
    if (!t || !m || mac(t) !== m) return null;
    const age = Date.now() - Number(t);
    return age >= 0 && age < 3600_000 ? age : null;
  }

  // ---- credential stuffing lock ----
  const lockKey = (ip, email) => ip + "|" + String(email).toLowerCase();
  function loginLocked(ip, email) {
    const f = loginFails.get(lockKey(ip, email));
    return !!f && f.n >= 5 && Date.now() - f.first < 10 * 60_000;
  }
  function loginFailed(ip, email) {
    const k = lockKey(ip, email), f = loginFails.get(k);
    if (!f || Date.now() - f.first > 10 * 60_000) loginFails.set(k, { n: 1, first: Date.now() }); else f.n++;
  }
  const loginOk = (ip, email) => loginFails.delete(lockKey(ip, email));


  // One call = full decision. Returns { pass, status, body, risk }.
  //  block      -> 429
  //  challenge  -> 428 + PoW challenge (client solves it and retries with powId/powNonce)
  //  allow      -> pass (alwaysPow forces the PoW step even for low-risk traffic, used for joining the drop)
  function gate(info, body = {}, { alwaysPow = false } = {}) {
    const risk = assess(info);
    if (risk.decision === "block")
      return { pass: false, status: 429, risk, body: { error: "Automated traffic detected. Please try again later." } };
    if (risk.decision === "challenge" || alwaysPow) {
      const ok = body.powId && verifyChallenge({ userId: info.userId ?? null, id: body.powId, nonce: body.powNonce }).ok;
      if (!ok) return { pass: false, status: 428, risk,
        body: { error: "Proof of work required", challenge: issueChallenge({ userId: info.userId ?? null, risk: risk.score }) } };
    }
    return { pass: true, risk };
  }

  const noteRegistration = (ip) => slide(regsByIp, ip, Date.now(), 600_000);

  function tick() {   // call once per second
    rates = { reqPerSec: metrics.total - last.total, blockedPerSec: metrics.blocked - last.blocked };
    last = { total: metrics.total, blocked: metrics.blocked };
    const now = Date.now();
    for (const [k, v] of blocked) if (v < now) blocked.delete(k);
    for (const [k, v] of challenges) if (v.exp < now) challenges.delete(k);
    for (const [k, a] of hits) if (!a.length || a[a.length - 1] < now - 10_000) hits.delete(k);
    for (const [k, a] of cadence) if (a[a.length - 1] < now - 120_000) cadence.delete(k);
  }
  const snapshot = () => ({ ...metrics, ...rates });

  return { assess, gate, issueChallenge, verifyChallenge, issueFormToken, formAge, loginLocked, loginFailed, loginOk,
           noteRegistration, tick, snapshot, hooks, config: C };
}

module.exports = { makeGuard, leadingZeroBits, sha256buf };
