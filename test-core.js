// Offline end-to-end test of everything except the Express/socket.io wiring.
// Run:  node --disable-warning=ExperimentalWarning test-core.js
const crypto = require("crypto");
const { openDb } = require("./src/db");
const { makeCore } = require("./src/core");
const { makeAuth } = require("./src/auth");
const { makeGuard, leadingZeroBits, sha256buf } = require("./src/botguard");
const { makeDrop } = require("./src/drop");
const { makeService } = require("./src/service");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36";
const t0 = Date.now(), T = () => String(((Date.now() - t0) / 1000).toFixed(2)).padStart(6);
const h = (s) => console.log(`\n=== ${s} ===`);

// small PoW settings so the demo is fast (production defaults: 16 / 20 bits, 5-min block, 3 strikes)
const db = openDb(":memory:");
const core = makeCore(db), { bus } = core;
const auth = makeAuth(db);
const guard = makeGuard({ db, audit: core.audit, cfg: { powBitsNormal: 12, powBitsHard: 16, blockMs: 250, strikesToBan: 2 } });
const SEATS = 20;
const drop = makeDrop({ db, core, totalSeats: SEATS, holdMs: 3000 });
const svc = makeService({ db, core, auth, guard, drop });
guard.hooks.onBan = (uid) => { auth.killSessions(uid); drop.removeUser(uid); };

// ---- the "admin live feed": what a socket.io admin would receive as it happens ----
let feedOn = false, shown = 0;
bus.on("audit", (e) => {
  if (!feedOn) return;
  const interesting = ["BOT_BLOCKED", "USER_BANNED", "DRAW_COMPLETE", "DROP_OPENED", "LOGOUT", "WAITLIST_PROMOTED", "HOLD_EXPIRED", "SEAT_SOLD", "LOGIN_FAILED"].includes(e.type);
  if (interesting && shown++ < 40) console.log(`  [admin:event +${T()}s] ${e.type.padEnd(17)} user=${String(e.userId ?? "-").padEnd(3)} ip=${String(e.ip ?? "-").padEnd(13)} risk=${String(e.risk ?? "-").padEnd(3)} ${(e.detail || "").slice(0, 110)}`);
});

const solve = (c) => { for (let n = 0; ; n++) if (leadingZeroBits(sha256buf(c.prefix + n)) >= c.bits) return n; };

// client helper: call an endpoint, auto-solve a 428 PoW challenge and retry once
async function withPow(call) {
  let r = call({});
  if (r.status === 428) { const c = r.body.challenge; r = call({ powId: c.id, powNonce: solve(c) }); }
  return r;
}
const mk = (n) => ({ ip: `10.1.${Math.floor(n / 250)}.${n % 250 + 1}`, ua: CHROME });

(async () => {
  // ---------------------------------------------------------------- 1. auth
  h("1. SIGN UP / SIGN IN / SIGN OUT (SQLite)");
  const tok = () => guard.issueFormToken();
  const base = { ip: "1.1.1.1", ua: CHROME };
  await sleep(1600);   // a human takes >1.5s to fill the form
  const f = tok(); await sleep(1600);
  console.log("register          ->", JSON.stringify(svc.register({ ...base, body: { name: "Asha Rao", email: "asha@x.com", password: "Secret@1", formToken: f } })));
  console.log("register duplicate->", JSON.stringify(svc.register({ ...base, body: { name: "Asha Rao", email: "asha@x.com", password: "Secret@1", formToken: f } })));
  console.log("register weak pw  ->", JSON.stringify(svc.register({ ...base, body: { name: "Bo", email: "bo@x.com", password: "123", formToken: f } })));
  console.log("login wrong pw    ->", JSON.stringify(svc.login({ ...base, body: { email: "asha@x.com", password: "nope", role: "user" } })));
  const adm = auth.register({ name: "Security Admin", email: "admin@fairdrop.test", password: "Admin@123", role: "admin" });
  console.log("user->admin tab   ->", JSON.stringify(svc.login({ ...base, body: { email: "asha@x.com", password: "Secret@1", role: "admin" } })));
  const L = svc.login({ ...base, body: { email: "asha@x.com", password: "Secret@1", role: "user" } });
  console.log("login ok          ->", JSON.stringify({ ...L.body, token: L.body.token.slice(0, 12) + "…" }));
  console.log("token valid?      ->", !!auth.authenticate(L.body.token));
  console.log("password stored as->", db.prepare("SELECT pw_hash FROM users WHERE email='asha@x.com'").get().pw_hash.slice(0, 40) + "…");
  svc.logout({ user: auth.authenticate(L.body.token), token: L.body.token, ip: base.ip });
  console.log("after logout valid->", !!auth.authenticate(L.body.token));

  // ---------------------------------------------------------------- 2. sign-up bots
  h("2. BOTS AT THE FRONT DOOR (sign-up)");
  feedOn = true;
  let res = { ok: 0, blocked: 0, pow: 0 };
  const tally = (r) => (r.status === 201 || r.status === 200 ? res.ok++ : r.status === 429 ? res.blocked++ : res.pow++);

  // A: dumb script — python UA, no form token
  for (let i = 0; i < 60; i++) tally(svc.register({ ip: "66.6.6.6", ua: "python-requests/2.31", body: { name: "bot" + i, email: `a${i}@bot.io`, password: "password1" } }));
  console.log(`A) 60 sign-ups, python-requests UA           -> created ${res.ok}, blocked ${res.blocked}`);

  // B: spoofs a browser UA but fills the hidden honeypot field
  res = { ok: 0, blocked: 0, pow: 0 };
  for (let i = 0; i < 20; i++) tally(svc.register({ ip: "77.7.7.7", ua: CHROME, body: { name: "bot" + i, email: `b${i}@bot.io`, password: "password1", website: "http://spam", formToken: tok() } }));
  console.log(`B) 20 sign-ups, fake Chrome, honeypot filled   -> created ${res.ok}, blocked ${res.blocked}`);

  // C: smart farm — fake Chrome, valid token, solves PoW, submits instantly
  res = { ok: 0, blocked: 0, pow: 0 };
  for (let i = 0; i < 30; i++) {
    const r = await withPow((pow) => svc.register({ ip: "88.8.8.8", ua: CHROME, body: { name: "farm" + i, email: `c${i}@bot.io`, password: "password1", formToken: tok(), ...pow } }));
    tally(r);
  }
  console.log(`C) 30 sign-ups, fake Chrome, solves PoW, instant -> created ${res.ok}, blocked ${res.blocked}  (PoW slows it, signup-farm rule stops it)`);

  // ---------------------------------------------------------------- 3. humans register + login
  h("3. 80 REAL USERS SIGN UP AND LOG IN (different IPs, normal timing)");
  feedOn = false;
  const N = 80, humans = [];
  const tokens = Array.from({ length: N }, tok); await sleep(1600);
  for (let i = 0; i < N; i++) {
    const c = mk(i);
    const r = svc.register({ ...c, body: { name: "User " + i, email: `u${i}@mail.com`, password: "Passw0rd!", formToken: tokens[i] } });
    const l = svc.login({ ...c, body: { email: `u${i}@mail.com`, password: "Passw0rd!", role: "user" } });
    if (r.status === 201 && l.status === 200) humans.push({ ...c, token: l.body.token, id: auth.authenticate(l.body.token).id });
  }
  console.log(`registered + logged in: ${humans.length}/${N}   |  users in DB: ${db.prepare("SELECT COUNT(*) c FROM users").get().c}`);

  // ---------------------------------------------------------------- 4. drop
  h(`4. THE DROP: ${SEATS} seats, 3s entry window`);
  feedOn = true; shown = 0;
  drop.open(3000);
  // bots with valid accounts: the fastest, most aggressive clients possible
  const botAccts = [];
  for (let i = 0; i < 6; i++) {
    const ip = `99.9.9.${i + 1}`; const f2 = tok();
    svc.register({ ip, ua: CHROME, body: { name: "sneaky" + i, email: `s${i}@bot.io`, password: "password1", formToken: f2, ...{} } });   // may be challenged (instant) - fine either way
    botAccts.push({ ip, email: `s${i}@bot.io` });
  }
  // (sneaky accounts that were challenged at sign-up don't exist; create them directly so they can attack)
  for (const b of botAccts) if (!auth.getUserByEmail(b.email)) auth.register({ name: "sneaky", email: b.email, password: "password1", ip: b.ip });
  const botSessions = botAccts.map((b) => ({ ...b, ua: CHROME, token: svc.login({ ip: b.ip, ua: CHROME, body: { email: b.email, password: "password1", role: "user" } }).body?.token }));

  // humans join in random order, spread out; bots hammer join() in tight loops with correct PoW
  const joinHuman = async (u) => { const user = auth.authenticate(u.token); return withPow((pow) => svc.join({ user, ip: u.ip, ua: u.ua, body: pow })); };
  const botAttack = async (b) => {
    let n = 0, ok = 0, blocked = 0;
    for (let round = 0; round < 3; round++) {
      for (let k = 0; k < 15; k++) {
        const user = auth.authenticate(b.token); if (!user) return { n, ok, blocked, banned: true };
        const r = await withPow((pow) => svc.join({ user, ip: b.ip, ua: b.ua, body: pow })); n++;
        if (r.status === 200) ok++; if (r.status === 429) blocked++;
      }
      await sleep(300);
    }
    return { n, ok, blocked, banned: !auth.authenticate(b.token) };
  };
  const shuffled = [...humans].sort(() => Math.random() - 0.5);
  const humanJobs = shuffled.map(async (u, i) => { await sleep(Math.random() * 1500); return (await joinHuman(u)).status; });
  const botJobs = botSessions.map(botAttack);
  const hs = await Promise.all(humanJobs), bs = await Promise.all(botJobs);
  console.log(`humans joined: ${hs.filter((s) => s === 200).length}/${N}`);
  console.log("bot results  :", bs.map((b) => `${b.n} reqs → ${b.ok} entered, ${b.blocked} blocked${b.banned ? ", BANNED" : ""}`).join(" | "));
  console.log("bot users banned in DB:", db.prepare("SELECT COUNT(*) c FROM users WHERE status='banned'").get().c);

  await sleep(3300);   // window closes -> draw
  const c = drop.counts();
  console.log(`\ndraw done  -> entries ${c.entries} | seats held ${c.seats.held} | waitlist ${c.waitlist}`);
  const botIds = new Set(db.prepare("SELECT id FROM users WHERE email LIKE '%@bot.io'").all().map((r) => r.id));
  const inDraw = db.prepare("SELECT user_id FROM drop_entries").all().filter((r) => botIds.has(r.user_id)).length;
  const seatsToBots = db.prepare("SELECT user_id FROM seats WHERE status='held'").all().filter((r) => botIds.has(r.user_id)).length;
  console.log(`bots present in the draw: ${inDraw}   seats held by bots: ${seatsToBots}`);

  // ---------------------------------------------------------------- 5. buy / expire / promote
  h("5. PURCHASE, HOLD EXPIRY AND WAITLIST PROMOTION (holds last 3s in this demo)");
  const winners = db.prepare("SELECT user_id FROM seats WHERE status='held' ORDER BY id").all().map((r) => r.user_id);
  const buyers = winners.slice(0, 10);
  const codes = buyers.map((uid) => { const u = auth.getUserById(uid); const h2 = humans.find((x) => x.id === uid); return svc.confirm({ user: u, ip: h2.ip, ua: CHROME }).status; });
  console.log(`10 winners paid  -> HTTP ${[...new Set(codes)].join(",")} | sold ${drop.counts().seats.sold} | still held ${drop.counts().seats.held}`);
  const late = auth.getUserById(winners[15]); console.log("paying a 2nd time  ->", JSON.stringify(svc.confirm({ user: auth.getUserById(buyers[0]), ip: "10.1.0.1", ua: CHROME }).body));
  await sleep(3100); drop.expireHolds();
  const c2 = drop.counts();
  console.log(`after expiry     -> sold ${c2.seats.sold} | held (re-offered to waitlist) ${c2.seats.held} | available ${c2.seats.available} | waitlist left ${c2.waitlist}`);

  // ---------------------------------------------------------------- 6. fairness proof
  h("6. FAIRNESS CHECK: does arriving first help?  (400 draws, same 80 users, 20 seats)");
  let firstWins = 0, lastWins = 0; const R = 400;
  for (let r = 0; r < R; r++) {
    drop.open(60000);
    for (const u of humans) drop.join(u.id, u.ip);          // humans[0] ALWAYS arrives first, humans[79] last
    drop.draw();
    const w = (id) => db.prepare("SELECT status FROM drop_entries WHERE user_id=?").get(id).status === "winner";
    firstWins += w(humans[0].id); lastWins += w(humans[N - 1].id);
  }
  console.log(`first-to-arrive wins: ${(firstWins / R * 100).toFixed(1)}%   last-to-arrive wins: ${(lastWins / R * 100).toFixed(1)}%   fair expectation: ${(SEATS / N * 100).toFixed(1)}%`);

  h("GUARD METRICS (what the admin charts show)");
  console.log(guard.snapshot());
  console.log("audit rows by type:", Object.fromEntries(db.prepare("SELECT type, COUNT(*) c FROM audit_log GROUP BY type ORDER BY c DESC").all().map((r) => [r.type, r.c])));
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
