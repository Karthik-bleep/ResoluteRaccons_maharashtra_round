const crypto = require("crypto");
const { tx } = require("./db");

/**
 * FAIR DROP = lottery, not a race.
 *   1. OPEN window (e.g. 60s): everyone who passes the bot checks + PoW gets ONE ticket.
 *      Arrival time inside the window is irrelevant, so 10,000 req/s buys a bot nothing.
 *   2. DRAW: tickets are shuffled with a cryptographic RNG. First N get seats (held 2 min),
 *      the rest get a waitlist position. Expired holds are re-offered down the waitlist.
 */
function makeDrop({ db, core, totalSeats = 500, holdMs = 120_000 }) {
  const { bus, audit } = core;
  const state = { phase: "idle", opensAt: null, closesAt: null, drawnAt: null };
  let timer = null;

  const ins = db.prepare("INSERT OR IGNORE INTO seats (id) VALUES (?)");
  tx(db, () => { for (let i = 1; i <= totalSeats; i++) ins.run(i); });

  const publicState = () => ({ ...state, totalSeats, ...counts() });

  function counts() {
    const s = Object.fromEntries(db.prepare("SELECT status, COUNT(*) c FROM seats GROUP BY status").all().map((r) => [r.status, r.c]));
    const e = Object.fromEntries(db.prepare("SELECT status, COUNT(*) c FROM drop_entries GROUP BY status").all().map((r) => [r.status, r.c]));
    const total = db.prepare("SELECT COUNT(*) c FROM drop_entries").get().c;
    return { seats: { available: s.available || 0, held: s.held || 0, sold: s.sold || 0 }, entries: total, waitlist: e.waitlist || 0 };
  }
  const seatMap = () => db.prepare("SELECT id, status FROM seats ORDER BY id").all();

  function open(windowMs = 60_000) {
    if (state.phase === "open" || state.phase === "drawing") throw Object.assign(new Error("A drop is already open."), { status: 409 });
    tx(db, () => { db.exec("DELETE FROM drop_entries; UPDATE seats SET status='available', user_id=NULL, held_until=NULL"); });
    state.phase = "open"; state.opensAt = Date.now(); state.closesAt = Date.now() + windowMs; state.drawnAt = null;
    clearTimeout(timer); timer = setTimeout(draw, windowMs);
    audit("DROP_OPENED", { detail: `window ${Math.round(windowMs / 1000)}s, ${totalSeats} seats` });
    bus.emit("drop", publicState());
    return publicState();
  }

  function join(userId, ip) {
    if (state.phase !== "open") throw Object.assign(new Error(state.phase === "idle" ? "No drop is open yet." : "The entry window has closed."), { status: 409 });
    const r = db.prepare("INSERT OR IGNORE INTO drop_entries (user_id, joined_at) VALUES (?,?)").run(userId, Date.now());
    if (!r.changes) throw Object.assign(new Error("You are already in this drop."), { status: 409 });
    audit("JOINED_DROP", { userId, ip, detail: "ticket issued (position is decided by the draw, not by arrival)" });
    bus.emit("drop", publicState());
    return { status: "waiting", closesAt: state.closesAt };
  }

  function draw() {
    state.phase = "drawing";
    const users = tx(db, () => {
      db.exec("DELETE FROM drop_entries WHERE user_id IN (SELECT id FROM users WHERE status='banned')");   // bots caught mid-window are out
      const ids = db.prepare("SELECT user_id FROM drop_entries").all().map((r) => r.user_id);
      for (let i = ids.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [ids[i], ids[j]] = [ids[j], ids[i]]; }  // Fisher-Yates, CSPRNG
      const upd = db.prepare("UPDATE drop_entries SET draw_position=?, status=? WHERE user_id=?");
      const seat = db.prepare("UPDATE seats SET status='held', user_id=?, held_until=? WHERE id=?");
      const until = Date.now() + holdMs;
      ids.forEach((uid, i) => {
        const win = i < totalSeats;
        upd.run(i + 1, win ? "winner" : "waitlist", uid);
        if (win) seat.run(uid, until, i + 1);
      });
      return ids;
    });
    state.phase = "live"; state.drawnAt = Date.now();
    audit("DRAW_COMPLETE", { detail: `${users.length} entrants → ${Math.min(users.length, totalSeats)} winners, ${Math.max(0, users.length - totalSeats)} waitlisted` });
    bus.emit("drop", publicState()); bus.emit("seats", seatMap());
    users.forEach((uid) => bus.emit("queue", queueStatus(uid)));
    return users.length;
  }

  function queueStatus(userId) {
    const e = db.prepare("SELECT * FROM drop_entries WHERE user_id = ?").get(userId);
    if (!e) return { userId, status: "none", phase: state.phase };
    const seat = db.prepare("SELECT id, held_until FROM seats WHERE user_id = ?").get(userId);
    return { userId, phase: state.phase, status: e.status, position: e.draw_position,
             waitlistPosition: e.status === "waitlist" ? e.draw_position - totalSeats : null,
             seatId: seat ? seat.id : null, heldUntil: seat && seat.held_until, closesAt: state.closesAt };
  }

  function confirm(userId, ip) {
    const seat = db.prepare("SELECT id, held_until FROM seats WHERE user_id = ? AND status = 'held'").get(userId);
    if (!seat) throw Object.assign(new Error("You have no active seat hold."), { status: 409 });
    if (seat.held_until < Date.now()) throw Object.assign(new Error("Your hold expired."), { status: 410 });
    tx(db, () => {
      db.prepare("UPDATE seats SET status='sold', held_until=NULL WHERE id=?").run(seat.id);
      db.prepare("UPDATE drop_entries SET status='purchased' WHERE user_id=?").run(userId);
    });
    audit("SEAT_SOLD", { userId, ip, detail: `seat #${seat.id}` });
    bus.emit("seats", seatMap()); bus.emit("seat", { id: seat.id, status: "sold" }); bus.emit("queue", queueStatus(userId));
    return { seatId: seat.id };
  }

  // free a seat and offer it to the next person on the waitlist
  function releaseSeat(seatId, reason) {
    const next = db.prepare("SELECT user_id FROM drop_entries WHERE status='waitlist' ORDER BY draw_position LIMIT 1").get();
    if (next) {
      db.prepare("UPDATE seats SET status='held', user_id=?, held_until=? WHERE id=?").run(next.user_id, Date.now() + holdMs, seatId);
      db.prepare("UPDATE drop_entries SET status='winner' WHERE user_id=?").run(next.user_id);
      audit("WAITLIST_PROMOTED", { userId: next.user_id, detail: `seat #${seatId} (${reason})` });
      bus.emit("queue", queueStatus(next.user_id));
    } else {
      db.prepare("UPDATE seats SET status='available', user_id=NULL, held_until=NULL WHERE id=?").run(seatId);
    }
    bus.emit("seat", { id: seatId, status: next ? "held" : "available" });
  }

  function expireHolds() {
    if (state.phase !== "live") return;
    const rows = db.prepare("SELECT id, user_id FROM seats WHERE status='held' AND held_until < ?").all(Date.now());
    for (const r of rows) {
      db.prepare("UPDATE drop_entries SET status='expired' WHERE user_id=?").run(r.user_id);
      audit("HOLD_EXPIRED", { userId: r.user_id, detail: `seat #${r.id}` });
      releaseSeat(r.id, "hold expired");
      bus.emit("queue", queueStatus(r.user_id));
    }
  }

  // a user was banned as a bot: pull them out of the drop
  function removeUser(userId) {
    const seat = db.prepare("SELECT id FROM seats WHERE user_id=? AND status='held'").get(userId);
    db.prepare("DELETE FROM drop_entries WHERE user_id=?").run(userId);
    if (seat) releaseSeat(seat.id, "holder banned as bot");
  }

  return { state, publicState, counts, seatMap, open, join, draw, confirm, queueStatus, expireHolds, removeUser };
}

module.exports = { makeDrop };
