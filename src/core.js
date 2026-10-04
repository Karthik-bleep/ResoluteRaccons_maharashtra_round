const { EventEmitter } = require("events");

// bus = everything the admin dashboard needs to hear about, in real time.
// audit() writes to the DB *and* publishes on the bus.
function makeCore(db) {
  const bus = new EventEmitter();
  const ins = db.prepare("INSERT INTO audit_log (ts,type,user_id,ip,risk,detail) VALUES (?,?,?,?,?,?)");
  function audit(type, o = {}) {
    const row = { ts: Date.now(), type, userId: o.userId ?? null, ip: o.ip ?? null, risk: o.risk ?? null, detail: o.detail ?? null };
    ins.run(row.ts, row.type, row.userId, row.ip, row.risk, row.detail);
    bus.emit("audit", row);
    return row;
  }
  return { bus, audit };
}
module.exports = { makeCore };
