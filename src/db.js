// SQLite storage. Uses Node's built-in node:sqlite (Node >= 22.5), falls back to better-sqlite3.
let Database;
try { Database = require("node:sqlite").DatabaseSync; }
catch { Database = require("better-sqlite3"); }

function openDb(file = process.env.DB_PATH || "fairdrop.db") {
  const db = new Database(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      pw_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      status TEXT NOT NULL DEFAULT 'active',      -- active | banned
      strikes INTEGER NOT NULL DEFAULT 0,
      fingerprint TEXT,
      signup_ip TEXT,
      created_at INTEGER NOT NULL,
      last_login_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      ip TEXT, user_agent TEXT,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      type TEXT NOT NULL,
      user_id INTEGER, ip TEXT,
      risk INTEGER, detail TEXT
    );
    CREATE TABLE IF NOT EXISTS drop_entries (
      user_id INTEGER PRIMARY KEY REFERENCES users(id),
      joined_at INTEGER NOT NULL,
      draw_position INTEGER,                      -- assigned by RANDOM draw, not arrival time
      status TEXT NOT NULL DEFAULT 'waiting'      -- waiting | winner | waitlist | purchased | expired
    );
    CREATE TABLE IF NOT EXISTS seats (
      id INTEGER PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'available',   -- available | held | sold
      user_id INTEGER,
      held_until INTEGER
    );
  `);
  return db;
}

// tiny transaction helper that works for both drivers
function tx(db, fn) {
  db.exec("BEGIN");
  try { const r = fn(); db.exec("COMMIT"); return r; }
  catch (e) { db.exec("ROLLBACK"); throw e; }
}

module.exports = { openDb, tx };
