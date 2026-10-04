# Fair Drop backend

Express + socket.io + SQLite. No new npm dependencies (uses Node's built-in `node:sqlite` and `crypto`).
Needs **Node ≥ 22.5** (if you're on older Node: `npm i better-sqlite3`, `src/db.js` falls back to it automatically).

```
npm install
cp .env.example .env     # set ADMIN_PASSWORD
npm start                # http://localhost:3000   (DB file: fairdrop.db)
npm test                 # offline simulation of humans vs bots (see test output)
```
Seeded logins (same as your frontend): `user@fairdrop.test / User@123`, `admin@fairdrop.test / Admin@123`.

## Files
| file | what it does |
|---|---|
| `server.js` | Express routes + socket.io live layer (thin glue) |
| `src/db.js` | SQLite schema: users, sessions, audit_log, drop_entries, seats |
| `src/auth.js` | scrypt password hashing, session tokens (stored hashed), role checks |
| `src/botguard.js` | risk scoring, proof-of-work, honeypot, form-timing token, login lockout |
| `src/drop.js` | the lottery: open window → random draw → holds → waitlist promotion |
| `src/service.js` | register / login / join / confirm logic (no Express, so it's testable) |
| `public/fairdrop-client.js` | replaces the mock `API` in your HTML + live socket helper |

## REST API
| | |
|---|---|
| `GET /api/auth/form-token` | signed timestamp; send back on register (proves the form was on screen) |
| `POST /api/auth/register` `{name,email,password,website,formToken,fingerprint}` | `website` is the hidden honeypot, must stay empty |
| `POST /api/auth/login` `{email,password,role}` | → `{token,name,email,role,exp}` (same shape your frontend stores) |
| `POST /api/auth/logout` · `GET /api/auth/me` | Bearer token; logout also kills the user's live socket |
| `POST /api/drop/join` | PoW always required: first call → `428 {challenge}`, retry with `{powId,powNonce}` |
| `GET /api/drop/me` · `POST /api/drop/confirm` | my queue status · pay for my held seat |
| `GET /api/drop/state` · `GET /api/stats` | public |
| **admin:** `GET /api/admin/stats\|users\|audit`, `POST /api/admin/drop/open {windowSeconds}`, `POST /api/admin/users/:id/ban\|unban` | role must be admin |

## Live updates (socket.io)
Connect with `io(URL, { auth: { token } })` (same token as REST). Admins receive:
`admin:snapshot` (on connect) · `admin:stats` (every 1s: totalRequests, reqPerSec, blockedBots, blockedPerSec, legitimateClaims, unsoldSeats, held, waitlist, online, latencyMs) · `admin:event` (every audit event the instant it happens: sign-ups, logins, logouts, bots blocked, bans, draw, sales) · `admin:online`.
Everyone gets `drop:state`, `seats`, `seat:update`; each user gets their own `queue:update`.

## How bots are filtered (3 layers)
**1. Don't reward speed (the main idea).** Entry is a *window*, then a *lottery*. Everyone who enters during the window is shuffled with a CSPRNG (`crypto.randomInt`, Fisher–Yates); the first N get seats, the rest a waitlist. Sending 10,000 req/s no longer helps. Measured: first-to-arrive wins 24.0%, last-to-arrive 25.7%, fair value 25.0% (5,000 draws).

**2. Make each ticket cost something.** One account = one ticket (DB primary key). Joining needs a proof-of-work (find a nonce so `sha256(prefix+nonce)` has 16 leading zero bits; 20 bits if the client is already suspicious). Single-use, 60 s expiry, bound to the user. Cheap for one human, expensive for 10,000 fake accounts.

**3. Risk score from many weak signals** (each one is easy to fake alone; faking all is costly). ≥30 → PoW challenge, ≥60 → block, 3 strikes → account banned, sessions/sockets killed, removed from the draw.
| signal | points |
|---|---|
| honeypot field filled | +100 |
| automation / empty user-agent | +45 / +40 |
| form submitted <1.5 s after render (server-signed time) / no form token | +45 / +20 |
| >40 / >120 requests per 10 s from one IP (lenient: campus NATs share IPs) | +35 / +65 |
| >8 / >20 requests per 10 s from one account | +40 / +70 |
| metronome-like request rhythm (low variance, <1.5 s apart) | +35 |
| >5 / >12 sign-ups from one IP in 10 min | +30 / +60 |
| same device fingerprint on >3 accounts | +40 |
| account created <5 s before joining | +25 |
| failed PoW attempts | +20 each |
Plus: 5 failed logins per IP+email → 10 min lockout, passwords scrypt-hashed, constant-time compare.
Thresholds live in `makeGuard` config (`src/botguard.js`).

## Honest limits
- PoW and scoring raise the cost of botting, they don't make it impossible. For a real launch add a CAPTCHA/Turnstile at sign-up and verified email or phone.
- The device fingerprint is client-supplied, so treat it as a weak signal.
- State for rate limits is in memory (single instance). For several instances move `botguard.js` maps to Redis.
- Serve over HTTPS in production; set `TRUST_PROXY=1` only behind a proxy you control.
