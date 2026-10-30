# Secure Records API — Nestack Cybersecurity Take-Home

A small multi-tenant records API: users register and sign in, create records, and read **only their own**; an **admin** can read any. Authentication, sessions and access control are written from scratch (no auth library).

**Stack:** Python 3.11+ · Flask (HTTP only) · SQLite (stdlib `sqlite3`) · scrypt from the standard library · pytest.
Flask is the only runtime dependency besides `gunicorn` for serving; Flask-Login, Passport-style libraries, JWT libraries and `bcrypt`/`argon2` packages are deliberately not used.

- **Live deployment:** _not deployed_ (optional per the brief)
- **Tests:** 155, run in ~3 s — `pytest`

---

## Run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# create the first admin (admins can ONLY be created out-of-band, see §5)
python -m app.cli create-admin alice-admin          # prompts for a password

# development
flask --app wsgi run                                 # http://127.0.0.1:5000
# production-style
gunicorn -w 2 -b 0.0.0.0:8000 wsgi:app
```

Configuration is environment-based (`.env.example` lists every knob; none is a secret — see §2 for why there are no secrets to configure). The SQLite file defaults to `./records.db` and is git-ignored.

```bash
pip install -r requirements-dev.txt
pytest
```

### API

| Method | Path | Body | Success | Failure statuses |
|---|---|---|---|---|
| POST | `/register` | `{username, password}` | `201 {id, username, role:"user"}` | 400 invalid · **403 if a role/privilege field is sent** · 409 username taken |
| POST | `/login` | `{username, password}` | `200 {token, token_type:"Bearer", expires_in}` | 400 invalid · 401 bad credentials · **429 locked** (+`Retry-After`) |
| POST | `/records` 🔒 | `{title, body}` | `201 {id, title}` + `Location` | 400 · 401 |
| GET | `/records/:id` 🔒 | — | `200 {id, owner_id, title, body, created_at}` | 401 · **404 if not yours / doesn't exist** |
| POST | `/logout` 🔒 | — | `204` | 401 |
| GET | `/me` 🔒 | — | `200 {id, username, role}` | 401 |
| PATCH | `/me` 🔒 | `{current_password, new_password}` | `200` | 400 · **403 on any role field** · 403 wrong current password · 429 |

🔒 = `Authorization: Bearer <token>`. `/logout`, `/me` are small extras beyond the required four routes (see §8 for why).

```bash
curl -s localhost:5000/register -H 'Content-Type: application/json' -d '{"username":"alice","password":"correct horse battery"}'
TOKEN=$(curl -s localhost:5000/login -H 'Content-Type: application/json' \
        -d '{"username":"alice","password":"correct horse battery"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s localhost:5000/records -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"title":"hello","body":"world"}'
```

---

## Threat model & design decisions

### 1. Password storage — scrypt, per-user salt, self-describing hash

- `scrypt` (stdlib/OpenSSL), **N=2¹⁵, r=8, p=3** (32 MiB, ≈0.3 s per hash on my machine) — one of OWASP's equivalent minimum configurations. A **fresh 16-byte random salt per password**, 32-byte output.
- Stored as `scrypt$N$r$p$salt$hash`. Parameters live in the string, so cost can be raised later and old hashes still verify.
- **Why scrypt:** it's a memory-hard KDF explicitly allowed by the brief, shipped in the standard library (no native-build dependency to audit), and memory-hardness blunts GPU/ASIC cracking. Argon2id would be my pick with an extra dependency; the format above makes migrating a one-function change.
- Comparison is `hmac.compare_digest`. Unknown usernames still burn one real scrypt verification against a dummy hash, so response time doesn't reveal whether an account exists.
- The environment cannot weaken hashing: `SCRYPT_N` below 2¹⁴ (or not a power of two) makes the service refuse to start.
- Verification tolerates garbage in the DB (returns `False`, bounded memory) instead of crashing or allocating gigabytes.

### 2. Sessions — opaque random tokens, stored server-side (as a hash)

**Choice: opaque tokens, not JWTs.** `secrets.token_urlsafe(32)` = 256 bits from the OS CSPRNG. The server stores only `SHA-256(token)` with `user_id` and `expires_at`.

Why not a signed JWT:
- **No signing key exists**, so there is no key to leak, rotate, confuse (`alg=none`, HS/RS confusion) or hard-code. The app needs *zero* secrets.
- **Instant revocation** — logout, password change and role change take effect on the very next request. With a JWT you either keep a deny-list (i.e. server state anyway) or wait for expiry.
- **The role is never in the token.** Authorisation data is read from the `users` row on every request, so a token can't carry a stale or forged `role: admin` claim (tested).
- The cost is one indexed DB lookup per request — irrelevant at this scale and the same lookup I'd need for revocation anyway.

Why storing the *hash* of the token: a leaked `sessions` table can't be replayed. A fast hash is correct here — the input has 256 bits of entropy, so there's nothing to brute-force (slow hashing is for low-entropy passwords).

**How a session is proven on every request** (`auth.require_auth`):
1. Parse `Authorization: Bearer <token>`; reject unless it matches the exact token shape (43 URL-safe chars) → `401`.
2. `SHA-256` it and look it up joined to `users` with `expires_at > now` → no row ⇒ `401` (`WWW-Authenticate: Bearer`).
3. Build the request's `User(id, username, role)` from the **database row**, not from anything the client sent.

Sessions are absolute-lifetime (default 1 h, no sliding refresh), deleted on logout, and all *other* sessions are revoked on password change. Bearer headers (not cookies) mean there is no ambient credential, so CSRF doesn't apply; no CORS is enabled.

### 3. Per-record access check — one policy function, uniform 404

- Records have random 128-bit ids (`uuid4().hex`), so ids aren't enumerable — but **I don't rely on that**.
- `GET /records/:id` does: `require_auth` → validate id shape → fetch by id → **`authz.can_read_record(user, record)`** → serialise. That function is the only place ownership is decided: admins pass; otherwise `record.owner_id == user.id`; everything else (including `None`) is denied. Default deny.
- **Denied, missing and malformed ids all return the same `404` with the same body**, so the API can't be used to probe which record ids exist (I chose 404 over 403 for this reason). Denials are logged (`access denied user=… record=…`).
- Ownership is never client-supplied: `POST /records` takes the owner from the session, and unknown fields such as `owner_id` are rejected with 400 (mass-assignment guard).
- Tests cover owner / other user / admin / unauthenticated / nonexistent / malformed / SQL-injection-shaped ids, and "a denied read has no side effects".

### 4. Input validation & injection

- Every endpoint parses the body through `validation.read_json_object`: must be a JSON **object**, exact key set (unknown ⇒ 400, missing ⇒ 400), then strict type/length checks (`bool`/`int`/`list`/`null` are not strings). Limits: username 3–32 `[A-Za-z0-9_.-]` (matched with `fullmatch`, so a trailing `\n` can't sneak by), password 8–128, title ≤ 200, body ≤ 10 000, request ≤ 128 KiB.
- Oversized bodies, malformed JSON, wrong content-type, invalid UTF-8, deeply-nested JSON, and lone surrogates (`"\ud800"`, which would otherwise crash hashing/SQLite) all return **400**. Anything unforeseen returns a generic `500 {"error":"internal server error"}`; the traceback goes to the server log only (tested).
- **All SQL lives in `app/store.py` as constant strings with `?` placeholders.** There is no formatting/concatenation anywhere, and a test greps the source for it. The `role` on registration is a SQL *literal*, not a parameter.
- Defensive headers on every response: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, restrictive CSP, `Referrer-Policy: no-referrer`.
- Log lines only contain values that already passed validation (no log injection), never passwords or tokens.

### 5. Preventing privilege escalation — role is server-assigned only

- Role is `'user'` by construction in `store.create_user` (SQL literal) and the column has `CHECK (role IN ('user','admin'))`.
- Any body on `/register` or `PATCH /me` containing a privilege-looking key (`role`, `roles`, `isAdmin`, `is_admin`, `permissions`, … after normalising case/`_`/`-`) is refused with **403** *before* anything else happens — and no account is created. Other unknown keys get 400.
- The only profile edit that exists is a password change; there is no endpoint that writes `role`. A test enumerates every registered route and fails if a new one appears unnoticed.
- **Admins are created out-of-band:** `python -m app.cli create-admin <name>` (needs shell + DB access on the host). `store.create_admin` is not imported by any route.
- Because the role is re-read from the DB on every request, promotion/demotion is immediate and can't be replayed from an old token.

### 6. Login abuse resistance — per-account, race-safe, escalating

- Throttle state is keyed by the **normalised username** (not IP): 5 failed attempts within 15 min ⇒ account locked 15 min ⇒ `429` + `Retry-After`. Repeat offenders escalate (15 min → 30 min → 1 h … capped at 24 h) and are forgiven after a quiet period. A successful login clears the counter.
- **While locked, even the correct password gets 429**, otherwise the lock wouldn't stop an attacker's eventual lucky guess.
- **Attempts are reserved *before* verifying the password** inside a `BEGIN IMMEDIATE` transaction, so a burst of parallel guesses cannot all squeeze in under the limit (a test fires 20 concurrent wrong guesses and asserts ≤ 5 were evaluated).
- Case games (`ALICE`/`alice`) hit the same counter. **Unknown usernames are throttled identically**, so 401-vs-429 can't enumerate accounts. Malformed usernames (can never exist) get 401 without creating throttle rows.
- `PATCH /me` runs the current-password check through the same throttle, so a stolen session can't be used as an unthrottled password oracle.
- **Trade-off I'm accepting knowingly:** anyone who knows a username can temporarily lock that account (availability traded for integrity). Locks expire and escalation is capped at 24 h. See §7 for the mitigation I'd add at the edge.

### ⭐ If the user table leaked, what could an attacker recover?

The leaked table (`users`) contains: `id`, `username`, `role`, `created_at`, and `password_hash = scrypt$32768$8$3$<salt>$<hash>`.

**Could:**
- Learn every username and **which accounts are admins** — a ready-made target list.
- Run an **offline guessing attack** per account. Salts mean no rainbow tables and no cracking many users at once with one pass; scrypt makes each guess cost 32 MiB and ~0.3 s of CPU. **Weak or reused passwords will still fall** (a dictionary attack is feasible against a poor password), and cracked passwords may work on other sites if reused.
- Know the exact KDF and cost parameters (they're not secret and shouldn't be).

**Could not:**
- **Recover a strong password** — scrypt is one-way and there's no reversible encryption or "secret answer" anywhere.
- **Log in with the hash** — login requires the plaintext, which is re-hashed server-side (no pass-the-hash).
- **Hijack or forge sessions** — tokens aren't in `users`. Even if `sessions` leaked too, it holds only SHA-256 digests of 256-bit random tokens (not invertible, not guessable), and there is **no signing key** to steal, so tokens can't be minted.
- **Escalate by editing a token** — the role isn't in the token.
- **Read records** from this table alone — they're in a separate table.

**What a *full database* leak adds (honest limits):**
- `records.title` / `records.body` are stored **in plaintext** — a stolen DB file exposes them. (Mitigation I'd add: field-level encryption with a key held outside the DB; see §8.)
- With no pepper, the attacker needs nothing but the file to start cracking offline (§8).
- Anyone with **write** access to the DB can set `role='admin'` directly; the app can't defend against its own datastore being compromised. DB file mode is `0600` and the file is git-ignored.

### Other threats considered

| Threat | Mitigation | Residual risk |
|---|---|---|
| Credential stuffing / brute force | Per-account lock, escalating, race-safe | Targeted lockout DoS (§6) |
| IDOR / broken object-level auth | Central `can_read_record`, default deny, uniform 404, random ids | None known; tested |
| Mass assignment | Exact-key bodies; owner/role never read from client | — |
| SQL injection | Constant SQL + bound params; grep tripwire test | — |
| Token theft from DB | Only SHA-256 digests stored | Token theft in transit/XSS-style client bugs is out of scope |
| Token forgery (JWT alg confusion etc.) | Opaque random tokens, no signature scheme | — |
| Session fixation / reuse | New token per login; revoked on logout/password change | — |
| User enumeration | Same 401 body, same hash work, throttle applies to unknown names | `/register` returns 409 for a taken name (inherent to username sign-up) |
| Info leakage via errors | Generic JSON errors, tracebacks only in server logs | — |
| Oversized / hostile bodies | 128 KiB cap, strict schemas, nesting/UTF-8 handled | — |

---

## 7. Deployment notes

- **Terminate TLS at a reverse proxy.** Bearer tokens must never travel over plain HTTP. The proxy should also set `Strict-Transport-Security`.
- **Add IP/global rate limiting at the proxy/WAF** for `/register` and `/login`. They are intentionally expensive (≈0.3 s, 32 MiB each), which is correct for password hashing but means unauthenticated floods cost CPU/memory. The brief asks for per-*account* throttling in the app (done); edge limits are complementary, and also blunt the targeted-lockout trade-off above.
- Run behind gunicorn with a few workers (`wsgi:app`); SQLite uses WAL + `busy_timeout`, fine for this scale. Move to Postgres with a least-privilege app role if it grows (the app role then genuinely couldn't update `role`).
- Logs go through the `nestack.security` logger (login failures, lockouts, denied reads, registrations). Ship them somewhere; set the level you want in your process manager.

## 8. What I did not do / what I'd do next

- **Encrypt `records.body` at rest** (envelope encryption, key in a KMS/secret manager). Biggest gap for "sensitive records".
- **Optional pepper:** HMAC the password with a key held outside the DB before scrypt, so a DB-only leak can't be cracked offline. Not implemented because a lost pepper locks out every user and I didn't want to ship key-rotation half-finished.
- Password breach-list check and MFA (admin accounts especially). Today: length ≥ 8, ≤ 128, not equal to the username.
- Session management extras (list/revoke devices, per-user session cap), and audit logs to an append-only sink.
- Rehash-on-login when stored scrypt params are weaker than current config.
- A `demote`/`promote` CLI command (today: direct SQL by an operator).
- **Extra endpoints I added** beyond the required four: `POST /logout` (revocation), `GET /me` (lets clients and tests see their own role), `PATCH /me` (password change — it exists to demonstrate that "edit your profile" can't touch the role, and to revoke other sessions).

### Where the spec was ambiguous, and what I chose

| Question | Choice | Reason |
|---|---|---|
| Role field at `/register`: ignore or reject? | **403** | The rule table says a privilege-escalation attempt returns 403, and rejecting makes the attempt visible instead of silently succeeding as a `user`. |
| Another user's record: 403 or 404? | **404** (same body as "doesn't exist") | Avoids an existence oracle. |
| Oversized body: 413 or 400? | **400** | The brief specifies 400. |
| Malformed record id | **404** | Indistinguishable from not-found. |
| 5th failed login | returns 401; **6th** returns 429 | The 5th guess is evaluated and the account is locked right after. Configurable via `MAX_FAILED_LOGINS`. |

---

## Layout

```
app/
  __init__.py     app factory, error handlers, security headers
  config.py       env-based config (+ scrypt floor)
  db.py           connection + schema
  store.py        ALL SQL (parameterised)
  security.py     scrypt hashing, token generation/hashing
  validation.py   request parsing + input validation
  lockout.py      per-account throttle (transactional)
  auth.py         credential check, sessions, require_auth
  authz.py        access-control policy (can_read_record)
  routes.py       HTTP handlers only
  cli.py          out-of-band admin creation
tests/            access control · privilege · lockout · validation · sessions · passwords
wsgi.py           gunicorn entry point
```

No secrets are committed: there are none to commit (`.env.example` holds defaults only; `.env` and `*.db` are git-ignored).
