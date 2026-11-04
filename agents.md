# agents.md — LLM agent orientation for chatstream-moderate

This file is written for LLM agents. Read it before exploring the codebase.

---

## What this project does

Eventyay sends chat messages to this tool via HMAC-signed webhooks. Moderators see the messages in a real-time queue, decide approve / reject / highlight / ban / allow, and approved messages are published via RSS. Multiple moderators can work the same queue simultaneously — competing decisions use most-restrictive-wins.

---

## Start here

| Goal | Read first |
|------|-----------|
| Understand the data | `src/models.py` — all 9 models, ~140 lines |
| Understand message intake | `src/webhook.py` — `_process_message()` |
| Understand moderation actions | `src/queue_bp.py` — `_set_status()`, `block_user()`, `whitelist_user()` |
| Understand auth/roles | `src/auth.py` — 72 lines, all decorators |
| Understand config + secrets | `app.py` — `_read_secret()`, `create_app()` |
| Understand the queue UI | `templates/queue.html` — the most complex template |

---

## Architecture

```
Eventyay → POST /webhook/channel/<id>   (HMAC verified)
               ↓
         webhook.py: _process_message()
               ↓
         checks: blacklisted? blocked pattern? whitelisted?
               ↓
         Message row inserted (status = queued | approved)
               ↓
Moderator ← GET /channel/<id>/queue/messages.json  (polled 500ms)
               ↓
         POST /api/channel/<id>/message/<id>/approve|reject|highlight
         POST /api/channel/<id>/block-user
         POST /api/channel/<id>/whitelist-user
               ↓
         ModerationLog row written
               ↓
RSS consumers ← GET /rss/<id>  (approved + highlighted)
```

---

## Data model

```
Channel
  id (slug), name, is_active, archived_at
  anonymous_label, anonymous_counter   ← used when screen_name absent
  emoji_auto_approve, language_detection_enabled
  default_language, likely_languages (JSON)
  display_token, webhook_hmac_secret

Message
  channel_id, status (queued|approved|highlighted|rejected)
  screen_name (display only), sender_id (primary identity), centralauth_id
  message, message_type (text|emoji|qa)
  arrived_at, processed_at, processed_by_centralauth_id

Blacklist / Whitelist          ← per-channel; nearly identical structure
  channel_id, screen_name, sender_id (unique key), centralauth_id
  added_by_centralauth_id, added_by_wiki_username

GlobalBlacklist                ← same structure, no channel_id

BlockedPattern
  channel_id, pattern_text     ← Levenshtein ≤ 2 match at intake

ModerationLog                  ← immutable; one row per effective decision
  channel_id, message_id (nullable FK), decision
  screen_name, message_text    ← denormalised; survives message deletion
  arrived_at, decided_at

ChannelMember
  channel_id, centralauth_id, wiki_username, role (admin|moderator)
```

**Identity priority**: `sender_id` > `centralauth_id` > `screen_name`.
`screen_name` is display-only; when absent, intake assigns `"<anonymous_label> #<counter>"`.

---

## Role hierarchy

```
superadmin         ← wiki_username in app.py SUPERADMIN_USERS list
  ↓ manages
channel admin      ← ChannelMember.role == 'admin'
  ↓ manages
channel moderator  ← ChannelMember.role == 'moderator'
```

Superadmins bypass all channel role checks (`is_superadmin()` short-circuits `channel_role_required`).

Auth decorators live in `src/auth.py`:
- `@superadmin_required`
- `@channel_role_required('admin')` or `('admin', 'moderator')`
- `verify_csrf()` — checks `csrf_token` form field or `X-CSRF-Token` header

---

## Key invariants

**Most-restrictive-wins** (`queue_bp.py:_set_status`):  
`DECISION_RANK = {highlighted: 1, approved: 2, rejected: 3}`  
Lower rank number = higher priority. A status can only move to a *lower* rank number, never higher. Returns `{superseded: True}` if ignored.

**Blacklist/whitelist dedup** (application-level, not DB constraint):  
Check by `sender_id` first when present, else by `screen_name`.  
The unique DB index is on `(channel_id, sender_id)` — NULLs are allowed multiple times in both SQLite and MySQL UNIQUE indexes.

**Webhook replay protection**:  
`timestamp` must be within 5 minutes of `now`. Check in `webhook.py:webhook_receive`.

**Simulation uses loopback HTTP** (`admin_bp.py:simulation_inject`):  
`requests.post(request.host_url + '/webhook/channel/simulation', ...)`.  
Do NOT use `test_client()` — it shares the SQLAlchemy session and causes teardown corruption.  
On Toolforge the call goes through the public ingress (round-trip), which is fine — HMAC auth still applies.

**`db.create_all()` runs on every startup** (`app.py:create_app`):  
New tables are created automatically. Schema changes that alter existing tables require a Flask-Migrate migration (`flask db migrate && flask db upgrade`).

---

## Message intake order

`webhook.py:webhook_receive()`, after HMAC and timestamp checks:

- **System messages** (`message_type == "system"` or `message_id` starting with `system-`) describe the connection, not chat. They are never stored as `Message` rows and always get `{"ok": true, "system": true}`. The latest message of each `meta.kind` is kept per room (`meta.room.id`, `''` if absent) in `Channel.eventyay_status` (JSON, no history). Limits: 50 rooms, 10 kinds per room, kind names `[A-Za-z0-9_.-]{1,32}` (fullmatch), and at most 60,000 bytes of JSON so it fits MariaDB TEXT; at the room or byte limit the oldest room is dropped, at the kind limit that room's oldest kind, with one warning in the log. Room ids, names and reasons are cleaned of unencodable and control characters. The challenge GET answers 404 for inactive channels, like the POST. A failed save is rolled back and logged; the sender still gets 200.
- Chat messages go to `_process_message()`; they don't touch `eventyay_status`.
- The challenge `GET` checks `X-Eventyay-Signature` (HMAC of the challenge token) when present and returns 403 on mismatch.

`webhook.py:_process_message()`:

1. Deduplicate by `eventyay_message_id` — silently skip
2. Skip emoji reactions with `meta.action == "remove"` — not content to moderate
3. Check global blacklist → drop
4. Check channel blacklist → drop
5. Check blocked patterns (Levenshtein ≤ 2 on lowercased text) → drop
6. Check channel whitelist → `status = 'approved'`
7. Emoji auto-approve (if enabled + identical emoji approved in last 10s) → `status = 'approved'`
8. Default → `status = 'queued'`
9. Run language detection (text only, if enabled)
10. Insert Message row

---

## Queue UI (templates/queue.html)

- Polls `GET /channel/<id>/queue/messages.json` every 500ms
- Response: `{messages, lang_codes, stats}`
- Query params: `lang=<code>` (repeatable), `type=text|emoji|qa` (default: all)
- Stats: all-time decision counts from ModerationLog grouped by decision string
- New cards prepend (newest at top); removed cards slide out with CSS transition
- `selectedId` — the keyboard-armed card; keys 1–6 fire actions
  - 1 highlight · 2 approve · 3 reject · 4 reject++ · 5 ban · 6 allow (whitelist)
- `typeFilter` — 'all' | 'text' | 'emoji'; type filter bar in channel bar switches this and re-polls
- `autoSelectAtPercentile()` — runs after each poll; selects card at percentile position when nothing is selected
- `centerSelected()` — always-instant scroll so the selected card is vertically centred in the space below the channel bar; called after every DOM mutation and on selection change. No smooth scroll — it caused jumpy behavior when polls interrupted in-flight animations.
- Focus percentile persisted in `localStorage` per channel (`focus:<channel_id>`); random initial value so moderators spread across the queue

---

## Common tasks

**Add a new per-message action**:
1. Add route in `queue_bp.py` (POST `/api/channel/<id>/message/<id>/...`)
2. Add button in `makeCard()` in `queue.html` (extend `actionDefs` array or add standalone like ban/allow)
3. Add key binding in the keydown handler

**Add a new channel config field**:
1. Add column to `Channel` in `models.py`
2. Add form field in `templates/admin/channel_settings.html`
3. Read it in `channel_settings_post` in `admin_bp.py`

**Add a new moderation log decision type**:
1. Call `_log(msg, 'your-decision-string')` before changing status
2. Update the decision badge in `templates/queue/log.html`

**Change who can do X**:
- Swap `@superadmin_required` ↔ `@channel_role_required('admin')` ↔ `@channel_role_required('admin', 'moderator')`

---

## Input sanitization

`nh3` (Rust-backed HTML sanitizer) is a dependency — used to strip unsafe HTML from user-supplied content before storage/display. If adding new fields that render user input, pass them through `nh3.clean()`.

---

## Files you will NOT need to touch for most tasks

- `src/display_bp.py` — RSS feed output, rarely changes
- `wsgi.py` — one line, WSGI entry point
- `uwsgi.ini` — uWSGI config, only for server tuning
- `static/css/app.css` — only for visual changes

---

## Secrets and config

Read at startup via `_read_secret(name)` in `app.py`:
- Tries `/etc/passwords/<name>` first (Toolforge Kubernetes secrets)
- Falls back to env var `<NAME_UPPERCASED>`

For local dev: set env vars directly or via `.env` (never committed).

Required secrets: `oauth-client-id`, `oauth-client-secret`, `oauth-redirect-uri`, `secret-key`.  
Optional (falls back to SQLite): `db-host`, `db-user`, `db-password`, `db-name`.

---

## Database

- **Local dev**: SQLite at `instance/dev.db` (auto-created)
- **Production**: MariaDB at `tools.db.svc.wikimedia.cloud`, database name `s12345__chatstream`, charset `utf8mb4`
- SQLAlchemy URL: `mysql+pymysql://USER:PASS@tools.db.svc.wikimedia.cloud/NAME?charset=utf8mb4`

---

## Toolforge reference

Lessons repo (ground truth for Toolforge deployment):
`../wikimedia-coding-agent-lessons/toolforge/lessons.md`

Fetch these docs at the start of any Toolforge-related task:
- https://wikitech.wikimedia.org/wiki/Help:Toolforge/Quickstart
- https://wikitech.wikimedia.org/wiki/Help:Toolforge/Web/Python
- https://wikitech.wikimedia.org/wiki/Help:Toolforge/Kubernetes/Webservices

**Lessons learned from initial deploy (2026-05-02)**:
- Use `python3.13` — bastion and webservice both run 3.13, eliminating version mismatch. We initially used 3.11, which caused venv corruption when pip ran from the bastion (3.13 against a 3.11 venv).
- `python3 -m venv` (with pip) and `ensurepip` hang in the webservice shell pod due to subprocess restrictions. Use `--without-pip` then bootstrap with `curl -sS https://bootstrap.pypa.io/get-pip.py | ~/www/python/venv/bin/python3`.
- Always use `~/www/python/venv/bin/python3 -m pip`, never the `pip` binary (it breaks after reinstalls).
- `WARNING: Ignoring invalid distribution ~ip` — corrupted pip. Fix: `rm -rf ~/www/python/venv/lib/python3.13/site-packages/~ip*` from bastion.
- `lseek: Illegal seek` in logs — harmless uWSGI noise on `/dev/stdout`. Filter with `grep -v lseek`.
- Wikimedia OAuth 2.0 scope is `basic`, not `openid`.
- `deploy.sh` needs no pip step — editable installs pick up code changes via symlink. Pip only needed in webservice shell when dependencies change.

---

## Testing without OAuth

With `FLASK_DEBUG=1`:
```
GET /dev-login?username=YourWikimediaName
```
Sets session directly. Username must be in `SUPERADMIN_USERS` for superadmin access.

## Integration tests

Run against an in-memory SQLite database — no server or OAuth required:

```bash
.venv/bin/python tests/test_webhook.py    # 20 tests: HMAC, replay protection, blacklist/whitelist, dedup
.venv/bin/python tests/test_multiuser.py  # 16 tests: two-moderator DECISION_RANK scenarios
```

`verify_csrf()` accepts the `X-CSRF-Token` request header as well as the `csrf_token` form field — use the header in API test calls to avoid form-encoding overhead.
