# Tests

Integration tests using Flask's test client and an in-memory SQLite database.
No running server or external services required.

```
.venv/bin/python tests/test_webhook.py
.venv/bin/python tests/test_multiuser.py
.venv/bin/python tests/test_system_messages.py
```

## test_system_messages.py (64 tests)

Eventyay system messages and the signed challenge:

- **System messages** — return 200 and add nothing to the queue, log or RSS feed; a `system-` message id alone is enough; bad signature → 403 and no change
- **Status** (`Channel.eventyay_status`) — latest of each kind per room, with reason; payloads without `meta.room` go under "room not reported"; chat messages don't touch it
- **Limits** — at 50 rooms the oldest room is dropped; at 10 kinds the oldest kind is dropped; every cap filled with non-ASCII stays within 65,535 bytes; invalid kinds (incl. a trailing newline) are ignored; long names are cut to 255
- **Malformed input** — non-dict `meta` or `room` never breaks intake; broken Unicode (lone surrogates) and control/bidi characters are cleaned, and the settings page stays up
- **Challenge and signatures** — unsigned and correctly signed challenges are echoed; a wrong or non-ASCII signature → 403 (never 500); `System` / ` SYSTEM ` count as system messages
- **Settings page** — shows the status table to superadmins and channel admins; hidden while nothing has been received

## test_webhook.py (28 tests)

Covers the webhook intake pipeline end-to-end:

- **HMAC auth** — wrong/missing/bad-secret signatures → 403
- **Timestamp replay** — messages older or newer than 5 minutes → 400
- **Malformed timestamp** — non-ISO strings now → 400 (was silently ignored)
- **Dedup** — duplicate `message_id` is dropped
- **Emoji remove** — `action: remove` reactions are not stored
- **Normal flow** — message arrives with `status=queued`
- **Blacklist** — message from blocked sender is not stored
- **Whitelist** — message from trusted sender arrives as `approved`
- **Inactive channel** — webhook returns 404

## test_multiuser.py (16 tests)

Simulates two moderators acting on the same queued message, verifying the
`DECISION_RANK` "most restrictive wins" rule:

| Mod1 → Mod2    | Expected outcome |
|----------------|-----------------|
| approve → approve | superseded, 1 log entry |
| approve → reject  | reject wins |
| reject → approve  | approve blocked |
| highlight → approve | approve wins |
| highlight → reject  | reject wins |
| approve → highlight | highlight blocked |
