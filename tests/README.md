# Tests

Integration tests using Flask's test client and an in-memory SQLite database.
No running server or external services required.

```
.venv/bin/python tests/test_webhook.py
.venv/bin/python tests/test_multiuser.py
.venv/bin/python tests/test_identity_matching.py
.venv/bin/python tests/test_settings_access.py
.venv/bin/python tests/test_system_messages.py
```

## test_settings_access.py (30 tests)

Who sees the webhook URL and HMAC secret on the channel settings page:
channel admins and superadmins do; moderators and admins of other channels get
403; anonymous visitors are redirected to login. Only superadmins see the
channel edit form and the signature-format note.

Also covers cutting a connection off: only a superadmin can tick "Regenerate
webhook secret"; afterwards the old secret gets 403 and the new one is
accepted. Saving that form no longer resets `is_public`.

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

## test_identity_matching.py (23 tests)

Allow/block lists match senders on stable IDs, not on display names (issue #6):

- **Allow list** — a copied display name, or a message without any ID, is never auto-approved; `centralauth_id` alone is enough; legacy name-only allow entries no longer auto-approve
- **Channel and global bans** — entries with an ID block only that sender (under any name); people sharing the name still get through; explicit name-only bans still block by name
- **Ban / Allow buttons** — retro-apply only to that sender's queued messages; Allow without any ID is refused; Ban dedupes on ID, so two people with the same name get two entries
- **Export to global list** — dedupes on ID; a same-name entry for another sender doesn't 500
