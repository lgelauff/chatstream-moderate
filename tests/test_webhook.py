#!/usr/bin/env python3
"""
Sequential webhook integration tests.

Covers HMAC auth, replay protection, timestamp parsing, dedup, emoji filtering,
blacklist/whitelist auto-routing, and inactive-channel rejection.

Usage:  python test_webhook.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone, timedelta

from app import create_app
from src.models import db as _db, Channel, Message, Blacklist, Whitelist

CHANNEL_ID  = 'test-wh'
HMAC_SECRET = 'webhook-test-secret'  # pragma: allowlist secret

# ── App + fixtures ─────────────────────────────────────────────────────────────

def _make_app():
    return create_app({
        'TESTING':                 True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SECRET_KEY':              'test-only',  # pragma: allowlist secret
        'SUPERADMIN_USERS':        [],
        'OAUTH_CLIENT_ID':         None,
        'SESSION_TYPE':            'sqlalchemy',
    })


def _setup(app):
    with app.app_context():
        _db.session.add(Channel(
            id=CHANNEL_ID, name='Webhook Test', is_active=True,
            display_token='tok', webhook_hmac_secret=HMAC_SECRET,
            emoji_auto_approve=True,
        ))
        _db.session.commit()


def _sig(body: bytes, secret: str = HMAC_SECRET) -> str:
    return 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _post(client, data: dict, secret: str = HMAC_SECRET, sig_override: str | None = None):
    body = json.dumps(data).encode()
    sig  = sig_override if sig_override is not None else _sig(body, secret)
    return client.post(
        f'/webhook/channel/{CHANNEL_ID}',
        data=body,
        headers={'Content-Type': 'application/json', 'X-Eventyay-Signature': sig},
    )


def _payload(**overrides) -> dict:
    base = {
        'message_id':   str(uuid.uuid4()),
        'sender_id':    'default-sender',
        'screen_name':  'User',
        'message':      'Hello world',
        'message_type': 'text',
    }
    base.update(overrides)
    return base


def _count(app) -> int:
    with app.app_context():
        return Message.query.filter_by(channel_id=CHANNEL_ID).count()


def _last_status(app) -> str | None:
    with app.app_context():
        m = Message.query.filter_by(channel_id=CHANNEL_ID).order_by(Message.id.desc()).first()
        return m.status if m else None


def _last_type(app) -> str | None:
    with app.app_context():
        m = Message.query.filter_by(channel_id=CHANNEL_ID).order_by(Message.id.desc()).first()
        return m.message_type if m else None


# ── Test runner ────────────────────────────────────────────────────────────────

_passed = _failed = 0


def check(name, cond, detail=''):
    global _passed, _failed
    if cond:
        print(f'  PASS  {name}')
        _passed += 1
    else:
        print(f'  FAIL  {name}' + (f'  ({detail})' if detail else ''))
        _failed += 1


def run(app, client):

    # [1] HMAC authentication
    print('\n[1] HMAC authentication')
    r = _post(client, _payload(), sig_override='sha256=deadbeef')
    check('wrong signature → 403',    r.status_code == 403, r.status_code)

    r = _post(client, _payload(), sig_override='')
    check('empty signature → 403',    r.status_code == 403, r.status_code)

    r = _post(client, _payload(), secret='wrong-secret')
    check('wrong secret → 403',       r.status_code == 403, r.status_code)

    r = _post(client, _payload())
    check('correct signature → 200',  r.status_code == 200, r.status_code)

    # [2] Timestamp replay protection
    print('\n[2] Timestamp replay protection')
    old = (datetime.now(timezone.utc) - timedelta(seconds=400)).isoformat()
    r = _post(client, _payload(timestamp=old))
    check('timestamp 400 s old → 400',    r.status_code == 400, r.status_code)

    future = (datetime.now(timezone.utc) + timedelta(seconds=400)).isoformat()
    r = _post(client, _payload(timestamp=future))
    check('timestamp 400 s future → 400', r.status_code == 400, r.status_code)

    fresh = datetime.now(timezone.utc).isoformat()
    r = _post(client, _payload(timestamp=fresh))
    check('fresh timestamp → 200',        r.status_code == 200, r.status_code)

    no_ts = _payload()
    no_ts.pop('timestamp', None)
    r = _post(client, no_ts)
    check('no timestamp field → 200',     r.status_code == 200, r.status_code)

    # [3] Malformed timestamp (security fix: was silently ignored before)
    print('\n[3] Malformed timestamp → 400  (was silently skipped before the fix)')
    r = _post(client, _payload(timestamp='not-a-date'))
    check('"not-a-date" → 400',  r.status_code == 400, r.status_code)

    r = _post(client, _payload(timestamp='2024-99-99T00:00:00'))
    check('"2024-99-99" → 400',  r.status_code == 400, r.status_code)

    r = _post(client, _payload(timestamp=''))
    check('empty string → 200',  r.status_code == 200, r.status_code)

    # [4] Duplicate message_id dedup
    print('\n[4] Duplicate message_id dedup')
    before = _count(app)
    mid = str(uuid.uuid4())
    _post(client, _payload(message_id=mid, message='First'))
    _post(client, _payload(message_id=mid, message='Second'))   # same ID
    check('duplicate not stored', _count(app) == before + 1, _count(app) - before)

    # [5] Emoji "remove" action filtered
    print('\n[5] Emoji "remove" action filtered')
    before = _count(app)
    r = _post(client, _payload(message_type='emoji', message='👍', meta={'action': 'remove'}))
    check('remove emoji → 200',   r.status_code == 200, r.status_code)
    check('not stored',           _count(app) == before, _count(app) - before)

    r = _post(client, _payload(message_type='emoji', message='👍', meta={'action': 'add'}))
    check('add emoji stored',     _count(app) == before + 1, _count(app) - before)

    # [6] Normal message arrives as queued
    print('\n[6] Normal message → queued')
    _post(client, _payload(sender_id='fresh-' + str(uuid.uuid4()), screen_name='Normal'))
    check('status = queued', _last_status(app) == 'queued', _last_status(app))

    # [7] Blacklisted sender → message dropped at intake
    print('\n[7] Blacklist → message dropped')
    blocked_sid = 'blocked-' + str(uuid.uuid4())
    with app.app_context():
        _db.session.add(Blacklist(
            channel_id=CHANNEL_ID, sender_id=blocked_sid, screen_name='BlockedUser',
            added_by_centralauth_id=1, added_by_wiki_username='admin',
        ))
        _db.session.commit()
    before = _count(app)
    _post(client, _payload(sender_id=blocked_sid, screen_name='BlockedUser'))
    check('blocked sender not stored', _count(app) == before, _count(app) - before)

    # [8] Whitelisted sender → message auto-approved
    print('\n[8] Whitelist → auto-approved')
    trusted_sid = 'trusted-' + str(uuid.uuid4())
    with app.app_context():
        _db.session.add(Whitelist(
            channel_id=CHANNEL_ID, sender_id=trusted_sid, screen_name='TrustedUser',
            added_by_centralauth_id=1, added_by_wiki_username='admin',
        ))
        _db.session.commit()
    _post(client, _payload(sender_id=trusted_sid, screen_name='TrustedUser'))
    check('whitelisted → approved', _last_status(app) == 'approved', _last_status(app))

    # [9] Inactive channel → 404
    print('\n[9] Inactive channel → 404')
    with app.app_context():
        Channel.query.get(CHANNEL_ID).is_active = False
        _db.session.commit()
    r = _post(client, _payload())
    check('inactive → 404', r.status_code == 404, r.status_code)
    with app.app_context():
        Channel.query.get(CHANNEL_ID).is_active = True
        _db.session.commit()

    # [10] Malformed JSON body → 400
    print('\n[10] Malformed JSON body → 400')
    body = b'not json at all'
    sig  = _sig(body)
    r = client.post(
        f'/webhook/channel/{CHANNEL_ID}',
        data=body,
        headers={'Content-Type': 'application/json', 'X-Eventyay-Signature': sig},
    )
    check('bad JSON → 400', r.status_code == 400, r.status_code)

    # [11] message_type normalisation (issue #2)
    # Eventyay may send its native event name; an out-of-range value used to
    # corrupt the row and 500 every queue read. It must be mapped to text/emoji/qa.
    print('\n[11] message_type normalisation → no out-of-range values reach the DB')
    cases = [
        ('channel.message', 'text',  'text'),
        ('message',         'text',  'text'),
        ('reaction',        'emoji', '👍'),
        ('event.reaction',  'emoji', '🔥'),
        ('question',        'qa',    'A question?'),
        ('totally-unknown', 'text',  'mystery'),   # unknown → safe default
        ('',                'text',  'empty type'),
    ]
    for raw, expected, body_text in cases:
        _post(client, _payload(sender_id='nt-' + str(uuid.uuid4()),
                               message=body_text, message_type=raw))
        check(f'{raw!r} → {expected!r}', _last_type(app) == expected, _last_type(app))

    # Every stored type must be one of the queue's renderable enum values, so a
    # row can never raise on load and stall the moderation queue.
    with app.app_context():
        bad = [m.message_type for m in Message.query.filter_by(channel_id=CHANNEL_ID).all()
               if m.message_type not in ('text', 'emoji', 'qa')]
    check('no out-of-range message_type persisted', not bad, bad)


def main():
    app = _make_app()
    _setup(app)
    with app.test_client() as client:
        run(app, client)
    print(f'\n{"─" * 40}')
    print(f'{_passed} passed   {_failed} failed')
    sys.exit(0 if _failed == 0 else 1)


if __name__ == '__main__':
    main()
