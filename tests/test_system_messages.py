#!/usr/bin/env python3
"""
Eventyay system message and signed-challenge tests.

System messages (message_type "system" or message_id "system-…") describe the
connection itself. They must never reach the queue, moderation log or RSS feed.
The latest message of each kind is kept per room in Channel.eventyay_status,
within size limits. A signed challenge is checked against the channel secret.

Usage:  python test_system_messages.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone

from app import create_app
from src.models import db as _db, Channel, ChannelMember, Message, ModerationLog
from src.webhook import STATUS_MAX_ROOMS, STATUS_MAX_KINDS, STATUS_MAX_BYTES

CHANNEL_ID  = 'test-sys'
LIMITS_ID   = 'test-sys-limits'
SIZE_ID     = 'test-sys-size'
EMPTY_ID    = 'test-sys-empty'
ARCHIVED_ID = 'test-sys-archived'
MARIADB_TEXT_BYTES = 65_535
HMAC_SECRET = 'system-test-secret'  # pragma: allowlist secret
SUPERADMIN  = 'Super Admin'


def _make_app():
    return create_app({
        'TESTING':                 True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SECRET_KEY':              'test-only',  # pragma: allowlist secret
        'SUPERADMIN_USERS':        [SUPERADMIN],
        'OAUTH_CLIENT_ID':         None,
        'SESSION_TYPE':            'sqlalchemy',
    })


def _setup(app):
    with app.app_context():
        for cid in (CHANNEL_ID, LIMITS_ID, SIZE_ID, EMPTY_ID):
            _db.session.add(Channel(
                id=cid, name=cid, is_active=True,
                display_token='tok', webhook_hmac_secret=HMAC_SECRET,
            ))
        _db.session.add(Channel(
            id=ARCHIVED_ID, name=ARCHIVED_ID, is_active=False,
            display_token='tok', webhook_hmac_secret=HMAC_SECRET,
        ))
        _db.session.add(ChannelMember(channel_id=CHANNEL_ID, centralauth_id=201,
                                      wiki_username='Chan Admin', role='admin'))
        _db.session.commit()


def _sig(body: bytes, secret: str = HMAC_SECRET) -> str:
    return 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _post(client, data: dict, secret: str = HMAC_SECRET, channel: str = CHANNEL_ID):
    body = json.dumps(data).encode()
    return client.post(
        f'/webhook/channel/{channel}',
        data=body,
        headers={'Content-Type': 'application/json', 'X-Eventyay-Signature': _sig(body, secret)},
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _system(kind='test', room=None, reason=None, **overrides) -> dict:
    meta = {'kind': kind}
    if room is not None:
        meta['room'] = room
    if reason is not None:
        meta['reason'] = reason
    base = {
        'message_id':   'system-' + uuid.uuid4().hex,
        'message_type': 'system',
        'channel':      'eventyay-channel',
        'timestamp':    _now(),
        'screen_name':  None,
        'sender_id':    None,
        'message':      'Test event from Eventyay room Main Hall',
        'meta':         meta,
    }
    base.update(overrides)
    return base


def _chat(room=None) -> dict:
    data = {
        'message_id':   str(uuid.uuid4()),
        'message_type': 'text',
        'timestamp':    _now(),
        'screen_name':  'User',
        'sender_id':    'sender-' + uuid.uuid4().hex,
        'message':      'Hello',
        'meta':         {},
    }
    if room is not None:
        data['meta']['room'] = room
    return data


def _counts(app):
    with app.app_context():
        return (Message.query.filter_by(channel_id=CHANNEL_ID).count(),
                ModerationLog.query.filter_by(channel_id=CHANNEL_ID).count())


def _status(app, channel=CHANNEL_ID) -> dict:
    with app.app_context():
        raw = _db.session.get(Channel, channel).eventyay_status
        return json.loads(raw) if raw else {}


def _set_status(app, status: dict, channel=LIMITS_ID):
    with app.app_context():
        _db.session.get(Channel, channel).eventyay_status = json.dumps(status)
        _db.session.commit()


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
    main_hall = {'id': 12, 'name': 'Main Hall'}

    print('\n[1] Signed test message: 200, status recorded, nothing queued')
    before = _counts(app)
    r = _post(client, _system('test', room=main_hall))
    check('status 200', r.status_code == 200, r.status_code)
    check('response marks system', (r.get_json() or {}).get('system') is True, r.get_json())
    check('no message or log row added', _counts(app) == before, (before, _counts(app)))
    st = _status(app).get('12', {})
    check('room name stored', st.get('name') == 'Main Hall', st)
    check('test time stored', 'at' in st.get('last', {}).get('test', {}), st)

    print('\n[3] Other kinds are kept too, with reason; latest only')
    _post(client, _system('disconnected', room=main_hall, reason='revoked'))
    _post(client, _system('test', room=main_hall))
    last = _status(app).get('12', {}).get('last', {})
    check('both kinds present', set(last) == {'test', 'disconnected'}, last)
    check('reason stored', last.get('disconnected', {}).get('reason') == 'revoked', last)
    check('one entry per kind (no history)', isinstance(last.get('test'), dict), last)

    print('\n[4] message_id prefix alone marks a system message')
    before = _counts(app)
    r = _post(client, _system('test', room=main_hall, message_type='text'))
    check('status 200', r.status_code == 200, r.status_code)
    check('nothing queued', _counts(app) == before)

    print('\n[5] Bad signature: 403 and status unchanged')
    before_status = _status(app)
    r = _post(client, _system('test', room={'id': 77, 'name': 'Fake'}), secret='wrong-secret')  # pragma: allowlist secret
    check('status 403', r.status_code == 403, r.status_code)
    check('status unchanged', _status(app) == before_status)

    print('\n[6] Chat messages are queued and do not touch the status')
    before_status = _status(app)
    before = _counts(app)
    r = _post(client, _chat(room=main_hall))
    check('status 200', r.status_code == 200, r.status_code)
    check('one message queued', _counts(app)[0] == before[0] + 1, (before, _counts(app)))
    check('status unchanged', _status(app) == before_status)

    print('\n[6b] RSS feed, with everything approved, has chat but no system messages')
    with app.app_context():
        for m in Message.query.filter_by(channel_id=CHANNEL_ID).all():
            m.status = 'approved'
            m.processed_at = datetime.now(timezone.utc)
        _db.session.commit()
    rss = client.get(f'/rss/{CHANNEL_ID}').get_data(as_text=True)
    check('approved chat message in feed', 'Hello' in rss)
    check('no system message in feed', 'Test event from Eventyay' not in rss)

    print('\n[7] No meta.room → stored under "" (room not reported)')
    _post(client, _system('test'))
    check('"" key present', 'test' in _status(app).get('', {}).get('last', {}), _status(app))

    print('\n[8] Malformed input never breaks intake')
    r = _post(client, _system('test', meta=['not', 'a', 'dict']))
    check('list meta → 200', r.status_code == 200, r.status_code)
    r = _post(client, _system('bad kind!', room=main_hall))
    check('invalid kind → 200', r.status_code == 200, r.status_code)
    check('invalid kind not stored', 'bad kind!' not in _status(app).get('12', {}).get('last', {}))
    r = _post(client, _system('test', room={'id': 13, 'name': 'x' * 400}))
    check('long name → 200', r.status_code == 200, r.status_code)
    check('name truncated to 255', len(_status(app).get('13', {}).get('name', '')) == 255)
    bad_chat = _chat()
    bad_chat['meta'] = {'room': 'not-a-dict'}
    r = _post(client, bad_chat)
    check('chat with non-dict room → 200', r.status_code == 200, r.status_code)

    print(f'\n[9] Room limit ({STATUS_MAX_ROOMS}): oldest room dropped')
    full = {str(i): {'name': f'R{i}', 'last': {'test': {'at': f'2026-01-01T00:{i:02d}:00Z'}}}
            for i in range(STATUS_MAX_ROOMS)}
    full['5']['last']['test']['at'] = '2025-01-01T00:00:00Z'   # room 5 is the oldest
    _set_status(app, full)
    r = _post(client, _system('test', room={'id': 'new', 'name': 'New'}), channel=LIMITS_ID)
    st = _status(app, LIMITS_ID)
    check('status 200', r.status_code == 200, r.status_code)
    check('still at the limit', len(st) == STATUS_MAX_ROOMS, len(st))
    check('new room kept', 'new' in st)
    check('oldest room dropped', '5' not in st)
    _post(client, _system('test', room={'id': '7', 'name': 'R7'}), channel=LIMITS_ID)
    check('updating a known room keeps the count', len(_status(app, LIMITS_ID)) == STATUS_MAX_ROOMS)

    print(f'\n[10] Kind limit ({STATUS_MAX_KINDS}): oldest kind dropped')
    kinds = {f'k{i}': {'at': f'2026-01-01T00:{i:02d}:00Z'} for i in range(STATUS_MAX_KINDS)}
    kinds['k3']['at'] = '2025-01-01T00:00:00Z'   # k3 is the oldest
    _set_status(app, {'1': {'name': 'One', 'last': kinds}})
    r = _post(client, _system('brand-new', room={'id': 1, 'name': 'One'}), channel=LIMITS_ID)
    last = _status(app, LIMITS_ID).get('1', {}).get('last', {})
    check('status 200', r.status_code == 200, r.status_code)
    check('still at the limit', len(last) == STATUS_MAX_KINDS, len(last))
    check('new kind kept', 'brand-new' in last)
    check('oldest kind dropped', 'k3' not in last)

    print('\n[11] Challenge: unsigned echoed, correct signature echoed, wrong refused')
    token = 'tok-' + uuid.uuid4().hex
    url = f'/webhook/channel/{CHANNEL_ID}?challenge={token}'
    r = client.get(url)
    check('unsigned → 200 + echo', r.status_code == 200 and (r.get_json() or {}).get('challenge') == token,
          (r.status_code, r.get_json()))
    r = client.get(url, headers={'X-Eventyay-Signature': _sig(token.encode())})
    check('correct signature → 200 + echo',
          r.status_code == 200 and (r.get_json() or {}).get('challenge') == token, r.status_code)
    r = client.get(url, headers={'X-Eventyay-Signature': _sig(token.encode(), 'wrong-secret')})  # pragma: allowlist secret
    check('wrong signature → 403', r.status_code == 403, r.status_code)

    print('\n[12] Settings page shows the status')
    with app.test_client() as admin:
        with admin.session_transaction() as s:
            s['centralauth_id'] = 1
            s['wiki_username']  = SUPERADMIN
        r = admin.get(f'/channel/{CHANNEL_ID}/settings')
        html = r.get_data(as_text=True)
        check('settings 200', r.status_code == 200, r.status_code)
        check('shows Main Hall', 'Main Hall' in html)
        check('shows reason', 'disconnected (revoked)' in html)
        check('shows unreported room', 'Room not reported' in html)
        r = admin.get(f'/channel/{LIMITS_ID}/settings')
        check('limits channel renders', r.status_code == 200, r.status_code)
        r = admin.get(f'/channel/{EMPTY_ID}/settings')
        html = r.get_data(as_text=True)
        check('empty status: page 200', r.status_code == 200, r.status_code)
        check('empty status: no Eventyay connection block', 'Eventyay connection' not in html)

    print('\n[12b] A plain channel admin sees the status block')
    with app.test_client() as chan_admin:
        with chan_admin.session_transaction() as s:
            s['centralauth_id'] = 201
            s['wiki_username']  = 'Chan Admin'
        r = chan_admin.get(f'/channel/{CHANNEL_ID}/settings')
        html = r.get_data(as_text=True)
        check('channel admin 200', r.status_code == 200, r.status_code)
        check('channel admin sees Main Hall status', 'Eventyay connection' in html and 'Main Hall' in html)

    print(f'\n[13] Size budget: every cap filled with non-ASCII stays within MariaDB TEXT')
    long_reason = 'é' * 200
    for room in range(STATUS_MAX_ROOMS):
        for k in range(STATUS_MAX_KINDS):
            _post(client, _system(f'k{k:02d}'.ljust(32, 'x'), reason=long_reason,
                                  room={'id': f'{room:064d}', 'name': '😀' * 400}), channel=SIZE_ID)
    with app.app_context():
        raw = _db.session.get(Channel, SIZE_ID).eventyay_status
    check('stored bytes within STATUS_MAX_BYTES', len(raw.encode()) <= STATUS_MAX_BYTES, len(raw.encode()))
    check('stored bytes within TEXT', len(raw.encode()) <= MARIADB_TEXT_BYTES, len(raw.encode()))
    st = json.loads(raw)
    check('round-trips as JSON object', isinstance(st, dict) and len(st) >= 1, type(st))
    check('newest room kept', f'{STATUS_MAX_ROOMS - 1:064d}' in st)

    print('\n[14] message_type casing and spacing still mark a system message')
    for variant in ('System', ' SYSTEM '):
        before = _counts(app)
        r = _post(client, _system('test', room=main_hall, message_type=variant,
                                  message_id=str(uuid.uuid4())))
        check(f'{variant!r} → 200 system', r.status_code == 200 and (r.get_json() or {}).get('system') is True,
              (r.status_code, r.get_json()))
        check(f'{variant!r} not queued', _counts(app) == before, (before, _counts(app)))

    print('\n[15] Kind with a trailing newline is not stored')
    _post(client, _system('test\n', room={'id': 15, 'name': 'Newline room'}))
    check('no entry for room 15', '15' not in _status(app), _status(app).get('15'))

    print('\n[16] Non-ASCII signature header → 403, not 500')
    body = json.dumps(_system('test', room=main_hall)).encode()
    r = client.post(f'/webhook/channel/{CHANNEL_ID}', data=body,
                    headers={'Content-Type': 'application/json', 'X-Eventyay-Signature': 'sha256=é'})
    check('POST → 403', r.status_code == 403, r.status_code)
    r = client.get(f'/webhook/channel/{CHANNEL_ID}?challenge=abc', headers={'X-Eventyay-Signature': 'sha256=é'})
    check('challenge GET → 403', r.status_code == 403, r.status_code)

    print('\n[17] Room id 0 is a real room, not "room not reported"')
    _post(client, _system('test', room={'id': 0, 'name': 'Room zero'}))
    check('stored under "0"', _status(app).get('0', {}).get('name') == 'Room zero', _status(app).get('0'))

    print('\n[18] Broken Unicode and control characters never break the settings page')
    r = _post(client, _system('disconnected', reason='bad\ud800‮reason',
                              room={'id': 'r\ud800\u0007', 'name': 'Bad\ud800‮Name'}))
    check('signed message accepted', r.status_code == 200, r.status_code)
    st = _status(app)
    stored = json.dumps(st, ensure_ascii=False)
    check('nothing unencodable stored', all(not (0xD800 <= ord(ch) <= 0xDFFF) for ch in stored))
    check('no control/bidi characters stored', '‮' not in stored and '\u0007' not in stored)
    with app.test_client() as admin:
        with admin.session_transaction() as s:
            s['centralauth_id'] = 1
            s['wiki_username']  = SUPERADMIN
        r = admin.get(f'/channel/{CHANNEL_ID}/settings')
        check('settings page still 200', r.status_code == 200, r.status_code)
    # A value stored before cleaning existed must not break the page either.
    with app.app_context():
        ch = _db.session.get(Channel, EMPTY_ID)
        ch.eventyay_status = json.dumps({'x': {'name': 'Old\ud800', 'last': {'test': {'at': 'now', 'reason': '\ud800'}}}})
        _db.session.commit()
    with app.test_client() as admin:
        with admin.session_transaction() as s:
            s['centralauth_id'] = 1
            s['wiki_username']  = SUPERADMIN
        r = admin.get(f'/channel/{EMPTY_ID}/settings')
        check('page with an old unclean value still 200', r.status_code == 200, r.status_code)

    print('\n[19] Archived channel: the setup challenge is refused like messages are')
    url = f'/webhook/channel/{ARCHIVED_ID}?challenge=abc'
    check('unsigned challenge → 404', client.get(url).status_code == 404)
    check('signed challenge → 404',
          client.get(url, headers={'X-Eventyay-Signature': _sig(b'abc')}).status_code == 404)


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
