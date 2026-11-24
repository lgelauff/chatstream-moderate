#!/usr/bin/env python3
"""
Sequential integration tests for issue #6: allow/block lists match senders on
stable IDs (sender_id, centralauth_id), never on the display name alone.

Usage:  python test_identity_matching.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
import hmac
import json
import uuid

from app import create_app
from src.models import db as _db, Blacklist, Channel, ChannelMember, GlobalBlacklist, Message, Whitelist

CHANNEL_ID  = 'test-ids'
HMAC_SECRET = 'ids-test-secret'  # pragma: allowlist secret
CSRF        = 'fixed-csrf-for-tests'
MOD_CAID    = 2001

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
            id=CHANNEL_ID, name='Identity Test', is_active=True,
            display_token='tok', webhook_hmac_secret=HMAC_SECRET,
        ))
        _db.session.add(ChannelMember(
            channel_id=CHANNEL_ID, centralauth_id=MOD_CAID,
            wiki_username='Mod', role='admin',
        ))
        _db.session.commit()


def _login(client):
    with client.session_transaction() as s:
        s['centralauth_id'] = MOD_CAID
        s['wiki_username']  = 'Mod'
        s['csrf_token']     = CSRF


def _post(client, **fields) -> int:
    """Send a signed chat message; return the new Message id, or None if not stored."""
    data = {
        'message_id':   str(uuid.uuid4()),
        'sender_id':    str(uuid.uuid4()),
        'screen_name':  'User',
        'message':      'Hello ' + uuid.uuid4().hex[:6],
        'message_type': 'text',
    }
    data.update(fields)
    body = json.dumps(data).encode()
    sig  = 'sha256=' + hmac.new(HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()
    r = client.post(
        f'/webhook/channel/{CHANNEL_ID}',
        data=body,
        headers={'Content-Type': 'application/json', 'X-Eventyay-Signature': sig},
    )
    assert r.status_code == 200, f'post failed {r.status_code}: {r.data}'
    m = Message.query.filter_by(channel_id=CHANNEL_ID, eventyay_message_id=data['message_id']).first()
    return m.id if m else None


def _status(mid):
    return _db.session.get(Message, mid).status if mid else None


def _api(client, action, **fields):
    return client.post(
        f'/api/channel/{CHANNEL_ID}/{action}',
        data=fields,
        headers={'X-CSRF-Token': CSRF},
    ).get_json()


def _add(model, **fields):
    defaults = {'added_by_centralauth_id': MOD_CAID, 'added_by_wiki_username': 'Mod'}
    if model is not GlobalBlacklist:
        defaults['channel_id'] = CHANNEL_ID
    _db.session.add(model(**defaults, **fields))
    _db.session.commit()


def _reset_lists():
    for model in (Blacklist, Whitelist, GlobalBlacklist):
        model.query.delete()
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
    _login(client)

    print('\n[1] Whitelist: a copied display name is not auto-approved')
    _reset_lists()
    _add(Whitelist, sender_id='trusted', screen_name='Alice')
    check('trusted sender → approved', _status(_post(client, sender_id='trusted', screen_name='Alice')) == 'approved')
    check('same name, other sender → queued',
          _status(_post(client, sender_id='impostor', screen_name='Alice')) == 'queued')
    check('same name, no ID → queued',
          _status(_post(client, sender_id='', screen_name='Alice')) == 'queued')

    print('\n[2] Whitelist: centralauth_id alone is enough')
    _reset_lists()
    _add(Whitelist, centralauth_id=42, screen_name='Bob')
    check('matching centralauth_id, new sender_id → approved',
          _status(_post(client, sender_id='bob-device-2', centralauth_id=42, screen_name='Bob')) == 'approved')

    print('\n[3] Whitelist: a legacy name-only entry no longer auto-approves')
    _reset_lists()
    _add(Whitelist, screen_name='Carol')
    check('name-only allow entry → queued', _status(_post(client, screen_name='Carol')) == 'queued')

    print('\n[4] Channel ban: other people with the same name are not affected')
    _reset_lists()
    _add(Blacklist, sender_id='troll', screen_name='Dave')
    check('banned sender dropped', _post(client, sender_id='troll', screen_name='Dave') is None)
    check('banned sender with a new name dropped', _post(client, sender_id='troll', screen_name='Not Dave') is None)
    check('other sender named Dave still queued',
          _status(_post(client, sender_id='real-dave', screen_name='Dave')) == 'queued')

    print('\n[5] Channel ban: an explicit name-only entry still blocks by name')
    _reset_lists()
    _add(Blacklist, screen_name='Spam Bot')
    check('name-only ban drops that name', _post(client, screen_name='Spam Bot') is None)
    check('other names pass', _status(_post(client, screen_name='Eve')) == 'queued')

    print('\n[6] Global ban: matched on IDs, not on the name')
    _reset_lists()
    _add(GlobalBlacklist, sender_id='global-troll', screen_name='Frank')
    check('globally banned sender dropped', _post(client, sender_id='global-troll', screen_name='Frank') is None)
    check('other sender named Frank still queued',
          _status(_post(client, sender_id='real-frank', screen_name='Frank')) == 'queued')

    print('\n[7] Ban button: retro-rejects only that sender\'s queued messages')
    _reset_lists()
    mine   = _post(client, sender_id='spammer', screen_name='Grace')
    theirs = _post(client, sender_id='innocent', screen_name='Grace')
    r = _api(client, 'block-user', screen_name='Grace', sender_id='spammer')
    check('block-user ok', r and r.get('ok'), r)
    check('banned sender\'s queued message rejected', _status(mine) == 'rejected', _status(mine))
    check('same-name sender\'s message still queued', _status(theirs) == 'queued', _status(theirs))

    print('\n[8] Allow button: retro-approves only that sender, needs an ID')
    _reset_lists()
    mine   = _post(client, sender_id='helper', screen_name='Heidi')
    theirs = _post(client, sender_id='copycat', screen_name='Heidi')
    r = _api(client, 'whitelist-user', screen_name='Heidi', sender_id='helper')
    check('whitelist-user ok', r and r.get('ok'), r)
    check('allowed sender\'s queued message approved', _status(mine) == 'approved', _status(mine))
    check('same-name sender\'s message still queued', _status(theirs) == 'queued', _status(theirs))
    r = _api(client, 'whitelist-user', screen_name='Heidi')
    check('allow without any ID refused', r and r.get('ok') is False, r)
    check('no name-only allow entry stored',
          Whitelist.query.filter_by(channel_id=CHANNEL_ID, sender_id=None, centralauth_id=None).count() == 0)

    print('\n[9] Ban button dedupes on ID, not on name')
    _reset_lists()
    _api(client, 'block-user', screen_name='Ivan', sender_id='ivan-1')
    _api(client, 'block-user', screen_name='Ivan', sender_id='ivan-2')
    check('two senders with the same name get two entries',
          Blacklist.query.filter_by(channel_id=CHANNEL_ID, screen_name='Ivan').count() == 2)

    print('\n[10] Export to global list dedupes on ID')
    _reset_lists()
    _add(Blacklist, sender_id='judy-1', screen_name='Judy')
    entry = Blacklist.query.filter_by(sender_id='judy-1').first()
    client.post(f'/channel/{CHANNEL_ID}/blacklist/export', data={'id': entry.id},
                headers={'X-CSRF-Token': CSRF})
    client.post(f'/channel/{CHANNEL_ID}/blacklist/export', data={'id': entry.id},
                headers={'X-CSRF-Token': CSRF})
    check('exported once', GlobalBlacklist.query.filter_by(sender_id='judy-1').count() == 1)
    _add(Blacklist, sender_id='judy-2', screen_name='Judy')
    other = Blacklist.query.filter_by(sender_id='judy-2').first()
    r = client.post(f'/channel/{CHANNEL_ID}/blacklist/export', data={'id': other.id},
                    headers={'X-CSRF-Token': CSRF})
    check('same-name export of another sender does not 500', r.status_code in (200, 302), r.status_code)


def main():
    app = _make_app()
    _setup(app)
    with app.test_client() as client, app.app_context():
        run(app, client)
    print(f'\n{"─" * 40}')
    print(f'{_passed} passed   {_failed} failed')
    sys.exit(0 if _failed == 0 else 1)


if __name__ == '__main__':
    main()
