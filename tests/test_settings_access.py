#!/usr/bin/env python3
"""
Channel settings page access tests.

Checks who sees the webhook URL and HMAC secret on /channel/<id>/settings:
channel admins and superadmins do; moderators and admins of other channels get
403; anonymous visitors are redirected to login. Only superadmins see the
channel edit form and the signature-format note. Only a superadmin can
regenerate the webhook secret (cut-off); the old secret then gets 403.

Usage:  python test_settings_access.py
"""

import hashlib
import hmac
import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from src.models import db as _db, Channel, ChannelMember

CHANNEL_ID  = 'test-settings'
HMAC_SECRET = 'settings-test-secret'  # pragma: allowlist secret
OTHER_ID     = 'test-settings-other'
OTHER_SECRET = 'other-channel-secret'  # pragma: allowlist secret
SUPERADMIN  = 'Super Admin'
CSRF        = 'fixed-csrf-for-tests'


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
        _db.session.add(Channel(
            id=CHANNEL_ID, name='Settings Test', is_active=True,
            display_token='tok', webhook_hmac_secret=HMAC_SECRET,
        ))
        _db.session.add(ChannelMember(channel_id=CHANNEL_ID, centralauth_id=101,
                                      wiki_username='Chan Admin', role='admin'))
        _db.session.add(ChannelMember(channel_id=CHANNEL_ID, centralauth_id=102,
                                      wiki_username='Chan Mod', role='moderator'))
        # A second channel with its own secret; user 101 has no role there.
        _db.session.add(Channel(
            id=OTHER_ID, name='Other', is_active=True,
            display_token='tok2', webhook_hmac_secret=OTHER_SECRET,
        ))
        _db.session.commit()


def _login(client, caid: int, username: str):
    with client.session_transaction() as s:
        s['centralauth_id'] = caid
        s['wiki_username']  = username
        s['csrf_token']     = CSRF


def _secret(app) -> str:
    with app.app_context():
        return _db.session.get(Channel, CHANNEL_ID).webhook_hmac_secret


def _is_public(app) -> bool:
    with app.app_context():
        return bool(_db.session.get(Channel, CHANNEL_ID).is_public)


def _set_public(app, value: bool):
    with app.app_context():
        _db.session.get(Channel, CHANNEL_ID).is_public = value
        _db.session.commit()


def _webhook(client, secret: str) -> int:
    """POST one chat message signed with `secret`; return the status code."""
    body = json.dumps({
        'message_id': f'rot-{secret[:6]}', 'message_type': 'text',
        'sender_id': 'tester', 'screen_name': 'Tester', 'message': 'hello',
    }).encode()
    sig = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return client.post(f'/webhook/channel/{CHANNEL_ID}', data=body, headers={
        'Content-Type': 'application/json', 'X-Eventyay-Signature': sig,
    }).status_code


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


def run(app):
    url = f'/channel/{CHANNEL_ID}/settings'

    print('\n[1] Channel admin sees webhook URL and secret')
    with app.test_client() as c:
        _login(c, 101, 'Chan Admin')
        r = c.get(url)
        html = r.get_data(as_text=True)
        check('status 200', r.status_code == 200, r.status_code)
        check('webhook URL shown', f'/webhook/channel/{CHANNEL_ID}' in html)
        check('HMAC secret shown', HMAC_SECRET in html)
        for target in ('webhook-url', 'webhook-secret'):
            check(f'copy button + target for {target}',
                  f'data-copy="{target}"' in html and f'id="{target}"' in html)
        check('Eventyay instruction shown', 'Chat Webhook Integration' in html)
        check('superadmin-only channel form hidden', 'name="custom_css"' not in html)
        check('developer signature line hidden', 'X-Eventyay-Signature' not in html)

    print('\n[1b] Channel admin cannot open another channel\'s settings')
    with app.test_client() as c:
        _login(c, 101, 'Chan Admin')
        r = c.get(f'/channel/{OTHER_ID}/settings')
        check('status 403', r.status_code == 403, r.status_code)
        check('other secret not leaked', OTHER_SECRET not in r.get_data(as_text=True))

    print('\n[2] Moderator cannot open settings')
    with app.test_client() as c:
        _login(c, 102, 'Chan Mod')
        r = c.get(url)
        check('status 403', r.status_code == 403, r.status_code)
        check('secret not leaked', HMAC_SECRET not in r.get_data(as_text=True))

    print('\n[3] Superadmin sees webhook and channel form')
    with app.test_client() as c:
        _login(c, 999, SUPERADMIN)
        r = c.get(url)
        html = r.get_data(as_text=True)
        check('status 200', r.status_code == 200, r.status_code)
        check('HMAC secret shown', HMAC_SECRET in html)
        check('channel form shown', 'name="custom_css"' in html)
        check('developer signature line shown', 'X-Eventyay-Signature' in html)

    print('\n[4] Anonymous visitor is redirected to login')
    with app.test_client() as c:
        r = c.get(url)
        check('redirect', r.status_code in (301, 302), r.status_code)
        check('secret not leaked', HMAC_SECRET not in r.get_data(as_text=True))

    # ── Cutting a connection off: "Regenerate webhook secret" ──────────────────
    edit_url = f'/admin/channels/{CHANNEL_ID}/edit'
    form = {'csrf_token': CSRF, 'name': 'Settings Test', 'is_active': 'on'}

    print('\n[5] Checkbox is superadmin-only')
    with app.test_client() as c:
        _login(c, 101, 'Chan Admin')
        check('hidden from channel admin',
              'rotate_webhook_secret' not in c.get(url).get_data(as_text=True))
    with app.test_client() as c:
        _login(c, 999, SUPERADMIN)
        check('shown to superadmin',
              'name="rotate_webhook_secret"' in c.get(url).get_data(as_text=True))

    print('\n[6] Channel admin cannot rotate by posting the form')
    with app.test_client() as c:
        _login(c, 101, 'Chan Admin')
        r = c.post(edit_url, data={**form, 'rotate_webhook_secret': 'on'})  # pragma: allowlist secret
        check('status 403', r.status_code == 403, r.status_code)
        check('secret unchanged', _secret(app) == HMAC_SECRET)

    print('\n[7] Saving without the checkbox keeps the secret and is_public')
    _set_public(app, True)
    with app.test_client() as c:
        _login(c, 999, SUPERADMIN)
        r = c.post(edit_url, data=form)
        check('redirect after save', r.status_code in (301, 302), r.status_code)
        check('secret unchanged', _secret(app) == HMAC_SECRET)
        check('is_public still on', _is_public(app))

    print('\n[8] Superadmin rotates: old secret is cut off, new one works')
    with app.test_client() as c:
        _login(c, 999, SUPERADMIN)
        c.post(edit_url, data={**form, 'rotate_webhook_secret': 'on'})  # pragma: allowlist secret
        new = _secret(app)
        check('secret changed', new != HMAC_SECRET and len(new) >= 32)
        check('is_public still on', _is_public(app))
        check('old secret → 403', _webhook(c, HMAC_SECRET) == 403)
        check('new secret accepted', _webhook(c, new) == 200)
        check('settings page shows new secret', new in c.get(url).get_data(as_text=True))


def main():
    app = _make_app()
    _setup(app)
    run(app)
    print(f'\n{"─" * 40}')
    print(f'{_passed} passed   {_failed} failed')
    sys.exit(0 if _failed == 0 else 1)


if __name__ == '__main__':
    main()
