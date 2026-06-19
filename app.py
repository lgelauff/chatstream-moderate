"""
app.py — Flask application factory for ChatStream Moderate.

Edit SUPERADMIN_USERS below before deploying.
"""

import base64
import hashlib
import os
import secrets
import urllib.parse

import requests
from flask import Flask, redirect, render_template, request, session, url_for
from flask_migrate import Migrate
from flask_session import Session
from src.models import db

TOOL_NAME = "chatstream-moderate"


def _git_version() -> str:
    try:
        import subprocess
        return subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        return 'unknown'


_GIT_VERSION = _git_version()

# ── Community configuration ────────────────────────────────────────────────────
# Add Wikimedia usernames of superadmins here.
SUPERADMIN_USERS: list[str] = ["Effeietsanders", "Exec8", "Arnav Angarkar"]
# ── End of community configuration ────────────────────────────────────────────


def _read_secret(name: str, default: str = '') -> str:
    try:
        with open(f'/etc/passwords/{name}') as f:
            return f.read().strip()
    except FileNotFoundError:
        return os.environ.get(name.upper().replace('-', '_'), default)


def _db_uri() -> str:
    host = _read_secret('db-host', 'tools.db.svc.wikimedia.cloud')
    user = _read_secret('db-user')
    pw   = _read_secret('db-password')
    name = _read_secret('db-name')
    if user and pw and name:
        return f'mysql+pymysql://{user}:{pw}@{host}/{name}?charset=utf8mb4'
    # No DB credentials present. Only fall back to SQLite when explicitly opted
    # in (local dev / tests). In production, refuse to start rather than
    # silently run on an ephemeral SQLite file and diverge or lose data.
    if os.environ.get('ALLOW_SQLITE') == '1':
        return 'sqlite:///dev.db'
    raise RuntimeError(
        'Database credentials missing: set DB_USER, DB_PASSWORD and DB_NAME '
        '(via Toolforge envvars, or /etc/passwords/* secrets). Refusing to fall '
        'back to SQLite in production — that loses data on restart. For local '
        'dev, export ALLOW_SQLITE=1.'
    )


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)

    app.config.update(
        SECRET_KEY                    = _read_secret('secret-key') or secrets.token_hex(32),
        SQLALCHEMY_TRACK_MODIFICATIONS = False,
        SESSION_TYPE                  = 'sqlalchemy',
        SESSION_SQLALCHEMY            = db,
        SESSION_PERMANENT             = False,
        SESSION_COOKIE_HTTPONLY       = True,
        SESSION_COOKIE_SAMESITE       = 'Lax',
        SUPERADMIN_USERS              = SUPERADMIN_USERS,
        OAUTH_CLIENT_ID               = _read_secret('oauth-client-id'),
        OAUTH_CLIENT_SECRET           = _read_secret('oauth-client-secret'),
        OAUTH_REDIRECT_URI            = _read_secret(
            'oauth-redirect-uri', 'http://localhost:5000/oauth-callback'
        ),
    )
    if test_config:
        app.config.update(test_config)

    # Resolve the DB URI only if a test/override hasn't already supplied one, so
    # the production credential check never runs (or raises) under tests.
    if 'SQLALCHEMY_DATABASE_URI' not in app.config:
        app.config['SQLALCHEMY_DATABASE_URI'] = _db_uri()

    if not app.debug:
        app.config['SESSION_COOKIE_SECURE'] = True
        if not _read_secret('secret-key'):
            import warnings
            warnings.warn('SECRET_KEY not set — using ephemeral random key; all sessions will be invalidated on restart', stacklevel=2)

    db.init_app(app)
    Migrate(app, db)
    Session(app)

    import json as _json
    app.jinja_env.filters['fromjson'] = _json.loads

    with app.app_context():
        db.create_all()

    from src.admin_bp  import admin_bp
    from src.display_bp import display_bp
    from src.queue_bp  import queue_bp
    from src.webhook   import webhook_bp
    for bp in (webhook_bp, queue_bp, display_bp, admin_bp):
        app.register_blueprint(bp)

    # ── CSRF token ─────────────────────────────────────────────────────────────
    @app.before_request
    def _ensure_csrf():
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)

    @app.context_processor
    def _globals():
        from src.auth import current_centralauth_id, current_wiki_username, is_superadmin
        return dict(
            csrf_token            = session.get('csrf_token', ''),
            current_username      = current_wiki_username(),
            current_centralauth_id = current_centralauth_id(),
            is_superadmin         = is_superadmin(),
            git_version           = _GIT_VERSION,
        )

    # ── Auth ───────────────────────────────────────────────────────────────────
    @app.get('/login')
    def login():
        if not app.config.get('OAUTH_CLIENT_ID'):
            return 'OAuth not configured — set OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI', 503
        verifier   = secrets.token_urlsafe(64)
        state      = secrets.token_urlsafe(32)
        challenge  = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b'=').decode()
        session['oauth_state']         = state
        session['oauth_code_verifier'] = verifier
        params = urllib.parse.urlencode({
            'response_type':         'code',
            'client_id':             app.config['OAUTH_CLIENT_ID'],
            'redirect_uri':          app.config['OAUTH_REDIRECT_URI'],
            'scope':                 'basic',
            'state':                 state,
            'code_challenge':        challenge,
            'code_challenge_method': 'S256',
        })
        return redirect(f'https://meta.wikimedia.org/w/rest.php/oauth2/authorize?{params}')

    @app.get('/oauth-callback')
    def oauth_callback():
        if request.args.get('state') != session.pop('oauth_state', None):
            app.logger.warning('OAuth state mismatch')
            return 'OAuth error: state mismatch', 400
        verifier = session.pop('oauth_code_verifier', '')
        try:
            tok = requests.post(
                'https://meta.wikimedia.org/w/rest.php/oauth2/access_token',
                data={
                    'grant_type':    'authorization_code',
                    'code':          request.args.get('code'),
                    'redirect_uri':  app.config['OAUTH_REDIRECT_URI'],
                    'client_id':     app.config['OAUTH_CLIENT_ID'],
                    'client_secret': app.config['OAUTH_CLIENT_SECRET'],
                    'code_verifier': verifier,
                },
                timeout=10,
            )
            tok.raise_for_status()
            prof = requests.get(
                'https://meta.wikimedia.org/w/rest.php/oauth2/resource/profile',
                headers={'Authorization': f'Bearer {tok.json()["access_token"]}'},
                timeout=10,
            )
            prof.raise_for_status()
            profile = prof.json()
        except Exception as exc:
            app.logger.warning('OAuth callback failed: %s', exc)
            return 'OAuth login failed', 500

        centralauth_id = profile.get('sub')
        username       = profile.get('username')
        if not centralauth_id or not username:
            return 'OAuth profile missing required fields', 500

        session.clear()
        session['centralauth_id'] = int(centralauth_id)
        session['wiki_username']  = username
        return redirect(url_for('index'))

    @app.post('/logout')
    def logout():
        from src.auth import verify_csrf
        verify_csrf()
        session.clear()
        return redirect(url_for('index'))

    if app.debug:
        @app.get('/dev-login')
        def dev_login():
            username = request.args.get('username', '').strip()
            if not username:
                return 'Usage: /dev-login?username=YourWikimediaName', 400
            session.clear()
            session['centralauth_id'] = abs(hash(username)) % 10_000_000
            session['wiki_username']  = username
            return redirect(url_for('index'))

    # ── Home ───────────────────────────────────────────────────────────────────
    @app.get('/')
    def index():
        from src.auth import current_centralauth_id, is_superadmin
        from src.models import Channel, ChannelMember
        uid      = current_centralauth_id()
        channels = []
        if uid:
            if is_superadmin():
                channels = Channel.query.filter_by(is_active=True).order_by(Channel.name).all()
            else:
                ids      = [m.channel_id for m in ChannelMember.query.filter_by(centralauth_id=uid).all()]
                channels = Channel.query.filter(
                    Channel.id.in_(ids), Channel.is_active == True  # noqa: E712
                ).order_by(Channel.name).all()
        return render_template('index.html', channels=channels)

    return app
