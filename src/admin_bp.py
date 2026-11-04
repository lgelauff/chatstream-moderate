import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
import requests as _http
from flask import Blueprint, current_app, abort, request, render_template, redirect, url_for, flash, jsonify
from src.models import db, Channel, ChannelMember, Blacklist, GlobalBlacklist, Whitelist
from src.auth import superadmin_required, channel_role_required, verify_csrf, current_centralauth_id, current_wiki_username
from src.utils import generate_token

SIMULATION_CHANNEL_ID = 'simulation'

admin_bp = Blueprint('admin', __name__)


# ── Superadmin ─────────────────────────────────────────────────────────────────

@admin_bp.get('/admin/')
@superadmin_required
def dashboard():
    all_channels = Channel.query.order_by(Channel.name).all()
    active   = [c for c in all_channels if not c.archived_at]
    archived = [c for c in all_channels if c.archived_at]
    return render_template('admin/dashboard.html', active=active, archived=archived)


@admin_bp.get('/admin/channels')
@superadmin_required
def channels():
    all_channels = Channel.query.order_by(Channel.name).all()
    return render_template('admin/channels.html',
                           active=[c for c in all_channels if not c.archived_at],
                           archived=[c for c in all_channels if c.archived_at])


@admin_bp.post('/admin/channels/create')
@superadmin_required
def channels_create():
    verify_csrf()
    cid  = request.form.get('id', '').strip().lower()
    name = request.form.get('name', '').strip()
    if not cid or not name:
        flash('ID and name are required.')
        return redirect(url_for('admin.channels'))
    if Channel.query.get(cid):
        flash('A channel with that ID already exists.')
        return redirect(url_for('admin.channels'))
    db.session.add(Channel(
        id=cid, name=name,
        description=request.form.get('description', '').strip() or None,
        display_token=generate_token(),
        webhook_hmac_secret=generate_token(),
    ))
    db.session.commit()
    return redirect(url_for('admin.channel_edit', channel_id=cid))


@admin_bp.get('/admin/channels/<channel_id>/edit')
@superadmin_required
def channel_edit(channel_id: str):
    return redirect(url_for('admin.channel_settings', channel_id=channel_id))


@admin_bp.post('/admin/channels/<channel_id>/edit')
@superadmin_required
def channel_edit_post(channel_id: str):
    verify_csrf()
    ch = Channel.query.get_or_404(channel_id)
    ch.name        = request.form.get('name', ch.name).strip()
    ch.description = request.form.get('description', '').strip() or None
    ch.is_active   = 'is_active' in request.form
    # is_public is owned by the Moderation form (channel_settings_post); this
    # form has no such field, so setting it here would make every save private.
    ch.custom_css  = request.form.get('custom_css', '').strip() or None
    # Cut-off: a new secret makes every sender holding the old one get 403.
    rotated = 'rotate_webhook_secret' in request.form
    if rotated:
        ch.webhook_hmac_secret = generate_token()
    db.session.commit()
    flash('Channel updated. New webhook secret generated: paste it into Eventyay to reconnect.'
          if rotated else 'Channel updated.')
    return redirect(url_for('admin.channel_edit', channel_id=channel_id))


@admin_bp.post('/admin/channels/<channel_id>/delete')
@superadmin_required
def channel_delete(channel_id: str):
    verify_csrf()
    db.session.delete(Channel.query.get_or_404(channel_id))
    db.session.commit()
    return redirect(url_for('admin.channels'))


@admin_bp.post('/channel/<channel_id>/members/add')
@channel_role_required('admin')
def member_add(channel_id: str):
    verify_csrf()
    from src.auth import is_superadmin
    Channel.query.get_or_404(channel_id)
    username = request.form.get('wiki_username', '').strip()
    caid     = request.form.get('centralauth_id', '').strip()
    role     = request.form.get('role', '').strip()
    if role not in ('admin', 'moderator') or not username or not caid:
        flash('Invalid request.')
        return redirect(url_for('admin.channel_settings', channel_id=channel_id))
    if role == 'admin' and not is_superadmin():
        abort(403)
    existing = ChannelMember.query.filter_by(channel_id=channel_id, centralauth_id=int(caid)).first()
    if existing:
        existing.role = role; existing.wiki_username = username
    else:
        db.session.add(ChannelMember(channel_id=channel_id, centralauth_id=int(caid),
                                     wiki_username=username, role=role))
    db.session.commit()
    return redirect(url_for('admin.channel_settings', channel_id=channel_id))


@admin_bp.post('/channel/<channel_id>/members/remove')
@channel_role_required('admin')
def member_remove(channel_id: str):
    verify_csrf()
    from src.auth import is_superadmin
    caid = request.form.get('centralauth_id', '').strip()
    role = request.form.get('role', '').strip()
    if not caid or role not in ('admin', 'moderator'):
        return redirect(url_for('admin.channel_settings', channel_id=channel_id))
    if role == 'admin' and not is_superadmin():
        abort(403)
    ChannelMember.query.filter_by(channel_id=channel_id, centralauth_id=int(caid), role=role).delete()
    db.session.commit()
    return redirect(url_for('admin.channel_settings', channel_id=channel_id))


@admin_bp.post('/admin/simulation/activate')
@superadmin_required
def simulation_activate():
    verify_csrf()
    ch = Channel.query.get(SIMULATION_CHANNEL_ID)
    if not ch:
        ch = Channel(
            id=SIMULATION_CHANNEL_ID,
            name='Simulation',
            description='Auto-created test channel for simulation.',
            is_active=True,
            display_token=generate_token(),
            webhook_hmac_secret=generate_token(),
        )
        db.session.add(ch)
        db.session.commit()
        flash('Simulation channel created and activated.')
    elif not ch.is_active:
        ch.is_active = True
        db.session.commit()
        flash('Simulation channel activated.')
    else:
        flash('Simulation channel is already active.')
    return redirect(url_for('admin.simulation'))


@admin_bp.get('/admin/simulation')
@superadmin_required
def simulation():
    channel = Channel.query.get(SIMULATION_CHANNEL_ID)
    return render_template('admin/simulation.html', channel=channel)


@admin_bp.post('/admin/simulation/inject')
@superadmin_required
def simulation_inject():
    verify_csrf()
    channel = Channel.query.get(SIMULATION_CHANNEL_ID)
    if not channel or not channel.is_active:
        return jsonify({'ok': False, 'error': 'Simulation channel not active'}), 400
    data = request.get_json(force=True) or {}
    data.setdefault('message_id', str(uuid.uuid4()))
    data.setdefault('timestamp', datetime.now(timezone.utc).isoformat())
    data.setdefault('screen_name', 'Tester')
    data.setdefault('message', 'Test message')
    data.setdefault('message_type', 'text')
    body = json.dumps(data).encode()
    sig  = 'sha256=' + hmac.new(
        channel.webhook_hmac_secret.encode(), body, hashlib.sha256
    ).hexdigest()
    base_url = request.host_url.rstrip('/')
    try:
        resp = _http.post(
            f'{base_url}/webhook/channel/{SIMULATION_CHANNEL_ID}',
            data=body,
            headers={
                'Content-Type': 'application/json',
                'X-Eventyay-Signature': sig,
            },
            timeout=10,
        )
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 502
    if resp.status_code == 200:
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': f'Webhook returned {resp.status_code}'}), 502


@admin_bp.get('/admin/global-blacklist')
@superadmin_required
def global_blacklist():
    return render_template('admin/global_blacklist.html',
                           entries=GlobalBlacklist.query.order_by(GlobalBlacklist.added_at.desc()).all())


@admin_bp.post('/admin/global-blacklist/remove')
@superadmin_required
def global_blacklist_remove():
    verify_csrf()
    GlobalBlacklist.query.filter_by(id=int(request.form.get('id', 0))).delete()
    db.session.commit()
    return redirect(url_for('admin.global_blacklist'))


# ── Channel admin ──────────────────────────────────────────────────────────────

@admin_bp.get('/channel/<channel_id>/settings')
@channel_role_required('admin')
def channel_settings(channel_id: str):
    channel     = Channel.query.get_or_404(channel_id)
    admins      = ChannelMember.query.filter_by(channel_id=channel_id, role='admin').all()
    moderators  = ChannelMember.query.filter_by(channel_id=channel_id, role='moderator').all()
    superadmins = current_app.config.get('SUPERADMIN_USERS', [])
    members_by_caid = {str(m.centralauth_id): m.role for m in admins + moderators}
    return render_template('admin/channel_settings.html', channel=channel,
                           admins=admins, moderators=moderators,
                           superadmins=superadmins, members_by_caid=members_by_caid)


@admin_bp.post('/channel/<channel_id>/settings')
@channel_role_required('admin')
def channel_settings_post(channel_id: str):
    verify_csrf()
    ch = Channel.query.get_or_404(channel_id)
    ch.is_public                 = 'is_public' in request.form
    ch.language_detection_enabled = 'language_detection_enabled' in request.form
    ch.default_language          = request.form.get('default_language', 'en').strip()
    ch.emoji_auto_approve        = 'emoji_auto_approve' in request.form
    anon = request.form.get('anonymous_label', '').strip()
    ch.anonymous_label           = anon or 'Anonymous'
    likely = request.form.get('likely_languages', '').strip()
    ch.likely_languages = json.dumps([l.strip() for l in likely.split(',') if l.strip()]) if likely else None
    db.session.commit()
    flash('Settings saved.')
    return redirect(url_for('admin.channel_settings', channel_id=channel_id))


@admin_bp.post('/channel/<channel_id>/archive')
@channel_role_required('admin')
def channel_archive(channel_id: str):
    verify_csrf()
    ch = Channel.query.get_or_404(channel_id)
    ch.is_active  = False
    ch.archived_at = datetime.now(timezone.utc)
    db.session.commit()
    flash(f'"{ch.name}" archived. No new messages will be accepted.')
    return redirect(url_for('queue.queue_page', channel_id=channel_id))


@admin_bp.post('/channel/<channel_id>/unarchive')
@channel_role_required('admin')
def channel_unarchive(channel_id: str):
    verify_csrf()
    ch = Channel.query.get_or_404(channel_id)
    ch.is_active  = True
    ch.archived_at = None
    db.session.commit()
    flash(f'"{ch.name}" reopened.')
    return redirect(url_for('queue.queue_page', channel_id=channel_id))


@admin_bp.post('/channel/<channel_id>/token/regenerate')
@channel_role_required('admin')
def channel_token_regenerate(channel_id: str):
    verify_csrf()
    Channel.query.get_or_404(channel_id).display_token = generate_token()
    db.session.commit()
    flash('Display token regenerated.')
    return redirect(url_for('admin.channel_settings', channel_id=channel_id))



@admin_bp.get('/channel/<channel_id>/blacklist')
@channel_role_required('admin', 'moderator')
def channel_blacklist(channel_id: str):
    channel = Channel.query.get_or_404(channel_id)
    entries = Blacklist.query.filter_by(channel_id=channel_id).order_by(Blacklist.added_at.desc()).all()
    return render_template('admin/channel_blacklist.html', channel=channel, entries=entries)


@admin_bp.post('/channel/<channel_id>/blacklist/remove')
@channel_role_required('admin', 'moderator')
def channel_blacklist_remove(channel_id: str):
    verify_csrf()
    Blacklist.query.filter_by(id=int(request.form.get('id', 0)), channel_id=channel_id).delete()
    db.session.commit()
    return redirect(url_for('admin.channel_blacklist', channel_id=channel_id))


@admin_bp.get('/channel/<channel_id>/whitelist')
@channel_role_required('admin', 'moderator')
def channel_whitelist(channel_id: str):
    channel = Channel.query.get_or_404(channel_id)
    entries = Whitelist.query.filter_by(channel_id=channel_id).order_by(Whitelist.added_at.desc()).all()
    return render_template('admin/channel_whitelist.html', channel=channel, entries=entries)


@admin_bp.post('/channel/<channel_id>/whitelist/remove')
@channel_role_required('admin', 'moderator')
def channel_whitelist_remove(channel_id: str):
    verify_csrf()
    Whitelist.query.filter_by(id=int(request.form.get('id', 0)), channel_id=channel_id).delete()
    db.session.commit()
    return redirect(url_for('admin.channel_whitelist', channel_id=channel_id))


@admin_bp.post('/channel/<channel_id>/blacklist/export')
@channel_role_required('admin')
def channel_blacklist_export(channel_id: str):
    verify_csrf()
    entry = Blacklist.query.filter_by(id=int(request.form.get('id', 0)), channel_id=channel_id).first_or_404()
    if not GlobalBlacklist.query.filter_by(screen_name=entry.screen_name).first():
        db.session.add(GlobalBlacklist(
            screen_name=entry.screen_name,
            sender_id=entry.sender_id,
            centralauth_id=entry.centralauth_id,
            added_by_centralauth_id=current_centralauth_id(),
            added_by_wiki_username=current_wiki_username() or '',
        ))
        db.session.commit()
        flash(f'{entry.screen_name} added to global blacklist.')
    else:
        flash(f'{entry.screen_name} is already on the global blacklist.')
    return redirect(url_for('admin.channel_blacklist', channel_id=channel_id))
