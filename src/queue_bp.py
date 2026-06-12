from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, render_template, abort
from sqlalchemy import func
from src.models import db, Channel, Message, Blacklist, BlockedPattern, ModerationLog, Whitelist
from src.auth import channel_role_required, verify_csrf, current_centralauth_id, current_wiki_username
from src.utils import levenshtein, parse_likely_languages

queue_bp = Blueprint('queue', __name__)

# ── Decision rank for "most restrictive wins" ─────────────────────────────
# A decision can only move a message to a higher rank, never lower.
# highlight(1) < approve(2) < reject(3)
# ban is handled separately (creates a blacklist entry); treated as rank 4.
DECISION_RANK: dict[str, int] = {
    'highlighted': 1,
    'approved':    2,
    'rejected':    3,
}


def _log(msg: Message, decision: str) -> None:
    db.session.add(ModerationLog(
        channel_id               = msg.channel_id,
        message_id               = msg.id,
        moderator_centralauth_id = current_centralauth_id(),
        moderator_wiki_username  = current_wiki_username() or '',
        decision                 = decision,
        screen_name              = msg.screen_name,
        message_text             = msg.message,
        message_type             = msg.message_type,
        arrived_at               = msg.arrived_at,
        decided_at               = datetime.now(timezone.utc),
    ))


def _set_status(channel_id: str, msg_id: int, new_status: str):
    verify_csrf()
    msg = Message.query.filter_by(id=msg_id, channel_id=channel_id).with_for_update().first_or_404()

    new_rank = DECISION_RANK.get(new_status, 0)
    cur_rank = DECISION_RANK.get(msg.status, 0)

    if msg.status != 'queued' and new_rank <= cur_rank:
        # A more-restrictive decision already took effect — do nothing.
        return jsonify({'ok': False, 'superseded': True, 'current': msg.status})

    _log(msg, new_status)
    msg.status                    = new_status
    msg.processed_at              = datetime.now(timezone.utc)
    msg.processed_by_centralauth_id = current_centralauth_id()
    db.session.commit()
    return jsonify({'ok': True})


# ── Queue page ────────────────────────────────────────────────────────────

@queue_bp.get('/channel/<channel_id>/queue')
@channel_role_required('admin', 'moderator')
def queue_page(channel_id: str):
    from src.auth import get_channel_role
    channel = Channel.query.get_or_404(channel_id)
    sim = Channel.query.get('simulation')
    sim_active   = bool(sim and sim.is_active and channel_id == 'simulation')
    channel_role = get_channel_role(channel_id)
    configured_languages = parse_likely_languages(channel.likely_languages)
    return render_template('queue.html', channel=channel, sim_active=sim_active,
                           channel_role=channel_role,
                           configured_languages=configured_languages)


# ── HTMX fragment (legacy, kept for compatibility) ────────────────────────

@queue_bp.get('/channel/<channel_id>/queue/messages')
@channel_role_required('admin', 'moderator')
def queue_messages(channel_id: str):
    channel = Channel.query.get_or_404(channel_id)
    lang_filter = request.args.getlist('lang')
    q = Message.query.filter_by(channel_id=channel_id, status='queued').order_by(Message.arrived_at)
    if lang_filter:
        q = q.filter(Message.detected_language.in_(lang_filter))
    messages = q.all()
    lang_rows = db.session.query(Message.detected_language).filter(
        Message.channel_id == channel_id,
        Message.status == 'queued',
        Message.detected_language.isnot(None),
    ).distinct().all()
    lang_codes = sorted({r[0] for r in lang_rows})
    return render_template('queue_messages.html',
                           messages=messages, channel=channel,
                           lang_codes=lang_codes, lang_filter=lang_filter)


# ── JSON polling endpoint ─────────────────────────────────────────────────

@queue_bp.get('/channel/<channel_id>/queue/messages.json')
@channel_role_required('admin', 'moderator')
def queue_messages_json(channel_id: str):
    channel = Channel.query.get_or_404(channel_id)
    lang_filter = request.args.getlist('lang')
    type_filter = request.args.get('type', 'all')
    q = (Message.query
         .filter_by(channel_id=channel_id, status='queued')
         .order_by(Message.arrived_at.desc()))
    if lang_filter:
        q = q.filter(Message.detected_language.in_(lang_filter))
    if type_filter in ('text', 'emoji', 'qa'):
        q = q.filter(Message.message_type == type_filter)
    messages = q.all()
    detected = {r[0] for r in db.session.query(Message.detected_language).filter(
        Message.channel_id == channel_id,
        Message.status == 'queued',
        Message.detected_language.isnot(None),
    ).distinct().all()}
    configured = set(parse_likely_languages(channel.likely_languages))

    # All-time decision counts from the moderation log
    stats_rows = (db.session.query(ModerationLog.decision, func.count(ModerationLog.id))
                  .filter(ModerationLog.channel_id == channel_id)
                  .group_by(ModerationLog.decision)
                  .all())
    stats = {row[0]: row[1] for row in stats_rows}

    return jsonify({
        'messages': [{
            'id':                m.id,
            'screen_name':       m.screen_name,
            'message':           m.message,
            'message_type':      m.message_type,
            'arrived_at':        m.arrived_at.isoformat() + 'Z',
            'detected_language': m.detected_language,
            'profile_img':       m.profile_img,
            'sender_id':         m.sender_id,
            'centralauth_id':    m.centralauth_id,
        } for m in messages],
        'lang_codes': sorted(detected | configured),
        'stats':      stats,
    })


# ── Moderation actions ────────────────────────────────────────────────────

@queue_bp.post('/api/channel/<channel_id>/message/<int:msg_id>/approve')
@channel_role_required('admin', 'moderator')
def approve(channel_id: str, msg_id: int):
    return _set_status(channel_id, msg_id, 'approved')


@queue_bp.post('/api/channel/<channel_id>/message/<int:msg_id>/reject')
@channel_role_required('admin', 'moderator')
def reject(channel_id: str, msg_id: int):
    return _set_status(channel_id, msg_id, 'rejected')


@queue_bp.post('/api/channel/<channel_id>/message/<int:msg_id>/highlight')
@channel_role_required('admin', 'moderator')
def highlight(channel_id: str, msg_id: int):
    return _set_status(channel_id, msg_id, 'highlighted')


@queue_bp.post('/api/channel/<channel_id>/message/<int:msg_id>/reject-similar')
@channel_role_required('admin', 'moderator')
def reject_similar(channel_id: str, msg_id: int):
    verify_csrf()
    msg = Message.query.filter_by(id=msg_id, channel_id=channel_id).first_or_404()
    now = datetime.now(timezone.utc)
    uid = current_centralauth_id()
    rejected = 0
    for m in Message.query.filter_by(channel_id=channel_id, status='queued').all():
        if levenshtein(m.message, msg.message) <= 2:
            _log(m, 'reject-similar')
            m.status                    = 'rejected'
            m.processed_at              = now
            m.processed_by_centralauth_id = uid
            rejected += 1
    db.session.commit()
    return jsonify({'ok': True, 'rejected': rejected})


@queue_bp.post('/api/channel/<channel_id>/block-user')
@channel_role_required('admin', 'moderator')
def block_user(channel_id: str):
    verify_csrf()
    screen_name = request.form.get('screen_name', '').strip()
    sender_id   = request.form.get('sender_id') or None
    if not screen_name and not sender_id:
        return jsonify({'ok': False, 'error': 'screen_name or sender_id required'})
    # Dedup: prefer sender_id as the canonical key when available
    existing = (
        Blacklist.query.filter_by(channel_id=channel_id, sender_id=sender_id).first()
        if sender_id else
        Blacklist.query.filter_by(channel_id=channel_id, screen_name=screen_name).first()
    )
    if not existing:
        db.session.add(Blacklist(
            channel_id=channel_id,
            screen_name=screen_name,
            sender_id=sender_id,
            centralauth_id=int(request.form['centralauth_id']) if request.form.get('centralauth_id') else None,
            added_by_centralauth_id=current_centralauth_id(),
            added_by_wiki_username=current_wiki_username() or '',
        ))
        now = datetime.now(timezone.utc)
        uid = current_centralauth_id()
        # Reject all queued messages from this sender (match by sender_id OR screen_name)
        for m in Message.query.filter_by(channel_id=channel_id, status='queued').all():
            if (sender_id and m.sender_id == sender_id) or \
               (screen_name and m.screen_name == screen_name):
                _log(m, 'ban')
                m.status                    = 'rejected'
                m.processed_at              = now
                m.processed_by_centralauth_id = uid
        db.session.commit()
    return jsonify({'ok': True})


@queue_bp.post('/api/channel/<channel_id>/whitelist-user')
@channel_role_required('admin', 'moderator')
def whitelist_user(channel_id: str):
    verify_csrf()
    screen_name = request.form.get('screen_name', '').strip()
    sender_id   = request.form.get('sender_id') or None
    if not screen_name and not sender_id:
        return jsonify({'ok': False, 'error': 'screen_name or sender_id required'})
    existing = (
        Whitelist.query.filter_by(channel_id=channel_id, sender_id=sender_id).first()
        if sender_id else
        Whitelist.query.filter_by(channel_id=channel_id, screen_name=screen_name).first()
    )
    if not existing:
        db.session.add(Whitelist(
            channel_id=channel_id,
            screen_name=screen_name,
            sender_id=sender_id,
            centralauth_id=int(request.form['centralauth_id']) if request.form.get('centralauth_id') else None,
            added_by_centralauth_id=current_centralauth_id(),
            added_by_wiki_username=current_wiki_username() or '',
        ))
        now = datetime.now(timezone.utc)
        uid = current_centralauth_id()
        # Auto-approve any queued messages from this sender
        for m in Message.query.filter_by(channel_id=channel_id, status='queued').all():
            if (sender_id and m.sender_id == sender_id) or \
               (screen_name and m.screen_name == screen_name):
                _log(m, 'approve')
                m.status                    = 'approved'
                m.processed_at              = now
                m.processed_by_centralauth_id = uid
        db.session.commit()
    return jsonify({'ok': True})


@queue_bp.post('/api/channel/<channel_id>/block-similar')
@channel_role_required('admin', 'moderator')
def block_similar(channel_id: str):
    verify_csrf()
    msg_id = request.form.get('message_id', '')
    msg = Message.query.filter_by(id=int(msg_id), channel_id=channel_id).first_or_404()
    db.session.add(BlockedPattern(
        channel_id=channel_id,
        pattern_text=msg.message.lower().strip(),
        original_message_id=msg.id,
        added_by_centralauth_id=current_centralauth_id(),
    ))
    now = datetime.now(timezone.utc)
    uid = current_centralauth_id()
    rejected = 0
    for m in Message.query.filter_by(channel_id=channel_id, status='queued').all():
        if levenshtein(m.message, msg.message) <= 2:
            _log(m, 'reject-similar')
            m.status                    = 'rejected'
            m.processed_at              = now
            m.processed_by_centralauth_id = uid
            rejected += 1
    db.session.commit()
    return jsonify({'ok': True, 'rejected': rejected})


# ── Moderation log view ───────────────────────────────────────────────────

@queue_bp.get('/channel/<channel_id>/log')
@channel_role_required('admin', 'moderator')
def channel_log(channel_id: str):
    channel = Channel.query.get_or_404(channel_id)
    entries = (ModerationLog.query
               .filter_by(channel_id=channel_id)
               .order_by(ModerationLog.decided_at.desc())
               .limit(500)
               .all())
    return render_template('queue/log.html', channel=channel, entries=entries)
