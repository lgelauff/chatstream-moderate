from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String, Text, Boolean, Integer, DateTime, Enum as SAEnum, UniqueConstraint, Index

db = SQLAlchemy()


class Channel(db.Model):
    __tablename__ = 'channels'
    id                        = db.Column(String(64), primary_key=True)
    name                      = db.Column(String(255), nullable=False)
    description               = db.Column(Text, nullable=True)
    is_active                 = db.Column(Boolean, nullable=False, default=True)
    is_public                 = db.Column(Boolean, nullable=False, default=True)
    display_token             = db.Column(String(64), nullable=False)
    webhook_hmac_secret       = db.Column(String(64), nullable=False)
    custom_css                = db.Column(Text, nullable=True)
    language_detection_enabled = db.Column(Boolean, nullable=False, default=False)
    default_language          = db.Column(String(10), nullable=False, default='en')
    likely_languages          = db.Column(Text, nullable=True)   # JSON array
    emoji_auto_approve        = db.Column(Boolean, nullable=False, default=True)
    anonymous_label           = db.Column(String(64), nullable=False, default='Anonymous')
    anonymous_counter         = db.Column(Integer, nullable=False, default=0)
    created_at                = db.Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    archived_at               = db.Column(DateTime, nullable=True)


class ChannelMember(db.Model):
    __tablename__ = 'channel_members'
    id              = db.Column(Integer, primary_key=True, autoincrement=True)
    channel_id      = db.Column(String(64), db.ForeignKey('channels.id', ondelete='CASCADE'), nullable=False)
    centralauth_id  = db.Column(Integer, nullable=False)
    wiki_username   = db.Column(String(255), nullable=False)
    role            = db.Column(SAEnum('admin', 'moderator'), nullable=False)
    added_at        = db.Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    __table_args__  = (UniqueConstraint('channel_id', 'centralauth_id', name='uq_channel_member'),)


class Message(db.Model):
    __tablename__ = 'messages'
    id                       = db.Column(Integer, primary_key=True, autoincrement=True)
    eventyay_message_id      = db.Column(String(255), nullable=True)
    channel_id               = db.Column(String(64), db.ForeignKey('channels.id', ondelete='CASCADE'), nullable=False)
    screen_name              = db.Column(String(255), nullable=False)
    wiki_username            = db.Column(String(255), nullable=True)   # Wikimedia global username when provided
    sender_id                = db.Column(String(255), nullable=True)
    centralauth_id           = db.Column(Integer, nullable=True)
    message                  = db.Column(Text, nullable=False)
    # Stored as a plain string (not a DB enum) so a message_type that falls
    # outside text/emoji/qa — e.g. a raw Eventyay event name slipping through —
    # can never make a row un-loadable and 500 the whole queue. Intake in
    # webhook._process_message normalises incoming values to one of these.
    message_type             = db.Column(String(16), nullable=False, default='text')
    meta                     = db.Column(Text, nullable=True)   # JSON
    profile_img              = db.Column(String(1024), nullable=True)
    user_language            = db.Column(String(10), nullable=True)
    detected_language        = db.Column(String(10), nullable=True)
    status                   = db.Column(SAEnum('queued', 'approved', 'highlighted', 'rejected'), nullable=False, default='queued')
    arrived_at               = db.Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    processed_at             = db.Column(DateTime, nullable=True)
    processed_by_centralauth_id = db.Column(Integer, nullable=True)
    __table_args__ = (
        Index('ix_messages_channel_status', 'channel_id', 'status'),
        Index('ix_messages_channel_id_asc', 'channel_id', 'id'),
        UniqueConstraint('channel_id', 'eventyay_message_id', name='uq_message_eventyay'),
    )


class Blacklist(db.Model):
    __tablename__ = 'blacklist'
    id                    = db.Column(Integer, primary_key=True, autoincrement=True)
    channel_id            = db.Column(String(64), db.ForeignKey('channels.id', ondelete='CASCADE'), nullable=False)
    screen_name           = db.Column(String(255), nullable=True, default='')  # display only; primary key is sender_id when available
    sender_id             = db.Column(String(255), nullable=True)
    centralauth_id        = db.Column(Integer, nullable=True)
    added_by_centralauth_id  = db.Column(Integer, nullable=False)
    added_by_wiki_username   = db.Column(String(255), nullable=False)
    added_at              = db.Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    __table_args__        = (Index('ix_blacklist_sender', 'channel_id', 'sender_id', unique=True),)
    # NULLs are allowed multiple times in UNIQUE indexes (SQLite + MySQL), so
    # entries without a sender_id are deduplicated at the application level.


class Whitelist(db.Model):
    """Per-channel allowlist: messages from these senders are auto-approved."""
    __tablename__ = 'whitelist'
    id                    = db.Column(Integer, primary_key=True, autoincrement=True)
    channel_id            = db.Column(String(64), db.ForeignKey('channels.id', ondelete='CASCADE'), nullable=False)
    screen_name           = db.Column(String(255), nullable=True, default='')
    sender_id             = db.Column(String(255), nullable=True)
    centralauth_id        = db.Column(Integer, nullable=True)
    added_by_centralauth_id  = db.Column(Integer, nullable=False)
    added_by_wiki_username   = db.Column(String(255), nullable=False)
    added_at              = db.Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    __table_args__        = (Index('ix_whitelist_sender', 'channel_id', 'sender_id', unique=True),)


class GlobalBlacklist(db.Model):
    __tablename__ = 'global_blacklist'
    id                    = db.Column(Integer, primary_key=True, autoincrement=True)
    screen_name           = db.Column(String(255), unique=True, nullable=False)
    sender_id             = db.Column(String(255), nullable=True)
    centralauth_id        = db.Column(Integer, nullable=True)
    added_by_centralauth_id  = db.Column(Integer, nullable=False)
    added_by_wiki_username   = db.Column(String(255), nullable=False)
    added_at              = db.Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class BlockedPattern(db.Model):
    __tablename__ = 'blocked_patterns'
    id                    = db.Column(Integer, primary_key=True, autoincrement=True)
    channel_id            = db.Column(String(64), db.ForeignKey('channels.id', ondelete='CASCADE'), nullable=False)
    pattern_text          = db.Column(Text, nullable=False)
    original_message_id   = db.Column(Integer, db.ForeignKey('messages.id', ondelete='SET NULL'), nullable=True)
    added_by_centralauth_id = db.Column(Integer, nullable=False)
    added_at              = db.Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class ModerationLog(db.Model):
    """Immutable record of every moderation decision that took effect.

    Decisions that were superseded (a less-restrictive action attempted after a
    more-restrictive one) are NOT recorded — only the winning action appears.
    Decision rank: highlighted(1) < approved(2) < rejected(3).  A decision can
    only move a message to a higher rank, never lower.
    """
    __tablename__ = 'moderation_log'
    id                       = db.Column(Integer, primary_key=True, autoincrement=True)
    channel_id               = db.Column(String(64), db.ForeignKey('channels.id', ondelete='CASCADE'),
                                         nullable=False, index=True)
    message_id               = db.Column(Integer, db.ForeignKey('messages.id', ondelete='SET NULL'),
                                         nullable=True)
    moderator_centralauth_id = db.Column(Integer, nullable=True)
    moderator_wiki_username  = db.Column(String(255), nullable=False, default='')
    # decision: approve / highlight / reject / reject-similar / ban
    decision                 = db.Column(String(32), nullable=False)
    # Denormalised message fields so the log survives message deletion
    screen_name              = db.Column(String(255), nullable=False, default='')
    message_text             = db.Column(Text, nullable=False, default='')
    message_type             = db.Column(String(16), nullable=False, default='text')
    arrived_at               = db.Column(DateTime, nullable=True)   # when message entered queue
    decided_at               = db.Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    __table_args__           = (
        Index('ix_modlog_channel_decided', 'channel_id', 'decided_at'),
        Index('ix_modlog_channel_decision', 'channel_id', 'decision'),
    )
