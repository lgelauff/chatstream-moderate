"""add wiki_username to messages

Revision ID: d762fcc9b2f9
Revises:
Create Date: 2026-05-02 16:04:26.459894

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd762fcc9b2f9'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # db.create_all() on first boot already creates `messages` with every column
    # in the current model — including wiki_username — so on a fresh deploy this
    # ADD COLUMN would fail with "duplicate column". Only add it if it's missing.
    bind = op.get_bind()
    columns = {c['name'] for c in sa.inspect(bind).get_columns('messages')}
    if 'wiki_username' not in columns:
        with op.batch_alter_table('messages', schema=None) as batch_op:
            batch_op.add_column(sa.Column('wiki_username', sa.String(length=255), nullable=True))


def downgrade():
    bind = op.get_bind()
    columns = {c['name'] for c in sa.inspect(bind).get_columns('messages')}
    if 'wiki_username' in columns:
        with op.batch_alter_table('messages', schema=None) as batch_op:
            batch_op.drop_column('wiki_username')
