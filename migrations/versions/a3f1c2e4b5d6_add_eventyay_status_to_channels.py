"""add eventyay_status to channels

Revision ID: a3f1c2e4b5d6
Revises: d762fcc9b2f9
Create Date: 2026-11-04 18:00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a3f1c2e4b5d6'  # pragma: allowlist secret
down_revision = 'd762fcc9b2f9'
branch_labels = None
depends_on = None


def upgrade():
    # db.create_all() on first boot already creates `channels` with every column
    # in the current model, so only add the column if it's missing.
    bind = op.get_bind()
    columns = {c['name'] for c in sa.inspect(bind).get_columns('channels')}
    if 'eventyay_status' not in columns:
        with op.batch_alter_table('channels', schema=None) as batch_op:
            batch_op.add_column(sa.Column('eventyay_status', sa.Text(), nullable=True))


def downgrade():
    bind = op.get_bind()
    columns = {c['name'] for c in sa.inspect(bind).get_columns('channels')}
    if 'eventyay_status' in columns:
        with op.batch_alter_table('channels', schema=None) as batch_op:
            batch_op.drop_column('eventyay_status')
