"""Persist the last 10 minutes of SSH TCP latency measurements."""
from alembic import op
from osgate.database import SSHLatencySample

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    SSHLatencySample.__table__.create(bind=op.get_bind(), checkfirst=True)


def downgrade():
    SSHLatencySample.__table__.drop(bind=op.get_bind(), checkfirst=True)
