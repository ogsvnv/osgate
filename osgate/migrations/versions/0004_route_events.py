"""Persist bounded seven-day route switching audit events."""
from alembic import op
from osgate.database import RouteEvent

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade():
    RouteEvent.__table__.create(bind=op.get_bind(), checkfirst=True)


def downgrade():
    RouteEvent.__table__.drop(bind=op.get_bind(), checkfirst=True)
