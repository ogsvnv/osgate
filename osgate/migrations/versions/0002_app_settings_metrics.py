"""Add operational settings and bounded dashboard samples to existing SQLite DBs."""
from alembic import op
from osgate.database import Base
revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None

def upgrade():
    # Migration 0001 uses dynamic Base metadata; checkfirst works both for fresh
    # installs (0001 created these) and upgrades from prior alpha schemas.
    Base.metadata.create_all(bind=op.get_bind(), checkfirst=True)

def downgrade():
    for name in ('traffic_samples', 'application_settings'):
        op.drop_table(name)
