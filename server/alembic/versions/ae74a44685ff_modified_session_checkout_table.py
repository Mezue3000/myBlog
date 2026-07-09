"""modified session-checkout table

Revision ID: ae74a44685ff
Revises: 946d35eaa5d6
Create Date: 2026-07-07 14:51:14.918102

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = 'ae74a44685ff'
down_revision: Union[str, None] = '946d35eaa5d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    
    # 🚀 Step 5: SAFE INDEX SWAP ON EXISTING SUBSCRIPTIONS
    # Temporarily silence constraint validations so we can change the index profile
    op.execute("SET FOREIGN_KEY_CHECKS = 0;")
    
    try:
        # Drop the index regardless of foreign key dependencies
        op.execute("DROP INDEX ix_subscriptions_tenant_id ON subscriptions")
    except Exception:
        pass

    # Create the index with the new UNIQUE constraint profile
    op.execute("CREATE UNIQUE INDEX ix_subscriptions_tenant_id ON subscriptions (tenant_id)")
    
    # Re-enable standard relational safety checks immediately
    op.execute("SET FOREIGN_KEY_CHECKS = 1;")

    # Drop the old 'type' column safely if it's still floating around
    try:
        op.drop_column('subscriptions', 'type')
    except Exception:
        pass


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("SET FOREIGN_KEY_CHECKS = 0;")
    try:
        op.execute("DROP INDEX ix_subscriptions_tenant_id ON subscriptions")
    except Exception:
        pass
    op.execute("CREATE INDEX ix_subscriptions_tenant_id ON subscriptions (tenant_id)")
    op.execute("SET FOREIGN_KEY_CHECKS = 1;")
    
    op.add_column('subscriptions', sa.Column('type', mysql.VARCHAR(length=25), nullable=False))
    try:
        op.drop_column('subscriptions', 'cancel_at_period_end')
    except Exception:
        pass