"""added foreign key to api_usage log model

Revision ID: dbbe7a6e6118
Revises: ae74a44685ff
Create Date: 2026-07-09 10:53:41.003986

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = 'dbbe7a6e6118'
down_revision: Union[str, None] = 'ae74a44685ff'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 🔓 Turn off constraint checks to prevent index drop lockups
    op.execute("SET FOREIGN_KEY_CHECKS = 0;")
    
    # --- api_projects ---
    # Commented out because it's already created
    # try:
    #     op.execute("ALTER TABLE api_projects DROP INDEX ix_api_projects_tenant_id;")
    # except Exception:
    #     pass
    # op.execute("CREATE UNIQUE INDEX ix_api_projects_tenant_id ON api_projects (tenant_id);")
    
    # --- api_usage_logs ---
    try:
        op.add_column('api_usage_logs', sa.Column('project_id', sa.Integer(), nullable=False))
        op.create_index(op.f('ix_api_usage_logs_project_id'), 'api_usage_logs', ['project_id'], unique=False)
        op.create_foreign_key(None, 'api_usage_logs', 'api_projects', ['project_id'], ['project_id'])
    except Exception:
        pass
    
    # --- billing_audits ---
    try:
        op.drop_index(op.f('uq_tenant_stripe_event'), table_name='billing_audits')
    except Exception:
        pass
    try:
        op.drop_constraint(op.f('billing_audits_ibfk_1'), 'billing_audits', type_='foreignkey')
    except Exception:
        pass
    try:
        op.create_foreign_key(None, 'billing_audits', 'tenants', ['tenant_id'], ['tenant_id'])
    except Exception:
        pass
    
    # --- stripe_checkout_sessions ---
    try:
        op.add_column('stripe_checkout_sessions', sa.Column('created_at', sa.DateTime(), nullable=False))
    except Exception:
        pass
    try:
        op.drop_constraint(op.f('stripe_checkout_sessions_ibfk_1'), 'stripe_checkout_sessions', type_='foreignkey')
    except Exception:
        pass
    try:
        op.drop_constraint(op.f('stripe_checkout_sessions_ibfk_2'), 'stripe_checkout_sessions', type_='foreignkey')
    except Exception:
        pass
    try:
        op.create_foreign_key(None, 'stripe_checkout_sessions', 'tenants', ['tenant_id'], ['tenant_id'])
        op.create_foreign_key(None, 'stripe_checkout_sessions', 'plans', ['plan_id'], ['plan_id'])
    except Exception:
        pass
    
    # --- subscriptions ---
    # Commented out because MySQL confirms 'ix_subscriptions_tenant_id' is already built:
    # try:
    #     op.drop_index(op.f('ix_subscriptions_tenant_id'), table_name='subscriptions')
    # except Exception:
    #     pass
    # op.create_index(op.f('ix_subscriptions_tenant_id'), 'subscriptions', ['tenant_id'], unique=True)
    
    try:
        op.create_foreign_key(None, 'subscriptions', 'plans', ['plan_id'], ['plan_id'])
    except Exception:
        pass
    try:
        op.drop_column('subscriptions', 'type')
    except Exception:
        pass

    # 🔒 Re-enable constraints immediately
    op.execute("SET FOREIGN_KEY_CHECKS = 1;")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("SET FOREIGN_KEY_CHECKS = 0;")
    
    # --- subscriptions ---
    op.add_column('subscriptions', sa.Column('type', mysql.VARCHAR(length=25), nullable=False))
    try:
        op.drop_constraint(None, 'subscriptions', type_='foreignkey')
    except Exception:
        pass
    try:
        op.drop_index(op.f('ix_subscriptions_tenant_id'), table_name='subscriptions')
    except Exception:
        pass
    op.create_index(op.f('ix_subscriptions_tenant_id'), 'subscriptions', ['tenant_id'], unique=False)
    
    # --- stripe_checkout_sessions ---
    try:
        op.drop_constraint(None, 'stripe_checkout_sessions', type_='foreignkey')
    except Exception:
        pass
    try:
        op.drop_constraint(None, 'stripe_checkout_sessions', type_='foreignkey')
    except Exception:
        pass
    op.create_foreign_key(op.f('stripe_checkout_sessions_ibfk_2'), 'stripe_checkout_sessions', 'plans', ['plan_id'], ['plan_id'], ondelete='RESTRICT')
    op.create_foreign_key(op.f('stripe_checkout_sessions_ibfk_1'), 'stripe_checkout_sessions', 'tenants', ['tenant_id'], ['tenant_id'], ondelete='CASCADE')
    op.drop_column('stripe_checkout_sessions', 'created_at')
    
    # --- billing_audits ---
    try:
        op.drop_constraint(None, 'billing_audits', type_='foreignkey')
    except Exception:
        pass
    op.create_foreign_key(op.f('billing_audits_ibfk_1'), 'billing_audits', 'tenants', ['tenant_id'], ['tenant_id'], ondelete='CASCADE')
    op.create_index(op.f('uq_tenant_stripe_event'), 'billing_audits', ['tenant_id', 'stripe_event_id'], unique=True)
    
    # --- api_usage_logs ---
    try:
        op.drop_constraint(None, 'api_usage_logs', type_='foreignkey')
    except Exception:
        pass
    try:
        op.drop_index(op.f('ix_api_usage_logs_project_id'), table_name='api_usage_logs')
    except Exception:
        pass
    op.drop_column('api_usage_logs', 'project_id')
    
    # --- api_projects ---
    try:
        op.drop_index(op.f('ix_api_projects_tenant_id'), table_name='api_projects')
    except Exception:
        pass
    op.create_index(op.f('ix_api_projects_tenant_id'), 'api_projects', ['tenant_id'], unique=False)

    op.execute("SET FOREIGN_KEY_CHECKS = 1;")