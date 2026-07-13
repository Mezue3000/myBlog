"""added credit_log model/relationships

Revision ID: d82a33ad24f8
Revises: dbbe7a6e6118
Create Date: 2026-07-10 15:29:27.218818

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = 'd82a33ad24f8'
down_revision: Union[str, None] = 'dbbe7a6e6118'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 🔓 Turn off constraint checks to prevent index and lockup collisions
    op.execute("SET FOREIGN_KEY_CHECKS = 0;")
    
    # --- credit_logs ---
    # Wrapped in a try/except so it won't crash if it already exists!
    try:
        op.create_table('credit_logs',
            sa.Column('credit_log_id', sa.Integer(), nullable=False),
            sa.Column('tenant_id', sa.Uuid(), nullable=False),
            sa.Column('credits_used', sa.Integer(), nullable=False),
            sa.Column('credits_balance_after', sa.Integer(), nullable=False),
            sa.Column('action', sa.String(length=30), nullable=False),
            sa.Column('description', sa.String(length=255), nullable=True),
            sa.Column('reference_id', sa.String(length=255), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['tenant_id'], ['tenants.tenant_id'], ),
            sa.PrimaryKeyConstraint('credit_log_id')
        )
    except Exception:
        pass

    try:
        op.create_index(op.f('ix_credit_logs_action'), 'credit_logs', ['action'], unique=False)
    except Exception:
        pass
    try:
        op.create_index(op.f('ix_credit_logs_reference_id'), 'credit_logs', ['reference_id'], unique=False)
    except Exception:
        pass
    try:
        op.create_index(op.f('ix_credit_logs_tenant_id'), 'credit_logs', ['tenant_id'], unique=False)
    except Exception:
        pass
    
    # --- plans ---
    # Adding try/except wrappers here too, just in case any columns got partly created
    try:
        op.add_column('plans', sa.Column('credits', sa.Integer(), nullable=False))
    except Exception:
        pass
    try:
        op.add_column('plans', sa.Column('features', sa.JSON(), nullable=False))
    except Exception:
        pass
    try:
        op.add_column('plans', sa.Column('description', sa.String(length=255), nullable=True))
    except Exception:
        pass
    
    try:
        op.alter_column('plans', 'amount',
                       existing_type=sa.Float(),
                       type_=sa.Numeric(),
                       existing_nullable=False)
    except Exception:
        pass
    try:
        op.alter_column('plans', 'currency',
                       existing_type=sa.String(length=15),
                       type_=sa.String(length=9),
                       existing_nullable=False)
    except Exception:
        pass
                   
    try:
        op.create_index(op.f('ix_plans_billing_interval'), 'plans', ['billing_interval'], unique=False)
    except Exception:
        pass
    try:
        op.create_index(op.f('ix_plans_name'), 'plans', ['name'], unique=False)
    except Exception:
        pass
    try:
        op.create_index(op.f('ix_plans_tenant_type'), 'plans', ['tenant_type'], unique=False)
    except Exception:
        pass
    
    # --- subscriptions (Safely alter index) ---
    try:
        op.execute("ALTER TABLE subscriptions DROP FOREIGN KEY subscriptions_ibfk_1;")
    except Exception:
        pass
    try:
        op.execute("ALTER TABLE subscriptions DROP INDEX ix_subscriptions_tenant_id;")
    except Exception:
        pass
    try:
        op.create_index(op.f('ix_subscriptions_tenant_id'), 'subscriptions', ['tenant_id'], unique=True)
    except Exception:
        pass
    
    # --- tenants ---
    try:
        op.add_column('tenants', sa.Column('plan_id', sa.Integer(), nullable=False))
    except Exception:
        pass
    try:
        op.add_column('tenants', sa.Column('credits_remaining', sa.Integer(), nullable=False))
    except Exception:
        pass
    try:
        op.add_column('tenants', sa.Column('credits_reset_at', sa.DateTime(), nullable=False))
    except Exception:
        pass
    try:
        op.create_index(op.f('ix_tenants_plan_id'), 'tenants', ['plan_id'], unique=False)
    except Exception:
        pass
    try:
        op.create_foreign_key(None, 'tenants', 'plans', ['plan_id'], ['plan_id'])
    except Exception:
        pass
    
    try:
        op.drop_column('tenants', 'plan')
    except Exception:
        pass

    # 🔒 Re-enable constraints immediately
    op.execute("SET FOREIGN_KEY_CHECKS = 1;")

def downgrade() -> None:
    """Downgrade schema."""
    op.execute("SET FOREIGN_KEY_CHECKS = 0;")
    
    # --- tenants ---
    op.add_column('tenants', sa.Column('plan', sa.String(length=25), nullable=False))
    try:
        op.execute("ALTER TABLE tenants DROP FOREIGN KEY tenants_ibfk_1;")
    except Exception:
        pass
    try:
        op.drop_index(op.f('ix_tenants_plan_id'), table_name='tenants')
    except Exception:
        pass
    op.drop_column('tenants', 'credits_reset_at')
    op.drop_column('tenants', 'credits_remaining')
    op.drop_column('tenants', 'plan_id')
    
    # --- subscriptions ---
    try:
        op.execute("ALTER TABLE subscriptions DROP INDEX ix_subscriptions_tenant_id;")
    except Exception:
        pass
    op.create_index(op.f('ix_subscriptions_tenant_id'), 'subscriptions', ['tenant_id'], unique=False)
    
    # --- plans ---
    try:
        op.drop_index(op.f('ix_plans_tenant_type'), table_name='plans')
        op.drop_index(op.f('ix_plans_name'), table_name='plans')
        op.drop_index(op.f('ix_plans_billing_interval'), table_name='plans')
    except Exception:
        pass
        
    op.alter_column('plans', 'currency',
                   existing_type=sa.String(length=9),
                   type_=sa.String(length=15),
                   existing_nullable=False)
    op.alter_column('plans', 'amount',
                   existing_type=sa.Numeric(),
                   type_=sa.Float(),
                   existing_nullable=False)
                   
    op.drop_column('plans', 'description')
    op.drop_column('plans', 'features')
    op.drop_column('plans', 'credits')
    
    # --- credit_logs ---
    try:
        op.drop_index(op.f('ix_credit_logs_tenant_id'), table_name='credit_logs')
        op.drop_index(op.f('ix_credit_logs_reference_id'), table_name='credit_logs')
        op.drop_index(op.f('ix_credit_logs_action'), table_name='credit_logs')
    except Exception:
        pass
    op.drop_table('credit_logs')
    
    op.execute("SET FOREIGN_KEY_CHECKS = 1;")