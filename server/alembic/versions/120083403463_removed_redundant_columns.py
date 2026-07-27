"""removed redundant columns

Revision ID: 120083403463
Revises: d82a33ad24f8
Create Date: 2026-07-20 23:29:24.785493

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# Revision identifiers, used by Alembic.
revision = '120083403463'
down_revision = None  # adjust if needed
branch_labels = None
depends_on = None


def drop_fk_if_exists(inspector, table_name: str, column_name: str):
    """
    Finds and drops any Foreign Key on a specific column dynamically
    to prevent MySQL Error 1553/3734 when dropping/modifying indexes.
    """
    if table_name not in inspector.get_table_names():
        return
    fks = inspector.get_foreign_keys(table_name)
    for fk in fks:
        if column_name in fk.get('constrained_columns', []):
            fk_name = fk.get('name')
            if fk_name:
                op.drop_constraint(fk_name, table_name, type_='foreignkey')


def upgrade() -> None:
    """Upgrade schema safely against MySQL non-transactional DDL state."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # ------------------------------------------------------------------
    # 1. stripe_webhook_events
    # ------------------------------------------------------------------
    if "stripe_webhook_events" not in existing_tables:
        op.create_table(
            'stripe_webhook_events',
            sa.Column('stripe_event_id', sa.String(length=255), nullable=False),
            sa.Column('event_type', sa.String(length=100), nullable=False),
            sa.Column('payload', sa.Text(), nullable=False),
            sa.Column('processed', sa.Boolean(), nullable=False),
            sa.Column('processed_at', sa.DateTime(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint('stripe_event_id'),
            sa.UniqueConstraint('stripe_event_id')
        )

    # ------------------------------------------------------------------
    # 2. webhook_events
    # ------------------------------------------------------------------
    if "webhook_events" in existing_tables:
        indexes = [idx['name'] for idx in inspector.get_indexes('webhook_events')]
        if 'ix_webhook_events_event_type' in indexes:
            op.drop_index('ix_webhook_events_event_type', table_name='webhook_events')
        if 'ix_webhook_events_processed' in indexes:
            op.drop_index('ix_webhook_events_processed', table_name='webhook_events')
        if 'stripe_event_id' in indexes:
            op.drop_index('stripe_event_id', table_name='webhook_events')
        op.drop_table('webhook_events')

    # ------------------------------------------------------------------
    # 3. api_keys & api_projects
    # ------------------------------------------------------------------
    if "api_keys" in existing_tables:
        op.alter_column(
            'api_keys', 
            'expires_at',
            existing_type=mysql.DATETIME(),
            nullable=False
        )
        api_keys_indexes = [idx['name'] for idx in inspector.get_indexes('api_keys')]
        if 'ix_api_keys_created_at' not in api_keys_indexes:
            op.create_index(op.f('ix_api_keys_created_at'), 'api_keys', ['created_at'], unique=False)

    if "api_projects" in existing_tables:
        api_projects_indexes = [idx['name'] for idx in inspector.get_indexes('api_projects')]
        if 'ix_api_projects_created_at' not in api_projects_indexes:
            op.create_index(op.f('ix_api_projects_created_at'), 'api_projects', ['created_at'], unique=False)

    # ------------------------------------------------------------------
    # 4. audit_logs (Defensive Fix for Error 3734 & Missing Column)
    # ------------------------------------------------------------------
    if "audit_logs" in existing_tables:
        audit_indexes = [idx['name'] for idx in inspector.get_indexes('audit_logs')]
        
        # Unlink FK before dropping index
        drop_fk_if_exists(inspector, 'audit_logs', 'target_user_id')
            
        if 'ix_audit_logs_target_user_id' in audit_indexes:
            op.drop_index('ix_audit_logs_target_user_id', table_name='audit_logs')
            
        # Dynamically determine the correct PK on users ('id' vs 'user_id')
        if "users" in existing_tables:
            user_cols = [col['name'] for col in inspector.get_columns('users')]
            target_pk = 'id' if 'id' in user_cols else ('user_id' if 'user_id' in user_cols else None)
            
            if target_pk:
                op.create_foreign_key(
                    'fk_audit_logs_target_user_id',
                    'audit_logs',
                    'users',
                    ['target_user_id'],
                    [target_pk]
                )

    # ------------------------------------------------------------------
    # 5. billing_audits & credit_logs
    # ------------------------------------------------------------------
    if "billing_audits" in existing_tables:
        billing_indexes = [idx['name'] for idx in inspector.get_indexes('billing_audits')]
        if 'ix_billing_audits_event_type' in billing_indexes:
            op.drop_index('ix_billing_audits_event_type', table_name='billing_audits')

    if "credit_logs" in existing_tables:
        credit_cols = [col['name'] for col in inspector.get_columns('credit_logs')]
        if 'amount' not in credit_cols:
            op.add_column('credit_logs', sa.Column('amount', sa.Integer(), nullable=False))
        if 'balance_after' not in credit_cols:
            op.add_column('credit_logs', sa.Column('balance_after', sa.Integer(), nullable=False))

        credit_indexes = [idx['name'] for idx in inspector.get_indexes('credit_logs')]
        if 'ix_credit_logs_action' in credit_indexes:
            op.drop_index('ix_credit_logs_action', table_name='credit_logs')

        if 'credits_used' in credit_cols:
            op.drop_column('credit_logs', 'credits_used')
        if 'credits_balance_after' in credit_cols:
            op.drop_column('credit_logs', 'credits_balance_after')

    # ------------------------------------------------------------------
    # 6. plans & stripe_checkout_sessions
    # ------------------------------------------------------------------
    if "plans" in existing_tables:
        plans_indexes = [idx['name'] for idx in inspector.get_indexes('plans')]
        for idx_name in ['ix_plans_billing_interval', 'ix_plans_name', 'ix_plans_tenant_type', 'stripe_price_id']:
            if idx_name in plans_indexes:
                op.drop_index(idx_name, table_name='plans')
                
        if 'ix_plans_stripe_price_id' not in plans_indexes:
            op.create_index(op.f('ix_plans_stripe_price_id'), 'plans', ['stripe_price_id'], unique=True)

    if "stripe_checkout_sessions" in existing_tables:
        stripe_sessions_indexes = [idx['name'] for idx in inspector.get_indexes('stripe_checkout_sessions')]
        if 'ix_stripe_checkout_sessions_status' in stripe_sessions_indexes:
            op.drop_index('ix_stripe_checkout_sessions_status', table_name='stripe_checkout_sessions')

    # ------------------------------------------------------------------
    # 7. subscriptions
    # ------------------------------------------------------------------
    if "subscriptions" in existing_tables:
        # STEP A: Drop ANY Foreign Key on 'subscriptions' pointing to 'tenant_id'
        drop_fk_if_exists(inspector, 'subscriptions', 'tenant_id')

        # STEP B: Drop indexes safely
        subs_indexes = [idx['name'] for idx in inspector.get_indexes('subscriptions')]
        if 'ix_subscriptions_tenant_id' in subs_indexes:
            op.drop_index('ix_subscriptions_tenant_id', table_name='subscriptions')
            
        if 'ix_subscriptions_stripe_customer_id' in subs_indexes:
            op.drop_index('ix_subscriptions_stripe_customer_id', table_name='subscriptions')

        # STEP C: Re-create unique index and foreign key constraint
        op.create_index(op.f('ix_subscriptions_tenant_id'), 'subscriptions', ['tenant_id'], unique=True)
        
        if "tenants" in existing_tables:
            tenant_cols = [col['name'] for col in inspector.get_columns('tenants')]
            tenant_pk = 'id' if 'id' in tenant_cols else ('tenant_id' if 'tenant_id' in tenant_cols else None)
            if tenant_pk:
                op.create_foreign_key(
                    'fk_subscriptions_tenant_id',
                    'subscriptions',
                    'tenants',
                    ['tenant_id'],
                    [tenant_pk]
                )

        if 'ix_subscriptions_created_at' not in subs_indexes:
            op.create_index(op.f('ix_subscriptions_created_at'), 'subscriptions', ['created_at'], unique=False)

        subs_cols = [col['name'] for col in inspector.get_columns('subscriptions')]
        if 'stripe_customer_id' in subs_cols:
            op.drop_column('subscriptions', 'stripe_customer_id')

    # ------------------------------------------------------------------
    # 8. tenant_invitations, tenant_memberships, tenants
    # ------------------------------------------------------------------
    if "tenant_invitations" in existing_tables:
        inv_cols = [col['name'] for col in inspector.get_columns('tenant_invitations')]
        if 'accepted_at' not in inv_cols:
            op.add_column('tenant_invitations', sa.Column('accepted_at', sa.DateTime(), nullable=False))

    if "tenant_memberships" in existing_tables:
        op.alter_column(
            'tenant_memberships', 
            'role',
            existing_type=mysql.VARCHAR(length=50),
            type_=sa.String(length=10),
            existing_nullable=False
        )

        memberships_cols = [col['name'] for col in inspector.get_columns('tenant_memberships')]
        if 'max_members' in memberships_cols:
            op.drop_column('tenant_memberships', 'max_members')

    if "tenants" in existing_tables:
        tenants_cols = [col['name'] for col in inspector.get_columns('tenants')]
        if 'next_credits_reset_at' not in tenants_cols:
            op.add_column('tenants', sa.Column('next_credits_reset_at', sa.DateTime(), nullable=True))

        tenants_indexes = [idx['name'] for idx in inspector.get_indexes('tenants')]
        if 'ix_tenants_stripe_customer_id' in tenants_indexes:
            op.drop_index('ix_tenants_stripe_customer_id', table_name='tenants')
        
        tenants_indexes = [idx['name'] for idx in inspector.get_indexes('tenants')]
        if 'ix_tenants_stripe_customer_id' not in tenants_indexes:
            op.create_index(op.f('ix_tenants_stripe_customer_id'), 'tenants', ['stripe_customer_id'], unique=True)
        if 'ix_tenants_created_at' not in tenants_indexes:
            op.create_index(op.f('ix_tenants_created_at'), 'tenants', ['created_at'], unique=False)

        for col_name in ['api_calls_used', 'max_members', 'api_call_limit']:
            if col_name in tenants_cols:
                op.drop_column('tenants', col_name)

    # ------------------------------------------------------------------
    # 9. users
    # ------------------------------------------------------------------
    if "users" in existing_tables:
        op.alter_column(
            'users', 
            'password_hash',
            existing_type=mysql.VARCHAR(length=255),
            nullable=True
        )

        users_indexes = [idx['name'] for idx in inspector.get_indexes('users')]
        if 'ix_users_created_at' not in users_indexes:
            op.create_index(op.f('ix_users_created_at'), 'users', ['created_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_users_created_at'), table_name='users')
    op.alter_column(
        'users', 
        'password_hash',
        existing_type=mysql.VARCHAR(length=255),
        nullable=False
    )
    op.add_column('tenants', sa.Column('api_call_limit', mysql.INTEGER(), autoincrement=False, nullable=True))
    op.add_column('tenants', sa.Column('max_members', mysql.INTEGER(), autoincrement=False, nullable=False))
    op.add_column('tenants', sa.Column('api_calls_used', mysql.INTEGER(), autoincrement=False, nullable=True))
    op.drop_index(op.f('ix_tenants_created_at'), table_name='tenants')
    op.drop_index(op.f('ix_tenants_stripe_customer_id'), table_name='tenants')
    op.create_index(op.f('ix_tenants_stripe_customer_id'), 'tenants', ['stripe_customer_id'], unique=False)
    op.drop_column('tenants', 'next_credits_reset_at')
    op.add_column('tenant_memberships', sa.Column('max_members', mysql.INTEGER(), autoincrement=False, nullable=False))
    op.alter_column(
        'tenant_memberships', 
        'role',
        existing_type=sa.String(length=10),
        type_=mysql.VARCHAR(length=50),
        existing_nullable=False
    )
    op.drop_column('tenant_invitations', 'accepted_at')
    op.add_column('subscriptions', sa.Column('stripe_customer_id', mysql.VARCHAR(length=255), nullable=False))
    op.drop_index(op.f('ix_subscriptions_created_at'), table_name='subscriptions')
    op.drop_index(op.f('ix_subscriptions_tenant_id'), table_name='subscriptions')
    op.create_index(op.f('ix_subscriptions_tenant_id'), 'subscriptions', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_subscriptions_stripe_customer_id'), 'subscriptions', ['stripe_customer_id'], unique=False)
    op.create_index(op.f('ix_stripe_checkout_sessions_status'), 'stripe_checkout_sessions', ['status'], unique=False)
    op.drop_index(op.f('ix_plans_stripe_price_id'), table_name='plans')
    op.create_index(op.f('stripe_price_id'), 'plans', ['stripe_price_id'], unique=True)
    op.create_index(op.f('ix_plans_tenant_type'), 'plans', ['tenant_type'], unique=False)
    op.create_index(op.f('ix_plans_name'), 'plans', ['name'], unique=False)
    op.create_index(op.f('ix_plans_billing_interval'), 'plans', ['billing_interval'], unique=False)
    op.add_column('credit_logs', sa.Column('credits_balance_after', mysql.INTEGER(), autoincrement=False, nullable=False))
    op.add_column('credit_logs', sa.Column('credits_used', mysql.INTEGER(), autoincrement=False, nullable=False))
    op.create_index(op.f('ix_credit_logs_action'), 'credit_logs', ['action'], unique=False)
    op.drop_column('credit_logs', 'balance_after')
    op.drop_column('credit_logs', 'amount')
    op.create_index(op.f('ix_billing_audits_event_type'), 'billing_audits', ['event_type'], unique=False)
    
    op.create_index(op.f('ix_audit_logs_target_user_id'), 'audit_logs', ['target_user_id'], unique=False)
    
    op.drop_index(op.f('ix_api_projects_created_at'), table_name='api_projects')
    op.drop_index(op.f('ix_api_keys_created_at'), table_name='api_keys')
    op.alter_column(
        'api_keys', 
        'expires_at',
        existing_type=mysql.DATETIME(),
        nullable=True
    )
    op.create_table(
        'webhook_events',
        sa.Column('stripe_event_id', mysql.VARCHAR(length=255), nullable=False),
        sa.Column('event_type', mysql.VARCHAR(length=100), nullable=False),
        sa.Column('payload', mysql.TEXT(), nullable=False),
        sa.Column('processed', mysql.TINYINT(display_width=1), autoincrement=False, nullable=False),
        sa.Column('processed_at', mysql.DATETIME(), nullable=True),
        sa.Column('created_at', mysql.DATETIME(), nullable=False),
        sa.PrimaryKeyConstraint('stripe_event_id'),
        mysql_collate='utf8mb4_0900_ai_ci',
        mysql_default_charset='utf8mb4',
        mysql_engine='InnoDB'
    )
    op.create_index(op.f('stripe_event_id'), 'webhook_events', ['stripe_event_id'], unique=True)
    op.create_index(op.f('ix_webhook_events_processed'), 'webhook_events', ['processed'], unique=False)
    op.create_index(op.f('ix_webhook_events_event_type'), 'webhook_events', ['event_type'], unique=False)
    op.drop_table('stripe_webhook_events')