"""modify/removed models

Revision ID: a196cbad4e57
Revises: b57f9cd229af
Create Date: 2026-06-19 11:14:27.816701

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = 'a196cbad4e57'
down_revision: Union[str, None] = 'b57f9cd229af'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 🚀 1. Drop the foreign key constraints first to break the table locks
    try:
        op.drop_constraint('comments_ibfk_1', table_name='comments', type_='foreignkey')
    except Exception:
        pass

    try:
        op.drop_constraint('posts_ibfk_1', table_name='posts', type_='foreignkey')
    except Exception:
        pass

    # 🚀 2. Drop the tables directly. MySQL will automatically drop all underlying indexes!
    op.drop_table('comments')
    op.drop_table('posts')

    # 🚀 3. Safely handle your actual B2B SaaS structural adjustments
    op.add_column('api_keys', sa.Column('revoked_by', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_api_keys_revoked_by', 'api_keys', 'users', ['revoked_by'], ['user_id'])
    
    try:
        op.drop_constraint('fk_subscriptions_owner_id', 'subscriptions', type_='foreignkey')
    except Exception:
        pass
    
    # Try dropping this index only if it exists; otherwise pass safely
    try:
        op.drop_index('ix_subscriptions_owner_id', table_name='subscriptions')
    except Exception:
        pass
        
    op.drop_column('subscriptions', 'owner_id')


def downgrade() -> None:
    """Downgrade schema."""
    # Reconstruct subscription column
    op.add_column('subscriptions', sa.Column('owner_id', sa.CHAR(length=32), nullable=False))
    op.create_foreign_key('fk_subscriptions_owner_id', 'subscriptions', 'tenants', ['owner_id'], ['tenant_id'])
    op.create_index('ix_subscriptions_owner_id', 'subscriptions', ['owner_id'], unique=False)
    
    op.drop_constraint('fk_api_keys_revoked_by', 'api_keys', type_='foreignkey')
    op.drop_column('api_keys', 'revoked_by')
    
    # Reconstruct tables if rolling back
    op.create_table('posts',
        sa.Column('post_id', sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column('title', sa.VARCHAR(length=125), nullable=False),
        sa.Column('content', sa.VARCHAR(length=450), nullable=False),
        sa.Column('created_at', sa.DATETIME(), server_default=sa.text('(now())'), nullable=False),
        sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], name='posts_ibfk_1'),
        sa.PrimaryKeyConstraint('post_id')
    )
    
    op.create_table('comments',
        sa.Column('comment_id', sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column('content', sa.VARCHAR(length=225), nullable=False),
        sa.Column('post_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.ForeignKeyConstraint(['post_id'], ['posts.post_id'], name='comments_ibfk_1'),
        sa.PrimaryKeyConstraint('comment_id')
    )