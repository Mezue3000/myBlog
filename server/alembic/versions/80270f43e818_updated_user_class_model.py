"""updated User class model

Revision ID: 80270f43e818
Revises: 1290df888cb5
Create Date: 2025-06-01 21:26:16.217246

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '80270f43e818'
down_revision: Union[str, None] = '1290df888cb5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('updated_at', sa.DateTime(), nullable=True))
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_unique_constraint(None, 'users', ['email'])
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='unique')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=False)
    op.drop_column('users', 'updated_at')
    # ### end Alembic commands ###
