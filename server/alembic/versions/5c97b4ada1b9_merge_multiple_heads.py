"""merge multiple heads

Revision ID: 5c97b4ada1b9
Revises: 120083403463, d82a33ad24f8
Create Date: 2026-07-20 23:43:03.856718

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5c97b4ada1b9'
down_revision: Union[str, None] = ('120083403463', 'd82a33ad24f8')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
