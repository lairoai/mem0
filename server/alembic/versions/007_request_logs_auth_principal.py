"""Record the authenticated caller identity on request logs

Revision ID: 007
Revises: 006
Create Date: 2026-07-12

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("request_logs", sa.Column("auth_principal", sa.String(320), nullable=True))


def downgrade() -> None:
    op.drop_column("request_logs", "auth_principal")
