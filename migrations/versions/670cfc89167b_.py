"""empty message

Revision ID: 670cfc89167b
Revises: 468c71a18923
Create Date: 2017-12-21 11:37:05.949810

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '670cfc89167b'
down_revision = '468c71a18923'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('posts', sa.Column('body_html', sa.Text(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('posts', 'body_html')
    # ### end Alembic commands ###
