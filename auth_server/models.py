"""
Data represented as models.

Author: Valtteri Rajalainen
"""

from auth_server.config.security import CLIENT_SECRET_LENGTH
from auth_server.extensions import orm
from auth_server.common import unix_utc_now
from auth_server.config.restrictions import (
    EMAIL_MAX_LENGTH,
    CLIENT_NAME_MAX_LENGTH,
)


# for testing
tables = list()

def export_table(obj):
    """
    Collect table in the tables list.
    Used mainly for testing, where db contents are reset
    after each test case.
    """
    tables.append(obj)
    return obj


@export_table
class User(orm.Model):
    id = orm.Column(orm.Integer, primary_key=True)
    email = orm.Column(orm.String(EMAIL_MAX_LENGTH), unique=True, nullable=False)
    password_hash = orm.Column(orm.Text, nullable=False)
    is_verified = orm.Column(orm.Boolean, default=False)


@export_table
class OTP(orm.Model):
    id = orm.Column(orm.Integer, primary_key=True)
    value = orm.Column(orm.Text, nullable=False)
    issued_at = orm.Column(orm.Integer, nullable=False)
    expires_at = orm.Column(orm.Integer, nullable=False)

    user_id = orm.Column(orm.Integer, orm.ForeignKey('user.id'))

    def is_expired(self):
        now = unix_utc_now()
        return self.expires_at - now < 0

    @property
    def raw_value(self):
        return bytes.fromhex(self.value)


@export_table
class Client(orm.Model):
    id = orm.Column(orm.Integer, primary_key=True)
    uuid = orm.Column(orm.Text, unique=True, nullable=False)
    name = orm.Column(orm.String(CLIENT_NAME_MAX_LENGTH), unique=True, nullable=False)
    url = orm.Column(orm.Text, nullable=False)
    secret_key_hex = orm.Column(orm.String(2 * CLIENT_SECRET_LENGTH), nullable=False)

    @property
    def secret_key(self) -> bytes:
        return bytes.fromhex(self.secret_key_hex)
            