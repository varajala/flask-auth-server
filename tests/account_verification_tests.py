import microtest
from auth_server.extensions import orm
from auth_server.models import User, OTP
from auth_server.common import unix_utc_now
import auth_server.security as security


USER_EMAIL = 'test@mail.com'

def create_test_user():
    user = User(email=USER_EMAIL, password_hash='')
    orm.session.add(user)


def create_test_otp(value: bytes, user_id):
    iat = unix_utc_now()
    eat = iat + 60
    otp = OTP(value = value.hex(), user_id = user_id, issued_at = iat, expires_at = eat)
    orm.session.add(otp)


@microtest.setup
def setup(app):
    global ctx
    ctx = app.app_context()
    ctx.push()


@microtest.reset
def reset():
    User.query.delete()
    OTP.query.delete()

    
@microtest.cleanup
def cleanup():
    reset_database()
    ctx.pop()


@microtest.test
def test_valid_account_verification():
    otp_value = b'\x00\x01'
    create_test_user()
    user = User.query.filter_by(email=USER_EMAIL).first()
    create_test_otp(otp_value, user.id)

    error = security.verify_user_account(email=USER_EMAIL, otp_hex=otp_value.hex())
    assert error is None

    user = User.query.filter_by(email=USER_EMAIL).first()
    assert user.is_verified


@microtest.test
def test_typechecking():
    #invalid types
    assert microtest.raises(
        security.verify_user_account,
        {'email': 10, 'otp_hex': 10},
        TypeError
        )
    #missing arg
    assert microtest.raises(
        security.verify_user_account,
        {'email': 'email.address@mail.com'},
        TypeError
        )


@microtest.test
def test_invalid_email():
    otp_value = b'\x00\x01'
    user_id = create_test_user()
    create_test_otp(otp_value, user_id)

    error = security.verify_user_account(email='email.address@mail.com', otp_hex=otp_value.hex())
    assert error is not None

    