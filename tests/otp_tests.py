import microtest
import flask

from auth_server.extensions import orm
from auth_server.security import generate_otp, is_valid_otp
from auth_server.common import unix_utc_now
from auth_server.models import OTP, User


USER_ID = None

@microtest.setup
def setup(app):
    global ctx, USER_ID
    ctx = app.app_context()
    ctx.push()
    
    test_user = User(email='test', password_hash='test')
    orm.session.add(test_user)
    
    user = User.query.first()
    USER_ID = user.id


@microtest.reset
def reset():
    OTP.query.delete()


@microtest.cleanup
def cleanup():
    reset_database()
    ctx.pop()


@microtest.test
def test_generating_otps():
    lifetime = 60
    hex_token = generate_otp(USER_ID, lifetime)
    otp = OTP.query.first()
    
    assert otp is not None
    assert otp.user_id == USER_ID
    assert otp.value == hex_token
    assert otp.raw_value == bytes.fromhex(hex_token)
    assert not otp.is_expired()


@microtest.test
def test_correct_otp_validation():
    token = b'\x00\x01'
    iat = unix_utc_now()
    eat = iat + 60

    otp = OTP(value = token.hex(), user_id = USER_ID, issued_at = iat, expires_at = eat)
    orm.session.add(otp)

    assert is_valid_otp(USER_ID, token.hex())
    assert OTP.query.first() is None


@microtest.test
def test_expired_otp_validation():
    token = b'\x00\x01'
    iat = unix_utc_now()
    eat = iat - 60

    otp = OTP(value = token.hex(), user_id = USER_ID, issued_at = iat, expires_at = eat)
    orm.session.add(otp)

    assert not is_valid_otp(USER_ID, token.hex())
    assert OTP.query.first() is None


@microtest.test
def test_wrong_otp_validation():
    token = b'\x00\x01'
    iat = unix_utc_now()
    eat = iat + 60

    otp = OTP(value = token.hex(), user_id = USER_ID, issued_at = iat, expires_at = eat)
    orm.session.add(otp)

    assert not is_valid_otp(USER_ID, b'\x00\x02'.hex())
    assert OTP.query.first() is not None


@microtest.test
def test_invalid_otp_validation():
    token = b'\x00\x01'
    iat = unix_utc_now()
    eat = iat + 60

    otp = OTP(value = token.hex(), user_id = USER_ID, issued_at = iat, expires_at = eat)
    orm.session.add(otp)

    assert not is_valid_otp(USER_ID, 'asdasd')
    assert OTP.query.first() is not None
