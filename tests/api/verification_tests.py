import microtest
import flask

from auth_server.extensions import orm
from auth_server.api import build_endpoint_url
from auth_server.models import User, OTP
from auth_server.common import unix_utc_now


@microtest.cleanup
def cleanup(app):
    with app.app_context():
        reset_database()


@microtest.test
def test_valid_verification(app):
    user_email = 'test@mail.com'
    token = b'\x0a\x0a'

    with app.app_context():
        user = User(email = user_email, password_hash='')
        orm.session.add(user)
        
        user_id = User.query.first().id
        iat = unix_utc_now()
        exp = iat + 60
        otp = OTP(value = token.hex(), user_id=user_id, issued_at = iat, expires_at = exp)
        orm.session.add(otp)
        
        with app.test_client() as client:
            json_data = {
                'email': user_email,
                'token': token.hex(),
            }
            response = client.post(build_endpoint_url('/verify'), json=json_data)

        user = User.query.filter_by(email = user_email).first()
        otp = OTP.query.filter_by(user_id = user.id).first()

        assert response.status_code == 200
        assert user is not None
        assert otp is None
        assert user.is_verified


@microtest.test
def test_invalid_request_json(app):
    with app.app_context():
        url = build_endpoint_url('/verify')
        with app.test_client() as client:
            json_data = {
                'email': 'test',
                'token': 100,
            }
            response = client.post(url, json=json_data)
    assert response.status_code == 400
