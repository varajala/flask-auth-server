import microtest
import flask

from auth_server.api import build_endpoint_url
from auth_server.models import User, OTP


@microtest.cleanup
def cleanup(app):
    with app.app_context():
        reset_database()


@microtest.test
def test_valid_registering(app, email_file):
    email_start = email_file.tell()
    user_email = 'test@mail.com'

    with app.app_context():
        url = build_endpoint_url('/register')
        with app.test_client() as client:
            json_data = {
                'email': user_email,
                'password': '12345678',
                'password_confirm': '12345678',
            }
            response = client.post(url, json=json_data)
    
        user = User.query.filter_by(email = user_email).first()
        otp = OTP.query.filter_by(user_id = user.id).first()
    
        email_file.seek(email_start)
        email = email_file.read()

        assert response.status_code == 200
        assert user is not None
        assert otp is not None
        assert email != ''

        assert otp.value in email
        assert f'To: {user.email}' in email
        assert not user.is_verified


@microtest.test
def test_invalid_request_json(app):
    with app.app_context():
        url = build_endpoint_url('/register')
        with app.test_client() as client:
            json_data = {
                'email': 'test',
                'password': 123,
                'password_confirm': 123,
            }
            response = client.post(url, json=json_data)
    assert response.status_code == 400
