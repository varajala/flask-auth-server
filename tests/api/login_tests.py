import microtest
import flask

import auth_server.security
import auth_server.jwt as jwt
from auth_server.extensions import orm
from auth_server.aes import encrypt
from auth_server.api import build_endpoint_url
from auth_server.models import User, Client
from auth_server.security import generate_password_hash, generate_refresh_token


USER_EMAIL = 'test@mail.com'
USER_PASSWORD = 'test'
CLIENT_UUID = '000-001'
CLIENT_URL = 'http://localhost:8080'
CLIENT_SECRET_KEY = b'\x41\x42\x42\x41'


@microtest.setup
def setup(app):
    with app.app_context():
        user = User(
            email = USER_EMAIL,
            password_hash = generate_password_hash(USER_PASSWORD),
            is_verified = True
            )
        orm.session.add(user)
        
        AES_KEY = flask.current_app.config['AES_KEY']
        client = Client(
            uuid=CLIENT_UUID,
            name='test_client',
            url=CLIENT_URL,
            secret_key_hex = encrypt(CLIENT_SECRET_KEY, AES_KEY).hex()
            )
        orm.session.add(client)


@microtest.cleanup
def cleanup(app):
    with app.app_context():
        reset_database()


@microtest.test
def test_valid_login(app):
    with app.app_context():
        url = build_endpoint_url(f'/login/{CLIENT_UUID}')
        with app.test_client() as client:
            json_data = {'email': USER_EMAIL, 'password': USER_PASSWORD}
            response = client.post(url, json=json_data)
            refresh_token = flask.session['refresh_token']
            auth = response.headers['Authorization']
            redirect_location = response.headers['Location']

    auth_schema, access_token = auth.split(' ')
    assert auth_schema == 'Bearer'
    assert access_token
    assert refresh_token
    assert redirect_location == CLIENT_URL

    header, payload, signature = jwt.decode(access_token)
    assert jwt.is_valid(header, payload, signature, CLIENT_SECRET_KEY)

    header, payload, signature = jwt.decode(refresh_token)
    assert jwt.is_valid(header, payload, signature, CLIENT_SECRET_KEY)


@microtest.test
def test_login_with_valid_refresh_token(app):
    with app.app_context():
        user_id = User.query.filter_by(email = USER_EMAIL).first().id
        user = Namespace({'id': user_id})
        refresh_token = generate_refresh_token(user, CLIENT_UUID, CLIENT_SECRET_KEY)
        url = build_endpoint_url(f'/login/{CLIENT_UUID}')
        with app.test_client() as client:
            with client.session_transaction() as session:
                session['refresh_token'] = refresh_token
            response = client.post(url)
            redirect_location = response.headers['Location']
            auth = response.headers['Authorization']
        
        auth_schema, access_token = auth.split(' ')
        assert redirect_location == CLIENT_URL
        assert auth_schema == 'Bearer'
        assert access_token
        
        header, payload, signature = jwt.decode(access_token)
        assert jwt.is_valid(header, payload, signature, CLIENT_SECRET_KEY)


@microtest.test
def test_login_with_invalid_refresh_token(app):
    with app.app_context():
        user_id = User.query.filter_by(email = USER_EMAIL).first().id
        user = Namespace({'id': user_id})
        with microtest.patch(auth_server.security, REFRESH_TOKEN_LIFETIME = -1):
            refresh_token = generate_refresh_token(user, CLIENT_UUID, CLIENT_SECRET_KEY)

        url = build_endpoint_url(f'/login/{CLIENT_UUID}')
        with app.test_client() as client:
            with client.session_transaction() as session:
                session['refresh_token'] = refresh_token
            response = client.post(url)
        assert response.status_code == 400


@microtest.test
def test_login_with_invalid_client_uuid(app):
    with app.app_context():
        url = build_endpoint_url(f'/login/not-a-client-uuid')
        with app.test_client() as client:
            response = client.post(url, json={'email': USER_EMAIL, 'password': USER_PASSWORD})
        assert response.status_code == 404


@microtest.test
def test_login_with_invalid_credentials(app):
    with app.app_context():
        url = build_endpoint_url(f'/login/{CLIENT_UUID}')
        with app.test_client() as client:
            response = client.post(url, json={'email': USER_EMAIL, 'password': 'not-user-password'})
        assert response.status_code == 401


@microtest.test
def test_login_with_invalid_json_types(app):
    with app.app_context():
        url = build_endpoint_url(f'/login/{CLIENT_UUID}')
        with app.test_client() as client:
            response = client.post(url, json={'email': USER_EMAIL, 'password': 10})
        assert response.status_code == 400
