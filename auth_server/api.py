"""
API for this service.
Endpoints implemented here.

Author: Valtteri Rajalainen
"""

import os
import typing
import flask
from flask.typing import ResponseReturnValue as Response

import auth_server.security as security
import auth_server.notifications as notifications
import auth_server.jwt as jwt

from auth_server.aes import decrypt
from auth_server.models import User, Client
from auth_server.common import capture_exception
from auth_server.config.api import (
    API_VERSION,
    SERVICE_NAME,
    ACCESS_TOKEN_HEADER,
    ACCESS_TOKEN_SCHEMA,
    REFRESH_TOKEN_KEY,
)


HTTP_OK = ('OK', 200)
HTTP_BAD_REQUEST = ('Bad Request', 400)
HTTP_NOT_AUTHORIZED = ('Unauthorized', 401)
HTTP_NOT_FOUND = ('Not Found', 404)


def build_endpoint_url(endpoint: str):
    prefix = f'/api/{API_VERSION}'
    return prefix + endpoint if endpoint.startswith('/') else prefix + '/' + endpoint


def get_email_template_folder():
    filepath = os.path.abspath(__file__)
    dir_path = os.path.dirname(filepath)
    return os.path.join(dir_path, 'emails')


blueprint = flask.Blueprint(
    'api', __name__,
    template_folder=get_email_template_folder()
    )


@blueprint.route(build_endpoint_url('/register'), methods=('POST',))
def register() -> Response:
    request = flask.request
    json_data = request.get_json()
    if json_data is None or not isinstance(json_data, dict):
        return HTTP_BAD_REQUEST

    email = json_data.get('email', None)
    password = json_data.get('password', None)
    password_confirm = json_data.get('password_confirm', None)

    error = None
    with capture_exception(TypeError) as capture:
        error = security.register_user(
            email = email,
            password = password,
            password_confirm = password_confirm
            )
    
    if capture.error is not None or error is not None:
        return HTTP_BAD_REQUEST

    user = User.query.filter_by(email = email).first()
    otp_token = security.generate_otp(
        user.id,
        security.EMAIL_VERIFICATION_OTP_LIFETIME
        )

    email_context = {
        'reciever': user.email,
        'service_name': SERVICE_NAME,
        'token': otp_token,
        'lifetime': security.EMAIL_VERIFICATION_OTP_LIFETIME // (60 * 60),
    }
    email_html = flask.render_template('verify_account.html', context=email_context)
    
    notifications.send_email(
        message = {'content': ('html', email_html), 'subject': 'Verify your new account'},
        reciever = user.email,
        host = flask.current_app.config['EMAIL_HOST'],
        credentials_path = flask.current_app.config['EMAIL_CREDENTIALS_PATH'],
        use_ssl = flask.current_app.config['EMAIL_USE_SSL']
    )
    return HTTP_OK


@blueprint.route(build_endpoint_url('/verify'), methods=('POST',))
def verify() -> Response:
    request = flask.request
    json_data = request.get_json()
    if json_data is None or not isinstance(json_data, dict):
        return HTTP_BAD_REQUEST

    email = json_data.get('email', None)
    hex_token = json_data.get('token', None)

    error = None
    with capture_exception(TypeError) as capture:
        error = security.verify_user_account(email = email, otp_hex = hex_token)
    
    if capture.error is not None or error is not None:
        return HTTP_BAD_REQUEST
    
    user = User.query.filter_by(email = email).first()
    user.is_verified = True
    return HTTP_OK


@blueprint.route(build_endpoint_url('/login/<client_id>'), methods=('POST',))
def login(client_id: str) -> Response:
    session = flask.session
    request = flask.request
    
    client = Client.query.filter_by(uuid = client_id).first()
    if client is None:
        return HTTP_NOT_FOUND

    # decrypt client secret
    AES_KEY = flask.current_app.config['AES_KEY']
    CLIENT_SECRET = decrypt(client.secret_key, AES_KEY)

    # check for valid refresh tokens provided in session cookie
    # refresh the access token if refresh toke is valid
    # otherwise continue normally with login
    refresh_token = session.get(REFRESH_TOKEN_KEY, None)
    if refresh_token is not None:
        with capture_exception(jwt.DecodingError) as capture:
            header, payload, signature = jwt.decode(refresh_token)
      
        context = {'aud': client.uuid, 'secret_key': CLIENT_SECRET}
        if capture.error is None and security.is_valid_jwt_for_context(header, payload, signature, context):
            user = User.query.get(payload['sub'])
            access_token = security.generate_access_token(user, client.uuid, CLIENT_SECRET)
            response = flask.redirect(client.url)
            response.headers[ACCESS_TOKEN_HEADER] = ACCESS_TOKEN_SCHEMA + access_token
            return response


    # no valid refresh token provided, continue with login
    json_data = request.get_json()
    if json_data is None or not isinstance(json_data, dict):
        return HTTP_BAD_REQUEST
    
    email = json_data.get('email', None)
    password = json_data.get('password', None)

    # verify login
    valid_login = False
    with capture_exception(TypeError) as capture:
        valid_login = security.is_valid_login(email = email, password = password)

    if capture.error:
        return HTTP_BAD_REQUEST

    if not valid_login:
        return HTTP_NOT_AUTHORIZED

    # generate jwts using client secret (access, refresh)
    user = User.query.filter_by(email = email).first()
    access_token = security.generate_access_token(user, client.uuid, CLIENT_SECRET)
    refresh_token = security.generate_refresh_token(user, client.uuid, CLIENT_SECRET)    
    # send access token in "Authorization" header with the "Bearer" schema
    # send refresh token in cookie (HTTP-ONLY)
    # redirect to the client
    response = flask.redirect(client.url)
    response.headers[ACCESS_TOKEN_HEADER] = ACCESS_TOKEN_SCHEMA + access_token
    session[REFRESH_TOKEN_KEY] = refresh_token
    return response
