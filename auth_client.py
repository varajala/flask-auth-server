import sys
import zlib
import base64
import requests
import auth_server.jwt as jwt
from json import dumps as json_dumps
from json import loads as json_loads


def b64url_decode(input_: bytes) -> bytes:
    padding = len(input_) % 4
    data = input_ if not padding else input_ + b'=' * (4 - padding)
    return base64.urlsafe_b64decode(data)


def decode_flask_session_cookie(cookie: str) -> dict:
    compressed = False

    if cookie.startswith('.'):
        compressed = True
        cookie = cookie[1:]

    data = cookie.split('.')[0]
    data = b64url_decode(data.encode())
    if compressed:
        data = zlib.decompress(data)
    return json_loads(data.decode("utf-8"))


def register_user(url: str, email: str, password: str) -> int:
    response = requests.post(url, json = dict(email=email, password=password, password_confirm=password), allow_redirects = False)
    return response.status_code


def verify_user(url: str, json_data: dict) -> int:
    response = requests.post(url, json = json_data, allow_redirects = False)
    return response.status_code


def login_and_refresh(url: str, json_data: dict) -> dict:
    response = requests.post(url, json = json_data, allow_redirects = False)
    
    redirect_location = response.headers.get('Location')
    auth_header = response.headers.get('Authorization')

    header, auth_token_str = auth_header.split(' ')
    header, payload, signature = jwt.decode(auth_token_str)
    auth_token = dict(
        header = header,
        payload = payload,
        signature = signature
    )

    raw_session_cookie = response.cookies['session']
    session_cookie = decode_flask_session_cookie(raw_session_cookie)
    header, payload, signature = jwt.decode(session_cookie['refresh_token'])
    refresh_token = dict(
        header = header,
        payload = payload,
        signature = signature
    )

    return dict(
        statuscode = response.status_code,
        redirect_location = redirect_location,
        auth_token = auth_token,
        refresh_token = refresh_token,
        session_cookie = session_cookie,
        raw_session_cookie = raw_session_cookie
    )


def refresh_access_token(url: str, raw_session_cookie: object) -> dict:
    response = requests.post(url, allow_redirects = False, cookies=dict(session=raw_session_cookie))
    
    redirect_location = response.headers.get('Location')
    auth_header = response.headers.get('Authorization')

    header, auth_token_str = auth_header.split(' ')
    header, payload, signature = jwt.decode(auth_token_str)
    auth_token = dict(
        header = header,
        payload = payload,
        signature = signature
    )
    return dict(
        statuscode = response.status_code,
        redirect_location = redirect_location,
        auth_token = auth_token
    )
