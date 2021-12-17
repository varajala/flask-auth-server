import sys
import zlib
import base64
import io
from json import dumps as json_dumps
from json import loads as json_loads

if sys.platform == 'linux':
    import readline

import requests
import auth_server.jwt as jwt


CLIENT_UUID = ''
API_PORT = 5000
API_VERSION = '1.0'
API_LOGIN_URL = f'http://localhost:{API_PORT}/api/{API_VERSION}/login/{CLIENT_UUID}'

USER_EMAIL = ''
USER_PASSWORD = ''


def format_dict(d: dict, indent_level = 1) -> str:
    buffer = io.StringIO()
    buffer.write('{\n')

    for name, value in d.items():
        buffer.write(indent_level * 2 * ' ')
        buffer.write(str(name))
        buffer.write(' = ')
    
        if isinstance(value, dict):
            buffer.write(format_dict(value, indent_level = indent_level + 1))
        else:
            buffer.write(str(value))
        buffer.write(',\n')

    buffer.write((indent_level - 1) * 2 * ' ')
    buffer.write('}')
    result = buffer.getvalue()
    buffer.close()
    return result




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


def do_login_and_refresh(url: str, json_data: dict):
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

    session_cookie = decode_flask_session_cookie(response.cookies['session'])
    header, payload, signature = jwt.decode(session_cookie['refresh_token'])
    refresh_token = dict(
        header = header,
        payload = payload,
        signature = signature
    )

    print('Got response.')
    print('Status: ', response.status_code)
    print('Redirect Location: ', redirect_location)
    print('Auth token: ', format_dict(auth_token))
    print('Refresh token: ', format_dict(refresh_token))


def main():
    do_login_and_refresh(API_LOGIN_URL, dict(email = USER_EMAIL, password = USER_PASSWORD))


if __name__ == '__main__':
    main()
