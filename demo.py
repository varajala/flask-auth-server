import os
import sys
import io
import re
import time
import atexit
import threading
import auth_server as wsgi_server
import auth_client as client
import auth_server.notifications as wsgi_server_notifications
import auth_server.manage as wsgi_server_management
from auth_server.config.security import OTP_LENGTH
from microtest.utils import start_wsgi_server, start_smtp_server


HTTP_OK_RESPONSES = { 200, 302 }
MIN_EMAIL_LENGTH = 256 # characters

LOCALHOST = '127.0.0.1'
SMTP_SERVER_PORT = 25000

API_PORT = 5000
API_VERSION = '1.0'

API_REGISTER_URL = f'http://localhost:{API_PORT}/api/{API_VERSION}/register'
API_VERIFY_URL = f'http://localhost:{API_PORT}/api/{API_VERSION}/verify'

USER_EMAIL = 'test@mail.com'
USER_PASSWORD = 'test1234'

CONFIG_OPTIONS = dict(
    EMAIL_USE_SSL   = False,
    EMAIL_HOST      = (LOCALHOST, SMTP_SERVER_PORT)
)


def format_api_login_url(client_uuid: str):
    return f'http://localhost:{API_PORT}/api/{API_VERSION}/login/{client_uuid}'


def find_account_verification_token(email: str) -> str:
    token_regex = re.compile('<b>\\w{' + str(OTP_LENGTH * 2) + '}</b>')
    match = re.search(token_regex, email)
    return '' if match is None else match.group()[3:-4]


def main():
    CONFIG_OPTIONS['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///:memory:'
    CONFIG_OPTIONS['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    wsgi_app = wsgi_server.create_app(CONFIG_OPTIONS)

    with wsgi_app.app_context():
        wsgi_server.orm.create_all()

    mutex = threading.Lock()
    wsgi_server_notifications.mutex = mutex

    client_uuid = None
    with wsgi_app.app_context():
        client_uuid = wsgi_server_management.create_test_client(wsgi_app, 'test', 'http://localhost:8080/index')
    
    if not client_uuid:
        print('FAILED: Failed to create a test client...')
        return

    smtp_server_proc = start_smtp_server(host = LOCALHOST, port = SMTP_SERVER_PORT, wait=True)
    wsgi_server_proc = start_wsgi_server(wsgi_app, host = LOCALHOST, port = API_PORT, wait=True)

    @atexit.register
    def terminate():
        wsgi_server_proc.terminate()
        smtp_server_proc.terminate()

    print('Registering a new user...')
    response_status = client.register_user(API_REGISTER_URL, USER_EMAIL, USER_PASSWORD)
    print('Got response: ', response_status)

    if response_status not in HTTP_OK_RESPONSES:
        print('FAILED: Registration not succesful...')
        return
    
    email = ''
    for i in range(4, 0, -1):
        with mutex:
            email = smtp_server_proc.read_output(read_all=True)
        
        if len(email) > MIN_EMAIL_LENGTH:
            break
        
        time.sleep(0.1)
        
    if not email:
        print('FAILED: No verification email sent...')
        return

    print('Server sent verification email: ')
    print(email)

    verification_token = find_account_verification_token(email)
    if not verification_token:
        print('FAILED: Account verification token not found in email...')
        return
    
    input('Press ENTER to verify user account.')
    print('\nVerfiying user account...')
    response_status = client.verify_user(API_VERIFY_URL, dict(email = USER_EMAIL, token = verification_token))
    print('Got response: ', response_status)
    if response_status not in HTTP_OK_RESPONSES:
        print('FAILED: Account verification not succesful...')
        return

    input('Press ENTER to login user.')
    print('\nLogging in user...')
    response_data = client.login_user(format_api_login_url(client_uuid), dict(email = USER_EMAIL, password = USER_PASSWORD))
    response_status = response_data['statuscode']
    print('Got response: ', response_status)
    if response_status not in HTTP_OK_RESPONSES:
        print('FAILED: User login not succesful...')
        return
    
    print('Redirect URL: ', response_data['redirect_location'])
    print()

    print('Access token: ', format_dict(response_data['access_token']))
    print()

    print('Refresh token: ', format_dict(response_data['refresh_token']))
    print()

    raw_session_cookie = response_data['raw_session_cookie']
    while True:
        input('Press ENTER to refresh access token, CTRL+C to quit...')
        print('\nRefreshing access token...')
        response_data = client.refresh_access_token(format_api_login_url(client_uuid), raw_session_cookie)
        response_status = response_data['statuscode']
        print('Got response: ', response_status)
        if response_status not in HTTP_OK_RESPONSES:
            print('FAILED: Access token refresh not succesful...')
            return 1
        
        print('Redirect URL: ', response_data['redirect_location'])
        print()

        print('Access token: ', format_dict(response_data['access_token']))
        print()


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


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n')
