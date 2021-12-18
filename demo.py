import os
import io
import sys
import atexit
import threading
import auth_server as wsgi_server
import auth_client as client
import auth_server.notifications as wsgi_server_notifications
import auth_server.manage as wsgi_server_management

from microtest.utils import start_wsgi_server, start_smtp_server


LOCALHOST = '127.0.0.1'
SMTP_SERVER_PORT = 25000

API_PORT = 5000
API_VERSION = '1.0'

API_REGISTER_URL = f'http://localhost:{API_PORT}/api/{API_VERSION}/register'
API_VERIFY_URL = f'http://localhost:{API_PORT}/api/{API_VERSION}/verify'

CONFIG_OPTIONS = dict(
    EMAIL_USE_SSL   = False,
    EMAIL_HOST      = (LOCALHOST, SMTP_SERVER_PORT)
)


def format_api_login_endpoint(client_uuid: str):
    return f'http://localhost:{API_PORT}/api/{API_VERSION}/login/{client_uuid}'


def main():
    CONFIG_OPTIONS['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///:memory:'
    CONFIG_OPTIONS['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    wsgi_app = wsgi_server.create_app(CONFIG_OPTIONS)

    smtp_server_proc = start_smtp_server(host = LOCALHOST, port = SMTP_SERVER_PORT)
    wsgi_server_proc = start_wsgi_server(wsgi_app, host = LOCALHOST, port = API_PORT)

    @atexit.register
    def terminate():
        wsgi_server_proc.terminate()
        smtp_server_proc.terminate()

    with wsgi_app.app_context():
        wsgi_server.orm.create_all()

    mutex = threading.Lock()
    wsgi_server_notifications.mutex = mutex

    client_uuid = wsgi_server_management.create_test_client(wsgi_app, 'test-client', 'localhost:8080/index')
    
    input('email and auth server running, press any key to stop...')

    # register_user(API_REGISTER_URL, USER_EMAIL, USER_PASSWORD))
    # verify_user(API_VERIFY_URL, dict(email = USER_EMAIL, token = input('Paste the verification token send via email: ').strip()))
    # login_and_refresh(API_LOGIN_URL, dict(email = USER_EMAIL, password = USER_PASSWORD))
    return 0


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
    sys.exit(main())
