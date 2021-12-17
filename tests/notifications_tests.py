import threading
import tempfile
import base64

import microtest
from microtest.utils import start_smtp_server


import auth_server.notifications as notifications


LOCALHOST = '127.0.0.1'
PORT = 25000
EMAIL_ADDR = 'test@email.com'
EMAIL_PASSWORD = 'password'


def open_credential_file(*args, **kwargs):
    return CredentialFile()


class CredentialFile:
    def __init__(self):
        self.count = 0

    def readline(self):
        if self.count == 0:
            self.count = 1
            return EMAIL_ADDR
        
        self.count = 0
        return EMAIL_PASSWORD

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        pass


@microtest.setup
def setup():
    global file, proc
    proc = start_smtp_server(port=PORT)
    file = tempfile.TemporaryFile(mode='w+')


@microtest.cleanup
def cleanup():
    proc.terminate()
    file.close()

    
@microtest.test
def test_email_sending():
    message = {
        'content': ('<p>Message</p>', 'html'),
        'subject':'Testing'
    }
    recv = 'recv@mail.com'

    test_builtins = notifications.__builtins__.copy()
    test_builtins['open'] = open_credential_file

    mutex = threading.Lock()
    notifications.mutex = mutex

    with microtest.patch(notifications, __builtins__ =  test_builtins):
        notifications.send_email(message, recv, (LOCALHOST, PORT), None, use_ssl=False)

    with mutex:
        email = proc.read_output()
        assert f'To: {recv}' in email
        assert f'From: {EMAIL_ADDR}' in email
        assert f'Subject: Testing' in email
        assert base64.b64encode(b'<p>Message</p>').decode() in email
    


@microtest.test
def test_writing_email_to_file():
    message = {
        'content': ('<p>Message</p>', 'html'),
        'subject':'Testing'
    }
    recv = 'recv@mail.com'

    test_builtins = notifications.__builtins__.copy()
    test_builtins['open'] = open_credential_file

    msg_start = file.tell()

    with microtest.patch(notifications, __builtins__ =  test_builtins):
        notifications.send_email(message, recv, (None, file), None)    

    file.seek(msg_start)
    email = file.read()
    assert f'To: {recv}' in email
    assert f'From: {EMAIL_ADDR}' in email
    assert f'Subject: Testing' in email
    assert '<p>Message</p>' in email

    
if __name__ == '__main__':
    microtest.run()
