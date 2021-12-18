"""
Standalone module for sending emails.
No dependencies outside of the Python standard library.

Author: Valtteri Rajalainen
"""


import smtplib
import ssl
import base64
import sys

from typing import TextIO
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread


#for testing purposes
mutex = None


def _load_credentials(filepath: str) -> tuple:
    """
    Open the provided filepath and read the credentials from it.

    Expected format is: "EMAIL\nPASSWORD"
    """
    with open(filepath) as file:
        email = file.readline().strip()
        password = file.readline().strip()
    return email, password


def _write_email_to_stream(content: str, stream: TextIO) -> None:
    """
    Write email to the provided TextIO stream. The stream is not closed.

    Content is expected to be valid email format: headers + '\n\n' + base64 encoded content.
    """
    meta, content = content.split('\n\n')
    stream.write(meta)
    stream.write('\n\n')
    stream.write(base64.b64decode(content).decode('utf-8'))
    stream.write('\n')


def send_email(message: dict, reciever: str, host: tuple, credentials_path: str, use_ssl=True):
    """
    Send the email to the specified reciever using the host credentials for the smtp relay.
    
    Message must be a dictionary. It is expected to have to entries: 'content' and 'subject'.
    The 'content'-entry must be a tuple: (CONTENT_TEXT: str, CONTENT_TYPE: str)
    The 'subject'-entrty is expected to be a simple string.
    
    Host must be a  tuple: (IP_ADDR: str, PORT: int).
    If IP_ADDR is None, PORT is expected to be a file-like object,
    where the email is written instead of sending it trough the network.

    Credential path specifies the file where the email credentials can be readfrom.
    Expected format for the file is: 'EMAIL_ADDR\nPASSWORD'

    The actual sending of the email is done in separate thread. If the mutex is not None,
    this separate thread acquires the lock while sending the email. This is useful in testing.
    """
    addr, port = host
    sender, password = _load_credentials(credentials_path)

    content, content_type = message.get('content', ('', 'plain'))
    mime_msg = MIMEText(content, content_type, _charset='utf-8')
    mime_msg['Subject'] = message.get('subject', '')
    mime_msg['From'] = sender
    mime_msg['To'] = reciever

    reply_to = message.get('reply-to', sender)
    mime_msg.add_header('Reply-To', reply_to)

    if addr is None:
        _write_email_to_stream(mime_msg.as_string(), port)
        return

    if use_ssl:
        context = ssl.create_default_context()
        server = smtplib.SMTP_SSL(addr, port, context=context)
    
    else:
        server = smtplib.SMTP(addr, port)

    def send():
        if mutex is not None:
            mutex.acquire()
        
        try:
            if use_ssl:
                server.login(sender, password)
            server.sendmail(sender, reciever, mime_msg.as_string())
        
        except smtplib.SMTPException as exc:
            sys.stderr.write(str(exc))

        finally:
            if mutex is not None:
                mutex.release()
            server.quit()
    
    Thread(target=send).start()
