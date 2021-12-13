import microtest

from auth_server.config.restrictions import *
from auth_server.security import (
    is_valid_email,
    is_valid_password,
    is_valid_url,
    is_valid_client_name,
    )


@microtest.test
def test_valid_emails():
    emails = [
        'test@gmail.com',
        'test.testing@gmail.com',
        'test.testing.test@gmail.com',
        'Tester.Tester@t.t',
        'abcdefghijklmonpqrstuvwxyz0123456789@domain.end',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@domain.end',
    ]
    for email in emails:
        assert is_valid_email(email), f'Valid email address "{email}" failed the validation.'


@microtest.test
def test_invalid_emails():
    emails = [
        '.test@gmail.com',
        'test.@gmail.com',
        'te..st@gmail.com',
        'äää@gmail.com',
        '"asd"#*@gmail.com',
        '"asd&%!?*@gmail.com',
        'test.com',
        'test@com',
        'test+test@com',
        'test@+com',
        'test@com.',
        'test@a11.com',
        'test@gmail.c1',
        ''.join([ str('a') for _ in range(EMAIL_MAX_LENGTH + 1) ]) + '@mail.com',
    ]
    for email in emails:
        assert not is_valid_email(email), f'Invalid email address "{email}" passed the validation.'


@microtest.test
def test_valid_passwords():
    passwords = [
        'asd123456',
        'A168&Ŋäö"a',
        '?*\\þffgHJK123',
        '1234567\u265E',
    ]
    for password in passwords:
        assert is_valid_password(password), f'Valid password "{password}" failed the validation.'


@microtest.test
def test_invalid_passwords():
    passwords = [
        '',
        ' asdasdasd',
        'asdasdasd ',
        '\tasdasdasd',
        'asdasdasd\t',
        'a b c d\r\ne f\tg',
        ''.join([ str('a') for _ in range(PASSWORD_MIN_LENGTH - 1) ]),
        ''.join([ str('a') for _ in range(PASSWORD_MAX_LENGTH + 1) ]),
    ]
    for password in passwords:
        assert not is_valid_password(password), f'Invalid password "{password}" passed the validation.'


@microtest.test
def test_valid_urls():
    urls = [
        'http://localhost',
        'https://localhost',
        'http://localhost/',
        'https://localhost/',
        'http://localhost/login',
        'http://localhost:8080',
        'http://localhost:8080/',
        'http://localhost:8080/login',
        'http://localhost:8080/login/',

        'http://www.example.com',
        'http://www.example.com/',
        'http://www.example.com/login',
        'http://www.example.com/login/',

        'http://www.example.com/user-login',
        'http://www.example.com/user/121',
        'http://www.example.com/user/121/',
    ]
    for url in urls:
        assert is_valid_url(url), f'Valid url "{url}" failed the validation.'


@microtest.test
def test_invalid_urls():
    urls = [
        'www.example.com',
        'http://localhöst',
        'http://.example.com',
        'http://example.',
        ' http://www.example.com',
        'http://www.example.com/ ',
        'http://www.example.com/login?password=password&username=user'
        'http://www.example.com/login#fragment'
        '; DELETE FROM clients;',
    ]
    for url in urls:
        assert not is_valid_url(url), f'Invalid url "{url}" passed the validation.'


@microtest.test
def test_valid_client_names():
    names = [
        'client',
        'c00',
        'c_01'
        'client_001',
    ]
    for name in names:
        assert is_valid_client_name(name), f'Valid name "{name}" failed the validation.'


@microtest.test
def test_invalid_client_names():
    names = [
        '_client',
        '001',
        'c_01_'
        'ä001',
        '?aaa',
        '/client',
        '!client',
        '()[]{}|<>;:.-'
    ]
    for name in names:
        assert not is_valid_client_name(name), f'Invalid name "{name}" passed the validation.'

    
if __name__ == '__main__':
    microtest.run()

