import microtest

from auth_server.extensions import orm
from auth_server.models import User
import auth_server.security as security


USER_EMAIL = 'test@mail.com'
USER_PASSWORD = 'password'


@microtest.setup
def setup(app):
    global ctx
    ctx = app.app_context()
    ctx.push()

    test_user = User(
        email=USER_EMAIL,
        password_hash=security.generate_password_hash(USER_PASSWORD),
        is_verified=True
        )
    orm.session.add(test_user)


@microtest.cleanup
def cleanup():
    reset_database()
    ctx.pop()


@microtest.test
def test_typechecking():
    #invalid_type
    assert microtest.raises(
        security.is_valid_login,
        {'email': 10, 'password': '1'},
        TypeError
        )
    #missing_arg
    assert microtest.raises(
        security.is_valid_login,
        {'email': '1'},
        TypeError
        )


@microtest.test
def test_valid_login():
    assert security.is_valid_login(email=USER_EMAIL, password=USER_PASSWORD)


@microtest.test
def test_login_invalid_email():
    assert not security.is_valid_login(email='email.address@mail.com', password=USER_PASSWORD)


@microtest.test
def test_login_invalid_password():
    assert not security.is_valid_login(email=USER_EMAIL, password='some other password')


@microtest.test
def test_login_account_not_verified():
    user = User.query.filter_by(email=USER_EMAIL).first()
    user.is_verified = False

    assert not security.is_valid_login(email=USER_EMAIL, password=USER_PASSWORD)

