import microtest
from auth_server.extensions import orm
from auth_server.models import User
import auth_server.security as security


@microtest.setup
def setup(app):
    global ctx
    ctx = app.app_context()
    ctx.push()


@microtest.reset
def reset():
    User.query.delete()

    
@microtest.cleanup
def cleanup():
    reset_database()
    ctx.pop()


@microtest.test
def test_typechecking():
    #invalid_type
    assert microtest.raises(
        security.register_user,
        {'email': 10, 'password': '1', 'password_confirm': '2'},
        TypeError
        )
    #missing_arg
    assert microtest.raises(
        security.register_user,
        {'email': '1', 'password': '2'},
        TypeError
        )


@microtest.test
def test_valid_registering():
    error = security.register_user(email='test@mail.com', password='12345678', password_confirm='12345678')
    assert error is None
    
    user = User.query.filter_by(email='test@mail.com').first()
    assert user is not None
    assert not user.is_verified


@microtest.test
def test_registering_invalid_email():
    error = security.register_user(email='asd', password='12345678', password_confirm='12345678')
    assert error is not None    
    assert len(User.query.all()) == 0


@microtest.test
def test_registering_email_in_user():
    USED_EMAIL = 'email.address@email.net'
    user = User(email = USED_EMAIL, password_hash = '')
    orm.session.add(user)
    
    error = security.register_user(email=USED_EMAIL, password='12345678', password_confirm='12345678')
    assert error is not None    


@microtest.test
def test_registering_invalid_password():
    error = security.register_user(email='test@mail.com', password=' 123', password_confirm=' 123')
    assert error is not None    
    assert len(User.query.all()) == 0


@microtest.test
def test_registering_invalid_password_confirm():
    error = security.register_user(email='test@mail.com', password='12345678', password_confirm='123')
    assert error is not None
    assert len(User.query.all()) == 0
