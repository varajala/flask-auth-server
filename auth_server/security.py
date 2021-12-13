"""
Security related functions.

Author: Valtteri Rajalainen
"""

import hmac
import os
import re
import functools
from typing import Union

import werkzeug.security

from auth_server.config.security import *
from auth_server.config.restrictions import *

from auth_server.extensions import orm
from auth_server.models import User, Client, OTP
from auth_server.common import unix_utc_now
import auth_server.jwt as jwt


def check_password_hash(password_hash, provided_password):
    return werkzeug.security.check_password_hash(password_hash, provided_password)


def generate_password_hash(password: str) -> str:
    method = f'pbkdf2:{PBKDF2_HASH}:{PBKDF2_ITERATIONS}'
    hash_ = werkzeug.security.generate_password_hash(password, method, SALT_LENGTH)
    return hash_


def generate_otp(user_id: int, lifetime: int) -> str:
    """
    Generate and store a one time password linked to the specified user id.
    Lifetime is in seconds.

    Returns the generated OTP as a bytestring.
    """
    token = os.urandom(OTP_LENGTH)
    while OTP.query.first() is not None:
        token = os.urandom(OTP_LENGTH)

    hex_token = token.hex()
    iat = unix_utc_now()
    eat = iat + lifetime
    otp = OTP(value=hex_token, issued_at=iat, expires_at=eat, user_id=user_id)
    orm.session.add(otp)
    return hex_token
    

def is_valid_otp(user_id: int, hex_token: str) -> bool:
    """
    Check if the provided OTP is valid for the specified user.
    If the OTP is valid or it is expired, it will be removed from the database.
    """
    otp = OTP.query.filter_by(user_id = user_id).first()
    if otp is None:
        return False

    try:
        token = bytes.fromhex(hex_token)
    except (ValueError, TypeError):
        token = b'\x00'

    matching_tokens = hmac.compare_digest(otp.raw_value, token)
    success = matching_tokens and not otp.is_expired()
    
    if otp.is_expired() or success:
        orm.session.delete(otp)
    return success


def is_valid_email(email: str) -> bool:
    """
    Restrictions:

    -> Length < 255
    -> Only characters [a-zA-Z0-9@.]
    -> Atleast 3 characters before the '@' sign
    -> No consecutive dots
    -> Doesn't start with a dot
    -> Contains '@' sign
    -> Atleast 1 [a-zA-Z] after '@' sign
    -> Ends with .[a-zA-Z]+
    """
    if len(email) > EMAIL_MAX_LENGTH:
        return False
    
    EMAIL_RE = r'[a-zA-Z0-9]([a-zA-Z0-9.][a-zA-Z0-9]+)+@[a-zA-Z]+\.[a-zA-Z]+'
    return re.fullmatch(re.compile(EMAIL_RE), email) is not None


def is_valid_password(password: str) -> bool:
    """
    Restrictions:

    -> 7 < Length < 255
    -> No whitespace at the start or the end
    -> No newlines
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return False
    
    if len(password) > PASSWORD_MAX_LENGTH:
        return False
    
    PASSWORD_RE = r'[^\s]+.*[^\s]+'
    return re.fullmatch(re.compile(PASSWORD_RE), password) is not None


def is_valid_url(url: str) -> bool:
    URL_RE = r'https?://\w[\w.-]+\w(:\d{2,5})?/?(\w[\w-]+\w/?)*'
    return re.fullmatch(re.compile(URL_RE, flags=re.ASCII), url) is not None


def is_valid_client_name(name: str) -> bool:
    if len(name) > CLIENT_NAME_MAX_LENGTH:
        return False
    
    NAME_RE = r'[a-zA-Z]\w\w(\w?[a-zA-Z0-9])*'
    return re.fullmatch(re.compile(NAME_RE, flags=re.ASCII), name) is not None


def typecheck(**signature):
    """
    Typecheck the function call in runtime.

    Raises TypeError if:
    -> Any arguments are missing
    -> Types don't match

    The type checking is done with the 'isinstance' function.
    The function decorated must accept only keyword arguments.

    Use:
    
    @typecheck(a=int, b=int)
    def function(*, a, b):
        return a + b

    """
    def outer(func):
        @functools.wraps(func)
        def inner(**kwargs):
            for arg, type_ in signature.items():
                if arg not in kwargs:
                    raise TypeError(f'Missing argument "{arg}" from call to "{func.__qualname__}"')
                value = kwargs[arg]
                if not isinstance(value, type_):
                    info = ''.join([
                        f'TypeError when calling "{func.__qualname__}":\n',
                        f'Invalid type {type(value)} for argument "{arg}", ',
                        f'Expected a value of type {type_}'
                    ])
                    raise TypeError(info)
            return func(**kwargs)
        return inner
    return outer


@typecheck(email=str, password=str, password_confirm=str)
def register_user(*, email: str, password: str, password_confirm: str) -> Union[str, None]:
    """
    Validate user email, password and create new user into the database if these are valid.
    Returns an error message if validation failed, None otherwise.

    Does not create OPT for email verfication, or send the verfiaction email.
    """
    checks = [
        is_valid_email(email),
        is_valid_password(password),
        User.query.filter_by(email = email).first() is None,
        password == password_confirm,
    ]
    if not all(checks):
        return 'Registration failed'

    user = User(email = email, password_hash = generate_password_hash(password))
    orm.session.add(user)
    return None


@typecheck(email=str, password=str)
def is_valid_login(*, email: str, password: str) -> bool:
    """
    Verify the login credentials. Return True if credentials are valid.
    Unverified users cannot login.
    """
    user = User.query.filter_by(email = email, is_verified = True).first()
    password_hash = generate_password_hash(' password ') if user is None else user.password_hash
    return check_password_hash(password_hash, password)


@typecheck(email=str, otp_hex=str)
def verify_user_account(*, email: str, otp_hex: str) -> Union[str, None]:
    """
    Check the email and OTP. Set user as verified if
    email matches user that the OTP is linked to.

    Returns an error message, or None if verification was succesful.
    """
    user = User.query.filter_by(email = email).first()
    user_id = 0 if user is None else user.id
    
    if not is_valid_otp(user_id, otp_hex):
        return 'Verification failed'

    user.is_verified = True
    return None


def generate_access_token(subject: object, audience: str, secret: bytes) -> str:
    """
    Generate short lived JWT access token.
    
    Claims:
        -> "iss": str
        -> "iat": int (inserted byt the jwt module)
        -> "exp": int (inserted byt the jwt module)
        -> "aud": str
        -> "sub": int
        -> "email": str
    """
    payload = {
        'aud': audience,
        'iss': JWT_ISSUER_NAME,
        'sub': subject.id,
        'email': subject.email
        }
    return jwt.generate(payload, secret, ACCESS_TOKEN_LIFETIME)
    


def generate_refresh_token(subject: object, audience: str, secret: bytes) -> str:
    """
    Generate longer lasting JWT refresh token.
    
    Claims:
        -> "iss": str
        -> "iat": int (inserted byt the jwt module)
        -> "exp": int (inserted byt the jwt module)
        -> "sub": int
        -> "aud": str
    """
    payload = {
        'aud': audience,
        'iss': JWT_ISSUER_NAME,
        'sub': subject.id
        }
    return jwt.generate(payload, secret, REFRESH_TOKEN_LIFETIME)


def is_valid_jwt_for_context(header: dict, payload: dict, signature: bytes, context: dict) -> bool:
    """
    Extended validation for JWTs specific to authenticating users to the given context.
    
    Claims checked:
    -> iat / exp
    -> aud (Single string excpected. This must match with client uuid.)
    -> iss (Must match with the servers whitelist.)

    The context dict MUST contain a "secret_key" entry. Otherwise ValueError is raised.
    
    The context dict must also contain the following entries, or the validation will fail:
        -> "aud"
    """
    secret_key = context.get('secret_key', None)
    if secret_key is None:
        raise ValueError('No "secret_key" in context')
    
    valid_signature_and_not_expired = jwt.is_valid(header, payload, signature, secret_key)
    audience = context.get('aud', None)

    checks = [
        valid_signature_and_not_expired,
        audience is not None and audience == payload.get('aud', None),
        payload.get('iss', None) in JWT_ISSUER_WHITELIST,
    ]
    return all(checks)
