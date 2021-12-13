import microtest

import auth_server.jwt as jwt
import auth_server.security
from auth_server.common import unix_utc_now
from auth_server.security import (
    generate_access_token,
    generate_refresh_token,
    is_valid_jwt_for_context,
)


SECRET = b'testing'


@microtest.test
def test_token_generation():
    lifetime = 10
    data = {'username': 'varajala'}
    token = jwt.generate(data, SECRET, lifetime)
    
    assert isinstance(token, str)
    assert len(token.split('.')) == 3


@microtest.test
def test_token_decoding():
    lifetime = 10
    data = {'username': 'varajala'}
    token = jwt.generate(data, SECRET, lifetime)
    
    header, payload, signature = jwt.decode(token)
    assert all((header, payload, signature))
    assert payload['username'] == 'varajala'
    
    now = jwt.unix_utc_now()
    expires = now + lifetime
    assert now - payload['iat'] <= 1
    assert expires - payload['exp'] <= 1


@microtest.test
def test_correct_signature_validation():
    lifetime = 10
    data = {'username': 'varajala'}
    token = jwt.generate(data, SECRET, lifetime)
    
    header, payload, signature = jwt.decode(token)
    assert jwt.is_valid(header, payload, signature, SECRET)


@microtest.test
def test_incorrect_signature_validation():
    lifetime = 10
    data = {'username': 'varajala'}
    token = jwt.generate(data, SECRET, lifetime)
    
    header, payload, signature = jwt.decode(token)
    payload['username'] = 'user'
    assert not jwt.is_valid(header, payload, signature, SECRET)


@microtest.test
def test_expired_signature_validation():
    lifetime = -1
    data = {'username': 'varajala'}
    token = jwt.generate(data, SECRET, lifetime)
    header, payload, signature = jwt.decode(token)
    assert not jwt.is_valid(header, payload, signature, SECRET)


@microtest.test
def test_validation_with_invalid_json_types():
    data = {'username': 'varajala'}

    def str_time():
        return str(unix_utc_now())
    
    with microtest.patch(jwt, unix_utc_now = str_time):
        token = jwt.generate(data, SECRET, 'lifetime')
    
    header, payload, signature = jwt.decode(token)
    assert not jwt.is_valid(header, payload, signature, SECRET)


@microtest.test
def test_decoding_invalid_token_string():
    assert microtest.raises(jwt.decode, ('123',), jwt.DecodingError)


@microtest.test
def test_decoding_token_with_non_b64_chars():
    assert microtest.raises(jwt.decode, ('1@3.1?%.1!!3',), jwt.DecodingError)


@microtest.test
def test_decoding_token_with_no_json():
    #token generated via jwt.io
    #payload = 'hello'
    token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aGVsbG8.aAre7E5aV-5OCeehBJ6hMttPzk6q7bCDdRTUrZ6suIA'
    assert microtest.raises(jwt.decode, (token,), jwt.DecodingError)


@microtest.test
def test_generating_access_tokens():
    user = Namespace({'email': 'user_email', 'id': 1})

    token = generate_access_token(user, '00-01', SECRET)
    header, payload, signature = jwt.decode(token)

    claims = (
        'iss',
        'exp',
        'iat',
        'sub',
        'aud',

        'email',
    )

    for claim in claims:
        assert claim in payload.keys(), f'Missing claim "{claim}"'
    
    assert payload['sub'] == 1
    assert payload['email'] == 'user_email'
    assert jwt.is_valid(header, payload, signature, SECRET)


@microtest.test
def test_generating_refresh_tokens():
    user = Namespace({'id': 1})

    token = generate_refresh_token(user, '00-01', SECRET)
    header, payload, signature = jwt.decode(token)

    claims = (
        'iss',
        'aud',
        'exp',
        'iat',
        'sub',
    )

    for claim in claims:
        assert claim in payload.keys(), f'Missing claim "{claim}"'
    
    assert payload['sub'] == 1
    assert jwt.is_valid(header, payload, signature, SECRET)


@microtest.test
def test_passing_extended_validation():
    user = Namespace({'id': 1})
    audience = '00-01'
    token = generate_refresh_token(user, audience, SECRET)

    context = {'secret_key': SECRET, 'aud':audience}
    assert is_valid_jwt_for_context(*jwt.decode(token), context)



@microtest.test
def test_failing_extended_validation_via_invalid_context():
    user = Namespace({'id': 1})
    audience = '00-01'
    token = generate_refresh_token(user, audience, SECRET)

    contexts = [
        {'audience': '00-02', 'secret_key': SECRET}, #wrong audience
        {'secret_key': SECRET},                      #missing audience
    ]
    for context in contexts:
        info = f'Invalid context {context} passed extended JWT validation'
        assert not is_valid_jwt_for_context(*jwt.decode(token), context), info

    assert microtest.raises(is_valid_jwt_for_context, (*jwt.decode(token), {}), ValueError)


@microtest.test
def test_failing_extended_validation_via_invalid_token():
    issuer = 'auth_server'
    audience = '00-01'
    context = {'aud': audience, 'secret_key': SECRET}

    with microtest.patch(auth_server.security, JWT_ISSUER_WHITELIST = {issuer}):
        payload = {'iss': issuer}
        token = jwt.generate(payload, SECRET, 10)
        assert not is_valid_jwt_for_context(*jwt.decode(token), context)

        payload = {'iss': issuer, 'aud': '00-02'}
        token = jwt.generate(payload, SECRET, 10)
        assert not is_valid_jwt_for_context(*jwt.decode(token), context)

        payload = {'aud': audience}
        token = jwt.generate(payload, SECRET, 10)
        assert not is_valid_jwt_for_context(*jwt.decode(token), context)

        payload = {'iss': 'not-allowed.site.com', 'aud': audience}
        token = jwt.generate(payload, SECRET, 10)
        assert not is_valid_jwt_for_context(*jwt.decode(token), context)
