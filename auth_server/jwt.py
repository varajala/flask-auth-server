"""
Functions for generating, decoding and validating JWTs.
Currently only SHA256 is supported.

Author: Valtteri Rajalainen
"""

import json
import base64
import hashlib
import hmac
import typing

from auth_server.common import unix_utc_now


class DecodingError(Exception):
    pass


def b64url_encode(data: bytes) -> bytes:
    """Base64 URL safe encoding. Padding '=' chars stripped"""
    return base64.urlsafe_b64encode(data).replace(b'=', b'')


def b64url_decode(input_: bytes) -> bytes:
    padding = len(input_) % 4
    data = input_ if not padding else input_ + b'=' * (4 - padding)
    return base64.urlsafe_b64decode(data)


def generate(payload: typing.Dict[str, typing.Any], secret: bytes, lifetime: int) -> str:
    """
    Generate a JWT string from payload dict and a secret bytestring.

    Entries 'iat' and 'exp' are always inserted into the payload
    overriding any possible existing values.

    Lifetime is in seconds.

    Header is always equal to: {"alg": "HS256", "typ": "JWT"}
    """
    header = {"alg": "HS256", "typ": "JWT"}

    issued_at = unix_utc_now()
    expires_at = issued_at + lifetime
    payload["iat"] = issued_at
    payload["exp"] = expires_at

    parts = list()

    b64_header_bytes = b64url_encode(json.dumps(header).encode())
    b64_payload_bytes = b64url_encode(json.dumps(payload).encode())

    parts.append(b64_header_bytes)
    parts.append(b64_payload_bytes)

    hash_data = b'.'.join(parts)
    hash_ = hmac.digest(secret, hash_data, 'sha256')
    b64_signature_bytes = b64url_encode(hash_)

    parts.append(b64_signature_bytes)
    return b'.'.join(parts).decode()



def decode(token: str) -> typing.Tuple[dict, dict, bytes]:
    """
    Decode JWT header, payload and signature into separate Python objects.
    No checks are done for input.
    
    Raises DecodingError if decoding fails for any reason.
    (json decoding, string encoding, base64 encoding, ...)

    Returns a tuple: (header: dict, payload: dict, signature: bytes)
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise DecodingError('Not valid JWT format') 
    
    b64_header, b64_payload, b64_signature = parts

    try:
        header = json.loads(b64url_decode(b64_header.encode()))
        payload = json.loads(b64url_decode(b64_payload.encode()))
        signature = b64url_decode(b64_signature.encode())
    
    except Exception:
        raise DecodingError('Decoding the JWT failed')
    
    return header, payload, signature


def is_valid(header: dict, payload: dict, signature: bytes, secret: bytes) -> bool:
    """
    Check the token signature and expiration.
    Return True if token is valid, False otherwise.

    Note that all other claims aren't verified in this function ("iss", "aud", etc...).

    The header is not checked in any way. This function always assumes the following
    header: {"alg": "HS256", "typ": "JWT"}
    """
    b64_header_bytes = b64url_encode(json.dumps(header).encode())
    b64_payload_bytes = b64url_encode(json.dumps(payload).encode())

    b64_header = b64_header_bytes.decode()
    b64_payload = b64_payload_bytes.decode()

    hash_data = f'{b64_header}.{b64_payload}'.encode()
    hash_ = hmac.digest(secret, hash_data, 'sha256')
    valid_signature =  hmac.compare_digest(signature, hash_)

    now = unix_utc_now()
    issued_at = payload.get('iat', now + 1)
    valid_issued_date = isinstance(issued_at, int) and issued_at <= now

    expires_at = payload.get('exp', 0)
    not_expired = isinstance(expires_at, int) and expires_at - now > 0

    return all((valid_signature, not_expired, valid_issued_date))
