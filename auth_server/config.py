"""
Application config options and constants. 

Submodules mimic builtin modules, they can be imported normally.
For example if you need all the security related constants:

    from auth_server.config.security import *


Author: Valtteri Rajalainen
"""


import sys
import os
from auth_server.common import NamespaceModule


SESSION_COOKIE_HTTPONLY = True

DATABASE = 'sqlite:////tmp/database.db'

SECRET_KEY = 'DEVELOPMENT'

# AES requires a key with a length of 128, 192, or 256 bits.
AES_KEY = b'\x0a' * (256 // 8)

# Normally (HOST: str, PORT: int)
# If host is None the email is dumped into the stream given instead of PORT.
# The stream must be a text stream (io.TextIO type)
EMAIL_HOST = (None, sys.stdout)

EMAIL_USE_SSL = True

# A file with email client credentials.
# Expected format: EMAIL_ADDR + "\n" + PASSWORD
EMAIL_CREDENTIALS_PATH = os.path.join(os.path.dirname(__file__), 'email-credentials')


# Only for mimicing a package.
# All submodules should be inserted into the sys.modules, or importing will fail.
__path__ = list()


security = NamespaceModule(f'{__name__}.security',

    PBKDF2_HASH = 'sha256',
    PBKDF2_ITERATIONS = 310_000,
    SALT_LENGTH = 32,                       #bytes

    EMAIL_VERIFICATION_OTP_LIFETIME = 7200, #s

    ACCESS_TOKEN_LIFETIME = 60,             #s
    REFRESH_TOKEN_LIFETIME = 60 * 60 * 24,  #s

    OTP_LENGTH = 32,                        #bytes
    CLIENT_SECRET_LENGTH = 32,              #bytes

    JWT_ISSUER_NAME = 'auth_server',
    JWT_ISSUER_WHITELIST = {'auth_server'},

)


restrictions = NamespaceModule(f'{__name__}.restrictions', 

    EMAIL_MAX_LENGTH = 254,
    CLIENT_NAME_MAX_LENGTH = 254,
    
    PASSWORD_MAX_LENGTH = 255,
    PASSWORD_MIN_LENGTH = 8,
    
)


api = NamespaceModule(f'{__name__}.api', 

    API_VERSION = '1.0',

    # Used in the account verification email to notify user where the email came from.
    SERVICE_NAME = 'Auth Service',

    # Token will be inserted into the headers in the following format:
    # response.headers[ACCESS_TOKEN_HEADER] = ACCESS_TOKEN_SCHEMA + token
    # Note when using Authorization: Bearer - schema the space
    # must be inserted into the ACCESS_TOKEN_SCHEMA constant.
    ACCESS_TOKEN_HEADER = 'Authorization',
    ACCESS_TOKEN_SCHEMA = 'Bearer ',

    REFRESH_TOKEN_KEY = 'refresh_token',
)

sys.modules[security.__name__] = security
sys.modules[restrictions.__name__] = restrictions
sys.modules[api.__name__] = api
