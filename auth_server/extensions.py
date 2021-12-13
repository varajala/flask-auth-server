"""
Single module to help manage extensions.
Mainly to prevent circular imports and centralize all extensions into one module.

Extension specific config options should be
inserted into the application in the "_config_extensions" function.

Author: Valtteri Rajalainen
"""

import flask_sqlalchemy


_extensions = list()


def _config_extensions(config):
    """
    Insert extension specific config options here.
    """
    default_database_uri = 'sqlite:///:memory:'
    
    config['SQLALCHEMY_DATABASE_URI'] = config.pop('DATABASE', default_database_uri)
    config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


def init_extensions(app, do_config=True):
    if do_config:
        _config_extensions(app.config)
    
    for extension in _extensions:
        extension.attach(app)


class ExtensionWrapper:
    def __init__(self, extension):
        self._extension = extension()
        _extensions.append(self)

    def attach(self, app):
        return self._extension.init_app(app)

    def __getattribute__(self, attr):
        try:
            return object.__getattribute__(self, attr)
        except AttributeError as err:
            extension = object.__getattribute__(self, '_extension')
            return object.__getattribute__(extension, attr)

    def __setattr__(self, attr, value):
        try:
            object.__setattr__(self, attr, value)
        except AttributeError as err:
            extension = object.__getattribute__(self, '_extension')
            object.__setattr__(extension, attr, value)


orm = ExtensionWrapper(flask_sqlalchemy.SQLAlchemy)
