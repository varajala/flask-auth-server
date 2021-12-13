"""
Simple authentication server implemented via Flask.

Author: Valtteri Rajalainen
"""

import os
import sys
import flask

from auth_server.extensions import init_extensions, orm

import auth_server.api as api
import auth_server.models as models
import auth_server.manage as manage


def create_app(test_config: dict = None):
    app = flask.Flask(__name__)
    
    app.config.from_object('auth_server.config')
    if test_config:
        for key, value in test_config.items():
            app.config[key] = value

    if not os.path.exists(app.config['EMAIL_CREDENTIALS_PATH']):
        sys.stdout.write('[ WARNING ]: Email credentials not found.\n')
        sys.stdout.write('A placeholder file is created into: ')
        sys.stdout.write(app.config['EMAIL_CREDENTIALS_PATH'] + '.\n\n')

        with open(app.config['EMAIL_CREDENTIALS_PATH'], 'wb') as file:
            file.write(b'email-address')
            file.write(b'\n')
            file.write(b'password')
        app.config['EMAIL_HOST'] = (None, sys.stdout)

    init_extensions(app, do_config=test_config is None)
    
    for cmd in manage.commands:
        app.cli.add_command(cmd)

    app.register_blueprint(api.blueprint)
    app.teardown_appcontext(on_appctx_teardown)
    return app


def on_appctx_teardown(exc=None):
    if exc is None:
        orm.session.commit()
