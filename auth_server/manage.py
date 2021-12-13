"""
CLI for the application.
Mainly commands for adding and managing clients.

Author: Valtteri Rajalainen
"""

import flask
import click
import uuid
import os
import traceback
import sys

from auth_server.extensions import orm
from auth_server.models import Client, User
from auth_server.aes import encrypt, decrypt
from auth_server.config.security import CLIENT_SECRET_LENGTH
import auth_server.security as security


commands = list()

def export_command(func):
    """
    Mark the command as exported.
    These commands are registered into the application.
    """
    commands.append(func)
    return func


def echo_error(message):
    click.secho('ERROR: ', fg='red', nl=False)
    click.echo(message)


def echo_client_data(client):
    click.secho(f' {client.uuid} ', fg='green', nl=False)
    click.echo(f'| {client.name} | {client.url}')


@export_command
@click.command('init-db')
@flask.cli.with_appcontext
def init_db():
    try:
        orm.create_all()
    except Exception as err:
        echo_error(f'Failed to initialize the database.')
        traceback.print_exception(type(err), err, err.__traceback__)
    else:
        click.secho('OK ', fg='green', nl=False)
        click.echo('Database Initialized')


@export_command
@click.command('create-client')
@click.argument('name', type=click.STRING)
@click.argument('url', type=click.STRING)
@flask.cli.with_appcontext
def create_client(name: str, url: str) -> None:
    if not security.is_valid_client_name(name):
        echo_error('Invalid client name')
        return

    if Client.query.filter_by(name=name).first() is not None:
        echo_error('Name is already in use')
        return

    if not security.is_valid_url(url):
        echo_error('Invalid client URL')
        return
    
    client_uuid = str(uuid.uuid4())
    CLIENT_SECRET = os.urandom(CLIENT_SECRET_LENGTH)
    
    AES_KEY = flask.current_app.config.get('AES_KEY', None)
    if AES_KEY is None:
        echo_error('No "AES_KEY" in app.config. Please provide a 256 bit bytestring as a key.')
        return
    
    client = Client(
        uuid = client_uuid,
        name = name,
        url = url,
        secret_key_hex = encrypt(CLIENT_SECRET, AES_KEY).hex()
        )
    
    orm.session.add(client)
    orm.session.commit()

    click.echo('The following string is the secret key used to sign the client JWTs in hex format:\n')

    sys.stderr.write(CLIENT_SECRET.hex() + '\n\n')
    input('Press ENTER to continue...')

    click.clear()

    echo_client_data(client)
    

@export_command
@click.command('list-clients')
@flask.cli.with_appcontext
def list_clients():
    clients = Client.query.all()
    if not clients:
        click.echo('No clients...')
        return

    for client in clients:
        echo_client_data(client)


@export_command
@click.command('manage-client')
@click.argument('client_id', type=click.STRING)
@flask.cli.with_appcontext
def manage_client(client_id):
    client = Client.query.filter_by(uuid = client_id).first()
    if client is None:
        echo_error('No client found with the specified uuid.')
        return

    CHANGE_URL = str(1)
    CHANGE_NAME = str(2)
    VIEW_SECRET_KEY = str(3)

    prompt = [
        'Insert one of the options below:\n',
        f'[{CHANGE_URL}] Change redirect URL',
        f'[{CHANGE_NAME}] Change client name',
        f'[{VIEW_SECRET_KEY}] View client secret key',
        '\n'
    ]

    click.echo('\n'.join(prompt))
    option = input('>> ')
    
    click.clear()
    if option == CHANGE_URL:
        click.echo('Insert new URL:')
        url = input('>> ')
        if not security.is_valid_url(url):
            echo_error('Invalid URL')
            return
        
        client.url = url
        orm.session.commit()
        
        click.clear()
        echo_client_data(client)
        return

    if option == CHANGE_NAME:
        click.echo('Insert new name:')
        name = input('>> ')
        if not security.is_valid_client_name(name):
            echo_error('Invalid name')
            return
        
        client.name = name
        orm.session.commit()
        
        click.clear()
        echo_client_data(client)
        return

    if option == VIEW_SECRET_KEY:
        AES_KEY = flask.current_app.config['AES_KEY']
        CLIENT_SECRET = decrypt(client.secret_key, AES_KEY)

        click.echo('The following string is the secret key used to sign the client JWTs in hex format:\n')
        sys.stderr.write(CLIENT_SECRET.hex() + '\n\n')
        input('Press ENTER to continue...')

        click.clear()
        return

    echo_error(f'Invalid option: "{option}".')


@export_command
@click.command('remove-client')
@click.argument('client_id', type=click.STRING)
@click.confirmation_option(prompt='Are you sure you want to remove this client?')
@flask.cli.with_appcontext
def remove_client(client_id):
    removed = Client.query.filter_by(uuid = client_id).delete()
    if not removed:
        echo_error('No client found with the specified uuid.')
        return
    orm.session.commit()


@export_command
@click.command('register-user')
@click.argument('email', type=click.STRING)
@click.password_option()
@flask.cli.with_appcontext
def register_user(email, password):
    checks = [
        security.is_valid_email(email),
        security.is_valid_password(password),
        User.query.filter_by(email = email).first() is None,
    ]
    if not all(checks):
        echo_error('Invalid email or password... (email might already be used)')
        return

    user = User(email = email, password_hash = security.generate_password_hash(password), is_verified = True)
    orm.session.add(user)
    orm.session.commit()        
    
    click.secho('OK ', fg='green', nl=False)
    click.echo('User registered')
