import microtest
import os
import tempfile

from auth_server import create_app
from auth_server.extensions import orm
import auth_server.models as models


# microtest.exclude_modules('notifications')

@microtest.utility
def reset_database():
    for table in models.tables:
        table.query.delete()


@microtest.utility
class Namespace:
    def __init__(self, data):
        self.data = data
    
    def __getattribute__(self, attr):
        data = object.__getattribute__(self, 'data')
        return data[attr]


@microtest.call
def setup():
    fd, path = tempfile.mkstemp()
    email_file = tempfile.TemporaryFile(mode='w+')
    config = {
        'TESTING': True,
        
        'SECRET_KEY': 'testing',
        'AES_KEY': (256 // 8) * b'\x01',

        'EMAIL_HOST': (None, email_file),
        'EMAIL_CREDENTIALS_PATH': '/home/varajala/dev/mail',
        
        'SQLALCHEMY_DATABASE_URI': f'sqlite:///{path}',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    }
    app = create_app(config)
    microtest.add_resource('app', app)
    microtest.add_resource('email_file', email_file)
    
    with app.app_context():
        orm.create_all()

    @microtest.on_exit
    def cleanup(exc_type, exc, tb):
        email_file.close()
        os.unlink(path)
        os.close(fd)
