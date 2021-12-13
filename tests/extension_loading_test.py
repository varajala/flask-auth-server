import microtest
import flask

from auth_server import create_app
from auth_server.extensions import orm


class TestModel(orm.Model):
    id = orm.Column(orm.Integer, primary_key=True)
    name = orm.Column(orm.String(64), unique=True, nullable=False)

    def __repr__(self):
        return f'Row: {self.id}'


config = {
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
}
app = create_app(config)


@microtest.setup
def setup():
    global ctx
    ctx = app.app_context()
    ctx.push()
    
    orm.create_all()
    
    row = TestModel(name = 'test')
    orm.session.add(row)
    orm.session.commit()


@microtest.cleanup
def cleanup():
    ctx.pop()


@microtest.test
def test_querying():
    results = TestModel.query.all()
    assert len(results) == 1
    assert results.pop().name == 'test'


if __name__ == '__main__':
    microtest.run()