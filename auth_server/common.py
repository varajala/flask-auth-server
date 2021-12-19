"""
Constants and utility functions used troughout the application.
Mainly for preventing circular imports...

Author: Valtteri Rajalainen
"""

import typing
from types import ModuleType
from datetime import datetime


def unix_utc_now() -> int:
    """
    Return the number of seconds passed from January 1, 1970 UTC.
    """
    delta = datetime.utcnow() - datetime(1970, 1, 1)
    return int(delta.total_seconds())


class _Capture:
    def __init__(self, exc_type: type):
        self.exc_type = exc_type
        self.error = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if isinstance(exc, self.exc_type):
            self.error = exc
            return True


def capture_exception(exc_type: type) -> _Capture:
    """
    Return a context manager that captures the given exception type.

    Use:

        with capture_exception(TypeError) as capture:
            print(1 + "1")

        capture.error is None
        >>> False
    """
    return _Capture(exc_type)


class NamespaceModule(ModuleType):
    """
    Mimic a builtin module. This can also be used to mimic
    a package structure. See auth_server.config for example...
    """

    def __init__(self, name: str, **kwargs):
        ModuleType.__init__(self, name)
        object.__setattr__(self, 'namespace', kwargs)


    @property
    def __all__(self):
        names = list(self.namespace.keys())
        return list(filter(lambda item: not item.startswith('_'), names))


    def __getattribute__(self, attr: str):
        try:
            return object. __getattribute__(self, attr)
        except AttributeError as err:
            namespace = object.__getattribute__(self, 'namespace')
            if attr not in namespace:
                raise AttributeError from err
            return namespace[attr]


    def __setattr__(self, attr: str, value: typing.Any):
        namespace = object.__getattribute__(self, 'namespace')
        if attr not in namespace:
            raise AttributeError
        namespace[attr] = value


    def __dir__(self):
        data = object.__dir__(self)
        data.remove('namespace')
        return data + self.__all__
