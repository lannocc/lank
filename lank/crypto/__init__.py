from abc import ABC, abstractmethod


VERSION = 1

cache = { }


def get_handler(version=None):
    if not version:
        version = VERSION

    if version not in cache:
        try:
            exec(f'from .v{version} import Handler as Crypto_v{version}')
            exec(f'cache[{version}] = Crypto_v{version}')

        except ModuleNotFoundError:
            cache[version] = None

    handler = cache[version]

    if not handler:
        raise ValueError(f'crypto version {version}')

    return handler()


class Handler(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def register(self):
        raise NotImplemented()

