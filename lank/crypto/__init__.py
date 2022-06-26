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

    @abstractmethod
    def get_private_key(self, label, password=None):
        raise NotImplemented()

    @abstractmethod
    def get_public_key(self, label):
        raise NotImplemented()

    @abstractmethod
    def encrypt(self, pub_key, data):
        raise NotImplemented()

    @abstractmethod
    def decrypt(self, priv_key, data):
        raise NotImplemented()

    @abstractmethod
    def sign(self, priv_key, data):
        raise NotImplemented()

    @abstractmethod
    def verify(self, pub_key, data, signature):
        raise NotImplemented()

