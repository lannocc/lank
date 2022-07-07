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

        except ModuleNotFoundError as e:
            cache[version] = e

    handler = cache[version]

    if isinstance(handler, Exception):
        raise ValueError(f'crypto handler version {version}') from handler

    return handler()


class Handler(ABC):
    @abstractmethod
    def make_keys(self, password=None):
        raise NotImplementedError()

    @abstractmethod
    def load_private_key(self, key_pair_pem, password=None):
        raise NotImplementedError()

    @abstractmethod
    def load_public_key(self, key_pair_pem):
        raise NotImplementedError()

    @abstractmethod
    def encrypt(self, pub_key, data):
        raise NotImplementedError()

    @abstractmethod
    def decrypt(self, priv_key, data):
        raise NotImplementedError()

    @abstractmethod
    def sign(self, priv_key, data):
        raise NotImplementedError()

    @abstractmethod
    def verify(self, pub_key, data, signature):
        raise NotImplementedError()

