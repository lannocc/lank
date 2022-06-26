from abc import ABC
import random


class Message(ABC):
    def __str__(self):
        txt = self._str_()
        return self.__repr__() + (f'[{txt}]' if txt else '')

    def _str_(self):
        return None

    def to_bytes(self, handler):
        return None

    @classmethod
    def from_bytes(cls, handler, data):
        return cls()


class Nonced(Message, ABC):
    NONCE_SIZE = 8 # bytes

    def __init__(self, nonce=None):
        super().__init__()
        if nonce is None:
            nonce = random.randrange(256**self.NONCE_SIZE)
        self.nonce = nonce

    def _str_(self):
        return f'nonce={self.nonce}'

    def to_bytes(self, handler):
        return self.nonce.to_bytes(self.NONCE_SIZE, handler.BYTE_ORDER)

    @classmethod
    def from_bytes(cls, handler, data):
        return cls(cls._from_bytes_(handler, data)[0])

    @classmethod
    def _from_bytes_(cls, handler, data):
        if data is None: return None
        assert len(data) >= cls.NONCE_SIZE
        return (int.from_bytes(data[:cls.NONCE_SIZE], handler.BYTE_ORDER),
                data[cls.NONCE_SIZE:])

