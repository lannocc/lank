import random
from abc import ABC


class Message(ABC):
    def __init__(self):
        pass

    def __str__(self):
        return self.__repr__()

    def send(self, handler):
        pass

    @classmethod
    def recv(cls, handler):
        return cls()


class PingPong(Message, ABC):
    NONCE_SIZE = 4 # bytes

    def __init__(self, nonce):
        super().__init__()
        self.nonce = nonce

    def __str__(self):
        return super().__str__() + f'[nonce={self.nonce}]'

    def send(self, handler):
        handler.sock.sendall(
            self.nonce.to_bytes(self.NONCE_SIZE, handler.BYTE_ORDER))

    @classmethod
    def recv(cls, handler):
        nonce = handler.recv_bytes(cls.NONCE_SIZE)
        if nonce is None: return None
        nonce = int.from_bytes(nonce, handler.BYTE_ORDER)
        return cls(nonce)


class Ping(PingPong):
    def __init__(self, nonce=None):
        if nonce is None:
            nonce = random.randrange(256**self.NONCE_SIZE)

        super().__init__(nonce)


class Pong(PingPong):
    pass

