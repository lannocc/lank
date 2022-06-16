from . import Message, Handler as Base

from bidict import bidict

import random
from abc import ABC


class PingPong(Message, ABC):
    NONCE_SIZE = 4 # bytes

    def __init__(self, nonce):
        self.nonce = nonce

    def __str__(self):
        return self.__repr__() + f'[nonce={self.nonce}]'

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
            nonce = random.randint(0, 256**self.NONCE_SIZE - 1)

        super().__init__(nonce)


class Pong(PingPong):
    def __init__(self, nonce):
        super().__init__(nonce)


class Handler(Base):
    MSG_BY_ID = bidict({
        1: Ping,
        2: Pong,
    })

    def __init__(self, sock, addr):
        super().__init__(sock, addr)

    def server(self):
        while msg := self.recv():
            print(f'     {self.addr} -> {msg}')

            if isinstance(msg, Ping):
                msg = Pong(msg.nonce)
                print(f'     {self.addr} <- {msg}')
                self.send(msg)

