from ..v1 import Handler as Base
from .ack import *
from .media import *

from bidict import bidict


class Handler(Base):
    VERSION = 2

    ENCODING = 'utf-8'
    BUFFER_SIZE = 2048 # bytes
    CRYPTO_SIG_SIZE = 512 # bytes
    CRYPTO_SIZE_SIZE = 3 # bytes

    MSG_BY_ID = bidict({
        1: Ping,
        2: Pong,
        3: Text,
    })

    def __init__(self, sock, addr, crypto, priv_key, pub_key=None):
        super().__init__(sock, addr)

        self.crypto = crypto
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.label = None

    def server(self, master):
        while msg := self.recv():
            print(f'     {self.addr} -> {msg}')
            reply = None

            if isinstance(msg, Ping):
                reply = Pong(msg.nonce)

            elif isinstance(msg, Text):
                #reply = Text('got your message')
                pass

            else:
                raise ValueError(f'unhandled message: {msg}')

            if reply:
                print(f'     {self.addr} <- {reply}')
                self.send(reply)

    def send(self, msg):
        id_bytes = self.get_id_bytes(msg)
        data = msg.to_bytes(self)

        data = self.crypto.encrypt(self.pub_key,
            id_bytes + (data if data else b''))

        sig = self.crypto.sign(self.priv_key, data)
        assert len(sig) == self.CRYPTO_SIG_SIZE

        size_bytes = len(data).to_bytes(self.CRYPTO_SIZE_SIZE, self.BYTE_ORDER)

        self.sock.sendall(sig + size_bytes + data)

    def recv(self):
        sig = self.recv_bytes(self.CRYPTO_SIG_SIZE)
        if not sig: return None
        sig = bytes(sig)

        crypto_size = self.recv_bytes(self.CRYPTO_SIZE_SIZE)
        if not crypto_size: return None
        crypto_size = int.from_bytes(crypto_size, self.BYTE_ORDER)
        if not crypto_size: return None

        data = self.recv_bytes(crypto_size)
        if not data: return None
        data = bytes(data)

        verify = (data, sig)
        data = self.crypto.decrypt(self.priv_key, data)

        msg = self.get_msg_type(data[:self.ID_SIZE])
        data = data[self.ID_SIZE:]

        if not issubclass(msg, Ping):
            if not self.pub_key:
                raise ValueError(f'have signed message but no key to check')

            if not self.crypto.verify(self.pub_key, verify[0], verify[1]):
                raise ValueError(f'signature verification failed')

        msg = msg.from_bytes(self, data)

        if isinstance(msg, Ping):
            if msg.label != self.label:
                self.pub_key = self.crypto.get_public_key(msg.label)

                if not self.pub_key:
                    raise ValueError(f'no key on file for label: {msg.label}')

                self.label = msg.label
                print(f'     {self.addr} is {self.label}')

            if not self.crypto.verify(self.pub_key, verify[0], verify[1]):
                raise ValueError(f'signature verification failed')

        return msg

