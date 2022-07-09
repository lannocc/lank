from .. import Handler as Base
from .message import Ping, Pong

from bidict import bidict


class Handler(Base):
    VERSION = 1

    BYTE_ORDER = 'big'
    ID_SIZE = 1 # bytes

    MSG_BY_ID = bidict({
        1: Ping,
        2: Pong,
    })

    def server(self, master):
        #while msg := self.recv():
        msg = self.recv()
        while msg:
            print(f'     {self.addr} -> {msg}')
            reply = None

            if isinstance(msg, Ping):
                reply = Pong(msg.nonce)

            else:
                raise ValueError(f'unhandled message: {msg}')

            if reply:
                print(f'     {self.addr} <- {reply}')
                self.send(reply)

            msg = self.recv()

    def send(self, msg):
        self.sock.sendall(self.get_id_bytes(msg))
        msg.send(self)

    def recv(self):
        id_bytes = self.recv_bytes(self.ID_SIZE)
        if id_bytes is None: return None
        msg = self.get_msg_type(id_bytes)
        return msg.recv(self)

    def get_id_bytes(self, msg):
        try:
            mid = self.MSG_BY_ID.inverse[type(msg)]
            try:
                return mid.to_bytes(self.ID_SIZE, self.BYTE_ORDER)

            except OverflowError as e:
                raise ValueError(f'msg type id too big: {mid}') from e

        except KeyError as e:
            raise ValueError(f'unsupported message type: {type(msg)}') from e

    def get_msg_type(self, id_bytes):
        mid = int.from_bytes(id_bytes, self.BYTE_ORDER)
        try:
            return self.MSG_BY_ID[mid]

        except KeyError as e:
            raise ValueError(f'unsupported message type id: {mid}') from e

