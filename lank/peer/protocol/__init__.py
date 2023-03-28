from .ack import *
from .wrap import *
from .media import *

from bidict import bidict

import asyncio


VERSION = 3
HELLO = b'\x04\x02\x00peerHOLANK\x00\x02\x04'
HELLO_SIZE = len(HELLO) # bytes
HELLO_TIMEOUT = 3 # seconds
#MAX_TIME_SKEW = 9 # seconds
KEEPALIVE = 90 # seconds
GENERAL_TIMEOUT = 2*KEEPALIVE # seconds


class VersionMismatch(BaseException):
    def __init__(self, want, got):
        super().__init__(f'want {want} but got {got}')


class Handler:
    #BUFFER_SIZE = 128 # bytes
    BYTE_ORDER = 'big'
    ID_SIZE = 1 # bytes
    ENCODING = 'utf-8'

    MSG_BY_ID = bidict({
        1: Ping,
        2: Pong,
        3: Signed,
        4: Text,
    })

    def __init__(self, addr, reader, writer, printer=print):
        self.addr = addr
        self.reader = reader
        self.writer = writer
        self.print = printer

    async def hello(self):
        assert VERSION > 0 and VERSION < 256
        self.writer.write(HELLO + VERSION.to_bytes(1, 'big'))
        return await asyncio.wait_for(
                self.writer.drain(), timeout=HELLO_TIMEOUT)

    async def ack(self):
        hello = await asyncio.wait_for(
                self.reader.readexactly(HELLO_SIZE+1), timeout=HELLO_TIMEOUT)
        if hello[:-1] != HELLO:
            return False

        version = hello[-1]
        if version != VERSION:
            # FIXME: more sophisticated version negotiation?
            raise VersionMismatch(VERSION, version)

        return True

    async def s_send(self, msg):
        self.print(f'S    {self.addr} <- {msg}')
        await self.send(msg)

    async def c_send(self, msg):
        self.print(f'C    {self.addr} <- {msg}')
        await self.send(msg)

    async def s_recv(self):
        msg = await self.recv()
        self.print(f'S    {self.addr} -> {msg}')
        return msg

    async def c_recv(self):
        msg = await asyncio.wait_for(
                self.recv(), timeout=KEEPALIVE)
        self.print(f'C    {self.addr} -> {msg}')
        return msg

    async def send(self, msg):
        id_bytes = self.get_id_bytes(msg)
        data = msg.to_bytes(self)
        self.writer.write(id_bytes + (data if data else b''))
        return await asyncio.wait_for(
                self.writer.drain(), timeout=GENERAL_TIMEOUT)

    async def recv(self):
        id_bytes = await self.recv_bytes(self.ID_SIZE)
        if id_bytes is None: return None
        msg = self.get_msg_type(id_bytes)
        return await msg.recv(self)

    async def recv_bytes(self, size, timeout=GENERAL_TIMEOUT):
        #FIXME
        #if size > self.BUFFER_SIZE:
        #    raise ValueError(f'request to read more than buffer allows: {size}')
        try:
            return await asyncio.wait_for(
                    self.reader.readexactly(size), timeout=timeout)

        except asyncio.IncompleteReadError:
            return None

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

