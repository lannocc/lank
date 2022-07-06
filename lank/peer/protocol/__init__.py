from abc import ABC, abstractmethod


HELLO = b'\x04\x02\x00peerHOLANK\x00\x02\x04'

cache = { }


def get_handler(sock, addr, crypto=None, priv_key=None):
    version = sock.recv(1)
    if not version: return None
    version = version[0]

    if version < 1:
        raise ValueError(f'protocol version {version}')

    elif version >= 2:
        assert crypto
        assert priv_key

    if version not in cache:
        try:
            exec(f'from .v{version} import Handler as Protocol_v{version}')
            exec(f'cache[{version}] = Protocol_v{version}')

        except ModuleNotFoundError as e:
            cache[version] = e

    handler = cache[version]

    if isinstance(handler, Exception):
        raise ValueError(f'protocol handler version {version}') from handler

    if version >= 2:
        return handler(sock, addr, crypto, priv_key)

    else:
        return handler(sock, addr)


class Handler(ABC):
    VERSION = 0 # subclass MUST change
    BUFFER_SIZE = 128 # bytes

    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self.buffer = memoryview(bytearray(self.BUFFER_SIZE))

    @abstractmethod
    def server(self, master):
        raise NotImplementedError()

    def hello(self):
        assert self.VERSION > 0 and self.VERSION < 256
        self.sock.sendall(HELLO + self.VERSION.to_bytes(1, 'big'))

    def recv_bytes(self, size):
        if size > self.BUFFER_SIZE:
            raise ValueError(f'request to read more than buffer allows: {size}')

        total = 0

        while total < size:
            read = self.sock.recv_into(self.buffer[total:], size - total)
            if not read: return None
            total += read

        return self.buffer[:total]

