from abc import ABC, abstractmethod


VERSION = 2
HELLO = b'\x04\x02\x00HOLANK\x00\x02\x04'
KEEPALIVE = 90 # seconds
MAX_TIME_SKEW = 9 # seconds

cache = { }


def get_handler(sock, addr, version=None):
    if not version:
        version = sock.recv(1)
        if not version: return None
        version = version[0]

    if version not in cache:
        try:
            exec(f'from .v{version} import Handler as Protocol_v{version}')
            exec(f'cache[{version}] = Protocol_v{version}')

        except ModuleNotFoundError as e:
            cache[version] = e

    handler = cache[version]

    if isinstance(handler, Exception):
        raise ValueError(f'protocol handler version {version}') from handler

    return handler(sock, addr)


class Handler(ABC):
    VERSION = 0 # subclass MUST change
    BUFFER_SIZE = 128 # bytes

    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self.buffer = memoryview(bytearray(self.BUFFER_SIZE))

    @abstractmethod
    def client(self, master):
        raise NotImplementedError()

    @abstractmethod
    def server(self, master):
        raise NotImplementedError()

    @abstractmethod
    def send(self, msg):
        raise NotImplementedError()

    @abstractmethod
    def recv(self):
        raise NotImplementedError()

    def hello(self):
        assert self.VERSION > 0 and self.VERSION < 256
        self.sock.sendall(HELLO + self.VERSION.to_bytes(1, 'big'))

    def c_send(self, msg):
        print(f'C    {self.addr} <- {msg}')
        self.send(msg)

    def s_send(self, msg):
        print(f'S    {self.addr} <- {msg}')
        self.send(msg)

    def c_recv(self):
        msg = self.recv()
        print(f'C    {self.addr} -> {msg}')
        return msg

    def s_recv(self):
        msg = self.recv()
        print(f'S    {self.addr} -> {msg}')
        return msg

    def recv_bytes(self, size):
        if size > self.BUFFER_SIZE:
            raise ValueError(f'request to read more than buffer allows: {size}')

        total = 0

        while total < size:
            read = self.sock.recv_into(self.buffer[total:], size - total)
            if not read: return None
            total += read

        return self.buffer[:total]

