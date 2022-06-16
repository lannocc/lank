from abc import ABC, abstractmethod


cache = { }


def get_handler(sock, addr):
    version = sock.recv(1)

    if version:
        version = version[0]

        if version not in cache:
            try:
                exec(f'from .v{version} import Handler as Protocol_v{version}')
                exec(f'cache[{version}] = Protocol_v{version}')

            except ModuleNotFoundError:
                cache[version] = None

        handler = cache[version]

        if not handler:
            raise ValueError(f'protocol version {version}')

        return handler(sock, addr)

    else:
        return None


class Handler(ABC):
    MSG_BY_ID = None # subclass defines (should be a bidict)
    ID_SIZE = 1 # bytes
    BYTE_ORDER = 'big'
    BUFFER_SIZE = 1024 # bytes

    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self.buffer = memoryview(bytearray(self.BUFFER_SIZE))

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

    def send(self, msg):
        self.sock.sendall(self.get_id_bytes(msg))
        msg.send(self)

    def recv(self):
        id_bytes = self.recv_bytes(self.ID_SIZE)
        if id_bytes is None: return None
        msg = self.get_msg_type(id_bytes)
        return msg.recv(self)

    def recv_bytes(self, size):
        assert size <= self.BUFFER_SIZE
        total = 0

        while total < size:
            read = self.sock.recv_into(self.buffer[total:], size - total)
            if not read: return None
            total += read

        return self.buffer[:total]

    @abstractmethod
    def server(self):
        raise NotImplemented()


class Message(ABC):
    def __init__(self):
        pass

    def send(self, handler):
        pass

    @classmethod
    def recv(cls, handler):
        return cls()

