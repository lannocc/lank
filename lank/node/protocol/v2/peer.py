from .base import Autographed, Identified, Labeled

from uuid import uuid4


class PeerOn(Autographed, Identified, Labeled):
    HOST_SIZE_SIZE = 1 # bytes
    PORT_SIZE = 2 # bytes

    def __init__(self, version, label, host, port, signature=None, uuid=None):
        Autographed.__init__(self, version, signature)
        if not uuid: uuid = uuid4()
        Identified.__init__(self, uuid)
        Labeled.__init__(self, label)
        self.host = host
        self.port = port

    def _str_(self):
        return ', '.join([
            Autographed._str_(self),
            Identified._str_(self),
            Labeled._str_(self),
            f'host={self.host}',
            f'port={self.port}',
        ])

    def to_bytes(self, handler):
        autograph = Autographed.to_bytes(self, handler)
        uuid = Identified.to_bytes(self, handler)
        label = Labeled.to_bytes(self, handler)

        host = self.host.encode(handler.ENCODING)
        host_size = len(host)
        assert host_size > 0 and host_size < 256**self.HOST_SIZE_SIZE
        host_size = host_size.to_bytes(self.HOST_SIZE_SIZE, handler.BYTE_ORDER)

        port = self.port
        assert port > 0 and port < 256**self.PORT_SIZE
        port = port.to_bytes(self.PORT_SIZE, handler.BYTE_ORDER)

        return autograph + uuid + label + host_size + host + port

    @classmethod
    def recv(cls, handler):
        ver = cls._version_(handler)
        if ver is None: return None

        sig = cls._signature_(handler)
        if sig is None: return None

        uuid = cls._uuid_(handler)
        if uuid is None: return None

        label = cls._label_(handler)
        if label is None: return None

        size = handler.recv_bytes(cls.HOST_SIZE_SIZE)
        if size is None: return None
        size = int.from_bytes(size, handler.BYTE_ORDER)
        host = handler.recv_bytes(size)
        if host is None: return None
        host = str(host, handler.ENCODING)

        port = handler.recv_bytes(cls.PORT_SIZE)
        if port is None: return None
        port = int.from_bytes(port, handler.BYTE_ORDER)

        return cls(ver, label, host, port, sig, uuid)

    def to_sign(self, crypto):
        return self._to_sign_(crypto, self.uuid, self.label, self.host,
                              self.port)

    @classmethod
    def _to_sign_(cls, crypto, uuid, label, host, port):
        return b'\xFF' + uuid.bytes + b'\x00' \
            + label.encode(crypto.ENCODING) + b'\x00' \
            + host.encode(crypto.ENCODING) + b'\x00' \
            + f'{port}'.encode(crypto.ENCODING) + b'\xFF'

