from .base import Autographed, Identified, Labeled, Message
from .sync import Signed

from uuid import uuid4


class PeerOn(Autographed, Identified, Labeled):
    HOST_SIZE_SIZE = 1 # bytes
    PORT_SIZE = 2 # bytes
    ALIAS_SIZE_SIZE = 1 # bytes

    def __init__(self, version, label, host, port, alias=None, signature=None,
                 uuid=None):
        Autographed.__init__(self, version, signature)
        if not uuid: uuid = uuid4()
        Identified.__init__(self, uuid)
        Labeled.__init__(self, label)
        self.host = host
        self.port = port
        self.alias = alias

    def _str_(self):
        return ', '.join([
            Autographed._str_(self),
            Identified._str_(self),
            Labeled._str_(self),
            f'host={self.host}',
            f'port={self.port}',
            f'alias={self.alias}',
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

        alias = self.alias.encode(handler.ENCODING) if self.alias else b''
        alias_size = len(alias)
        assert alias_size < 256**self.ALIAS_SIZE_SIZE
        alias_size = alias_size.to_bytes(self.ALIAS_SIZE_SIZE,
                                         handler.BYTE_ORDER)

        return autograph + uuid + label + host_size + host + port \
            + alias_size + alias

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

        size = handler.recv_bytes(cls.ALIAS_SIZE_SIZE)
        if size is None: return None
        size = int.from_bytes(size, handler.BYTE_ORDER)
        alias = handler.recv_bytes(size)
        if alias is None: return None
        alias = str(alias, handler.ENCODING) if alias else None

        return cls(ver, label, host, port, alias, sig, uuid)

    def to_sign(self, crypto):
        return self._to_sign_(crypto, self.uuid, self.label, self.host,
                              self.port, self.alias)

    @classmethod
    def _to_sign_(cls, crypto, uuid, label, host, port, alias):
        return b'\xFF' + uuid.bytes + b'\x00' \
            + label.encode(crypto.ENCODING) + b'\x00' \
            + host.encode(crypto.ENCODING) + b'\x00' \
            + f'{port}'.encode(crypto.ENCODING) + b'\xFF' \
            + ((alias.encode(crypto.ENCODING) + b'\x42') if alias else b'')


class ListLabels(Message):
    pass


class LabelsList(Message):
    COUNT_SIZE = 1 # bytes
    LABEL_SIZE_SIZE = Labeled.LABEL_SIZE_SIZE # bytes

    def __init__(self, labels):
        self.labels = labels

    def _str_(self):
        return f'count={len(self.labels)}'

    def to_bytes(self, handler):
        count = len(self.labels)
        assert count < 256**self.COUNT_SIZE
        count = count.to_bytes(self.COUNT_SIZE, handler.BYTE_ORDER)

        labels = b''
        for label in self.labels:
            label = label.encode(handler.ENCODING)
            size = len(label)
            assert size > 0 and size < 256**self.LABEL_SIZE_SIZE
            size = size.to_bytes(self.LABEL_SIZE_SIZE, handler.BYTE_ORDER)
            labels += size + label

        return count + labels

    @classmethod
    def recv(cls, handler):
        count = handler.recv_bytes(cls.COUNT_SIZE)
        if count is None: return None
        count = int.from_bytes(count, handler.BYTE_ORDER)

        labels = [ ]
        for i in range(count):
            size = handler.recv_bytes(cls.LABEL_SIZE_SIZE)
            if size is None: return None
            size = int.from_bytes(size, handler.BYTE_ORDER)
            label = handler.recv_bytes(size)
            if label is None: return None
            label = str(label, handler.ENCODING)
            labels.append(label)

        return cls(labels)


class LabelInterest(Labeled):
    pass


class LabelIgnore(Labeled):
    pass


class GetHistory(Labeled):
    START_SIZE = 1 # bytes
    COUNT_SIZE = 1 # bytes

    def __init__(self, label, start=0, count=5):
        Labeled.__init__(self, label)
        self.start = start
        self.count = count

    def _str_(self):
        return ', '.join([
            Labeled._str_(self),
            f'start={self.start}',
            f'count={self.count}',
        ])

    def to_bytes(self, handler):
        label = Labeled.to_bytes(self, handler)

        start = self.start
        assert start >= 0 and start < 256**self.START_SIZE
        start = start.to_bytes(self.START_SIZE, handler.BYTE_ORDER)

        count = self.count
        assert count > 0 and count < 256**self.COUNT_SIZE
        count = count.to_bytes(self.COUNT_SIZE, handler.BYTE_ORDER)

        return label + start + count

    @classmethod
    def recv(cls, handler):
        label = cls._label_(handler)
        if label is None: return None

        start = cls._start_(handler)
        if start is None: return None

        count = cls._count_(handler)
        if count is None: return None

        return cls(label, start, count)

    @classmethod
    def _start_(cls, handler):
        start = handler.recv_bytes(cls.START_SIZE)
        if start is None: return None
        return int.from_bytes(start, handler.BYTE_ORDER)

    @classmethod
    def _count_(cls, handler):
        count = handler.recv_bytes(cls.COUNT_SIZE)
        if count is None: return None
        return int.from_bytes(count, handler.BYTE_ORDER)


class History(GetHistory):
    def __init__(self, label, start, items):
        GetHistory.__init__(self, label, start, len(items))
        self.items = items

    def to_bytes(self, handler):
        label_start_count = GetHistory.to_bytes(self, handler)
        assert self.count == len(self.items)

        items = b''
        for signed in self.items:
            assert isinstance(signed, Signed)
            items += signed.to_bytes(handler)

        return label_start_count + items

    @classmethod
    def recv(cls, handler):
        label = cls._label_(handler)
        if label is None: return None

        start = cls._start_(handler)
        if start is None: return None

        count = cls._count_(handler)
        if count is None: return None

        items = [ ]
        for i in range(count):
            item = Signed.recv(handler)
            if item is None: return None
            items.append(item)

        return cls(label, start, items)

