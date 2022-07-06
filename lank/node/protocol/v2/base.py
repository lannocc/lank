from abc import ABC
import random
from datetime import datetime, timezone, timedelta
from uuid import UUID


class Message(ABC):
    def __str__(self):
        txt = self._str_()
        return self.__repr__() + (f'[{txt}]' if txt else '')

    def _str_(self):
        return None

    def to_bytes(self, handler):
        return None

    @classmethod
    def recv(cls, handler):
        return cls()


class Nonced(Message, ABC):
    NONCE_SIZE = 8 # bytes

    def __init__(self, nonce=None):
        if nonce is None:
            nonce = random.randrange(256**self.NONCE_SIZE)
        self.nonce = nonce

    def _str_(self):
        return f'nonce={self.nonce}'

    def to_bytes(self, handler):
        return self.nonce.to_bytes(self.NONCE_SIZE, handler.BYTE_ORDER)

    @classmethod
    def recv(cls, handler):
        nonce = cls._nonce_(handler)
        if nonce is None: return None
        return cls(nonce)

    @classmethod
    def _nonce_(cls, handler):
        nonce = handler.recv_bytes(cls.NONCE_SIZE)
        if nonce is None: return None
        return int.from_bytes(nonce, handler.BYTE_ORDER)


class Timestamped(Message, ABC):
    TIMESTAMP_SIZE = 6 # bytes
    TS_PRECISION = 100000
    # 6 bytes at 10-ns precision is good until year 2059

    def __init__(self, timestamp):
        self.timestamp = self._from_datetime_(timestamp)

    def _str_(self):
        time = self._to_datetime_(self.timestamp).isoformat()
        return f'timestamp={time}'

    def check_time_skew(self, now, max_skew):
        now = self._from_datetime_(now)
        skew = abs(now / self.TS_PRECISION - self.timestamp / self.TS_PRECISION)
        return skew <= max_skew

    def to_bytes(self, handler):
        return self._timestamp_bytes_(handler, self.timestamp)

    @classmethod
    def _timestamp_bytes_(cls, handler, ts):
        return ts.to_bytes(cls.TIMESTAMP_SIZE, handler.BYTE_ORDER)

    @classmethod
    def recv(cls, handler):
        timestamp = cls._timestamp_(handler)
        if timestamp is None: return None
        return cls(cls._to_datetime_(timestamp))

    @classmethod
    def _timestamp_(cls, handler):
        timestamp = handler.recv_bytes(cls.TIMESTAMP_SIZE)
        if timestamp is None: return None
        return int.from_bytes(timestamp, handler.BYTE_ORDER)

    @classmethod
    def _from_datetime_(cls, dt):
        return int(dt.timestamp() * cls.TS_PRECISION)

    @classmethod
    def _to_datetime_(cls, ts):
        return datetime.fromtimestamp(ts / cls.TS_PRECISION, timezone.utc)


class Identified(Message, ABC):
    UUID_SIZE = 16 # bytes

    def __init__(self, uuid):
        assert isinstance(uuid, UUID)
        self.uuid = uuid

    def _str_(self):
        return f'uuid={self.uuid}'

    def to_bytes(self, handler):
        return self._uuid_bytes_(handler, self.uuid)

    @classmethod
    def _uuid_bytes_(cls, handler, uuid):
        return uuid.bytes

    @classmethod
    def recv(cls, handler):
        uuid = cls._uuid_(handler)
        if uuid is None: return None
        return cls(uuid)

    @classmethod
    def _uuid_(cls, handler):
        uuid = handler.recv_bytes(cls.UUID_SIZE)
        if uuid is None: return None
        return UUID(bytes=bytes(uuid))


class Labeled(Message, ABC):
    LABEL_SIZE_SIZE = 1 # bytes

    def __init__(self, label):
        assert label
        self.label = label

    def _str_(self):
        return f'label={self.label}'

    def to_bytes(self, handler):
        label = self.label.encode(handler.ENCODING)
        size = len(label)
        assert size > 0 and size < 256**self.LABEL_SIZE_SIZE
        size = size.to_bytes(self.LABEL_SIZE_SIZE, handler.BYTE_ORDER)
        return size + label

    @classmethod
    def recv(cls, handler):
        label = cls._label_(handler)
        if label is None: return None
        return cls(label)

    @classmethod
    def _label_(cls, handler):
        size = handler.recv_bytes(cls.LABEL_SIZE_SIZE)
        if size is None: return None
        size = int.from_bytes(size, handler.BYTE_ORDER)

        label = handler.recv_bytes(size)
        if label is None: return None
        label = str(label, handler.ENCODING)
        return label

