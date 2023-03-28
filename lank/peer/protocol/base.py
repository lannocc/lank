from abc import ABC
import random
from datetime import datetime, timezone
from json import JSONEncoder
from base64 import b64encode


class Message(ABC):
    def __str__(self):
        txt = self._str_()
        return self.__repr__() + (f'[{txt}]' if txt else '')

    def _str_(self):
        return None

    def to_bytes(self, handler):
        return None

    @classmethod
    async def recv(cls, handler):
        return cls()


class MessageEncoder(JSONEncoder):
        def __init__(self, sort_keys=False):
            super().__init__(sort_keys=sort_keys)

        def default(self, obj):
            if isinstance(obj, Message):
                data = vars(obj)
                #if hasattr(obj, 'to_sign'):
                #    data = data.copy()
                #    data['to_sign'] = obj.to_sign(self.crypto)
                return { type(obj).__name__: data }

            elif isinstance(obj, bytes):
                return b64encode(obj).decode()

            elif isinstance(obj, UUID):
                return str(obj)

            else:
                return json.JSONEncoder.default(self, obj)


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
    async def recv(cls, handler):
        nonce = await cls._nonce_(handler)
        if nonce is None: return None
        return cls(nonce)

    @classmethod
    async def _nonce_(cls, handler):
        nonce = await handler.recv_bytes(cls.NONCE_SIZE)
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

    #def check_time_skew(self, now, max_skew):
    #    now = self._from_datetime_(now)
    #    skew = abs(now / self.TS_PRECISION - self.timestamp / self.TS_PRECISION)
    #    return skew <= max_skew

    def to_bytes(self, handler):
        return self._timestamp_bytes_(handler, self.timestamp)

    @classmethod
    def _timestamp_bytes_(cls, handler, ts):
        return ts.to_bytes(cls.TIMESTAMP_SIZE, handler.BYTE_ORDER)

    @classmethod
    async def recv(cls, handler):
        timestamp = await cls._timestamp_(handler)
        if timestamp is None: return None
        return cls(cls._to_datetime_(timestamp))

    @classmethod
    async def _timestamp_(cls, handler):
        timestamp = await handler.recv_bytes(cls.TIMESTAMP_SIZE)
        if timestamp is None: return None
        return int.from_bytes(timestamp, handler.BYTE_ORDER)

    @classmethod
    def _from_datetime_(cls, dt):
        print(f'XXXXX {dt}')
        return int(dt.timestamp() * cls.TS_PRECISION)

    @classmethod
    def _to_datetime_(cls, ts):
        return datetime.fromtimestamp(ts / cls.TS_PRECISION, timezone.utc)


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
    async def recv(cls, handler):
        label = await cls._label_(handler)
        if label is None: return None
        return cls(label)

    @classmethod
    async def _label_(cls, handler):
        size = await handler.recv_bytes(cls.LABEL_SIZE_SIZE)
        if size is None: return None
        size = int.from_bytes(size, handler.BYTE_ORDER)

        label = await handler.recv_bytes(size)
        if label is None: return None
        label = str(label, handler.ENCODING)
        return label


class Autographed(Message, ABC):
    VERSION_SIZE = 1 # bytes
    SIG_SIZE = 512 # bytes

    def __init__(self, version, signature):
        self.version = version
        self.signature = signature

    def _str_(self):
        return f'version={self.version} ' \
            + ('(signed)' if self.signature else '(NOT SIGNED)')

    def to_bytes(self, handler):
        ver = self.version
        assert ver > 0 and ver < 256**self.VERSION_SIZE
        ver = ver.to_bytes(self.VERSION_SIZE, handler.BYTE_ORDER)

        sig = self.signature
        assert len(sig) == self.SIG_SIZE

        return ver + sig

    @classmethod
    async def recv(cls, handler):
        ver = await cls._version_(handler)
        if ver is None: return None

        sig = await cls._signature_(handler)
        if sig is None: return None

        return cls(ver, sig)

    @classmethod
    async def _version_(cls, handler):
        ver = await handler.recv_bytes(cls.VERSION_SIZE)
        if ver is None: return None
        ver = int.from_bytes(ver, handler.BYTE_ORDER)
        return ver

    @classmethod
    async def _signature_(cls, handler):
        sig = await handler.recv_bytes(cls.SIG_SIZE)
        if sig is None: return None
        sig = bytes(sig)
        return sig

