from .base import Nonced #, Autographed, Labeled, Timestamped


class Ping(Nonced):
    pass


class Pong(Nonced):
    def __init__(self, nonce):
        assert nonce is not None
        super().__init__(nonce)


'''
class Signed(Autographed):
    PAYLOAD_SIZE_SIZE = 3 # bytes

    def __init__(self, version, signature, data):
        Autographed.__init__(self, version, signature)
        self.data = data

    def _str_(self):
        return ', '.join([
            Autographed._str_(self),
            f'size={len(self.data)}',
        ])

    def to_bytes(self, handler):
        autograph = Autographed.to_bytes(self, handler)

        size = len(self.data)
        assert size > 0 and size < 256**self.PAYLOAD_SIZE_SIZE
        size = size.to_bytes(self.PAYLOAD_SIZE_SIZE, handler.BYTE_ORDER)

        return autograph + size + self.data

    @classmethod
    async def recv(cls, handler):
        ver = await cls._version_(handler)
        if ver is None: return None

        sig = await cls._signature_(handler)
        if sig is None: return None

        size = await handler.recv_bytes(cls.PAYLOAD_SIZE_SIZE)
        if size is None: return None
        size = int.from_bytes(size, handler.BYTE_ORDER)

        data = await handler.recv_bytes(size)
        if data is None: return None

        return cls(ver, sig, data)


class Identification(Labeled, Timestamped):
    def __init__(self, label, timestamp):
        Labeled.__init__(self, label)
        Timestamped.__init__(self, timestamp)

    def _str_(self):
        return ', '.join([
            Labeled._str_(self),
            Timestamped._str_(self),
        ])

    def to_bytes(self, handler):
        label = Labeled.to_bytes(self, handler)
        timestamp = Timestamped.to_bytes(self, handler)

        return label + timestamp

    @classmethod
    async def recv(cls, handler):
        label = await cls._label_(handler)
        if label is None: return None

        timestamp = await cls._timestamp_(handler)
        if timestamp is None: return None

        return cls(label, timestamp)
'''

