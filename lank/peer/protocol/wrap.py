from .base import Labeled, Autographed


class Signed(Labeled, Autographed):
    PAYLOAD_SIZE_SIZE = 3 # bytes

    def __init__(self, label, version, signature, data):
        Labeled.__init__(self, label)
        Autographed.__init__(self, version, signature)
        self.data = data

    def _str_(self):
        return ', '.join([
            Labeled._str_(self),
            Autographed._str_(self),
            f'size={len(self.data)}',
        ])

    def to_bytes(self, handler):
        label = Labeled.to_bytes(self, handler)
        autograph = Autographed.to_bytes(self, handler)

        size = len(self.data)
        assert size > 0 and size < 256**self.PAYLOAD_SIZE_SIZE
        size = size.to_bytes(self.PAYLOAD_SIZE_SIZE, handler.BYTE_ORDER)

        return label + autograph + size + self.data

    @classmethod
    async def recv(cls, handler):
        label = await cls._label_(handler)
        if label is None: return None

        ver = await cls._version_(handler)
        if ver is None: return None

        sig = await cls._signature_(handler)
        if sig is None: return None

        size = await handler.recv_bytes(cls.PAYLOAD_SIZE_SIZE)
        if size is None: return None
        size = int.from_bytes(size, handler.BYTE_ORDER)

        data = await handler.recv_bytes(size)
        if data is None: return None

        return cls(label, ver, sig, data)

