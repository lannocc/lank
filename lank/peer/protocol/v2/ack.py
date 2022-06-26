from .base import Nonced


class Ping(Nonced):
    #LABEL_SIZE_SIZE = 1 # bytes

    def __init__(self, label, nonce=None):
        assert label
        self.label = label
        super().__init__(nonce)

    def _str_(self):
        return super()._str_() + ', ' + f'label={self.label}'

    def to_bytes(self, handler):
        label = self.label.encode(handler.ENCODING)
        #size = len(label)
        #assert size > 0 and size < 256**self.LABEL_SIZE_SIZE

        #return super().to_bytes(handler) \
        #    + size.to_bytes(self.LABEL_SIZE_SIZE, handler.BYTE_ORDER) \
        #    + label
        return super().to_bytes(handler) + label

    @classmethod
    def from_bytes(cls, handler, data):
        if data is None: return None
        nonce, data = cls._from_bytes_(handler, data)
        #assert len(data) > cls.LABEL_SIZE_SIZE

        #size = int.from_bytes(data[:cls.LABEL_SIZE_SIZE], handler.BYTE_ORDER)
        #assert size > 0

        #data = data[cls.LABEL_SIZE_SIZE:]
        #assert len(data) == size
        label = str(data, handler.ENCODING)

        return cls(label, nonce)


class Pong(Nonced):
    def __init__(self, nonce):
        assert nonce is not None
        super().__init__(nonce)

