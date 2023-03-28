from .base import Timestamped


class Text(Timestamped):
    TEXT_SIZE_SIZE = 2 # bytes

    def __init__(self, timestamp, text):
        Timestamped.__init__(self, timestamp)
        self.text = text

    def _str_(self):
        return ', '.join([
            Timestamped._str_(self),
            f'text={self.text}',
        ])

    def to_bytes(self, handler):
        timestamp = Timestamped.to_bytes(self, handler)

        text = self.text.encode(handler.ENCODING)
        size = len(text)
        assert size < 256**self.TEXT_SIZE_SIZE
        size = size.to_bytes(self.TEXT_SIZE_SIZE, handler.BYTE_ORDER)

        return timestamp + size + text

    @classmethod
    async def recv(cls, handler):
        timestamp = await cls._timestamp_(handler)
        if timestamp is None: return None
        timestamp = cls._to_datetime_(timestamp)

        size = await handler.recv_bytes(cls.TEXT_SIZE_SIZE)
        if size is None: return None
        size = int.from_bytes(size, handler.BYTE_ORDER)

        text = await handler.recv_bytes(size)
        if text is None: return None
        text = str(text, handler.ENCODING)

        return cls(timestamp, text)

