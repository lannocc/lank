from .base import Message


class Text(Message):
    def __init__(self, text):
        super().__init__()
        self.text = text

    def _str_(self):
        return f'text={self.text}'

    def to_bytes(self, handler):
        return self.text.encode(handler.ENCODING)

    @classmethod
    def from_bytes(cls, handler, data):
        if data is None: return None
        return cls(str(data, handler.ENCODING))

