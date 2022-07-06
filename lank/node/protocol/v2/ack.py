from .base import Nonced, Labeled


class Ping(Nonced):
    pass


class Pong(Nonced):
    def __init__(self, nonce):
        assert nonce is not None
        super().__init__(nonce)


class LabelNotFound(Labeled):
    pass

