from .base import Message

from abc import ABC


class Negative(Message, ABC):
    pass


class NodeIsSelf(Negative):
    pass


class NodeAlreadyConnected(Negative):
    pass


class NodeTimeSkewed(Negative):
    pass


class NodeIsIsolated(Negative):
    pass

class NodesOnly(Negative):
    pass

