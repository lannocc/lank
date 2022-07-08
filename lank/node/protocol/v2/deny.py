from .base import Message, Identified

from abc import ABC


class Denial(Message, ABC):
    pass


class NodeIsSelf(Denial):
    pass


class NodeAlreadyConnected(Denial):
    pass


class NodeTimeSkewed(Denial):
    pass


class NodeIsIsolated(Denial):
    pass


class NodesOnly(Denial):
    pass


class SignatureFailure(Identified, Denial):
    pass


class PeerAlreadyConnected(Denial):
    pass

