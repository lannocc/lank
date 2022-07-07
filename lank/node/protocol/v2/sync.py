from .base import Nonced, Timestamped, Identified, Labeled


class NodeOn(Nonced, Timestamped, Identified):
    def __init__(self, timestamp, uuid, synced=None, nonce=None):
        Nonced.__init__(self, nonce)
        Timestamped.__init__(self, timestamp)
        Identified.__init__(self, uuid)
        self.synced = Timestamped._from_datetime_(synced) if synced else 0

    def _str_(self):
        synced = Timestamped._to_datetime_(self.synced).isoformat() \
                 if self.synced else None

        return ', '.join([
            Nonced._str_(self),
            Timestamped._str_(self),
            Identified._str_(self),
            f'synced={synced}',
        ])

    def to_bytes(self, handler):
        return Nonced.to_bytes(self, handler) \
            + Timestamped.to_bytes(self, handler) \
            + Identified.to_bytes(self, handler) \
            + self._timestamp_bytes_(handler, self.synced)

    @classmethod
    def recv(cls, handler):
        nonce = cls._nonce_(handler)
        if nonce is None: return None

        timestamp = cls._timestamp_(handler)
        if timestamp is None: return None
        timestamp = cls._to_datetime_(timestamp)

        uuid = cls._uuid_(handler)
        if uuid is None: return None

        synced = cls._timestamp_(handler)
        if synced is None: return None
        synced = Timestamped._to_datetime_(synced)

        return cls(timestamp, uuid, synced, nonce)


class Signed(Identified, Labeled, Timestamped):
    VERSION_SIZE = 1 # bytes
    NAME_SIZE = 1 # bytes
    KEY_SIZE_SIZE = 2 # bytes
    ADDR_SIZE_SIZE = 2 # bytes
    SIG_SIZE = 512 # bytes

    def __init__(self, version, uuid, label, name_id, key, address, signature,
                 node_uuid, created):
        self.version = version
        Identified.__init__(self, uuid)
        Labeled.__init__(self, label)
        self.name = name_id
        self.key = key
        self.address = address
        self.signature = signature
        self.node_uuid = node_uuid
        Timestamped.__init__(self, created)

    def _str_(self):
        return ', '.join([
            f'version={self.version}',
            Identified._str_(self),
            Labeled._str_(self),
            f'name={self.name}',
            f'node_uuid={self.node_uuid}',
            Timestamped._str_(self),
        ])

    def to_bytes(self, handler):
        ver = self.version
        assert ver > 0 and ver < 256**self.VERSION_SIZE
        ver = ver.to_bytes(self.VERSION_SIZE, handler.BYTE_ORDER)

        uuid = Identified.to_bytes(self, handler)
        label = Labeled.to_bytes(self, handler)

        name = self.name
        assert name > 0 and name < 256**self.NAME_SIZE
        name = name.to_bytes(self.NAME_SIZE, handler.BYTE_ORDER)

        key = self.key.encode(handler.ENCODING)
        key_size = len(key)
        assert key_size > 0 and key_size < 256**self.KEY_SIZE_SIZE
        key_size = key_size.to_bytes(self.KEY_SIZE_SIZE, handler.BYTE_ORDER)

        addr = self.address.encode(handler.ENCODING)
        addr_size = len(addr)
        assert addr_size > 0 and addr_size < 256**self.ADDR_SIZE_SIZE
        addr_size = addr_size.to_bytes(self.ADDR_SIZE_SIZE, handler.BYTE_ORDER)

        sig = self.signature
        assert len(sig) == self.SIG_SIZE

        node_uuid = self._uuid_bytes_(handler, self.node_uuid)
        created = Timestamped.to_bytes(self, handler)

        return ver + uuid + label + name + key_size + key \
            + addr_size + addr + sig + node_uuid + created

    @classmethod
    def recv(cls, handler):
        ver = handler.recv_bytes(cls.VERSION_SIZE)
        if ver is None: return None
        ver = int.from_bytes(ver, handler.BYTE_ORDER)

        uuid = cls._uuid_(handler)
        if uuid is None: return None

        label = cls._label_(handler)
        if label is None: return None

        name = handler.recv_bytes(cls.NAME_SIZE)
        if name is None: return None
        name = int.from_bytes(name, handler.BYTE_ORDER)

        size = handler.recv_bytes(cls.KEY_SIZE_SIZE)
        if size is None: return None
        size = int.from_bytes(size, handler.BYTE_ORDER)
        key = handler.recv_bytes(size)
        if key is None: return None
        key = str(key, handler.ENCODING)

        size = handler.recv_bytes(cls.ADDR_SIZE_SIZE)
        if size is None: return None
        size = int.from_bytes(size, handler.BYTE_ORDER)
        addr = handler.recv_bytes(size)
        if addr is None: return None
        addr = str(addr, handler.ENCODING)

        sig = handler.recv_bytes(cls.SIG_SIZE)
        if sig is None: return None
        sig = bytes(sig)

        node_uuid = cls._uuid_(handler)
        if node_uuid is None: return None

        created = cls._timestamp_(handler)
        if created is None: return None
        created = cls._to_datetime_(created)

        return cls(ver, uuid, label, name, key, addr, sig, node_uuid, created)


class SignedUUIDNotFound(Identified):
    pass


class SignedLabelMismatch(Identified, Labeled):
    def __init__(self, uuid, label):
        Identified.__init__(self, uuid)
        Labeled.__init__(self, label)

    def _str_(self):
        return ', '.join([
            Identified._str_(self),
            Labeled._str_(self),
        ])

    def to_bytes(self, handler):
        uuid = Identified.to_bytes(self, handler)
        label = Labeled.to_bytes(self, handler)

        return uuid + label

    @classmethod
    def recv(cls, handler):
        uuid = cls._uuid_(handler)
        if uuid is None: return None

        label = cls._label_(handler)
        if label is None: return None

        return cls(uuid, label)


class SignedNameMismatch(Identified):
    NAME_SIZE = 1 # bytes

    def __init__(self, uuid, name_id):
        Identified.__init__(self, uuid)
        self.name_id = name_id

    def _str_(self):
        return ', '.join([
            Identified._str_(self),
            f'name_id={self.name_id}',
        ])

    def to_bytes(self, handler):
        uuid = Identified.to_bytes(self, handler)

        assert self.name_id > 0 and self.name_id < 256**self.NAME_SIZE
        name = self.name_id.to_bytes(self.NAME_SIZE, handler.BYTE_ORDER)

        return uuid + name

    @classmethod
    def recv(cls, handler):
        uuid = cls._uuid_(handler)
        if uuid is None: return None

        name = handler.recv_bytes(cls.NAME_SIZE)
        if name is None: return None
        name = int.from_bytes(name, handler.BYTE_ORDER)

        return cls(uuid, name)

