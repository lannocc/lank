from .base import Labeled, Identified, Autographed

from uuid import UUID, uuid4


class Reservation(Labeled, Identified):
    def __init__(self, label, uuid=None):
        Labeled.__init__(self, label)
        Identified.__init__(self, uuid if uuid else uuid4())

    def _str_(self):
        return ', '.join([
            Labeled._str_(self),
            Identified._str_(self),
        ])

    def to_bytes(self, handler):
        return Labeled.to_bytes(self, handler) \
            + Identified.to_bytes(self, handler)

    @classmethod
    def recv(cls, handler):
        label = cls._label_(handler)
        if label is None: return None

        uuid = cls._uuid_(handler)
        if uuid is None: return None

        return cls(label, uuid)


class ReservationCancel(Labeled):
    def __init__(self, label, exists=False):
        Labeled.__init__(self, label)
        self.exists = exists

    def _str_(self):
        return ', '.join([
            Labeled._str_(self),
            f'exists={self.exists}'
        ])

    def to_bytes(self, handler):
        return Labeled.to_bytes(self, handler) \
            + (b'\xFF' if self.exists else b'\x00')

    @classmethod
    def recv(cls, handler):
        label = cls._label_(handler)
        if label is None: return None

        exists = handler.recv_bytes(1)
        if exists is None: return None

        return cls(label, exists==b'\xFF')


class ReservationRequired(Labeled):
    pass


class Registration(Autographed, Identified, Labeled):
    TIME_NONCE_SIZE_SIZE = 1 # bytes
    KEY_PAIR_SIZE_SIZE = 2 # bytes

    def __init__(self, uuid, label, version, time_nonce, key_pair_pem,
                 signature):
        Identified.__init__(self, uuid)
        Labeled.__init__(self, label)
        Autographed.__init__(self, version, signature)
        self.time_nonce = time_nonce
        self.key_pair_pem = key_pair_pem

    def _str_(self):
        return ', '.join([
            Identified._str_(self),
            Labeled._str_(self),
            Autographed._str_(self),
            #f'time_nonce={self.time_nonce}',
        ])

    def to_bytes(self, handler):
        autograph = Autographed.to_bytes(self, handler)
        uuid = Identified.to_bytes(self, handler)
        label = Labeled.to_bytes(self, handler)

        time_nonce = self.time_nonce.encode(handler.ENCODING)
        time_nonce_size = len(time_nonce)
        assert time_nonce_size > 0 \
            and time_nonce_size < 256**self.TIME_NONCE_SIZE_SIZE
        time_nonce_size = time_nonce_size.to_bytes(self.TIME_NONCE_SIZE_SIZE,
                                                   handler.BYTE_ORDER)

        key_pair = self.key_pair_pem
        key_pair_size = len(key_pair)
        assert key_pair_size > 0 \
            and key_pair_size < 256**self.KEY_PAIR_SIZE_SIZE
        key_pair_size = key_pair_size.to_bytes(self.KEY_PAIR_SIZE_SIZE,
                                               handler.BYTE_ORDER)

        return autograph + uuid + label + time_nonce_size + time_nonce \
            + key_pair_size + key_pair

    @classmethod
    def recv(cls, handler):
        ver = cls._version_(handler)
        if ver is None: return None

        sig = cls._signature_(handler)
        if sig is None: return None

        uuid = cls._uuid_(handler)
        if uuid is None: return None

        label = cls._label_(handler)
        if label is None: return None

        size = handler.recv_bytes(cls.TIME_NONCE_SIZE_SIZE)
        if size is None: return None
        size = int.from_bytes(size, handler.BYTE_ORDER)

        time_nonce = handler.recv_bytes(size)
        if time_nonce is None: return None
        time_nonce = str(time_nonce, handler.ENCODING)

        size = handler.recv_bytes(cls.KEY_PAIR_SIZE_SIZE)
        if size is None: return None
        size = int.from_bytes(size, handler.BYTE_ORDER)

        key_pair = handler.recv_bytes(size)
        if key_pair is None: return None
        key_pair = bytes(key_pair)

        return cls(uuid, label, ver, time_nonce, key_pair, sig)


class ReRegistration(Registration):
    def __init__(self, uuid, label, version, ref_uuid, key_pair_pem, signature):
        super().__init__(uuid, label, version, ref_uuid, key_pair_pem,
                         signature)

    def _str_(self):
        return ', '.join([
            super()._str_(),
            f'ref_uuid={self.ref_uuid}'
        ])

    @property
    def ref_uuid(self):
        return UUID(self.time_nonce)


class RegistrationSuccess(Identified):
    pass


class GetRegistration(Labeled):
    pass

