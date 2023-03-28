from .v1 import Handler as Base, hashes


class Handler(Base):
    VERSION = 2

    SIGN_PAD_MGF_ALGO = hashes.SHA512
    SIGN_PAD_SALT_LENGTH = 420
    SIGN_ALGO = hashes.SHA512

    #ENCRYPT_PAD_MGF_ALGO = hashes.SHA256 # FIXME SHA512
    #ENCRYPT_PAD_ALGO = hashes.SHA256 # FIXME SHA512
    #ENCRYPT_PAD_LABEL = None

