from . import Handler as Base
#import lank.db as ldb

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from password_strength import PasswordPolicy
#from password_strength.tests import (
#    Length, Uppercase, Numbers, Special, NonLetters, Strength)

from getpass import getpass
from datetime import datetime
import random
import sys


# Basic process from:
#   https://dev.to/aaronktberry/generating-encrypted-key-pairs-in-python-69b

class Handler(Base):
    VERSION = 1

    TEXT_ENCODING = 'utf-8'
    PASS_POLICY = PasswordPolicy.from_names(
        length=8, uppercase=1, numbers=1, special=1, #nonletters=1,
        strength=0.5)

    #KEY_SIZE = 15360 # too slow!
    KEY_SIZE = 4096
    KEY_PUBLIC_EXPONENT = 65537
    KEY_ENCODING = serialization.Encoding.PEM
    KEY_ENCRYPTED_FORMAT = serialization.PrivateFormat.PKCS8
    KEY_OPEN_FORMAT = serialization.PrivateFormat.TraditionalOpenSSL
    KEY_PUBLIC_FORMAT = serialization.PublicFormat.SubjectPublicKeyInfo

    SIGN_PAD = padding.PSS
    SIGN_PAD_MGF = padding.MGF1
    SIGN_PAD_MGF_ALGO = hashes.SHA256
    SIGN_PAD_SALT_LENGTH = SIGN_PAD.MAX_LENGTH
    SIGN_ALGO = hashes.SHA256

    ENCRYPT_PAD = padding.OAEP
    ENCRYPT_PAD_MGF = padding.MGF1
    ENCRYPT_PAD_MGF_ALGO = hashes.SHA256
    ENCRYPT_PAD_ALGO = hashes.SHA256
    ENCRYPT_PAD_LABEL = None

    REGISTER_MSG = 'Spread love everywhere you go.' \
        + ' Let no one ever come to you without leaving happier.'
        # --Mother Teresa

    REREGISTER_MSG = 'Tis a lesson you should heed, try, try again.' \
        + " If at first you don't succeed, try, try, and try again."
        # --Thomas H. Palmer

    def make_time_nonce(self):
        return f'{datetime.now().timestamp()}|{random.randrange(2**32)}'

    def get_register_message(self, label, time_nonce):
        assert label
        assert time_nonce

        msg = f'{label}~{self.REGISTER_MSG}~{time_nonce}'
        return msg.encode(self.TEXT_ENCODING) + b'\x81'

    def get_reregister_message(self, existing_tn_or_ref, existing_uuid,
                               new_key_pair_pem):
        assert existing_tn_or_ref
        assert existing_uuid
        assert new_key_pair_pem

        msg = f'{existing_uuid}~{self.REREGISTER_MSG}~{existing_tn_or_ref}~'
        msg = msg.encode(self.TEXT_ENCODING) + new_key_pair_pem + b'\x42'
        #print(f'*****\n{msg}\n*****')
        return msg

    def make_keys(self, password=None):
        priv_key = rsa.generate_private_key(
            key_size=self.KEY_SIZE,
            public_exponent=self.KEY_PUBLIC_EXPONENT)

        if password:
            priv_key_pem = priv_key.private_bytes(
                encoding=self.KEY_ENCODING,
                format=self.KEY_ENCRYPTED_FORMAT,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    password.encode(self.TEXT_ENCODING)))

        else:
            priv_key_pem = priv_key.private_bytes(
                encoding=self.KEY_ENCODING,
                format=self.KEY_OPEN_FORMAT,
                encryption_algorithm=serialization.NoEncryption())

        pub_key_pem = priv_key.public_key().public_bytes(
            encoding=self.KEY_ENCODING,
            format=self.KEY_PUBLIC_FORMAT)

        return (priv_key, priv_key_pem, pub_key_pem)

    def load_private_key(self, key_pair_pem, password=None):
        if password:
            password = password.encode(self.TEXT_ENCODING)

        return serialization.load_pem_private_key(key_pair_pem,
                                                  password=password)

    def load_public_key(self, key_pair_pem):
        return serialization.load_pem_public_key(key_pair_pem)

    def encrypt(self, pub_key, data):
        return pub_key.encrypt(
            plaintext=data,
            padding=self.ENCRYPT_PAD(
                mgf=self.ENCRYPT_PAD_MGF(algorithm=self.ENCRYPT_PAD_MGF_ALGO()),
                algorithm=self.ENCRYPT_PAD_ALGO(),
                label=self.ENCRYPT_PAD_LABEL))

    def decrypt(self, priv_key, data):
        return priv_key.decrypt(
            ciphertext=data,
            padding=self.ENCRYPT_PAD(
                mgf=self.ENCRYPT_PAD_MGF(algorithm=self.ENCRYPT_PAD_MGF_ALGO()),
                algorithm=self.ENCRYPT_PAD_ALGO(),
                label=self.ENCRYPT_PAD_LABEL))

    def sign(self, priv_key, data):
        return priv_key.sign(
            data=data,
            padding=self.SIGN_PAD(
                mgf=self.SIGN_PAD_MGF(algorithm=self.SIGN_PAD_MGF_ALGO()),
                salt_length=self.SIGN_PAD_SALT_LENGTH),
            algorithm=self.SIGN_ALGO())

    def verify(self, pub_key, data, signature):
        try:
            pub_key.verify(
                signature=signature,
                data=data,
                padding=self.SIGN_PAD(
                    mgf=self.SIGN_PAD_MGF(algorithm=self.SIGN_PAD_MGF_ALGO()),
                    salt_length=self.SIGN_PAD_SALT_LENGTH),
                algorithm=self.SIGN_ALGO())

            return True

        except InvalidSignature:
            return False

