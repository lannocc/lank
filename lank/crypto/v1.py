from . import Handler as Base
import lank.db as ldb

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

    REGISTER_MSG = 'Spread love everywhere you go. ' \
        + 'Let no one ever come to you without leaving happier.'
        # --Mother Teresa

    def register(self):
        print()
        print('Create/update a label with a new key pair for signing.')
        print()

        label = input('Label: ')
        if label: label = label.strip()
        if not label:
            print('ABORTED')
            return

        label_id = ldb.get_label_by_name(label)
        if label_id:
            print('   A label with that name already exists.')
            label_id = label_id['id']
            registration = ldb.find_signed(label_id, ldb.NAME_REGISTER, limit=1)
            assert registration is not None
            registration = registration[0]
            #FIXME: check signed version

            try:
                priv_key = serialization.load_pem_private_key(
                    registration['address'], password=None)

                print('   ERROR: The existing key is OPEN and must remain so.')
                print('ABORTED')
                return

            except TypeError:
                pass

            password = getpass('Existing Password: ')
            if not password:
                print('ABORTED')
                return

            try:
                priv_key = serialization.load_pem_private_key(
                    registration['address'],
                    password=password.encode(self.TEXT_ENCODING))

            except ValueError as e:
                if e.args: e = ' | '.join(e.args)
                print(f'   ERROR: {e}')
                print('ABORTED')
                return

            password = getpass('New Password: ')

        else:
            password = getpass('Password: ')

        if password:
            results = self.PASS_POLICY.test(password)
            if label.lower() in password.lower():
                results.append('Contains Label Name')
            if results:
                print('   WARNING: You have entered a WEAK PASSWORD.')
                print('      This makes it VERY LIKELY somebody will STEAL it.')
                print('      The following tests FAILED:')
                for result in results:
                    print(f'         - {result}')
                print('      Proceed with CAUTION!')

            confirm = getpass('Confirm Password: ')
            if confirm != password:
                print('ABORTED (passwords do not match)')
                return

        else:
            print('   WARNING: Empty password creates an OPEN key pair.')
            print('      This means EVERYBODY is allowed to control the label')
            print('      FOREVER and CANNOT BE UNDONE. Proceed with CAUTION!')

            agree = input('Type AGREE to continue: ')
            if agree != 'AGREE':
                print('ABORTED')
                return

        print()
        print('Generating key pair...', end='')
        sys.stdout.flush()

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

        print(' [done]')

        print('Creating signature...', end='')
        sys.stdout.flush()
        time_nonce = f'{datetime.now().timestamp()}|{random.randrange(2**32)}'
        msg = f'{self.REGISTER_MSG}~{time_nonce}'.encode(self.TEXT_ENCODING)
        signature = self.sign(priv_key, msg)
        print(' [done]')

        print('Sanity check...', end='')
        sys.stdout.flush()
        assert self.verify(priv_key.public_key(), msg, signature)
        print(' [done]')

        print('Saving to database...', end='')
        sys.stdout.flush()

        with ldb.Transaction():
            if not label_id:
                label_id = ldb.insert_label(label)

            signed_id = ldb.insert_signed(label_id, ldb.NAME_REGISTER,
                time_nonce, priv_key_pem + pub_key_pem, signature, self.VERSION)

        print(' [done]')

    def get_private_key(self, label, password=None):
        label_id = ldb.get_label_by_name(label)
        if not label_id: return None

        label_id = label_id['id']
        registration = ldb.find_signed(label_id, ldb.NAME_REGISTER, limit=1)
        assert registration is not None
        registration = registration[0]
        #FIXME: check signed version

        if password:
            password = password.encode(self.TEXT_ENCODING)

        return serialization.load_pem_private_key(
            registration['address'], password=password)

    def get_public_key(self, label):
        label_id = ldb.get_label_by_name(label)
        if not label_id: return None

        label_id = label_id['id']
        registration = ldb.find_signed(label_id, ldb.NAME_REGISTER, limit=1)
        assert registration is not None
        registration = registration[0]
        #FIXME: check signed version

        return serialization.load_pem_public_key(
            registration['address'])

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

