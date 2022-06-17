from . import Handler as Base
import lank.db as ldb

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from password_strength import PasswordPolicy
#from password_strength.tests import (
#    Length, Uppercase, Numbers, Special, NonLetters, Strength)

from getpass import getpass
import sys


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
SIGN_PAD_MGF_HASH = hashes.SHA256
SIGN_PAD_SALT_LENGTH = SIGN_PAD.MAX_LENGTH
SIGN_HASH = hashes.SHA256
SIGN_MESSAGE = b'Spread love everywhere you go. ' \
    + b'Let no one ever come to you without leaving happier.' # --Mother Teresa


# Basic process from:
#   https://dev.to/aaronktberry/generating-encrypted-key-pairs-in-python-69b

class Handler(Base):
    def __init__(self):
        super().__init__()

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
                    registration['address'], password=password.encode())

            except ValueError as e:
                if e.args: e = ' | '.join(e.args)
                print(f'   ERROR: {e}')
                print('ABORTED')
                return

            password = getpass('New Password: ')

        else:
            password = getpass('Password: ')

        if password:
            results = PASS_POLICY.test(password)
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
            key_size=KEY_SIZE,
            public_exponent=KEY_PUBLIC_EXPONENT)

        if password:
            priv_key_pem = priv_key.private_bytes(
                encoding=KEY_ENCODING,
                format=KEY_ENCRYPTED_FORMAT,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    password.encode()))

        else:
            priv_key_pem = priv_key.private_bytes(
                encoding=KEY_ENCODING,
                format=KEY_OPEN_FORMAT,
                encryption_algorithm=serialization.NoEncryption())

        pub_key_pem = priv_key.public_key().public_bytes(
            encoding=KEY_ENCODING,
            format=KEY_PUBLIC_FORMAT)

        print(' [done]')
        print('Creating signature...', end='')
        sys.stdout.flush()

        signature = priv_key.sign(
            SIGN_MESSAGE,
            SIGN_PAD(
                mgf=SIGN_PAD_MGF(SIGN_PAD_MGF_HASH()),
                salt_length=SIGN_PAD_SALT_LENGTH),
            SIGN_HASH())

        print(' [done]')
        print('Saving to database...', end='')
        sys.stdout.flush()

        with ldb.Transaction():
            if not label_id:
                label_id = ldb.insert_label(label)

            signed_id = ldb.insert_signed(label_id, ldb.NAME_REGISTER, 'FIXME',
                priv_key_pem + pub_key_pem, signature, 1)

        print(' [done]')

