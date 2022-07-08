from .crypto import get_handler as crypto
from .node import NODES, HELLO_TIMEOUT, GENERAL_TIMEOUT, KEEPALIVE
from .node.protocol.v2 import *

from threading import Thread, Event
import socket
import sys
from getpass import getpass
from uuid import uuid4


class Interactive:
    def __init__(self):
        self.crypto = crypto()
        print(f' - crypto handler v{self.crypto.VERSION}')

    def run(self):
        client = Client()
        client.start()

        try:
            client.ready.wait()

            if not client.go:
                print('ABORTED: unable to connect to node')
                return

            print()
            print('Ready to create/update a label with a new key pair.')
            print()

            label = input('Label: ')
            if label: label = label.strip()
            if not label or not client.go:
                print('ABORTED')
                return

            uuid = uuid4()
            exists = client.check_label(uuid, label)
            exists_priv_key = None

            if exists is None:
                print('ABORTED')
                return

            elif not exists:
                password = getpass('Password: ')

            else:
                print('   A label with that name already exists.')
                uuid = exists.uuid

                try:
                    priv_key = self.crypto.load_private_key(exists.key_pair_pem)

                    print('   ' \
                        + 'ERROR: The existing key is OPEN and must remain so.')
                    print('ABORTED')
                    return

                except TypeError: # (needs a password)
                    pass # this is expected

                exists_password = getpass('Existing Password: ')
                if not exists_password:
                    print('ABORTED')
                    return

                try:
                    priv_key = self.crypto.load_private_key(exists.key_pair_pem,
                        password=exists_password)

                except ValueError as e:
                    if e.args: e = ' | '.join(e.args)
                    print(f'   ERROR: {e}')
                    print('ABORTED')
                    return

                exists_priv_key = priv_key
                password = getpass('New Password: ')

                if password == exists_password:
                    print('   ' \
                        + 'WARNING: New password is same as the old password.')

            if password:
                results = self.crypto.PASS_POLICY.test(password)
                if label.lower() in password.lower():
                    results.append('Contains Label Name')
                if results:
                    print('   WARNING: You have entered a WEAK PASSWORD.')
                    print('      ' \
                        + 'This makes it VERY LIKELY somebody will STEAL it.')
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
                print('      ' \
                    + 'This means EVERYBODY is allowed to control the label')
                print('      ' \
                    + 'FOREVER and CANNOT BE UNDONE. Proceed with CAUTION!')

                agree = input('Type AGREE to continue: ')
                if agree != 'AGREE':
                    print('ABORTED')
                    return

            print()
            print('Generating key pair...', end='')
            sys.stdout.flush()
            keys = self.crypto.make_keys(password)
            print(' [done]')

            priv_key = keys[0]
            priv_key_pem = keys[1]
            pub_key_pem = keys[2]

            print('Creating signature...', end='')
            sys.stdout.flush()
            if not exists:
                time_nonce = self.crypto.make_time_nonce()
                msg = self.crypto.get_register_message(label, time_nonce)
                signature = self.crypto.sign(priv_key, msg)
            else:
                time_nonce = None
                msg = self.crypto.get_reregister_message(
                    exists.time_nonce,
                    exists.uuid,
                    priv_key_pem + pub_key_pem)
                signature = self.crypto.sign(exists_priv_key, msg)
            print(' [done]')

            print('Sanity check...', end='')
            sys.stdout.flush()
            if not exists:
                assert self.crypto.verify(priv_key.public_key(), msg, signature)
            else:
                assert self.crypto.verify(exists_priv_key.public_key(), msg,
                                          signature)
            print(' [done]')

            print('Transmitting...', end='')
            sys.stdout.flush()
            if client.register_label(uuid, label, priv_key_pem, pub_key_pem,
                    signature, self.crypto.VERSION, time_nonce):
                print(' [SUCCESS]')

            else:
                print(' [FAIL]')

        finally:
            client.stop()
            client.join()


class Client(Thread):
    def __init__(self):
        super().__init__(name='registration client')
        self.go = False

        self.ready = Event()
        self.input = None
        self.output = None

    def stop(self):
        #print('STOP')
        self.go = False

    def check_label(self, uuid, label):
        self.ready.clear()
        self.input = Reservation(label, uuid)
        self.ready.wait()

        if isinstance(self.output, Reservation):
            return False

        elif isinstance(self.output, ReservationCancel):
            #return False if self.output.exists else None
            # FIXME: if exists, transmit request to get the key

            if not self.output.exists:
                self._error_('LABEL RESERVATION CONFLICT')
                return None

            self.ready.clear()
            self.input = GetRegistration(label)
            self.ready.wait()

            assert isinstance(self.output, Registration)
            return self.output

        else:
            return None

    def register_label(self, uuid, label, priv_key_pem, pub_key_pem,
                       signature, version, time_nonce=None):
        self.ready.clear()

        if time_nonce:
            self.input = Registration(uuid, label, version, time_nonce,
                                      priv_key_pem + pub_key_pem,
                                      signature)
        else:
            self.input = ReRegistration(uuid4(), label, version, str(uuid),
                                      priv_key_pem + pub_key_pem,
                                      signature)

        self.ready.wait()

        if isinstance(self.output, RegistrationSuccess):
            return True

        else:
            return False

    def run(self):
        self.go = True

        print(' - connecting to node:')
        node = None

        for addr in NODES:
            print(f'   * trying {addr}... ', end='')
            sys.stdout.flush()

            try:
                sock = socket.create_connection(addr, timeout=HELLO_TIMEOUT)
                sock.settimeout(HELLO_TIMEOUT)
                node = Handler(sock, addr)
                node.hello()
                print('[READY]')
                break

            except ConnectionRefusedError:
                print('[REFUSED]')
                node = None

            except socket.timeout:
                print('[TIMEOUT]')
                node = None

        self.ready.set()

        if not node:
            self.go = False

        while self.go:
            node.sock.settimeout(1)
            seconds = 0

            while self.go and not self.input and seconds < KEEPALIVE:
                try:
                    msg = node.recv()
                    if not msg:
                        self._error_('LOST CONNECTION')
                        return
                    else:
                        self._error_(f'UNEXPECTED RESPONSE: {msg}')
                        return
                except socket.timeout:
                    pass # this is expected

                seconds += 1

            if self.go and not self.input:
                self._handle_(node, Ping())

            if self.go and self.input:
                self._handle_(node, self.input)
                self.input = None

    def _handle_(self, node, req):
        node.sock.settimeout(GENERAL_TIMEOUT)

        try:
            node.send(req)
            resp = node.recv()

            if not resp:
                self._error_('LOST CONNECTION')
                return

            elif isinstance(resp, NodeIsIsolated):
                self._error_('NODE IS ISOLATED')
                return

            if isinstance(req, Ping):
                if not isinstance(resp, Pong):
                    self._error_(f'UNEXPECTED RESPONSE: {resp}')

                elif resp.nonce != req.nonce:
                    self._error_(f'BAD NONCE: {resp}')

            elif isinstance(req, Reservation):
                if isinstance(resp, Reservation) \
                        or isinstance(resp, ReservationCancel):
                    self.output = resp
                    self.ready.set()

                else:
                    self._error_(f'UNEXPECTED RESPONSE: {resp}')

            elif isinstance(req, Registration):
                if isinstance(resp, RegistrationSuccess):
                    self.output = resp
                    self.ready.set()

                else:
                    self._error_(f'UNEXPECTED RESPONSE: {resp}')

            elif isinstance(req, GetRegistration):
                if isinstance(resp, Registration):
                    self.output = resp
                    self.ready.set()

                else:
                    self._error_(f'UNEXPECTED RESPONSE: {resp}')

            else:
                self._error_(f'UNHANDLED REQUEST: {req}')

        except socket.timeout:
            self._error_('TIMEOUT')

        except BrokenPipeError:
            self._error_('BROKEN PIPE')

        except ConnectionResetError:
            self._error_('CONNECTION RESET')

    def _error_(self, txt):
        print()
        print(f'** ERROR ** [{txt}]')
        self.go = False
        self.ready.set()

