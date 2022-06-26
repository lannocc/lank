from . import DEFAULT_PORT
from .protocol.v2 import *
from ..crypto import get_handler

from gevent import socket

import sys
from getpass import getpass


#LABEL_SELF = 'anonymous'
LABEL_SELF = 'LANNOCC'
LABEL_OTHER = 'anonymous'


def begin(txt):
    print(f'   {txt}...', end='')
    sys.stdout.flush()

def end():
    print(' [done]')


class TestClient:
    def __init__(self):
        pass

    def run(self):
        begin('instantiating crypto handler')
        crypto = get_handler()
        end()

        begin(f'loading private key for "{LABEL_SELF}" (self)')
        try:
            priv_key = crypto.get_private_key(LABEL_SELF)

        except TypeError:
            print()
            password = getpass('      Password: ')
            priv_key = crypto.get_private_key(LABEL_SELF, password)
        end()

        begin(f'loading public key for "{LABEL_OTHER}" (other)')
        pub_key = crypto.get_public_key(LABEL_OTHER)
        end()

        addr = ('localhost', DEFAULT_PORT)
        begin(f'connecting to {addr}')
        sock = socket.create_connection(addr)
        end()

        begin('instantiating protocol handler')
        handler = Handler(sock, addr, crypto, priv_key, pub_key)
        end()

        begin(f'sending HELLO v{handler.VERSION}')
        handler.hello()
        end()

        #handler.hello()
        #handler.sock.sendall(bytes(1024))

        begin('ping-pong')
        for i in range(9):
            ping = Ping(LABEL_SELF)

            print('<', end='')
            sys.stdout.flush()
            handler.send(ping)

            msg = handler.recv()

            if isinstance(msg, Pong):
                print('>', end='')
                sys.stdout.flush()

                if msg.nonce != ping.nonce:
                    print()
                    print(f'      OOPS: sent {ping.nonce}, got {msg.nonce}')
                    break

            else:
                print()
                print(f'      OOPS: {msg}')
                break
        end()

        '''
        begin(f'switching identity to {LABEL_OTHER}')
        LABEL_SELF = LABEL_OTHER
        end()

        begin('ping-pong')
        for i in range(9):
            ping = Ping(LABEL_SELF)

            print('<', end='')
            sys.stdout.flush()
            handler.send(ping)

            msg = handler.recv()

            if isinstance(msg, Pong):
                print('>', end='')
                sys.stdout.flush()

                if msg.nonce != ping.nonce:
                    print()
                    print(f'      OOPS: sent {ping.nonce}, got {msg.nonce}')
                    break

            else:
                print()
                print(f'      OOPS: {msg}')
                break
        end()
        '''

        begin('sending a text message')
        msg = Text('Today is the beginning of the rest of your life!')
        handler.send(msg)
        end()

        '''
        begin('awaiting text reply')
        msg = handler.recv()
        if not isinstance(msg, Text):
            print()
            print(f'      OOPS: {msg}')
        end()
        '''

