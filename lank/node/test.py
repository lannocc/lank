from . import DEFAULT_PORT
from .protocol.v1 import *

from gevent import socket

import sys


def begin(txt):
    print(f'   {txt}...', end='')
    sys.stdout.flush()

def end():
    print(' [done]')


class TestClient:
    def run(self):
        addr = ('localhost', DEFAULT_PORT)

        begin(f'connecting to {addr}')
        sock = socket.create_connection(addr)
        end()

        begin('instantiating protocol handler')
        handler = Handler(sock, addr)
        end()

        begin(f'sending HELLO v{handler.VERSION}')
        handler.hello()
        end()

        begin('ping-pong')
        for i in range(9):
            ping = Ping()

            print('<', end='')
            sys.stdout.flush()
            handler.send(ping)

            msg = handler.recv()
            print('>', end='')
            sys.stdout.flush()

            if isinstance(msg, Pong):
                if msg.nonce != ping.nonce:
                    print()
                    print(f'      NONCE: sent {ping.nonce}, got {msg.nonce}')
                    break

            else:
                print()
                print(f'      {msg}')
                break
        end()

