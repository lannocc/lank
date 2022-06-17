from . import DEFAULT_PORT, HELLO
from .protocol.v1 import Handler, Ping, Pong

from gevent import socket

import sys


def begin(txt):
    print(f'   {txt}...', end='')
    sys.stdout.flush()

def end():
    print(' [done]')


class TestClient:
    def __init__(self):
        pass

    def run(self):
        addr = ('localhost', DEFAULT_PORT)

        begin('connecting')
        sock = socket.create_connection(addr)
        end()

        begin('sending HELLO v1')
        sock.sendall(HELLO + b'\x01')
        end()

        begin('instantiating protocol handler')
        handler = Handler(sock, addr)
        end()

        begin('ping-pong')
        for i in range(999):
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

