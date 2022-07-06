from . import DEFAULT_PORT

from gevent import socket

import sys


def begin(txt):
    print(f'   {txt}...', end='')
    sys.stdout.flush()

def end():
    print(' [done]')


class TestClient_v1:
    def run(self):
        from .protocol.v1 import Handler, Ping, Pong

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
        #for i in range(999):
        while True:
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


class TestClient_v2:
    TEST_LABEL = 'just_a_test'

    def run(self):
        from .protocol.v2 import Handler, Ping, Pong

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
        #for i in range(999):
        while True:
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

        '''
        begin('label find #1')
        find = LabelFind(self.TEST_LABEL)
        handler.send(find)
        msg = handler.recv()
        print()
        print(f'      {msg}', end=' ')
        end()

        begin('sign on')
        sign_on = SignOn(self.TEST_LABEL)
        handler.send(sign_on)
        end()

        begin('label find #2')
        handler.send(find)
        msg = handler.recv()
        print()
        print(f'      {msg}', end=' ')
        end()

        begin('sign off')
        sign_off = SignOff(self.TEST_LABEL)
        handler.send(sign_off)
        end()

        begin('label find #3')
        handler.send(find)
        msg = handler.recv()
        print()
        print(f'      {msg}', end=' ')
        end()
        '''

