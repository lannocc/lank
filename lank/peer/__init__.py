from .protocol import get_handler, HELLO

from gevent.pool import Pool
from gevent.server import StreamServer

from socket import timeout


DEFAULT_PORT = 42819

HELLO_SIZE = len(HELLO)
HELLO_TIMEOUT = 9 # seconds

GENERAL_TIMEOUT = 9 * 60 # seconds


class Server:
    def __init__(self, crypto, priv_key, port=DEFAULT_PORT):
        self.crypto = crypto
        self.priv_key = priv_key
        self.port = port

        self.pool = Pool()
        self.server = StreamServer(('0.0.0.0', self.port), self.handle,
            spawn=self.pool)

        self.buffer = bytearray(HELLO_SIZE)

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.stop()

    def handle(self, sock, addr):
        print(f' + connection from {addr}')
        sock.settimeout(HELLO_TIMEOUT)

        try:
            read = sock.recv_into(self.buffer)

            if read == HELLO_SIZE:
                if self.buffer == HELLO:
                    sock.settimeout(GENERAL_TIMEOUT)

                    try:
                        protocol = get_handler(sock, addr,
                            self.crypto, self.priv_key)

                        if protocol:
                            try:
                                protocol.server(self)
                                print(f' - finished {addr}')

                            except BrokenPipeError:
                                print(f' - closed {addr} [BROKEN PIPE]')

                            except ValueError as e:
                                print(f' - terminated {addr}' \
                                    + f' [BAD MESSAGE: {e}]')

                        else:
                            print(f' - closed {addr} [CLIENT ABORT]')

                    except ValueError as e:
                        print(f' - terminated {addr} [PROTOCOL VERSION]')

                    except timeout:
                        print(f' - terminated {addr} [GENERAL TIMEOUT]')

                else:
                    print(f' - terminated {addr} [BAD HELLO]')

            elif read:
                print(f' - terminated {addr} [BAD HELLO]')

            else:
                print(f' - closed {addr} [CLIENT ABORT]')

        except timeout:
            print(f' - terminated {addr} [HELLO TIMEOUT]')

