from .protocol import get_handler

from gevent.pool import Pool
from gevent.server import StreamServer

from socket import timeout


DEFAULT_PORT = 42024

HELLO = b'\x04\x02\x00HOLANK\x00\x02\x04'
HELLO_SIZE = len(HELLO)
HELLO_TIMEOUT = 9 # seconds


class Server:
    def __init__(self):
        self.port = DEFAULT_PORT

        self.pool = Pool()
        self.server = StreamServer(('0.0.0.0', self.port), self.handle,
            spawn=self.pool)

        self.buffer = bytearray(HELLO_SIZE)

    def run(self):
        self.server.serve_forever()

    def handle(self, sock, addr):
        print(f' + connection from {addr}')
        sock.settimeout(HELLO_TIMEOUT)

        try:
            read = sock.recv_into(self.buffer)

            if read == HELLO_SIZE:
                if self.buffer == HELLO:
                    try:
                        protocol = get_handler(sock, addr)

                        if protocol:
                            try:
                                protocol.server()
                                print(f' - finished {addr}')

                            except BrokenPipeError:
                                print(f' - closed {addr} [BROKEN PIPE]')

                        else:
                            print(f' - closed {addr} [CLIENT ABORT]')

                    except ValueError:
                        print(f' - terminated {addr} [PROTOCOL VERSION]')

                else:
                    print(f' - terminated {addr} [BAD HELLO]')

            elif read:
                print(f' - terminated {addr} [BAD HELLO]')

            else:
                print(f' - closed {addr} [CLIENT ABORT]')

        except timeout:
            print(f' - terminated {addr} [HELLO TIMEOUT]')

