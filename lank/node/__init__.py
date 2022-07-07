from .protocol import get_handler, HELLO, KEEPALIVE, VERSION
import lank.node.db as ldb

from gevent import socket, wait #, spawn
from gevent.pool import Pool
from gevent.server import StreamServer
from bidict import bidict
from ntplib import NTPClient

from uuid import UUID
from datetime import datetime, timedelta, timezone


DEFAULT_PORT = 42024

HELLO_SIZE = len(HELLO)
HELLO_TIMEOUT = 9 # seconds

GENERAL_TIMEOUT = KEEPALIVE * 2 # seconds

NODES = [ # FIXME -- this is temporary (put in database?)
    ('localhost', 42024),
    #('localhost', 42124),
    ('72.202.195.53', 42024),
    ('ruckusist.com', 42024),
]

NODES_MIN = 3
NODES_MAX = 9
NODES_WAIT = 3 * 60 # seconds

NTP = 'pool.ntp.org'


class Master:
    def __init__(self, port=DEFAULT_PORT):
        self.port = port

        uuid = ldb.get_meta(ldb.META_NODE_UUID)
        assert uuid
        self.uuid = UUID(uuid)
        print(f'   our uuid is {self.uuid}')

        print(f'   getting time from {NTP}...')
        ntp = NTPClient().request(NTP, version=3)
        self.offset = ntp.offset
        print(f'      our clock is {abs(self.offset)} seconds ', end='')
        if self.offset < 0: print('fast')
        else: print('slow')

        self.pool = Pool()
        self.stream_server = StreamServer(('0.0.0.0', self.port), self.server,
            spawn=self.pool)

        self.buffer = bytearray(HELLO_SIZE)

        #self.peers_by_sock = bidict({ })
        #self.labels = { }

        self.labels_by_id = bidict({ })

        self.nodes_by_uuid = { }
        self.nodes_client = { }

        self.reservations = { }
        self.registrations = { }

        self.signed_recently = { }

    def run(self):
        for label in ldb.list_labels():
            self.labels_by_id[label['id']] = label['name']

        print(f'S  listening on port {self.port}')
        self.stream_server.start()

        while True:
            if len(self.nodes_by_uuid) < NODES_MIN:
                # FIXME: limit spawning to NODES_MAX - len(self.nodes)
                #        and then wait

                for addr in NODES:
                    if len(self.nodes_by_uuid) >= NODES_MAX:
                        break
                    if addr in self.nodes_client:
                        continue

                    self.pool.spawn(self.client, addr)

            wait(timeout=NODES_WAIT)
            self.status()

    def now(self):
        return datetime.now(timezone.utc) + timedelta(seconds=self.offset)

    def status(self):
        nodes = len(self.nodes_by_uuid)
        time = self.now().isoformat()
        print(f'** STATUS ** nodes={nodes} ** time={time}')

    def broadcast_nodes(self, msg, skip=None):
        print(f'B    (NODES) <- {msg}')
        self.pool.spawn(self._broadcast_nodes_, msg, skip)

    def _broadcast_nodes_(self, msg, skip=None):
        for handler in self.nodes_by_uuid.values():
            if handler is skip:
                continue

            handler.send(msg)

    def client(self, addr):
        print(f'C+ connecting to {addr}')
        self.nodes_client[addr] = True

        try:
            sock = socket.create_connection(addr, timeout=HELLO_TIMEOUT)
            sock.settimeout(HELLO_TIMEOUT)

            try:
                handler = get_handler(sock, addr, VERSION)
                handler.hello()
                sock.settimeout(GENERAL_TIMEOUT)

                try:
                    handler.client(self)
                    print(f'C- finished {addr}')

                except KeyError as e:
                    print(f'C- terminated {addr} [DENIED: {e}]')
                    if 'NodeIsSelf' in str(e):
                        self.nodes_client[addr] = False

                except ValueError as e:
                    print(f'C- terminated {addr} [BAD MESSAGE: {e}]')

                except socket.timeout:
                    print(f'C- terminated {addr} [GENERAL TIMEOUT]')

            except BrokenPipeError:
                print(f'C- closed {addr} [BROKEN PIPE]')

            except ConnectionResetError:
                print(f'C- closed {addr} [CONNECTION RESET]')

            except socket.timeout:
                print(f'C- terminated {addr} [HELLO TIMEOUT]')

        except ConnectionRefusedError:
            print(f'C- closed {addr} [CONNECTION REFUSED]')

        except socket.timeout:
            print(f'C- terminated {addr} [CONNECT TIMEOUT]')

        finally:
            if self.nodes_client[addr]:
                del self.nodes_client[addr]

    def server(self, sock, addr):
        print(f'S+ connection from {addr}')
        sock.settimeout(HELLO_TIMEOUT)

        try:
            read = sock.recv_into(self.buffer)

            if read == HELLO_SIZE:
                if self.buffer == HELLO:
                    sock.settimeout(GENERAL_TIMEOUT)

                    try:
                        protocol = get_handler(sock, addr)

                        if protocol:
                            try:
                                protocol.server(self)
                                print(f'S- finished {addr}')

                            except KeyError as e:
                                print(f'S- terminated {addr} [DENIED: {e}]')

                            except ValueError as e:
                                print(f'S- terminated {addr}' \
                                    + f' [BAD MESSAGE: {e}]')

                        else:
                            print(f'S- closed {addr} [CLIENT ABORT]')

                    except ValueError as e:
                        print(f'S- terminated {addr} [PROTOCOL VERSION]')

                    except socket.timeout:
                        print(f'S- terminated {addr} [GENERAL TIMEOUT]')

                else:
                    print(f'S- terminated {addr} [BAD HELLO]')

            elif read:
                print(f'S- terminated {addr} [BAD HELLO]')

            else:
                print(f'S- closed {addr} [CLIENT ABORT]')

        except BrokenPipeError:
            print(f'S- closed {addr} [BROKEN PIPE]')

        except ConnectionResetError:
            print(f'S- closed {addr} [CONNECTION RESET]')

        except socket.timeout:
            print(f'S- terminated {addr} [HELLO TIMEOUT]')

        #finally:
        #    if sock in self.peers_by_sock:
        #        self.sign_off(self.peers_by_sock[sock])

    '''
    def sign_on(self, sock, label, addr):
        self.sign_off(label)
        self.peers_by_sock[sock] = label
        self.labels[label] = addr

    def sign_off(self, label):
        if label not in self.labels: return
        del self.peers_by_sock.inverse[label]
        del self.labels[label]
    '''

