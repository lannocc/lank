from .. import __version__
from .protocol import Handler, VersionMismatch, HELLO_TIMEOUT

from bidict import bidict
from ntplib import NTPClient

import asyncio
from socket import getaddrinfo, SOCK_STREAM
from uuid import UUID
from datetime import datetime, timedelta, timezone
import random


DEFAULT_PORT = 42024

NODES = 'node.lank.im' # initial nodes will be gathered from DNS
NODES_MIN = 3
NODES_MAX = 9
NODES_WAIT = 3 * 60 # seconds

NTP = 'pool.ntp.org'


def get_nodes():
    nodes = getaddrinfo(NODES, 0, type=SOCK_STREAM)
    nodes = [ (node[4][0], DEFAULT_PORT) for node in nodes ]
    random.shuffle(nodes)
    return nodes


class Master:
    def __init__(self, port=DEFAULT_PORT, printer=print):
        self.port = port
        self.print = printer

        import lank.node.db as ldb
        self.ldb = ldb

        uuid = ldb.get_meta(ldb.META_NODE_UUID)
        assert uuid
        self.uuid = UUID(uuid)
        self.print(f'   our uuid is {self.uuid}')

        self.num_established = 0
        self.offset = 0
        self.labels_by_id = bidict({ })
        self.nodes_by_uuid = { }
        self.nodes_client = { }
        self.reservations = { }
        self.registrations = { }
        self.signed_recently = { }
        self.label_interests_by_label = { }
        self.label_interests_by_handler = { }

    def run(self):
        def exception(loop, context):
            func = context.get('future').get_coro().__name__
            msg = context.get('exception', context['message'])
            name = type(msg).__name__
            self.print(f'!!EE!! ({func}) {name} !! {msg}')

        async def main():
            asyncio.get_running_loop().set_exception_handler(exception)
            await self.main()

        asyncio.run(main())

    async def main(self):

        for label in self.ldb.list_labels():
            self.labels_by_id[label['id']] = label['name']

        self.print(f'   getting time from {NTP}...')
        ntp = NTPClient().request(NTP, version=3)
        self.offset = ntp.offset
        self.print(f'      our clock is {abs(self.offset)} seconds ', end='')
        if self.offset < 0: self.print('fast')
        else: self.print('slow')

        self.print(f'S  listening on port {self.port}')
        await asyncio.start_server(self.serve, '0.0.0.0', self.port)

        while True:
            if len(self.nodes_by_uuid) < NODES_MIN:
                # FIXME: limit spawning to NODES_MAX - len(self.nodes)
                #        and then wait

                for addr in get_nodes():
                    if len(self.nodes_by_uuid) >= NODES_MAX:
                        break
                    if addr in self.nodes_client:
                        continue

                    await self.client(addr)

            await asyncio.sleep(NODES_WAIT)
            self.status()

    async def serve(self, reader, writer):
        addr = reader._transport.get_extra_info('peername')
        self.print(f'S+ connection from {addr}')

        try:
            handler = Handler(addr, reader, writer, self.print)

            if await handler.ack():
                try:
                    self.num_established += 1
                    await handler.serve(self)
                    self.print(f'S- finished {addr}')

                except KeyError as e:
                    self.print(f'S- terminated {addr} [DENIED: {e}]')

                except ValueError as e:
                    self.print(f'S- terminated {addr} [BAD MESSAGE: {e}]')

                except asyncio.TimeoutError:
                    self.print(f'S- terminated {addr} [GENERAL TIMEOUT]')

                finally:
                    self._handler_cleanup_(handler)
                    self.num_established -= 1

            else:
                self.print(f'S- terminated {addr} [BAD HELLO]')

        except BrokenPipeError:
            self.print(f'S- closed {addr} [BROKEN PIPE]')

        except ConnectionResetError:
            self.print(f'S- closed {addr} [CONNECTION RESET]')

        except OSError:
            self.print(f'S- closed {addr} [GENERAL NETWORK ERROR]')

        except asyncio.TimeoutError:
            self.print(f'S- terminated {addr} [HELLO TIMEOUT]')

        except asyncio.IncompleteReadError:
            self.print(f'S- terminated {addr} [HELLO TIMEOUT]')

        except VersionMismatch as e:
            self.print(f'S- terminated {addr} [PROTOCOL VERSION: {e}]')

        except Exception as e:
            name = type(e).__name__
            self.print(f'S- terminated {addr} [ERROR: {name}] !! {e}')
            raise e

        finally:
            try:
                writer.close()
                await writer.wait_closed()

            except ConnectionResetError:
                pass

    async def client(self, addr):
        try:
            self.print(f'C+ connecting to {addr}')
            self.nodes_client[addr] = True
            host, port = addr

            reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=HELLO_TIMEOUT)

            try:
                handler = Handler(addr, reader, writer, printer=self.print)
                await handler.hello()

                try:
                    self.num_established += 1
                    await handler.client(self)
                    self.print(f'C- finished {addr}')

                except KeyError as e:
                    self.print(f'C- terminated {addr} [DENIED: {e}]')
                    if 'NodeIsSelf' in str(e):
                        self.nodes_client[addr] = False

                except ValueError as e:
                    self.print(f'C- terminated {addr} [BAD MESSAGE: {e}]')

                except asyncio.TimeoutError:
                    self.print(f'C- terminated {addr} [GENERAL TIMEOUT]')

                finally:
                    self._handler_cleanup_(handler)
                    self.num_established -= 1

            except BrokenPipeError:
                self.print(f'C- closed {addr} [BROKEN PIPE]')

            except ConnectionResetError:
                self.print(f'C- closed {addr} [CONNECTION RESET]')

            except OSError:
                self.print(f'C- closed {addr} [GENERAL NETWORK ERROR]')

            except asyncio.TimeoutError:
                self.print(f'C- terminated {addr} [HELLO TIMEOUT]')

            finally:
                try:
                    writer.close()
                    await writer.wait_closed()

                except ConnectionResetError:
                    pass

        except ConnectionRefusedError:
            self.print(f'C- closed {addr} [CONNECTION REFUSED]')

        except asyncio.TimeoutError:
            self.print(f'C- terminated {addr} [CONNECT TIMEOUT]')

        except Exception as e:
            name = type(e).__name__
            self.print(f'C- terminated {addr} [ERROR: {name}] !! {e}')
            raise e

        finally:
            if self.nodes_client[addr]:
                del self.nodes_client[addr]

    def status(self):
        nodes = len(self.nodes_by_uuid)
        other = self.num_established - nodes
        time = self.now().isoformat()
        self.print(f'>>>[STATUS]>>> v{__version__} ** NODES={nodes}' \
            + f' ** OTHER={other} ** TIME={time} ** <<<[STATUS]<<<')

    def now(self):
        return datetime.now(timezone.utc) + timedelta(seconds=self.offset)

    async def broadcast_nodes(self, msg, skip=None):
        self.print(f'B    (NODES) <- {msg}')

        try:
            handlers = self.label_interests_by_label[msg.label]
        except KeyError:
            handlers = [ ]

        for handler in self.nodes_by_uuid.values():
            if handler is skip:
                continue

            if handler not in handlers:
                await handler.send(msg)

        for handler in handlers:
            await handler.send(msg)

    def add_label_interest(self, label, handler):
        try:
            handlers = self.label_interests_by_label[label]
        except KeyError:
            handlers = [ ]
            self.label_interests_by_label[label] = handlers

        if handler not in handlers:
            handlers.append(handler)

        try:
            labels = self.label_interests_by_handler[handler]
        except KeyError:
            labels = [ ]
            self.label_interests_by_handler[handler] = labels

        if label not in labels:
            labels.append(label)

    def remove_label_interest(self, label, handler):
        try:
            handlers = self.label_interests_by_label[label]
        except KeyError:
            return

        if handler not in handlers:
            return

        del handlers[handlers.index(handler)]
        labels = self.label_interests_by_handler[handler]
        del labels[labels.index(label)]

    def _handler_cleanup_(self, handler):
        if handler not in self.label_interests_by_handler:
            return

        labels = self.label_interests_by_handler[handler]
        for label in labels:
            handlers = self.label_interests_by_label[label]
            del handlers[handlers.index(handler)]

        del self.label_interests_by_handler[handler]

