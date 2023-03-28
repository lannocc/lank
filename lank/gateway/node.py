from ..node import get_nodes
from ..node.protocol import *
from .. import name as names

from requests import get

import asyncio
#from threading import Thread, current_thread
#from queue import Queue, Empty
#import socket


class Client():
    def __init__(self, printer=print):
        #def __init__(self, port, label, pwd, alias,
        #    on_error, on_connect, verbose=True):
        self.print = printer

        self.host = self.get_public_ip()
        #self.port = port
        #self.label = label
        #self.pwd = pwd or None
        #self.alias = alias or None
        #self.on_error = on_error
        #self.on_connect = on_connect

        self.node = None
        #self.input = Queue()
        #self.output = Queue()

        #self.ping = None
        #self.sign_on = False
        #self.labels_callback = None
        #self.history_callback = None
        #self.register_callback = None

        #self.sender_thread = Thread(
        #    name='node-sender', target=self.sender)
        #self.receiver_thread = Thread(
        #    name='node-return', target=self.receiver)

    def __str__(self):
        if not self.node:
            return 'no connection'

        #if not self.node.sock:
        #    return 'no connection (sock)'

        return f'{self.node.reader._transport.get_extra_info("peername")}'

    def get_public_ip(self):
        ip = get('http://api.ipify.org').content.decode('utf-8')
        self.print(f'   / our public IP address: {ip}')
        return ip

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
        # FIXME: this needs to be smarter (keep a pool of active nodes?)

        for addr in get_nodes():
            try:
                self.print(f'N+ connecting to {addr}')
                host, port = addr

                reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=HELLO_TIMEOUT)

                try:
                    handler = Handler(addr, reader, writer, printer=self.print)
                    await handler.hello()

                    try:
                        self.node = handler

                        while True:
                            await asyncio.sleep(KEEPALIVE)

                            ping = Ping()
                            await self.send(ping)
                            pong = await self.recv()

                            if not pong:
                                break

                            if not isinstance(pong, Pong):
                                raise ValueError('unhandled message')

                            if pong.nonce != ping.nonce:
                                raise ValueError('nonce mismatch')

                        self.print(f'N- finished {addr}')

                    except KeyError as e:
                        self.print(f'N- terminated {addr} [DENIED: {e}]')
                        #if 'NodeIsSelf' in str(e):
                        #    self.nodes_client[addr] = False

                    except ValueError as e:
                        self.print(f'N- terminated {addr} [BAD MESSAGE: {e}]')

                    except asyncio.TimeoutError:
                        self.print(f'N- terminated {addr} [GENERAL TIMEOUT]')

                    finally:
                        self.node = None

                except BrokenPipeError:
                    self.print(f'N- closed {addr} [BROKEN PIPE]')

                except ConnectionResetError:
                    self.print(f'N- closed {addr} [CONNECTION RESET]')

                except OSError:
                    self.print(f'N- closed {addr} [GENERAL NETWORK ERROR]')

                except asyncio.TimeoutError:
                    self.print(f'N- terminated {addr} [HELLO TIMEOUT]')

                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()

                    except ConnectionResetError:
                        pass

            except ConnectionRefusedError:
                self.print(f'N- closed {addr} [CONNECTION REFUSED]')

            except asyncio.TimeoutError:
                self.print(f'N- terminated {addr} [CONNECT TIMEOUT]')

            except Exception as e:
                name = type(e).__name__
                self.print(f'N- terminated {addr} [ERROR: {name}] !! {e}')
                raise e

        if not self.node: return

    async def send(self, msg):
        if not self.node: return
        self.print(f'N    {self.node.addr} <- {msg}')
        await self.node.send(msg)

    async def recv(self):
        if not self.node: return None
        msg = await self.node.recv()
        self.print(f'N    {self.node.addr} -> {msg}')
        return msg

    async def list_labels(self):
        await self.send(ListLabels())
        return await self.recv()

    async def get_registration(self, label):
        await self.send(GetRegistration(label))
        return await self.recv()

    async def get_sign_ons(self, label):
        await self.send(GetHistory(label, name=names.PEER))
        return await self.recv()

    async def signed(self, msg):
        assert isinstance(msg, Autographed)
        assert msg.signature
        await self.send(msg)
        return await self.recv()

