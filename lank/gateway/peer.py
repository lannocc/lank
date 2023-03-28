from ..peer.protocol import *
from ..peer.protocol.base import MessageEncoder

import asyncio
import json


class Server:
    def __init__(self, channels, websocket, host, port=None, printer=print):
        self.channels = channels
        self.websocket = websocket
        self.host = host
        self.port = port
        self.print = printer
        self.server = None
        self.channel = 0

    def run(self):
        def exception(loop, context):
            func = context.get('future').get_coro().__name__
            msg = context.get('exception', context['message'])
            name = type(msg).__name__
            self.print(f'!!EE!! ({func}) {name} !! {msg}')

        async def run():
            asyncio.get_running_loop().set_exception_handler(exception)
            await self.start()
            await self.main()

        asyncio.run(run())

    async def start(self):
        server = await asyncio.start_server(self.serve, self.host, self.port)
        if not self.port:
            assert len(server._sockets) == 1
            socket = server._sockets[0]
            self.port = socket.getsockname()[1]
        self.server = server

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()
        self.server = None

    async def main(self):
        async with self.server:
            await self.server.serve_forever()

    async def serve(self, reader, writer):
        addr = reader._transport.get_extra_info('peername')
        self.print(f'S+ connection from {addr}')

        try:
            handler = Handler(addr, reader, writer, self.print)

            if await handler.ack():
                self.channel += 1
                channel = f'S{self.channel}'

                out = { 'Peer': { 'channel': channel,
                                  'address': str(addr) } }
                self.print(f'W    {channel} {self.websocket.remote_address} <- {out}')
                await self.websocket.send(json.dumps(out))

                async def relay(msg):
                    await handler.s_send(msg)
                handler.relay = relay

                self.channels[channel] = handler

                try:
                    #FIXME
                    #await handler.serve(self)
                    while msg := await handler.s_recv():
                        msg.channel = channel
                        out = MessageEncoder(sort_keys=True).encode(msg)
                        self.print(f'W    {channel} {self.websocket.remote_address} <- {out}')
                        await self.websocket.send(out)

                    self.print(f'S- finished {addr}')

                except KeyError as e:
                    self.print(f'S- terminated {addr} [DENIED: {e}]')

                except ValueError as e:
                    self.print(f'S- terminated {addr} [BAD MESSAGE: {e}]')

                except asyncio.TimeoutError:
                    self.print(f'S- terminated {addr} [GENERAL TIMEOUT]')

                finally:
                    del self.channels[channel]

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


class Client:
    def __init__(self, channel, websocket, host, port, printer=print):
        self.channel = channel
        self.websocket = websocket
        self.host = host
        self.port = port
        self.print = printer
        self.handler = None

    def run(self):
        def exception(loop, context):
            func = context.get('future').get_coro().__name__
            msg = context.get('exception', context['message'])
            name = type(msg).__name__
            self.print(f'!!EE!! ({func}) {name} !! {msg}')

        async def run():
            asyncio.get_running_loop().set_exception_handler(exception)
            await self.start()
            await self.main()

        asyncio.run(run())

    async def start(self):
        reader, writer = await asyncio.open_connection(self.host, self.port)

        self.handler = Handler((self.host, self.port), reader, writer)
        await self.handler.hello()

    async def main(self):
        while msg := await self.handler.s_recv():
            msg.channel = self.channel
            out = MessageEncoder(sort_keys=True).encode(msg)
            self.print(f'W    {self.channel} {self.websocket.remote_address} <- {out}')
            await self.websocket.send(out)

    async def relay(self, msg):
        await self.handler.c_send(msg)

