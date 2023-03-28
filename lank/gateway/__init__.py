from .node import Client as Node
from .peer import Server, Client
from ..node.protocol import *
from ..node.protocol.base import MessageEncoder
from ..peer.protocol.wrap import Signed as PeerSigned
from .. import crypto

import websockets
from websockets.exceptions import *

import asyncio
import json
from base64 import b64decode
from datetime import datetime


PORT = 42824
VERSION = 1
PREAMBLE = f'::LANK:{VERSION}::'
MAX_SIZE = 9_018_081 # max websocket message size (bytes)


class Master:
    def __init__(self, printer=print):
        self.print = printer
        self.node = Node(printer)
        self.crypto = crypto.get_handler()

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
        self.print(f'   / websocket server listening port {PORT}')
        async with websockets.serve(self.handler, '', PORT, max_size=MAX_SIZE):
            #await asyncio.Future() # run forever
            await self.node.main()

    async def handler(self, websocket):
        self.print(f'W+ got connection: {websocket}')
        self.print(f'   / {websocket.remote_address} :: {websocket.id}')

        try:
            signing = None
            servers = [ ] # FIXME should be just one here, not a list
            #channel = 0
            channels = { }

            async for message in websocket:
                if not message.startswith(PREAMBLE):
                    self.print(f' --IGNORED-- {message}')
                    continue

                message = message[len(PREAMBLE):]
                event = json.loads(message)
                self.print(f'W    {websocket.remote_address} -> {event}')

                if 'type' not in event:
                    self.print(f' !!ERROR!! no event type')
                    continue
                etype = event['type']

                if etype == 'GetNodeInfo':
                    await self.web(websocket, str(self.node), 'NODE_INFO')

                elif etype == 'ListLabels':
                    await self.web(websocket, await self.node.list_labels())

                elif etype == 'GetRegistration':
                    label = event['label']
                    reg = await self.node.get_registration(label)
                    #await self.web(websocket, reg, 'key_pair_pem')
                    await self.web(websocket, reg)

                elif etype == 'GetSignOns':
                    label = event['label']
                    history = await self.node.get_sign_ons(label)
                    await self.web(websocket, history)

                elif etype == 'On':
                    assert not signing
                    label = event['label']
                    host = self.node.host
                    #host = '127.0.0.1' #FIXME
                    server = Server(channels, websocket, host, printer=self.print)
                    await server.start()
                    servers.append([ server, None ])
                    self.print('S@ listening for connections on port ' \
                            + f'{server.port}')
                    signing = PeerOn(self.crypto.VERSION, label, host,
                                     server.port)
                    to_sign = signing.to_sign(self.crypto)
                    #print(f'----TO SIGN:\n{to_sign}\n')
                    await self.web(websocket, to_sign, 'OnSign')

                elif etype == 'OnSigned':
                    assert signing
                    try:
                        sig = event['signature']
                        signing.signature = b64decode(sig)
                        #print(f'----SIG:\n{signing.signature}\n')
                        signed = await self.node.signed(signing)

                        if isinstance(signed, Signed):
                            tag = 'On:OK'
                            task = asyncio.create_task(servers[-1][0].main())
                            servers[-1][1] = task

                        else:
                            tag = 'On:NO'
                            await servers.pop()[0].stop()
                            self.print('S! server stopped')

                        await self.web(websocket, signed, tag)

                    finally:
                        signing = None

                elif etype == 'Peer':
                    address = event['address']
                    sep = address.index(':')
                    host = address[:sep]
                    port = int(address[sep+1:])
                    #channel += 1
                    channel = f'U{event["id"]}'
                    if channel in channels:
                        #FIXME: close existing connection?
                        raise ValueError(f'already have channel id: {channel}')

                    client = Client(channel, websocket, host, port, self.print)
                    try:
                        await client.start()
                        task = asyncio.create_task(client.main())
                        channels[channel] = client
                        await self.web(websocket, channel, 'Peer:OK', channel)

                    except:
                        await self.web(websocket, channel, 'Peer:NO', channel)
                        raise

                elif etype == 'Send':
                    channel = event['id']
                    if channel not in channels:
                        #FIXME: error? connection already closed?
                        raise ValueError(f'channel id not found: {channel}')

                    handler = channels[channel]
                    label = event['label']
                    version = event['version']
                    signature = b64decode(event['signature'])
                    data = b64decode(event['data'])

                    #msg = Text(datetime.now(), data)
                    msg = PeerSigned(label, version, signature, data)

                    await handler.relay(msg)

                else:
                    self.print(f' !!UNKNOWN!! {event["type"]}')

            self.print(f'W- finished {websocket.remote_address} :: ' \
                    + f'{websocket.id}')

        except ConnectionClosedError:
            self.print(f'W- closed {websocket.remote_address} :: ' \
                    + f'{websocket.id} [CONNECTION CLOSED]')

        except Exception as e:
            name = type(e).__name__
            self.print(f'W- terminated {websocket.remote_address} :: ' \
                    + f'{websocket.id} [ERROR: {name}] !! {e}')
            raise e

        finally:
            for server in servers:
                self.print('S. canceling...')
                server[1].cancel()
                try:
                    await server[1]
                    self.print('S! server done')
                except asyncio.CancelledError:
                    self.print('S! server canceled')

    async def web(self, websocket, data, tag=None, channel=None):
        if not isinstance(data, Message): assert tag
        if tag: data = { tag: data }
        msg = MessageEncoder(self.crypto, sort_keys=True).encode(data)
        c = f'{channel} ' if channel else ''
        self.print(f'W    {c}{websocket.remote_address} <- {msg}')
        await websocket.send(msg)

