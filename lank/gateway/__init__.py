from .node import Client as Node

import websockets

import asyncio
import json


PORT = 42824
VERSION = 0
PREAMBLE = f'::LANK:{VERSION}::'
MAX_SIZE = 9_018_081 # max websocket message size (bytes)


class Master:
    def __init__(self, printer=print):
        self.print = printer
        self.node = Node(printer)

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
        self.print(f' - websocket server listening port {PORT}')
        async with websockets.serve(self.handler, '', PORT, max_size=MAX_SIZE):
            #await asyncio.Future() # run forever
            await self.node.main()

    async def handler(self, websocket):
        self.print(f'got connection: {websocket}')
        self.print(f'     {websocket.id}')
        self.print(f'     {websocket.remote_address}')

        async for message in websocket:
            if not message.startswith(PREAMBLE):
                self.print(f' --IGNORED-- {message}')
                continue

            message = message[len(PREAMBLE):]
            event = json.loads(message)
            self.print(f' @@ {event}')

            if 'type' not in event:
                self.print(f' !!ERROR!! no event type')
                continue
            etype = event['type']

            if etype == 'GetNodeInfo':
                await self.reply(websocket, self.node)

            elif etype == 'ListLabels':
                labels = await self.node.list_labels()
                await self.reply(websocket, labels, 'labels')

            elif etype == 'GetRegistration':
                label = event['label']
                reg = await self.node.get_registration(label)
                await self.reply(websocket, reg, 'key_pair_pem')

            elif etype == 'GetHistory':
                label = event['label']
                history = await self.node.get_history(label)
                await self.reply(websocket, history, 'items')

            else:
                self.print(f' !!UNKNOWN!! {event["type"]}')

        self.print('bye!')

    async def reply(self, websocket, result, prop=None):
        txt = f'{result}'
        if prop is not None:
            try:
                extra = getattr(result, prop)
                txt += f'\n  :: {prop} => {extra}'
            except AttributeError as e:
                txt += f'\n  !!!! {e}'
        await websocket.send(txt)

