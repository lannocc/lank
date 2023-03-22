from .crypto import get_handler as get_crypto
from .node import get_nodes
from .node.protocol import *

import asyncio
from concurrent.futures import ThreadPoolExecutor
from getpass import getpass
from uuid import uuid4


class Interactive:
    def __init__(self, printer=print):
        self.print = printer
        self.client = Client(printer)
        self.crypto = get_crypto()

    def run(self):
        def exception(loop, context):
            func = context.get('future').get_coro().__name__
            msg = context.get('exception', context['message'])
            name = type(msg).__name__
            if name == 'KeyboardInterrupt': return
            self.print(f'!!EE!! ({func}) {name} !! {msg}')

        async def main():
            asyncio.get_running_loop().set_exception_handler(exception)
            await self.main()

        asyncio.run(main())

    async def main(self):
        # TODO?: python 3.11
        #async with asyncio.TaskGroup() as group:
        #    group.create_task(self.client.main())
        #    group.create_task(self.console())

        #await asyncio.gather(
        #        self.client.main(),
        #        self.console())

        node = asyncio.create_task(self.client.main())
        try:
            await self.console()

        except BrokenPipeError:
            self.print('ABORTED: lost connection to node')
            await self.client.close()

        node.cancel()

    async def console(self):
        await self.client.ready.wait()
        if not self.client.node:
            self.print('ABORTED: unable to connect to node')
            return

        self.print()
        self.print('Ready to create/update a label with a new key pair.')
        self.print()

        label = await self.input('Label: ')
        if label: label = label.strip()
        if not label or not await self.client.online():
            self.print('ABORTED')
            return

        uuid = uuid4()
        exists = await self.client.check_label(uuid, label)
        exists_priv_key = None

        if exists is None:
            self.print('ABORTED')
            return

        elif not exists:
            password = await self.getpass('Password: ')

        else:
            self.print('   A label with that name already exists.')
            uuid = exists.uuid

            try:
                priv_key = self.crypto.load_private_key(exists.key_pair_pem)

                self.print('   ' \
                    + 'ERROR: The existing key is OPEN and must remain so.')
                self.print('ABORTED')
                return

            except TypeError: # (needs a password)
                pass # this is expected

            exists_password = await self.getpass('Existing Password: ')
            if not exists_password:
                self.print('ABORTED')
                return

            try:
                priv_key = self.crypto.load_private_key(exists.key_pair_pem,
                    password=exists_password)

            except ValueError as e:
                if e.args: e = ' | '.join(e.args)
                self.print(f'   ERROR: {e}')
                self.print('ABORTED')
                return

            exists_priv_key = priv_key
            password = await self.getpass('New Password: ')

            if password == exists_password:
                self.print('   ' \
                    + 'WARNING: New password is same as the old password.')

        if password:
            results = self.crypto.PASS_POLICY.test(password)
            if label.lower() in password.lower():
                results.append('Contains Label Name')
            if results:
                self.print('   WARNING: You have entered a WEAK PASSWORD.')
                self.print('      ' \
                    + 'This makes it VERY LIKELY somebody will STEAL it.')
                self.print('      The following tests FAILED:')
                for result in results:
                    self.print(f'         - {result}')
                self.print('      Proceed with CAUTION!')

            confirm = await self.getpass('Confirm Password: ')
            if confirm != password:
                self.print('ABORTED (passwords do not match)')
                return

        else:
            self.print('   ' \
                + 'WARNING: Empty password creates an OPEN key pair.')
            self.print('      ' \
                + 'This means EVERYBODY is allowed to control the label')
            self.print('      ' \
                + 'FOREVER and CANNOT BE UNDONE. Proceed with CAUTION!')

            agree = await self.input('Type AGREE to continue: ')
            if agree != 'AGREE':
                self.print('ABORTED')
                return

        self.print()
        self.print('Generating key pair...', end='')
        keys = self.crypto.make_keys(password)
        self.print(' [done]')

        priv_key = keys[0]
        priv_key_pem = keys[1]
        pub_key_pem = keys[2]

        self.print('Creating signature...', end='')
        if not exists:
            time_nonce = self.crypto.make_time_nonce()
            msg = self.crypto.get_register_message(label, time_nonce)
            signature = self.crypto.sign(priv_key, msg)
        else:
            time_nonce = None
            msg = self.crypto.get_reregister_message(
                exists.time_nonce,
                exists.uuid,
                priv_key_pem + pub_key_pem)
            signature = self.crypto.sign(exists_priv_key, msg)
        self.print(' [done]')

        self.print('Sanity check...', end='')
        if not exists:
            assert self.crypto.verify(priv_key.public_key(), msg, signature)
        else:
            assert self.crypto.verify(exists_priv_key.public_key(), msg,
                                      signature)
        self.print(' [done]')

        self.print('Transmitting...')
        if await self.client.register_label(uuid, label, priv_key_pem,
                pub_key_pem, signature, self.crypto.VERSION, time_nonce):
            self.print(' [SUCCESS]')

        else:
            self.print(' [FAIL]')

        await self.client.close()

    async def input(self, prompt=''):
        with ThreadPoolExecutor(1, "Interactive") as exe:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(exe, input, prompt)

    async def getpass(self, prompt=''):
        with ThreadPoolExecutor(1, "Interactive") as exe:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(exe, getpass, prompt)









class Client():
    def __init__(self, printer=print):
        self.print = printer
        self.node = None
        self.ready = asyncio.Event()
        self.closing = False

    def __str__(self):
        if not self.node:
            return 'no connection'

        return f'{self.node.reader._transport.get_extra_info("peername")}'

    def run(self):
        def exception(loop, context):
            func = context.get('future').get_coro().__name__
            msg = context.get('exception', context['message'])
            name = type(msg).__name__
            if name == 'KeyboardInterrupt': return
            self.print(f'!!EE!! ({func}) {name} !! {msg}')

        async def main():
            asyncio.get_running_loop().set_exception_handler(exception)
            await self.main()

        asyncio.run(main())

    async def main(self):
        for addr in get_nodes():
            if self.closing: break

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
                        self.ready.set()
                        self.print('N  ready')

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

                    except ValueError as e:
                        self.print(f'N- terminated {addr} [BAD MESSAGE: {e}]')

                    except asyncio.TimeoutError:
                        self.print(f'N- terminated {addr} [GENERAL TIMEOUT]')

                    finally:
                        self.ready.clear()
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
                self._error_(f'N- terminated {addr} [ERROR: {name}] !! {e}')
                raise e

        self.ready.set()

    async def _error_(self, txt):
        if self.closing: return
        self.print()
        self.print(f'** ERROR ** [{txt}]')
        await self.close()

    async def send(self, msg):
        if not await self.online(): return
        self.print(f'N    {self.node.addr} <- {msg}')
        await self.node.send(msg)

    async def recv(self):
        if not await self.online(): return
        msg = await self.node.recv()
        if not msg: raise BrokenPipeError()
        self.print(f'N    {self.node.addr} -> {msg}')
        return msg

    async def online(self):
        if not self.node:
            await self.ready.wait()

        return self.node

    async def close(self):
        self.closing = True
        if self.node:
            self.node.writer.close()
            await self.node.writer.wait_closed()
        self.node = None
        self.ready.set()

    async def check_label(self, uuid, label):
        await self.send(Reservation(label, uuid))
        resp = await self.recv()

        if isinstance(resp, Reservation):
            return False

        elif isinstance(resp, ReservationCancel):
            #return False if resp.exists else None
            # FIXME: if exists, transmit request to get the key

            if not resp.exists:
                self._error_('LABEL RESERVATION CONFLICT')
                return None

            await self.send(GetRegistration(label))
            resp = await self.recv()

            assert isinstance(resp, Registration)
            return resp

        else:
            return None

    async def register_label(self, uuid, label, priv_key_pem, pub_key_pem,
                       signature, version, time_nonce=None):
        if time_nonce:
            req = Registration(uuid, label, version, time_nonce,
                               priv_key_pem + pub_key_pem,
                               signature)
        else:
            req = ReRegistration(uuid4(), label, version, str(uuid),
                                 priv_key_pem + pub_key_pem,
                                 signature)

        await self.send(req)
        resp = await self.recv()

        if isinstance(resp, RegistrationSuccess):
            return True

        else:
            return False

