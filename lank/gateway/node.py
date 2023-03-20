from ..node import get_nodes
from ..node.protocol import *

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

        '''
        self.input.put_nowait(GetRegistration(self.label))
        msg = self.output.get(timeout=GENERAL_TIMEOUT)
        if not msg: return
        if not isinstance(msg, Registration):
            return self.error(f'failed to get label info: {msg}')

        try:
            crypto = get_crypto(msg.version)
            priv_key = crypto.load_private_key(msg.key_pair_pem, self.pwd)

            self.app.server.crypto = crypto
            self.app.server.priv_key = priv_key

        except TypeError as e:
            return self.error(f'failed to unlock private key: {e}')
        except ValueError as e:
            return self.error(f'failed to unlock private key: {e}')

        msg = PeerOn(crypto.VERSION, self.label, self.host, self.port,
                     self.alias if self.alias else None)
        msg.signature = crypto.sign(priv_key, msg.to_sign(crypto))

        self.sign_on = True
        self.input.put_nowait(msg)
        msg = self.output.get(timeout=GENERAL_TIMEOUT)
        if not msg: return
        if not isinstance(msg, Signed):
            return self.error(f'failed to sign on: {msg}')
        self.sign_on = False

        config.save_connect_label(self.label)
        config.save_connect_alias(self.alias)

        self.input.put_nowait(ListLabels())
        msg = self.output.get(timeout=GENERAL_TIMEOUT)
        if not msg: return
        if not isinstance(msg, LabelsList):
            return self.error(f'failed to get labels list: {msg}')

        for label in msg.labels:
            if label in self.app.interests:
                self.input.put(LabelInterest(label))

        self.on_connect(msg.labels)
        '''

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

    async def get_history(self, label):
        await self.send(GetHistory(label))
        return await self.recv()

    '''
    def interest(self, label, notify=True):
        self.input.put_nowait(
            LabelInterest(label) if notify else LabelIgnore(label))

    def get_labels(self, callback):
        if self.labels_callback:
            return self.error(f'never received last labels request')

        self.labels_callback = callback
        self.input.put_nowait(ListLabels())

    def get_registration(self, label, callback):
        if self.register_callback:
            return self.error(f'never received last registration request')

        self.register_callback = callback
        self.input.put_nowait(GetRegistration(label))

    def get_history(self, label, callback):
        if self.history_callback:
            return self.error(f'never received last history request')

        self.history_callback = callback
        self.register_callback = self._get_history_

        self.input.put_nowait(GetRegistration(label))

    def _get_history_(self, registration):
        callback = self.history_callback
        def history_callback(history):
            callback(registration, history)
        self.history_callback = history_callback
        self.input.put_nowait(GetHistory(registration.label))

    def stop(self):
        if not self.node: return
        self.print('stopping')
        node = self.node
        self.node = None

        node.sock.shutdown(socket.SHUT_RDWR)
        node.sock.close()
        self.output.put_nowait(None)
        self.input.put_nowait(None)

    def join(self):
        self.receiver_thread.join()
        self.sender_thread.join()
        super().join()

    def sender(self):
        try:
            while self.node:
                try:
                    #while msg := self.input.get(timeout=KEEPALIVE):
                    msg = self.input.get(timeout=KEEPALIVE)
                    if msg:
                        if not self.node: break
                        self.send(msg)

                except Empty:
                    if self.ping:
                        return self.error('ping sent but no pong received')

                    if self.node:
                        self.ping = Ping()
                        self.send(self.ping)

        finally:
            self.stop()

    def receiver(self):
        try:
            #while msg := self.recv():
            msg = self.recv()
            while msg:
                if isinstance(msg, Pong):
                    if not self.ping:
                        return self.error(f'received pong without ping: {msg}')

                    if msg.nonce != self.ping.nonce:
                        return self.error(f'ping-pong nonce mismatch')

                    self.ping = None

                elif isinstance(msg, Signed):
                    self.app.notify(msg)

                    if self.sign_on:
                        self.output.put(msg)

                else:
                    self.output.put(msg)

                msg = self.recv()

            self.error('lost connection')

        except OSError as e:
            self.error(e)

        finally:
            self.stop()

    def error(self, e):
        if not self.node: return
        self.print(f'** ERROR ** {e}')
        #self.on_error(e)
        self.stop()
    '''

    def get_public_ip(self):
        ip = get('http://api.ipify.org').content.decode('utf-8')
        self.print(f' - our public IP address: {ip}')
        return ip

