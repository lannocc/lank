from ..node import get_nodes, HELLO_TIMEOUT, GENERAL_TIMEOUT, KEEPALIVE
from ..node.protocol.v2 import *
#from ..crypto import get_handler as get_crypto

from requests import get

from threading import Thread, current_thread
from queue import Queue, Empty
#import janus
import socket
import sys


class Client(Thread):
    def __init__(self, verbose=True):
        #def __init__(self, port, label, pwd, alias,
        #    on_error, on_connect, verbose=True):
        super().__init__(name='node')
        self.verbose = verbose

        self.host = self.get_public_ip()
        #self.port = port
        #self.label = label
        #self.pwd = pwd or None
        #self.alias = alias or None
        #self.on_error = on_error
        #self.on_connect = on_connect

        self.node = None
        self.input = Queue()
        self.output = Queue()

        self.ping = None
        self.sign_on = False
        self.labels_callback = None
        self.history_callback = None
        self.register_callback = None

        self.sender_thread = Thread(
            name='node-sender', target=self.sender)
        self.receiver_thread = Thread(
            name='node-return', target=self.receiver)

    def __str__(self):
        if not self.node:
            return 'no connection'

        if not self.node.sock:
            return 'no connection (sock)'

        return f'{self.node.sock.getpeername()}'

    def run(self):
        self.print(' - connecting to node:')

        for addr in get_nodes():
            self.print(f'   * trying {addr}... ', False)

            try:
                sock = socket.create_connection(addr, timeout=HELLO_TIMEOUT)
                sock.settimeout(HELLO_TIMEOUT)
                self.node = Handler(sock, addr)
                self.node.hello()
                self.node.sock.settimeout(GENERAL_TIMEOUT)
                self.print('[READY]')
                break

            except ConnectionRefusedError:
                self.print(f'[REFUSED] {addr}')
                self.node = None

            except socket.timeout:
                self.print(f'[TIMEOUT] {addr}')
                self.node = None

        if not self.node: return
        self.receiver_thread.start()
        self.sender_thread.start()

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

    def list_labels(self):
        self.input.put_nowait(ListLabels())
        return self.output.get()

    def get_registration(self, label):
        self.input.put_nowait(GetRegistration(label))
        return self.output.get()

    def get_history(self, label):
        self.input.put_nowait(GetHistory(label))
        return self.output.get()

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
    '''

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

    def send(self, msg):
        if not self.node: return
        self.print(f'N    {self.node.addr} <- {msg}')
        self.node.send(msg)

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

    def recv(self):
        if not self.node: return None
        msg = self.node.recv()
        if msg: self.print(f'N    {self.node.addr} -> {msg}')
        return msg

    def get_public_ip(self):
        ip = get('http://api.ipify.org').content.decode('utf-8')
        self.print(f' - our public IP address: {ip}')
        return ip

    def print(self, msg, newline=True):
        if not self.verbose: return
        thread = current_thread().name
        msg = f'[{thread}] {msg}'
        if newline: print(msg)
        else:
            print(msg, end='')
            sys.stdout.flush()

    def error(self, e):
        if not self.node: return
        print(f'** ERROR ** {e}')
        #self.on_error(e)
        self.stop()

