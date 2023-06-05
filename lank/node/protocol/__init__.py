from .ack import *
from .deny import *
from .sync import *
from .register import *
from .peer import *
from lank.crypto import get_handler as get_crypto

from bidict import bidict

import asyncio
from datetime import datetime, timedelta
from uuid import UUID


VERSION = 4
HELLO = b'\x04\x02\x00HOLANK\x00\x02\x04'
HELLO_SIZE = len(HELLO) # bytes
HELLO_TIMEOUT = 3 # seconds
MAX_TIME_SKEW = 9 # seconds
KEEPALIVE = 99 # seconds
GENERAL_TIMEOUT = 2*KEEPALIVE # seconds


class VersionMismatch(BaseException):
    def __init__(self, want, got):
        super().__init__(f'want {want} but got {got}')


class Handler:
    #BUFFER_SIZE = 8192 # bytes
    BYTE_ORDER = 'big'
    ID_SIZE = 1 # bytes
    ENCODING = 'utf-8'
    SYNC_MARGIN = 9 * 60 # seconds

    MSG_BY_ID = bidict({
         1: Ping,
         2: Pong,
         3: NodeOn,
         4: NodeIsSelf,
         5: NodeAlreadyConnected,
         6: NodeTimeSkewed,
         7: NodeIsIsolated,
         8: NodesOnly,
         9: Reservation,
        10: ReservationRequired,
        11: ReservationCancel,
        12: Registration,
        13: ReRegistration,
        14: RegistrationSuccess,
        15: GetRegistration,
        16: LabelNotFound,
        17: Signed,
        18: SignedUUIDNotFound,
        19: SignedLabelMismatch,
        20: SignedNameMismatch,
        21: SignatureFailure,
        22: PeerOn,
        #23: PeerAlreadyConnected,
        24: ListLabels,
        25: LabelsList,
        26: LabelInterest,
        27: LabelIgnore,
        28: GetHistory,
        29: History,
    })

    def __init__(self, addr, reader, writer, printer=print):
        self.addr = addr
        self.reader = reader
        self.writer = writer
        self.print = printer

    async def hello(self):
        assert VERSION > 0 and VERSION < 256
        self.writer.write(HELLO + VERSION.to_bytes(1, 'big'))
        return await asyncio.wait_for(
                self.writer.drain(), timeout=HELLO_TIMEOUT)

    async def ack(self):
        hello = await asyncio.wait_for(
                self.reader.readexactly(HELLO_SIZE+1), timeout=HELLO_TIMEOUT)
        if hello[:-1] != HELLO:
            return False

        version = hello[-1]
        if version != VERSION:
            # FIXME: more sophisticated version negotiation?
            raise VersionMismatch(VERSION, version)

        return True

    async def serve(self, master):
        self.node_uuid = None

        try:
            #while msg := await self.s_recv():
            msg = await self.s_recv()
            while msg:
                reply = None

                if isinstance(msg, Ping):
                    reply = Pong(msg.nonce)

                elif isinstance(msg, NodeOn):
                    reply = await self.node_on(master, msg)

                elif isinstance(msg, Reservation):
                    reply = await self.reservation(master, msg)

                elif isinstance(msg, ReservationCancel):
                    await self.reservation_cancel(master, msg)

                elif isinstance(msg, Registration):
                    if isinstance(msg, ReRegistration):
                        reply = await self.reregistration(master, msg)
                    else:
                        reply = await self.registration(master, msg)

                elif isinstance(msg, GetRegistration):
                    reply = self.get_registration(master, msg)

                elif isinstance(msg, Signed):
                    reply = await self.signed(master, msg)

                elif isinstance(msg, PeerOn):
                    reply = await self.peer_on(master, msg)

                elif isinstance(msg, ListLabels):
                    reply = self.list_labels(master, msg)

                elif isinstance(msg, LabelInterest):
                    reply = self.label_interest(master, msg)

                elif isinstance(msg, LabelIgnore):
                    reply = self.label_ignore(master, msg)

                elif isinstance(msg, GetHistory):
                    reply = self.get_history(master, msg)

                else:
                    raise ValueError('unhandled message')

                if reply:
                    await self.s_send(reply)

                    if isinstance(reply, Denial):
                        break

                msg = await self.s_recv()

        finally:
            if self.node_uuid:
                del master.nodes_by_uuid[self.node_uuid]
                master.status()

    async def client(self, master):
        self.node_uuid = None

        sync = master.ldb.get_last_signed_created()
        if sync:
            sync = datetime.fromisoformat(sync)
            sync -= timedelta(seconds=self.SYNC_MARGIN)
        msg = NodeOn(master.now(), master.uuid, sync)
        await self.c_send(msg)

        reply = await self.c_recv()
        if not reply: return

        if isinstance(reply, Denial):
            raise KeyError(reply.__class__.__name__)
        elif not isinstance(reply, NodeOn):
            raise ValueError('expecting NodeOn reply')
        elif reply.uuid == master.uuid:
            raise KeyError(NodeIsSelf.__name__)
        elif reply.nonce != msg.nonce:
            raise ValueError('nonce mismatch')
        elif reply.uuid in master.nodes_by_uuid:
            raise ValueError('node already connected (uuid match)')
        elif not reply.check_time_skew(master.now(), MAX_TIME_SKEW):
            raise ValueError('time skew')

        self.node_uuid = reply.uuid

        await self.sync_signed(master, self.c_send, sync, reply)

        master.nodes_by_uuid[self.node_uuid] = self
        master.status()

        try:
            ping = None

            while msg:
                try:
                    #while msg := await self.c_recv():
                    msg = await self.c_recv()
                    while msg:
                        reply = None

                        if isinstance(msg, Pong):
                            if not ping:
                                raise ValueError('pong without ping')
                            elif msg.nonce != ping.nonce:
                                raise ValueError('nonce mismatch')
                            ping = None

                        elif isinstance(msg, Reservation):
                            reply = await self.reservation(master, msg)

                        elif isinstance(msg, ReservationCancel):
                            await self.reservation_cancel(master, msg)

                        elif isinstance(msg, GetRegistration):
                            reply = self.get_registration(master, msg)

                        elif isinstance(msg, Signed):
                            reply = await self.signed(master, msg)

                        else:
                            raise ValueError('unhandled message')

                        if reply:
                            await self.c_send(reply)

                            if isinstance(reply, Denial):
                                msg = None
                                break

                        msg = await self.c_recv()

                except asyncio.TimeoutError as e:
                    if ping: raise e
                    ping = Ping()
                    await self.c_send(ping)

        finally:
            del master.nodes_by_uuid[self.node_uuid]
            master.status()

    async def s_send(self, msg):
        self.print(f'S    {self.addr} <- {msg}')
        await self.send(msg)

    async def c_send(self, msg):
        self.print(f'C    {self.addr} <- {msg}')
        await self.send(msg)

    async def s_recv(self):
        msg = await self.recv()
        self.print(f'S    {self.addr} -> {msg}')
        return msg

    async def c_recv(self):
        msg = await asyncio.wait_for(
                self.recv(), timeout=KEEPALIVE)
        self.print(f'C    {self.addr} -> {msg}')
        return msg

    async def send(self, msg):
        id_bytes = self.get_id_bytes(msg)
        data = msg.to_bytes(self)
        self.writer.write(id_bytes + (data if data else b''))
        return await asyncio.wait_for(
                self.writer.drain(), timeout=GENERAL_TIMEOUT)

    async def recv(self):
        id_bytes = await self.recv_bytes(self.ID_SIZE)
        if id_bytes is None: return None
        msg = self.get_msg_type(id_bytes)
        return await msg.recv(self)

    async def recv_bytes(self, size, timeout=GENERAL_TIMEOUT):
        #FIXME
        #if size > self.BUFFER_SIZE:
        #    raise ValueError(f'request to read more than buffer allows: {size}')
        try:
            return await asyncio.wait_for(
                    self.reader.readexactly(size), timeout=timeout)

        except asyncio.IncompleteReadError:
            return None

    def get_id_bytes(self, msg):
        try:
            mid = self.MSG_BY_ID.inverse[type(msg)]
            try:
                return mid.to_bytes(self.ID_SIZE, self.BYTE_ORDER)

            except OverflowError as e:
                raise ValueError(f'msg type id too big: {mid}') from e

        except KeyError as e:
            raise ValueError(f'unsupported message type: {type(msg)}') from e

    def get_msg_type(self, id_bytes):
        mid = int.from_bytes(id_bytes, self.BYTE_ORDER)
        try:
            return self.MSG_BY_ID[mid]

        except KeyError as e:
            raise ValueError(f'unsupported message type id: {mid}') from e








    async def node_on(self, master, msg):
        assert isinstance(msg, NodeOn)

        if self.node_uuid:
            return NodeAlreadyConnected()

        if msg.uuid == master.uuid:
            return NodeIsSelf()

        if msg.uuid in master.nodes_by_uuid:
            return NodeAlreadyConnected()

        if not msg.check_time_skew(master.now(), MAX_TIME_SKEW):
            return NodeTimeSkewed()

        self.node_uuid = msg.uuid

        sync = master.ldb.get_last_signed_created()
        if sync:
            sync = datetime.fromisoformat(sync)
            sync -= timedelta(seconds=self.SYNC_MARGIN)

        await self.s_send(NodeOn(master.now(), master.uuid, sync, msg.nonce))
        await self.sync_signed(master, self.s_send, sync, msg)

        master.nodes_by_uuid[self.node_uuid] = self
        master.status()

        return None

    async def reservation(self, master, msg):
        assert isinstance(msg, Reservation)
        reply = None

        if not master.nodes_by_uuid:
            reply = NodeIsIsolated()

        elif msg.label in master.reservations:
            reservation = master.reservations[msg.label]
            res_uuid = reservation[0]

            if msg.uuid != res_uuid: # collision
                reply = ReservationCancel(msg.label)
                await master.broadcast_nodes(reply, skip=self)
                del master.reservations[msg.label]

            else: # just an echo from another node?
                pass

        elif master.ldb.get_label_by_name(msg.label):
            reply = ReservationCancel(msg.label, True)

        else:
            reservation = (msg.uuid, self.addr, master.now())
            master.reservations[msg.label] = reservation
            await master.broadcast_nodes(msg, skip=self)
            if not self.node_uuid: reply = msg

        return reply

    async def reservation_cancel(self, master, msg):
        assert isinstance(msg, ReservationCancel)

        if msg.label in master.reservations:
            await master.broadcast_nodes(msg, skip=self)
            del master.reservations[msg.label]

    async def registration(self, master, msg):
        assert isinstance(msg, Registration)

        if not master.nodes_by_uuid:
            return NodeIsIsolated()

        if msg.label not in master.reservations:
            return ReservationRequired(msg.label)

        reservation = master.reservations[msg.label]
        res_uuid = reservation[0]
        res_addr = reservation[1]

        #FIXME enable imposter checks?

        #if res_uuid != msg.uuid: # imposter
        #    return ReservationRequired(msg.label)

        #if res_addr != self.addr: # imposter
        #    return ReservationRequired(msg.label)

        crypto = get_crypto(msg.version)
        pub_key = crypto.load_public_key(msg.key_pair_pem)
        data = crypto.get_register_message(msg.label, msg.time_nonce)

        if not crypto.verify(pub_key, data, msg.signature):
            return SignatureFailure(msg.uuid)

        label_id = None
        addr = str(msg.key_pair_pem, crypto.ENCODING)

        with master.ldb.Transaction():
            label_id = master.ldb.insert_label(msg.label)
            time = master.now()

            master.ldb.insert_signed(str(msg.uuid), label_id,
                master.ldb.NAME_REGISTER, msg.time_nonce, addr,
                msg.signature, msg.version, str(master.uuid), time)

            master.signed_recently[res_uuid] = time
            del master.reservations[msg.label]

        master.labels_by_id[label_id] = msg.label

        await master.broadcast_nodes(Signed(
            msg.version,
            res_uuid,
            msg.label,
            master.ldb.NAME_REGISTER,
            msg.time_nonce,
            addr,
            msg.signature,
            master.uuid,
            time
        ), skip=self)

        return RegistrationSuccess(res_uuid)

    async def reregistration(self, master, msg):
        assert isinstance(msg, ReRegistration)

        if not master.nodes_by_uuid:
            return NodeIsIsolated()

        signed = master.ldb.get_signed_by_uuid(str(msg.ref_uuid))

        if not signed:
            return SignedUUIDNotFound(msg.ref_uuid)
        if master.labels_by_id[signed['label']] != msg.label:
            return SignedLabelMismatch(msg.ref_uuid, msg.label)
        if signed['name'] != master.ldb.NAME_REGISTER:
            return SignedNameMismatch(msg.ref_uuid, master.ldb.NAME_REGISTER)

        crypto = get_crypto(signed['version'])
        pub_key = crypto.load_public_key(
                        signed['address'].encode(crypto.ENCODING))
        data = crypto.get_reregister_message(signed['key'], signed['uuid'],
                                             msg.key_pair_pem)

        if not crypto.verify(pub_key, data, msg.signature):
            return SignatureFailure(msg.uuid)

        key = f'M:{msg.ref_uuid}'
        addr = str(msg.key_pair_pem, crypto.ENCODING)

        with master.ldb.Transaction():
            time = master.now()

            master.ldb.insert_signed(str(msg.uuid), signed['label'],
                master.ldb.NAME_REGISTER, key, addr,
                msg.signature, msg.version, str(master.uuid), time)

            master.signed_recently[msg.uuid] = time

        await master.broadcast_nodes(Signed(
            msg.version,
            msg.uuid,
            msg.label,
            master.ldb.NAME_REGISTER,
            key,
            addr,
            msg.signature,
            master.uuid,
            time
        ), skip=self)

        return RegistrationSuccess(msg.uuid)

    def get_registration(self, master, msg):
        assert isinstance(msg, GetRegistration)

        if msg.label not in master.labels_by_id.inverse:
            return LabelNotFound(msg.label)

        label_id = master.labels_by_id.inverse[msg.label]
        signed = master.ldb.find_signed_by_label_name(label_id,
                                master.ldb.NAME_REGISTER,
                                               limit=1)

        assert signed
        assert len(signed)==1
        signed = signed[0]

        crypto = get_crypto(signed['version'])

        return Registration(
            UUID(signed['uuid']),
            msg.label,
            signed['version'],
            signed['key'],
            signed['address'].encode(crypto.ENCODING),
            signed['signature'])

    async def signed(self, master, msg):
        assert isinstance(msg, Signed)

        if not self.node_uuid:
            return NodesOnly()

        if msg.uuid in master.signed_recently:
            return None

        exists = master.ldb.get_signed_by_uuid(str(msg.uuid))
        if exists:
            return None

        crypto = get_crypto(msg.version)

        if msg.name == master.ldb.NAME_REGISTER:
            if msg.key.startswith('M:'): # re-register (ref uuid)
                ref_uuid = msg.key[2:]
                signed = master.ldb.get_signed_by_uuid(ref_uuid)

                if not signed:
                    raise KeyError(f'signed uuid ref not found: {ref_uuid}')
                if master.labels_by_id[signed['label']] != msg.label:
                    raise KeyError(f'signed label mismatch: {msg.label}')
                if signed['name'] != master.ldb.NAME_REGISTER:
                    raise KeyError(f'signed name mismatch: {signed["name"]}')

                pub_key = crypto.load_public_key(
                            signed['address'].encode(crypto.ENCODING))
                data = crypto.get_reregister_message(signed['key'],
                            signed['uuid'], msg.address.encode(crypto.ENCODING))

                if not crypto.verify(pub_key, data, msg.signature):
                    return SignatureFailure(msg.uuid)

            else: # initial registration (time_nonce)
                pub_key = crypto.load_public_key(
                    msg.address.encode(crypto.ENCODING))
                data = crypto.get_register_message(msg.label, msg.key)

                if not crypto.verify(pub_key, data, msg.signature):
                    return SignatureFailure(msg.uuid)

        elif msg.name == master.ldb.NAME_PEER:
            if msg.label not in master.labels_by_id.inverse:
                return LabelNotFound(msg.label)

            label_id = master.labels_by_id.inverse[msg.label]
            signed = master.ldb.find_signed_by_label_name(label_id,
                                master.ldb.NAME_REGISTER,
                                                   limit=1)

            assert signed
            assert len(signed)==1
            signed = signed[0]

            pub_key = crypto.load_public_key(
                signed['address'].encode(crypto.ENCODING))
            host = msg.address[:msg.address.index(':')]
            port = int(msg.address[msg.address.index(':')+1:])
            alias = None
            if ':' in msg.key[msg.key.index(':')+1:]:
                alias = msg.key[msg.key.index(':')+1:]
                alias = alias[alias.index(':')+1:]
            port = int(port)
            data = PeerOn._to_sign_(crypto, msg.uuid, msg.label, host, port,
                                    alias)

            if not crypto.verify(pub_key, data, msg.signature):
                return SignatureFailure(msg.uuid)

        else:
            raise ValueError(f'unsupported signed name id: {msg.name}')

        label_id = None
        with master.ldb.Transaction():
            try:
                label_id = master.labels_by_id.inverse[msg.label]
            except KeyError:
                label_id = master.ldb.insert_label(msg.label)

            master.ldb.insert_signed(str(msg.uuid), label_id, msg.name, msg.key,
                              msg.address, msg.signature, msg.version,
                              str(msg.node_uuid),
                              msg._to_datetime_(msg.timestamp))

        if label_id not in master.labels_by_id:
            master.labels_by_id[label_id] = msg.label

        if msg.label in master.reservations:
            del master.reservations[msg.label]

        master.signed_recently[msg.uuid] = master.now()
        await master.broadcast_nodes(msg, skip=self)

        return None

    async def sync_signed(self, master, send, sync, msg):
        assert isinstance(msg, NodeOn)

        msg_sync = msg._to_datetime_(msg.synced) \
                   if msg.synced else None

        if sync and (not msg_sync or msg_sync < sync):
            if not msg_sync:
                signed_list = master.ldb.list_signed()
            else:
                signed_list = master.ldb.find_signed_since(msg_sync)

            for signed in signed_list:
                await send(Signed(
                    signed['version'],
                    UUID(signed['uuid']),
                    master.labels_by_id[signed['label']],
                    signed['name'],
                    signed['key'],
                    signed['address'],
                    signed['signature'],
                    UUID(signed['node_uuid']),
                    signed['created']
                ))

        #sync = ldb.get_last_signed_created()
        #if sync:
        #    sync = datetime.fromisoformat(sync)
        #    sync -= timedelta(seconds=self.SYNC_MARGIN)

        #reply = NodeOn(master.now(), master.uuid, sync,
        #    msg.nonce)

    async def peer_on(self, master, msg):
        assert isinstance(msg, PeerOn)

        if self.node_uuid:
            return NodeAlreadyConnected()

        if not master.nodes_by_uuid:
            return NodeIsIsolated()

        try:
            label_id = master.labels_by_id.inverse[msg.label]

        except KeyError:
            return LabelNotFound(msg.label)

        signed = master.ldb.find_signed_by_label_name(label_id,
                                                master.ldb.NAME_REGISTER,
                                                limit=1)

        assert signed
        assert len(signed)==1
        signed = signed[0]

        crypto = get_crypto(msg.version)
        key_pair_pem = signed['address'].encode(crypto.ENCODING)
        pub_key = crypto.load_public_key(key_pair_pem)
        data = msg.to_sign(crypto)

        if not crypto.verify(pub_key, data, msg.signature):
            return SignatureFailure(msg.uuid)

        assert ':' not in self.addr[0]
        key = f'{self.addr[0]}:{self.addr[1]}'
        if msg.alias: key += f':{msg.alias}'

        assert ':' not in msg.host
        addr = f'{msg.host}:{msg.port}'

        with master.ldb.Transaction():
            time = master.now()

            master.ldb.insert_signed(str(msg.uuid), label_id,
                master.ldb.NAME_PEER, key, addr,
                msg.signature, msg.version, str(master.uuid), time)

            master.signed_recently[msg.uuid] = time

        master.status()

        reply = Signed(
            msg.version,
            msg.uuid,
            msg.label,
            master.ldb.NAME_PEER,
            key,
            addr,
            msg.signature,
            master.uuid,
            time
        )

        await master.broadcast_nodes(reply, skip=self)
        return reply

    def list_labels(self, master, msg):
        assert isinstance(msg, ListLabels)

        return LabelsList(master.labels_by_id.values())

    def label_interest(self, master, msg):
        assert isinstance(msg, LabelInterest)

        master.add_label_interest(msg.label, self)

    def label_ignore(self, master, msg):
        assert isinstance(msg, LabelIgnore)

        master.remove_label_interest(msg.label, self)

    def get_history(self, master, msg):
        assert isinstance(msg, GetHistory)

        try:
            label_id = master.labels_by_id.inverse[msg.label]

        except KeyError:
            return LabelNotFound(msg.label)

        if msg.name:
            signed_list = master.ldb.find_signed_by_label_name(
                label_id, msg.name, limit=msg.start+msg.count)

        else:
            signed_list = master.ldb.find_signed_by_label(
                label_id, limit=msg.start+msg.count)

        items = [ ]
        idx = 0
        end = msg.start + msg.count - 1

        for signed in signed_list:
            if idx >= msg.start:
                items.append(Signed(
                    signed['version'],
                    UUID(signed['uuid']),
                    msg.label,
                    signed['name'],
                    signed['key'],
                    signed['address'],
                    signed['signature'],
                    UUID(signed['node_uuid']),
                    signed['created']
                ))

            idx += 1
            if idx > end: break

        return History(msg.label, msg.start, items)

