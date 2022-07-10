from ..v1 import Handler as Base
from .. import KEEPALIVE, MAX_TIME_SKEW
from .ack import *
from .sync import *
from .peer import *
from .register import *
from .deny import *
from lank.crypto import get_handler as get_crypto

from bidict import bidict
from gevent import socket

from datetime import datetime, timedelta
from uuid import UUID


class Handler(Base):
    VERSION = 2

    BUFFER_SIZE = 8192
    ENCODING = 'utf-8'
    SYNC_MARGIN = 10 * 60 # seconds

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
        23: PeerAlreadyConnected,
        24: ListLabels,
        25: LabelsList,
        26: LabelInterest,
        27: LabelIgnore,
        28: GetHistory,
        29: History,
    })

    def client(self, master):
        self.node_uuid = None
        self.peer_label = None

        sync = master.ldb.get_last_signed_created()
        if sync:
            sync = datetime.fromisoformat(sync)
            sync -= timedelta(seconds=self.SYNC_MARGIN)
        msg = NodeOn(master.now(), master.uuid, sync)
        self.c_send(msg)

        reply = self.c_recv()
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

        self.sync_signed(master, self.c_send, sync, reply)

        master.nodes_by_uuid[self.node_uuid] = self
        master.status()

        try:
            self.sock.settimeout(KEEPALIVE)
            ping = None

            while msg:
                try:
                    #while msg := self.c_recv():
                    msg = self.c_recv()
                    while msg:
                        reply = None

                        if isinstance(msg, Pong):
                            if not ping:
                                raise ValueError('pong without ping')
                            elif msg.nonce != ping.nonce:
                                raise ValueError('nonce mismatch')
                            ping = None

                        elif isinstance(msg, Reservation):
                            reply = self.reservation(master, msg)

                        elif isinstance(msg, ReservationCancel):
                            self.reservation_cancel(master, msg)

                        elif isinstance(msg, GetRegistration):
                            reply = self.get_registration(master, msg)

                        elif isinstance(msg, Signed):
                            reply = self.signed(master, msg)

                        else:
                            raise ValueError('unhandled message')

                        if reply:
                            self.c_send(reply)

                            if isinstance(reply, Denial):
                                msg = None
                                break

                        msg = self.c_recv()

                except socket.timeout as e:
                    if ping: raise e
                    ping = Ping()
                    self.c_send(ping)

        finally:
            del master.nodes_by_uuid[self.node_uuid]
            master.status()

    def server(self, master):
        self.node_uuid = None
        self.peer_label = None

        try:
            #while msg := self.s_recv():
            msg = self.s_recv()
            while msg:
                reply = None

                if isinstance(msg, Ping):
                    reply = Pong(msg.nonce)

                elif isinstance(msg, NodeOn):
                    reply = self.node_on(master, msg)

                elif isinstance(msg, Reservation):
                    reply = self.reservation(master, msg)

                elif isinstance(msg, ReservationCancel):
                    self.reservation_cancel(master, msg)

                elif isinstance(msg, Registration):
                    if isinstance(msg, ReRegistration):
                        reply = self.reregistration(master, msg)
                    else:
                        reply = self.registration(master, msg)

                elif isinstance(msg, GetRegistration):
                    reply = self.get_registration(master, msg)

                elif isinstance(msg, Signed):
                    reply = self.signed(master, msg)

                elif isinstance(msg, PeerOn):
                    reply = self.peer_on(master, msg)

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
                    self.s_send(reply)

                    if isinstance(reply, Denial):
                        break

                msg = self.s_recv()

        finally:
            if self.node_uuid:
                del master.nodes_by_uuid[self.node_uuid]
                master.status()

            if self.peer_label:
                del master.peers_by_label[self.peer_label]
                master.status()

    def send(self, msg):
        id_bytes = self.get_id_bytes(msg)
        data = msg.to_bytes(self)
        self.sock.sendall(id_bytes + (data if data else b''))

    def node_on(self, master, msg):
        assert isinstance(msg, NodeOn)

        if self.node_uuid:
            return NodeAlreadyConnected()

        if self.peer_label:
            return PeerAlreadyConnected()

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

        self.s_send(NodeOn(master.now(), master.uuid, sync,
            msg.nonce))

        self.sync_signed(master, self.s_send, sync, msg)

        master.nodes_by_uuid[self.node_uuid] = self
        master.status()

        return None

    def reservation(self, master, msg):
        assert isinstance(msg, Reservation)
        reply = None

        if not master.nodes_by_uuid:
            reply = NodeIsIsolated()

        elif msg.label in master.reservations:
            reservation = master.reservations[msg.label]
            res_uuid = reservation[0]

            if msg.uuid != res_uuid: # collision
                reply = ReservationCancel(msg.label)
                master.broadcast_nodes(reply, skip=self)
                del master.reservations[msg.label]

            else: # just an echo from another node?
                pass

        elif master.ldb.get_label_by_name(msg.label):
            reply = ReservationCancel(msg.label, True)

        else:
            reservation = (msg.uuid, self.sock, master.now())
            master.reservations[msg.label] = reservation
            master.broadcast_nodes(msg, skip=self)
            if not self.node_uuid: reply = msg

        return reply

    def reservation_cancel(self, master, msg):
        assert isinstance(msg, ReservationCancel)

        if msg.label in master.reservations:
            master.broadcast_nodes(msg, skip=self)
            del master.reservations[msg.label]

    def registration(self, master, msg):
        assert isinstance(msg, Registration)

        if not master.nodes_by_uuid:
            return NodeIsIsolated()

        if msg.label not in master.reservations:
            return ReservationRequired(msg.label)

        reservation = master.reservations[msg.label]
        res_uuid = reservation[0]
        res_sock = reservation[1]

        if res_sock != self.sock: # imposter
            return ReservationRequired(msg.label)

        if res_uuid != msg.uuid: # imposter
            return ReservationRequired(msg.label)

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

        master.broadcast_nodes(Signed(
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

    def reregistration(self, master, msg):
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

        master.broadcast_nodes(Signed(
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

    def signed(self, master, msg):
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
        master.broadcast_nodes(msg, skip=self)

        return None

    def sync_signed(self, master, send, sync, msg):
        assert isinstance(msg, NodeOn)

        msg_sync = msg._to_datetime_(msg.synced) \
                   if msg.synced else None

        if sync and (not msg_sync or msg_sync < sync):
            if not msg_sync:
                signed_list = master.ldb.list_signed()
            else:
                signed_list = master.ldb.find_signed_since(msg_sync)

            for signed in signed_list:
                send(Signed(
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

    def peer_on(self, master, msg):
        assert isinstance(msg, PeerOn)

        if self.peer_label:
            # FIXME: maybe allow this?
            #       (e.g. peer switching identity or multiple-login)
            return PeerAlreadyConnected()

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

        self.peer_label = msg.label
        master.peers_by_label[self.peer_label] = self
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

        master.broadcast_nodes(reply, skip=self)
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

        signed_list = master.ldb.find_signed_by_label(
            label_id, msg.start + msg.count)

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

