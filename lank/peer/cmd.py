

def main(args):
    print('LANK PEER: ', end='')

    cmd = args[0] if args else 'help'
    args = args[1:]

    if cmd in SET:
        cmd = SET[cmd]
        print(cmd[1])
        cmd[0](args)

    else:
        print(f'unknown command: {cmd}')
        print('Try `lank peer help` for a list of commands.')


def help(args):
    print()
    print('USAGE:')
    print('   lank peer <command>')
    print()
    print('The following commands are available:')
    for name, cmd in SET.items():
        print(f'   {name} - {cmd[1]}')


def run(args):
    from . import Master
    from ..crypto import get_handler
    import lank.node.db as ldb

    try:
        crypto = get_handler()

        label = 'anonymous'
        print(f'Loading private key for "{label}"...')

        label = ldb.get_label_by_name(label)
        assert label
        label = label['id']

        registration = ldb.find_signed_by_label_name(label, ldb.NAME_REGISTER,
                                                     limit=1)
        assert registration
        assert registration[0]
        registration = registration[0]
        key_pair_pem = registration['address'].encode(crypto.ENCODING)

        priv_key = crypto.load_private_key(key_pair_pem)

        print('Starting server process...')
        server = Master(crypto, priv_key)

        def get_public_key(crypto, label):
            label = ldb.get_label_by_name(label)
            assert label
            label = label['id']

            registration = ldb.find_signed_by_label_name(label,
                                                         ldb.NAME_REGISTER,
                                                         limit=1)
            assert registration
            assert registration[0]
            registration = registration[0]
            key_pair_pem = registration['address'].encode(crypto.ENCODING)

            return crypto.load_public_key(key_pair_pem)

        server.get_public_key = get_public_key
        print(f'   listening on port {server.port}')
        server.run()

    finally:
        ldb.close()


def test(args):
    from .test import TestClient
    tester = TestClient()
    print('Testing...')
    tester.run()


SET = {
    'help': (help,
        'help for peer commands'),
    'run': (run,
        'run the peer'),
    'test': (test,
        'test the peer'),
}

