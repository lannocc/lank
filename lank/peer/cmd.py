

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
    from . import Server
    from ..crypto import get_handler

    crypto = get_handler()

    label = 'anonymous'
    print(f'Loading private key for "{label}"...')
    priv_key = crypto.get_private_key(label)

    print('Starting server process...')
    server = Server(crypto, priv_key)
    print(f'   listening on port {server.port}')
    server.run()


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

