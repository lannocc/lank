

def main(args):
    print('LANK NODE: ', end='')

    cmd = args[0] if args else 'help'
    args = args[1:]

    if cmd in SET:
        cmd = SET[cmd]
        print(cmd[1])
        cmd[0](args)

    else:
        print(f'unknown command: {cmd}')
        print('Try `lank node help` for a list of commands.')


def help(args):
    print()
    print('USAGE:')
    print('   lank node <command>')
    print()
    print('The following commands are available:')
    for name, cmd in SET.items():
        print(f'   {name} - {cmd[1]}')


def run(args):
    from . import Server

    print('Starting server process...')
    server = Server()
    print(f'   listening on port {server.port}')
    server.run()


def test(args):
    from .test import TestClient
    tester = TestClient()
    print('Testing...')
    tester.run()


SET = {
    'help': (help,
        'help for node commands'),
    'run': (run,
        'run the node'),
    'test': (test,
        'test the node'),
}

