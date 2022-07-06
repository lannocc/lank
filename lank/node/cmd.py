

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
    from . import Master
    import lank.node.db as ldb

    try:
        print('Starting node process...')
        node = Master()
        node.run()

    finally:
        ldb.close()


def run2(args):
    from . import Master
    import lank.node.db as ldb

    try:
        print('Starting node process...')
        node = Master(42124)
        node.run()

    finally:
        ldb.close()


def test_v1(args):
    from .test import TestClient_v1
    tester = TestClient_v1()
    print('Testing...')
    tester.run()


def test_v2(args):
    from .test import TestClient_v2
    tester = TestClient_v2()
    print('Testing...')
    tester.run()


def dbinfo(args):
    from ..config import DB
    from .db import VERSION
    from os.path import getsize

    print(f'  db file: {DB}')
    print(f'  version: {VERSION}')
    print(f'     size: {getsize(DB)} (bytes)')


SET = {
    'help': (help,
        'help for node commands'),
    'run': (run,
        'run the node'),
    'run2': (run2,
        'run a second node'),
    'test': (test_v1,
        'test the node (protocol v1)'),
    'test2': (test_v2,
        'test the node (protocol v2)'),
    'dbinfo': (dbinfo,
        'database information'),
}

