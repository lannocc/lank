

def main(args):
    print('LANK: ', end='')

    cmd = args[0] if args else 'help'
    args = args[1:]

    if cmd in SET:
        cmd = SET[cmd]
        print(cmd[1])
        cmd[0](args)

    else:
        print(f'unknown command: {cmd}')
        print('Try `lank help` for a list of commands.')


def help(args):
    print('Listening Anchor Nodes for K')
    print()
    print('USAGE:')
    print('   lank <command>')
    print()
    print('The following commands are available:')
    for name, cmd in SET.items():
        print(f'   {name} - {cmd[1]}')


def version(args):
    from . import __version__
    print(f'Installed version is {__version__}')


def dbinfo(args):
    from .config import DB
    from .db import VERSION
    from os.path import getsize

    print(f'  db file: {DB}')
    print(f'  version: {VERSION}')
    print(f'     size: {getsize(DB)} (bytes)')


def register(args):
    from .crypto import get_handler

    get_handler().register()


def node(args):
    from .node.cmd import main as node_main

    node_main(args)


def peer(args):
    from .peer.cmd import main as peer_main

    peer_main(args)


SET = {
    'help': (help,
        'help for this program'),
    'version': (version,
        'version information'),
    'dbinfo': (dbinfo,
        'database information'),
    'register': (register,
        'register a new label'),
    'node': (node,
        'node commands'),
    'peer': (peer,
        'peer commands'),
}
