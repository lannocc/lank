from . import __version__
from .config import *
import lank.db as ldb

import sys


def main():
    try:
        print('LANK: ', end='')

        cmd = sys.argv[1] if len(sys.argv) > 1 else 'help'

        if cmd in SET:
            cmd = SET[cmd]
            print(cmd[1])
            cmd[0]()

        else:
            print(f'unknown command: {cmd}')
            print('Try `lank help` for a list of commands.')

    finally:
        ldb.close()


def help():
    print('Listening Anchor Nodes for K')
    print()
    print('USAGE:')
    print('   lank <command>')
    print()
    print('The following commands are available:')
    for name, cmd in SET.items():
        print(f'   {name} - {cmd[1]}')
    #print()
    #print('For example, to see version information:')
    #print('   lank version')


def version():
    print(f'Installed version is {__version__}')


def dbinfo():
    from os.path import getsize
    print(f'  db file: {DB}')
    print(f'  version: {ldb.VERSION}')
    print(f'     size: {getsize(DB)} (bytes)')


SET = {
    'help': (help,
        'help for this program'),
    'version': (version,
        'version information'),
    'dbinfo': (dbinfo,
        'database information'),
}

