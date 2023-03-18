from .cmd import main

import sys


def run():
    try:
        main(sys.argv[1:])

    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    run()

