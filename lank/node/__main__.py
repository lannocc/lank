from .cmd import main
import lank.db as ldb

import sys


def run():
    try:
        main(sys.argv[1:])

    except KeyboardInterrupt:
        pass

    finally:
        ldb.close()


if __name__ == '__main__':
    run()

