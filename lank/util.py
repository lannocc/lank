from sys import stdout


def print_flush(*args, **kwargs):
    print(*args, **kwargs)
    stdout.flush()

