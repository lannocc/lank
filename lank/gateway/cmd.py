

def main(args):
    print('LANK GATEWAY: ', end='')

    cmd = args[0] if args else 'help'
    args = args[1:]

    if cmd in SET:
        cmd = SET[cmd]
        print(cmd[1])
        cmd[0](args)

    else:
        print(f'unknown command: {cmd}')
        print('Try `lank gateway help` for a list of commands.')


def help(args):
    print()
    print('USAGE:')
    print('   lank gateway <command>')
    print()
    print('The following commands are available:')
    for name, cmd in SET.items():
        print(f'   {name} - {cmd[1]}')


def run(args):
    from . import Master

    print('Starting gateway process...')
    gateway = Master()
    gateway.run()


SET = {
    'help': (help,
        'help for gateway commands'),
    'run': (run,
        'run the gateway'),
}

