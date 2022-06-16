

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


SET = {
    'help': (help,
        'help for peer commands'),
}

