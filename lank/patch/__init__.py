import sys


def upgrade(dbfile, cur, fetchall, set_meta, meta_version, from_ver, to_ver):
    print()
    print()
    print('#################################')
    print('    DATABASE UPGRADE REQUIRED')
    print('---------------------------------')
    print(f'  database file: {dbfile}')
    print(f'   your version: {from_ver}')
    print(f' needed version: {to_ver}')
    print('---------------------------------')
    print('The database must be patched')
    print('before it can be used by this')
    print('release.')
    print()
    print('! WARNING: It is recommended that')
    print('you make a backup copy of the')
    print('database file before continuing!!')
    print()
    print('Patches will apply incrementally.')
    print('---------------------------------')
    print('      USE <CTRL>-C TO EXIT')
    print('#################################')

    v = from_ver
    while v < to_ver:
        v += 1
        try:
            apply_patch(cur, fetchall, v)
            set_meta(meta_version, v)
            print('SUCCESS')

        except KeyboardInterrupt:
            print('ANCELLED BY USER') # not a typo (piggy back off ^C)
            sys.exit(1)

        except Exception as e:
            print('FAILED')
            raise RuntimeError(f'Failed to apply version {v} patch', e)

def apply_patch(cur, fetchall, version):
    print()
    print(f'Hit <ENTER> to apply version {version}...')
    input()

    exec(f'from .patch.v{version} import patch as patch_v{version}')

    cur.execute('PRAGMA foreign_keys=OFF')
    cur.execute('BEGIN')

    exec(f'patch_v{version}(cur)')

    cur.execute('PRAGMA foreign_key_check')
    fails = fetchall()
    if fails:
        print('!!! FOREIGN KEY FAILURE !!!')
        for fail in fails:
            print(f'   table={fail[0]}, id={fail[1]}, column={fail[2]}')
        raise RuntimeError('one or more foreign key constraints failed')

    cur.execute('COMMIT')
    cur.execute('PRAGMA foreign_keys=ON')
    cur.execute('VACUUM')

