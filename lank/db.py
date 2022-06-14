from .config import DB

import sqlite3
from datetime import datetime


VERSION = 1

# meta table entries
META_VERSION = 'db_version'


#print(f'databasing "{DB}" ...')

con = sqlite3.connect(DB, isolation_level=None,
    detect_types=sqlite3.PARSE_DECLTYPES)
con.row_factory = sqlite3.Row
sqlite3.register_adapter(bool, int)
sqlite3.register_converter('BOOLEAN', lambda v: bool(int(v)))
cur = con.cursor()
#cur.execute('.dbconfig defensive on')
cur.execute('PRAGMA journal_mode=WAL')
cur.execute('PRAGMA synchronous=NORMAL')
cur.execute('PRAGMA temp_store=MEMORY')
#cur.execute('PRAGMA locking_mode=EXCLUSIVE')
cur.execute('PRAGMA foreign_keys=ON')


def cur_fetch():
    for row in cur:
        return row  # returns first row only

    return None  # if there were no rows

def cur_fetchcol(name):
    row = cur_fetch()
    if not row:
        return None

    return row[name]

def cur_fetchall():
    rows = [ ]

    for row in cur:
        rows.append(row)

    return rows

def close():
    cur.execute('VACUUM')
    con.close()


###
### META
###

cur.execute('''
    CREATE TABLE IF NOT EXISTS meta (
        name    TEXT PRIMARY KEY,
        value   TEXT
    )
''')

cur.executemany('''
    INSERT OR IGNORE INTO meta (
        name,
        value
    )
    VALUES (
        ?, ?
    )
''', [
    (META_VERSION, VERSION),
])

def get_meta(name):
    cur.execute('''
        SELECT value
        FROM meta
        WHERE name = ?
    ''', (
        name,
    ))

    return cur_fetchcol('value')

def set_meta(name, value):
    cur.execute('''
        UPDATE meta
        SET value = ?
        WHERE name = ?
    ''', (
        value,
        name
    ))

def _upgrade_if_needed_():
    v = int(get_meta(META_VERSION))

    if v < VERSION:
        from .patch import upgrade
        upgrade(DB, cur, cur_fetchall, set_meta, META_VERSION, v, VERSION)

_upgrade_if_needed_() # pause here and patch the db before continuing


###
### FOO
###



#print('db ready :-)')

