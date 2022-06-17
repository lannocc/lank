from .config import DB

import sqlite3
from contextlib import AbstractContextManager


VERSION = 2

# meta table entries
META_VERSION = 'db_version'

# name table entries
NAME_REGISTER = 10


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


class Transaction(AbstractContextManager):
    def __init__(self):
        super().__init__()

    def __enter__(self):
        cur.execute('BEGIN')
        return self

    def __exit__(self, exc_type=None, exc_value=None, traceback=None):
        if exc_type or exc_value or traceback:
            cur.execute('ROLLBACK')
        else:
            cur.execute('COMMIT')
        return None


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
        upgrade(DB, close, cur, cur_fetchall,
                set_meta, META_VERSION, v, VERSION)

_upgrade_if_needed_() # pause here and patch the db before continuing


###
### LABEL
###

cur.execute('''
    CREATE TABLE IF NOT EXISTS label (
        id      INTEGER PRIMARY KEY,
        name    TEXT NOT NULL COLLATE NOCASE UNIQUE
    )
''')

def insert_label(name):
    cur.execute('''
        INSERT INTO label (
            name
        )
        VALUES (
            ?
        )
    ''', (
        name,
    ))

    return cur.lastrowid

def get_label(label_id):
    cur.execute('''
        SELECT *
        FROM label
        WHERE id = ?
    ''', (
        label_id,
    ))

    return cur_fetch()

def get_label_by_name(name):
    cur.execute('''
        SELECT *
        FROM label
        WHERE name = ?
    ''', (
        name,
    ))

    return cur_fetch()

def list_labels():
    cur.execute('''
        SELECT *
        FROM label
        ORDER BY name
    ''')

    return cur_fetchall()


###
### NAME
###

cur.execute('''
    CREATE TABLE IF NOT EXISTS name (
        id      INTEGER PRIMARY KEY,
        name    TEXT NOT NULL COLLATE NOCASE UNIQUE
    )
''')

cur.executemany('''
    INSERT OR IGNORE INTO name (
        id,
        name
    )
    VALUES (
        ?, ?
    )
''', [
    (NAME_REGISTER, 'registration'),
])

def get_name(name_id):
    cur.execute('''
        SELECT *
        FROM name
        WHERE id = ?
    ''', (
        name_id,
    ))

    return cur_fetch()

def list_names():
    cur.execute('''
        SELECT *
        FROM name
        ORDER BY name
    ''')

    return cur_fetchall()


###
### SIGNED
###

cur.execute('''
    CREATE TABLE IF NOT EXISTS signed (
        id          INTEGER PRIMARY KEY,
        label       INTEGER NOT NULL,
        name        INTEGER NOT NULL,
        key         TEXT NOT NULL,
        address     TEXT NOT NULL,
        signature   BLOB NOT NULL,
        version     INTEGER NOT NULL,

        FOREIGN KEY (label) REFERENCES label (id),
        FOREIGN KEY (name) REFERENCES name (id)
    )
''')

cur.execute('''
    CREATE INDEX IF NOT EXISTS signed_label_name_key ON signed (
        label,
        name,
        key
    )
''')

cur.execute('''
    CREATE INDEX IF NOT EXISTS signed_name_key ON signed (
        name,
        key
    )
''')

def insert_signed(label, name, key, address, signature, version):
    cur.execute('''
        INSERT INTO signed (
            label,
            name,
            key,
            address,
            signature,
            version
        )
        VALUES (
            ?, ?, ?, ?, ?, ?
        )
    ''', (
        label,
        name,
        key,
        address,
        signature,
        version
    ))

    return cur.lastrowid

def find_signed(label, name, limit=None):
    sql = '''
        SELECT *
        FROM signed
        WHERE label = ? AND name = ?
        ORDER BY id DESC
    '''

    if limit:
        sql += f'LIMIT {limit}'

    cur.execute(sql, (label, name))

    return cur_fetchall()



#print('db ready :-)')

