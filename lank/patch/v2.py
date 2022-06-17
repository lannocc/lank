

NAME_REGISTER = 10


def patch(cur):
    cur.execute('''
        CREATE TABLE label (
            id      INTEGER PRIMARY KEY,
            name    TEXT NOT NULL COLLATE NOCASE UNIQUE
        )
    ''')

    cur.execute('''
        CREATE TABLE name (
            id      INTEGER PRIMARY KEY,
            name    TEXT NOT NULL COLLATE NOCASE UNIQUE
        )
    ''')

    cur.executemany('''
        INSERT INTO name (
            id,
            name
        )
        VALUES (
            ?, ?
        )
    ''', [
        (NAME_REGISTER, 'registration'),
    ])

    cur.execute('''
        CREATE TABLE signed (
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
        CREATE INDEX signed_label_name_key ON signed (
            label,
            name,
            key
        )
    ''')

    cur.execute('''
        CREATE INDEX signed_name_key ON signed (
            name,
            key
        )
    ''')

