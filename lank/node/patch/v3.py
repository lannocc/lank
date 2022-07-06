

def patch(cur):
    print('!!! WARNING -- PROCEED WITH CAUTION !!!')
    print('    This patch will delete any and all existing signed entries.')
    print('    Hit <ENTER> to continue...')
    input()

    cur.execute('DROP TABLE signed')

    cur.execute('''
        CREATE TABLE signed (
            id          INTEGER PRIMARY KEY,
            uuid        TEXT NOT NULL UNIQUE,
            label       INTEGER NOT NULL,
            name        INTEGER NOT NULL,
            key         TEXT NOT NULL,
            address     TEXT NOT NULL,
            signature   BLOB NOT NULL,
            version     INTEGER NOT NULL,
            node_uuid   TEXT NOT NULL,
            created     TIMESTAMP NOT NULL,

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

    cur.execute('''
        CREATE INDEX signed_created ON signed (
            created
        )
    ''')

