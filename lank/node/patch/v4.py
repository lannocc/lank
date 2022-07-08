

NAME_PEER = 20

def patch(cur):
    cur.executemany('''
        INSERT INTO name (
            id,
            name
        )
        VALUES (
            ?, ?
        )
    ''', [
        (NAME_PEER, 'peer'),
    ])

