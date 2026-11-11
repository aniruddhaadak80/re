# Builds samples/webrt/fixture.sqlite with the python3 standard library sqlite3 module.
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
c = db.cursor()
c.execute("PRAGMA page_size=1024")
c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT, score REAL, avatar BLOB)")
c.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id), kind TEXT, payload TEXT)")
c.execute("CREATE INDEX idx_events_user ON events(user_id)")
c.execute("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID")
c.execute("CREATE VIEW active_users AS SELECT id, name FROM users WHERE score > 50")
users = [(i, f"user{i}", f"user{i}@example.com" if i % 3 else None, i * 1.5, bytes([i % 256, 0xAB]) if i % 5 == 0 else None) for i in range(1, 301)]
c.executemany("INSERT INTO users VALUES (?,?,?,?,?)", users)
long = "x" * 5000  # forces overflow pages
events = [(None, (i % 300) + 1, ["login", "logout", "purchase"][i % 3], long if i == 7 else '{"n":%d}' % i) for i in range(1000)]
c.executemany("INSERT INTO events VALUES (?,?,?,?)", events)
c.executemany("INSERT INTO kv VALUES (?,?)", [("theme", "dark"), ("lang", "bn"), ("version", "1.0.0")])
db.commit()
db.close()
