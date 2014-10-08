-- Websites table.
CREATE TABLE website (
  domain    TEXT PRIMARY KEY,
  url       TEXT NOT NULL,
  failed    BOOLEAN
);

-- Cookies table.
CREATE TABLE cookie (
  id       INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  name     TEXT                              NOT NULL,
  value    TEXT,
  domain   TEXT,
  path     TEXT,
  secure   BOOLEAN,
  expiry   INTEGER,
  website  TEXT NOT NULL,
  FOREIGN KEY (website) REFERENCES website (domain) ON DELETE CASCADE
);

-- Authentication token table
CREATE TABLE token (
  id          INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  cardinality INTEGER
);

-- Junction table between cookie and token.
CREATE TABLE cookie_token (
  cookie_id INTEGER,
  token_id  INTEGER,
  PRIMARY KEY (cookie_id, token_id),
  FOREIGN KEY (cookie_id) REFERENCES cookie (id) ON DELETE CASCADE,
  FOREIGN KEY (token_id) REFERENCES token (id) ON DELETE CASCADE
);