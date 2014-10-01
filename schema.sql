-- Websites table.
CREATE TABLE IF NOT EXISTS website (
  domain    TEXT PRIMARY KEY,
  url       TEXT NOT NULL,
  failed    BOOLEAN
);

-- Cookies table.
CREATE TABLE IF NOT EXISTS cookie (
  cookie_id   INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  name        TEXT                              NOT NULL,
  value       TEXT,
  domain      TEXT,
  path        TEXT,
  secure      BOOLEAN,
  expiry      INTEGER,
  httponly    BOOLEAN,
  js          BOOLEAN,
  website     TEXT NOT NULL,
  FOREIGN KEY (website) REFERENCES website (domain) ON DELETE CASCADE
);

-- Authentication token table
CREATE TABLE  IF NOT EXISTS token (
  token_id    INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  cardinality INTEGER
);

-- Junction table between cookie and token.
CREATE TABLE  IF NOT EXISTS cookie_token (
  cookie_id INTEGER,
  token_id  INTEGER,
  PRIMARY KEY (cookie_id, token_id),
  FOREIGN KEY (cookie_id) REFERENCES cookie (cookie_id) ON DELETE CASCADE,
  FOREIGN KEY (token_id) REFERENCES token (token_id) ON DELETE CASCADE
);
