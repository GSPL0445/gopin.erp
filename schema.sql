-- Gopin Semicon ERP — database schema (PostgreSQL 14+)
-- Safe to run many times: every statement is IF NOT EXISTS.

-- People who can sign in
CREATE TABLE IF NOT EXISTS users (
  id             TEXT PRIMARY KEY,
  email          TEXT NOT NULL,
  name           TEXT NOT NULL,
  password_hash  TEXT NOT NULL,
  role           TEXT NOT NULL DEFAULT 'Viewer',
  active         BOOLEAN NOT NULL DEFAULT TRUE,
  token_version  INTEGER NOT NULL DEFAULT 0,      -- bumped to sign a user out everywhere
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower ON users (lower(email));

-- Every ERP record (item, supplier, PO, GRN, ledger entry, …) is one JSON document.
-- collection = which master / transaction it belongs to, id = its code or number.
CREATE TABLE IF NOT EXISTS docs (
  collection  TEXT NOT NULL,
  id          TEXT NOT NULL,
  data        JSONB NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by  TEXT,
  PRIMARY KEY (collection, id)
);
CREATE INDEX IF NOT EXISTS docs_updated ON docs (updated_at DESC);

-- Server-side audit trail of every save and delete
CREATE TABLE IF NOT EXISTS audit (
  id          BIGSERIAL PRIMARY KEY,
  at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id     TEXT,
  user_name   TEXT,          -- name at the moment of the change
  collection  TEXT NOT NULL,
  doc_id      TEXT NOT NULL,
  action      TEXT NOT NULL,          -- save | delete
  data        JSONB
);
CREATE INDEX IF NOT EXISTS audit_doc ON audit (collection, doc_id, at DESC);
