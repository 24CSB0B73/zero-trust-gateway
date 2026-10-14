-- Zero Trust Gateway schema (PostgreSQL 13+)
CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'employee' CHECK (role ~ '^[a-z_]{1,32}$'),
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS resources (
  id           BIGSERIAL PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  upstream_url TEXT NOT NULL,              -- internal service address, never exposed to clients
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One policy per resource. No policy row == deny.
CREATE TABLE IF NOT EXISTS policies (
  id                     BIGSERIAL PRIMARY KEY,
  resource_id            BIGINT NOT NULL UNIQUE REFERENCES resources(id) ON DELETE CASCADE,
  allowed_roles          TEXT[] NOT NULL,
  require_healthy_device BOOLEAN NOT NULL DEFAULT TRUE,
  max_posture_age_sec    INT NOT NULL DEFAULT 900 CHECK (max_posture_age_sec BETWEEN 30 AND 86400),
  active                 BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,             -- the JWT "jti"
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked    BOOLEAN NOT NULL DEFAULT FALSE,
  ip         TEXT
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);

-- Enrolled devices. The secret simulates a key provisioned to a trusted device agent / MDM.
CREATE TABLE IF NOT EXISTS devices (
  id         TEXT PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  secret     TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_status (
  device_id      TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  healthy        BOOLEAN NOT NULL,
  details        JSONB NOT NULL,
  last_report_ts BIGINT NOT NULL,          -- timestamp inside the signed report (replay protection)
  last_check     TIMESTAMPTZ NOT NULL
);

-- No foreign keys on purpose: audit rows must survive deletion of users/resources.
CREATE TABLE IF NOT EXISTS audit_logs (
  id          BIGSERIAL PRIMARY KEY,
  ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id     BIGINT,
  email       TEXT NOT NULL DEFAULT '',
  resource_id BIGINT,
  action      TEXT NOT NULL,
  decision    TEXT NOT NULL CHECK (decision IN ('allow','deny','error')),
  reason      TEXT NOT NULL,
  ip          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit_logs(ts DESC);
CREATE INDEX IF NOT EXISTS audit_decision_idx ON audit_logs(decision, id DESC);
