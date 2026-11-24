-- Schema PostgreSQL initial pour CongoConnect
-- Tables : service_providers, issued_tokens, audit_logs

CREATE TABLE IF NOT EXISTS service_providers (
  id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(160) NOT NULL,
  category VARCHAR(64) NOT NULL,
  city VARCHAR(100) NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_service_providers_category ON service_providers (category);

CREATE TABLE IF NOT EXISTS issued_tokens (
  jti UUID PRIMARY KEY,
  subject_hash VARCHAR(64) NOT NULL,
  scope VARCHAR(120) NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_issued_tokens_expires_at ON issued_tokens (expires_at);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  event_type VARCHAR(64) NOT NULL,
  identifier_masked VARCHAR(64) NOT NULL,
  outcome VARCHAR(32) NOT NULL,
  details TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_event_time ON audit_logs (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs (event_type);

-- Donnees initiales des fournisseurs
INSERT INTO service_providers (id, name, category, city, active) VALUES
  ('etat-civil-sim', 'Guichet Identite Simule', 'identite', 'Brazzaville', TRUE),
  ('mobile-money-sim', 'Passerelle Paiement Simulee', 'paiement', 'Pointe-Noire', TRUE)
ON CONFLICT (id) DO NOTHING;
