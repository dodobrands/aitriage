package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  email         TEXT,
  full_name     TEXT,
  password_hash TEXT NOT NULL,
  global_role   TEXT NOT NULL DEFAULT 'viewer',
  is_active     INTEGER NOT NULL DEFAULT 1,
  avatar_url    TEXT,
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login    DATETIME
);

CREATE TABLE IF NOT EXISTS product_types (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT UNIQUE NOT NULL,
  description TEXT,
  created_by  INTEGER REFERENCES users(id),
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  product_type_id INTEGER REFERENCES product_types(id),
  name            TEXT NOT NULL,
  description     TEXT,
  repo_url        TEXT,
  lifecycle       TEXT DEFAULT 'production',
  origin          TEXT DEFAULT 'internal',
  business_criticality TEXT DEFAULT 'high',
  platform        TEXT,
  tech_stack      TEXT,
  sla_critical    INTEGER DEFAULT 1,
  sla_high        INTEGER DEFAULT 7,
  sla_medium      INTEGER DEFAULT 30,
  sla_low         INTEGER DEFAULT 90,
  created_by      INTEGER REFERENCES users(id),
  created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS system_config (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  config_key  TEXT UNIQUE NOT NULL,
  config_val  TEXT NOT NULL,
  updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS product_members (
  product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  role       TEXT NOT NULL DEFAULT 'viewer',
  PRIMARY KEY (product_id, user_id)
);

CREATE TABLE IF NOT EXISTS engagements (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id    INTEGER REFERENCES products(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  description   TEXT,
  scan_path     TEXT,
  engagement_type TEXT DEFAULT 'ci_cd',
  status        TEXT DEFAULT 'in_progress',
  started_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at  DATETIME,
  target_start  DATETIME,
  target_end    DATETIME,
  triggered_by  INTEGER REFERENCES users(id),
  build_id      TEXT,
  branch        TEXT,
  commit_hash   TEXT,
  scanner_version TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id   INTEGER REFERENCES engagements(id) ON DELETE CASCADE,
  product_id      INTEGER REFERENCES products(id),
  rule_id         TEXT NOT NULL,
  title           TEXT NOT NULL,
  severity        TEXT NOT NULL,
  cvss_score      REAL,
  cve_id          TEXT,
  cwe_id          TEXT,
  file_path       TEXT,
  line_number     INTEGER,
  col_number      INTEGER,
  code_snippet    TEXT,
  description     TEXT,
  impact          TEXT,
  fix_suggestion  TEXT,
  references_     TEXT,
  hash_code       TEXT,
  is_duplicate    INTEGER DEFAULT 0,
  duplicate_of    INTEGER REFERENCES findings(id),
  status          TEXT NOT NULL DEFAULT 'open',
  kanban_column   TEXT DEFAULT 'backlog',
  sla_deadline    DATETIME,
  sla_breached    INTEGER DEFAULT 0,
  risk_accepted         INTEGER DEFAULT 0,
  risk_accepted_by      INTEGER REFERENCES users(id),
  risk_accepted_reason  TEXT,
  risk_accepted_expiry  DATETIME,
  assigned_to     INTEGER REFERENCES users(id),
  is_verified     INTEGER DEFAULT 0,
  verified_by     INTEGER REFERENCES users(id),
  verified_at     DATETIME,
  created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
  resolved_at     DATETIME,
  resolved_by     INTEGER REFERENCES users(id),
  is_false_positive INTEGER DEFAULT 0,
  fp_reason         TEXT,
  stack             TEXT,
  ai_triage_status  TEXT,
  ai_triage_summary TEXT,
  agent_prompt      TEXT,
  agent_prompt_generated_at DATETIME,
  verification_status TEXT,
  verification_summary TEXT,
  verification_last_run_at DATETIME,
  verification_last_success_at DATETIME
);

CREATE TABLE IF NOT EXISTS finding_notes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
  author_id  INTEGER REFERENCES users(id),
  content    TEXT NOT NULL,
  note_type  TEXT DEFAULT 'comment',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER REFERENCES users(id),
  username    TEXT,
  action      TEXT NOT NULL,
  entity_type TEXT,
  entity_id   INTEGER,
  old_value   TEXT,
  new_value   TEXT,
  ip_address  TEXT,
  user_agent  TEXT,
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT NOT NULL,
  body       TEXT,
  type       TEXT DEFAULT 'info',
  is_read    INTEGER DEFAULT 0,
  link       TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  prefix      TEXT NOT NULL,
  key_hash    TEXT NOT NULL,
  status      TEXT DEFAULT 'ACTIVE',
  created_by  INTEGER REFERENCES users(id),
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_used   DATETIME
);

CREATE TABLE IF NOT EXISTS topology_nodes (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  type        TEXT NOT NULL,
  status      TEXT DEFAULT 'HEALTHY',
  risk        TEXT DEFAULT 'LOW',
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS topology_links (
  source TEXT REFERENCES topology_nodes(id) ON DELETE CASCADE,
  target TEXT REFERENCES topology_nodes(id) ON DELETE CASCADE,
  PRIMARY KEY (source, target)
);

CREATE TABLE IF NOT EXISTS reports (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
  target_scope TEXT NOT NULL,
  format       TEXT NOT NULL,
  status       TEXT NOT NULL,
  download_url TEXT,
  triggered_by INTEGER REFERENCES users(id),
  product_id   INTEGER REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS chat_sessions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT NOT NULL DEFAULT 'New Chat',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chat_messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER REFERENCES chat_sessions(id) ON DELETE CASCADE,
  role       TEXT NOT NULL,
  content    TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ignored_findings (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  vuln_id             TEXT NOT NULL UNIQUE,
  rule_id             TEXT NOT NULL,
  file_path           TEXT NOT NULL,
  line_number         INTEGER DEFAULT 0,
  code_snippet        TEXT,
  content_hash        TEXT NOT NULL,
  vulnerability_class TEXT,
  reason              TEXT NOT NULL DEFAULT 'False Positive',
  created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_by          TEXT
);
CREATE INDEX IF NOT EXISTS idx_ignored_findings_hash ON ignored_findings(content_hash);
CREATE INDEX IF NOT EXISTS idx_ignored_findings_rule ON ignored_findings(rule_id);

CREATE TABLE IF NOT EXISTS runway_sessions (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id          INTEGER REFERENCES products(id) ON DELETE CASCADE,
  status              TEXT NOT NULL DEFAULT 'in_progress',
  current_step        INTEGER NOT NULL DEFAULT 0,
  progress_message    TEXT,
  auto_mode           INTEGER DEFAULT 0,
  threat_model        TEXT,
  security_plan       TEXT,
  remediation         TEXT,
  poc                 TEXT,
  audit_report        TEXT,
  scan_count_before   INTEGER DEFAULT 0,
  scan_count_after    INTEGER DEFAULT 0,
  error_message       TEXT,
  created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS runway_artifacts (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id          INTEGER NOT NULL REFERENCES runway_sessions(id) ON DELETE CASCADE,
  kind                TEXT NOT NULL,
  media_type          TEXT NOT NULL,
  schema_version      INTEGER NOT NULL DEFAULT 1,
  content             TEXT NOT NULL,
  sha256              TEXT NOT NULL,
  created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(session_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_runway_artifacts_session ON runway_artifacts(session_id);

CREATE TABLE IF NOT EXISTS ai_summaries (
  product_id    INTEGER NOT NULL,
  lang          TEXT NOT NULL,
  summary       TEXT NOT NULL,
  generated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (product_id, lang)
);

`

func InitDB(dbPath string) (*sql.DB, error) {
	// Enable WAL mode via DSN options
	// PRAGMA foreign_keys=ON is also set below explicitly to be safe
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// 1. Create tables
	if err := RunMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}
	if dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:") {
		if err := os.Chmod(dbPath, 0o600); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("secure database file: %w", err)
		}
	}

	// 2. Add stack column to findings if it doesn't exist (Migration)
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN stack TEXT")
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN ai_triage_status TEXT")
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN ai_triage_summary TEXT")
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN agent_prompt TEXT")
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN agent_prompt_generated_at DATETIME")
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN verification_status TEXT")
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN verification_summary TEXT")
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN verification_last_run_at DATETIME")
	if err := migrateVerificationFreshness(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate verification freshness: %w", err)
	}
	_, _ = db.Exec("ALTER TABLE runway_sessions ADD COLUMN progress_message TEXT")

	// 2b. Patch old engine_llm_model to gemini-2.5-flash
	_, _ = db.Exec("UPDATE system_config SET config_val = 'gemini-2.5-flash' WHERE config_key = 'engine_llm_model' AND config_val = 'gemini-2.0-flash'")

	legacyUsersPath := ""
	if dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:") {
		legacyUsersPath = filepath.Join(filepath.Dir(dbPath), "users.json")
	}
	if err := migrateUsersJSON(db, legacyUsersPath); err != nil {
		log.Printf("Warning: failed to migrate users.json: %v\n", err)
	}

	if err := SeedDefaultData(db); err != nil {
		return nil, fmt.Errorf("failed to seed default data: %w", err)
	}

	return db, nil
}

func RunMigrations(db *sql.DB) error {
	_, err := db.Exec(schema)
	return err
}

func migrateVerificationFreshness(db *sql.DB) error {
	var exists int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('findings') WHERE name = 'verification_last_success_at'").Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		if _, err := db.Exec("ALTER TABLE findings ADD COLUMN verification_last_success_at DATETIME"); err != nil {
			return err
		}
	}
	_, err := db.Exec("UPDATE findings SET verification_last_success_at = verification_last_run_at WHERE verification_last_success_at IS NULL AND verification_status IN ('fixed', 'not_fixed')")
	return err
}

func SeedDefaultData(db *sql.DB) error {
	var count int
	err := db.QueryRow("SELECT count(*) FROM users").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		_, err = db.Exec(`
			INSERT INTO users (username, password_hash, global_role)
			VALUES (?, ?, ?)
		`, "admin", string(hash), "superadmin")
		if err != nil {
			return err
		}
	}

	// Seed default config
	defaultConfigs := map[string]string{
		"engine_llm_provider": "gemini",
		"engine_llm_model":    "gemini-2.5-flash",
		"engine_concurrency":  "5",
		"engine_scan_depth":   "thorough",
		"sla_critical":        "1",
		"sla_high":            "7",
		"sla_medium":          "30",
		"sla_low":             "90",
		"enterprise_name":     "AITriage Enterprise",
		"enterprise_support":  "security@dodobrands.io",
	}

	for k, v := range defaultConfigs {
		_, err = db.Exec(`
			INSERT INTO system_config (config_key, config_val)
			VALUES (?, ?)
			ON CONFLICT(config_key) DO NOTHING
		`, k, v)
		if err != nil {
			return err
		}
	}

	// No fake seed data — topology and reports are populated by real scans only

	return nil
}

type oldUser struct {
	Username string `json:"username"`
	Password string `json:"password"` // Hashed
	IsAdmin  bool   `json:"is_admin"`
}

func migrateUsersJSON(db *sql.DB, usersFile string) error {
	if usersFile == "" {
		return nil
	}
	migratedFile := usersFile + ".migrated"

	data, err := os.ReadFile(usersFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Nothing to migrate
		}
		return err
	}

	var oldUsers []oldUser
	if err := json.Unmarshal(data, &oldUsers); err != nil {
		return fmt.Errorf("failed to parse users.json: %w", err)
	}

	for _, ou := range oldUsers {
		var role string
		if ou.IsAdmin {
			role = "superadmin"
		} else {
			role = "viewer"
		}

		_, err := db.Exec(`
			INSERT INTO users (username, password_hash, global_role)
			VALUES (?, ?, ?)
			ON CONFLICT(username) DO UPDATE SET
				global_role=excluded.global_role
		`, ou.Username, ou.Password, role)
		if err != nil {
			return fmt.Errorf("failed to insert user %s: %w", ou.Username, err)
		}
	}

	// Rename file after successful migration
	return os.Rename(usersFile, migratedFile)
}
