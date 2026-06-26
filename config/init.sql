-- MCP Sample: Policy database schema
-- These tables are auto-created by PolicyStore.ensure_tables() and
-- PolicyDbOAuthStore.ensure_table() at startup. This file is provided
-- as reference documentation and for manual DB provisioning.

CREATE TABLE IF NOT EXISTS users (
    github_login    VARCHAR(255) NOT NULL PRIMARY KEY,
    role            ENUM('admin', 'useradmin', 'user') NOT NULL DEFAULT 'user',
    email           VARCHAR(320) NULL,
    password_hash   VARCHAR(255) NULL,
    mfa_enabled     TINYINT NOT NULL DEFAULT 0,
    mfa_secret_enc  TEXT NULL,
    mfa_setup_expires_at DATETIME NULL,
    mfa_backup_generated_at DATETIME NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by      VARCHAR(255) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_backup_codes (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    github_login    VARCHAR(255) NOT NULL,
    code_hash       CHAR(64) NOT NULL,
    used_at         DATETIME NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_backup_user_hash (github_login, code_hash),
    FOREIGN KEY (github_login) REFERENCES users(github_login) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS api_tokens (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    github_login    VARCHAR(255) NOT NULL,
    token_hash      CHAR(64) NOT NULL,
    token_prefix    CHAR(8) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by      VARCHAR(255) NOT NULL,
    last_used_at    DATETIME NULL,
    expires_at      DATETIME NULL,
    revoked         TINYINT NOT NULL DEFAULT 0,
    auto_rotate     TINYINT NOT NULL DEFAULT 0,
    rotation_days   INT NULL,
    UNIQUE INDEX idx_token_hash (token_hash),
    INDEX idx_token_user (github_login),
    INDEX idx_token_auto_rotate (auto_rotate, revoked, expires_at),
    FOREIGN KEY (github_login) REFERENCES users(github_login) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS policy_settings (
    setting_key   VARCHAR(64) NOT NULL PRIMARY KEY,
    setting_value VARCHAR(255) NOT NULL,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by    VARCHAR(255) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor           VARCHAR(255) NOT NULL,
    action          VARCHAR(100) NOT NULL,
    target          VARCHAR(255),
    detail          JSON,
    INDEX idx_audit_timestamp (timestamp DESC),
    INDEX idx_audit_actor (actor)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS oauth_kv (
    kv_key      VARCHAR(512) NOT NULL PRIMARY KEY,
    kv_value    MEDIUMTEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_oauth_kv_updated (updated_at)
) ENGINE=InnoDB;
