-- Enable UUID support
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =========================
-- USERS (core identity)
-- =========================
CREATE TABLE users (
                       id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                       email           VARCHAR(255) NOT NULL UNIQUE,
                       role            VARCHAR(50)  NOT NULL,        -- USER / RECRUITER
                       auth_provider   VARCHAR(50)  NOT NULL,        -- LOCAL / GOOGLE
                       account_status  VARCHAR(50)  NOT NULL DEFAULT 'ACTIVE',
                       created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                       updated_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- =========================
-- CREDENTIALS (email/password)
-- =========================
CREATE TABLE credentials (
                             user_id         UUID PRIMARY KEY,
                             password_hash   TEXT NOT NULL,
                             created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

                             CONSTRAINT fk_credentials_user
                                 FOREIGN KEY (user_id)
                                     REFERENCES users(id)
                                     ON DELETE CASCADE
);

-- =========================
-- OAUTH ACCOUNTS
-- =========================
CREATE TABLE oauth_accounts (
                                id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                user_id             UUID NOT NULL,
                                provider            VARCHAR(50) NOT NULL,     -- GOOGLE
                                provider_user_id    VARCHAR(255) NOT NULL,
                                created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

                                CONSTRAINT uq_oauth_provider UNIQUE (provider, provider_user_id),
                                CONSTRAINT fk_oauth_user
                                    FOREIGN KEY (user_id)
                                        REFERENCES users(id)
                                        ON DELETE CASCADE
);

-- =========================
-- REFRESH TOKENS
-- =========================
CREATE TABLE refresh_tokens (
                                id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                user_id         UUID NOT NULL,
                                expires_at      TIMESTAMP NOT NULL,
                                revoked         BOOLEAN NOT NULL DEFAULT FALSE,
                                created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

                                CONSTRAINT fk_refresh_user
                                    FOREIGN KEY (user_id)
                                        REFERENCES users(id)
                                        ON DELETE CASCADE
);

-- =========================
-- INDEXES (performance)
-- =========================
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
