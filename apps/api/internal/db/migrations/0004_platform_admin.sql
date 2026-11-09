ALTER TABLE users ADD COLUMN is_platform_admin BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX users_platform_admin_idx ON users (is_platform_admin) WHERE is_platform_admin;
