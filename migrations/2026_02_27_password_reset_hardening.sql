-- Password reset hardening migration
-- Adds indexes used by rate-limiting and monitoring queries.

SET @db := DATABASE();

SET @idx_exists := (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = @db
      AND table_name = 'password_reset_tokens'
      AND index_name = 'idx_created_at'
);
SET @sql := IF(@idx_exists = 0,
    'CREATE INDEX idx_created_at ON password_reset_tokens (created_at)',
    'SELECT "idx_created_at already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @idx_exists := (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = @db
      AND table_name = 'password_reset_tokens'
      AND index_name = 'idx_ip_created_at'
);
SET @sql := IF(@idx_exists = 0,
    'CREATE INDEX idx_ip_created_at ON password_reset_tokens (ip_address, created_at)',
    'SELECT "idx_ip_created_at already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @idx_exists := (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = @db
      AND table_name = 'password_reset_tokens'
      AND index_name = 'idx_user_created_at'
);
SET @sql := IF(@idx_exists = 0,
    'CREATE INDEX idx_user_created_at ON password_reset_tokens (user_id, created_at)',
    'SELECT "idx_user_created_at already exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
