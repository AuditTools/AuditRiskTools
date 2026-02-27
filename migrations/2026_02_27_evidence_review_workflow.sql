-- ====================================================
-- MIGRATION: Evidence Review Workflow
-- Date: 2026-02-27
-- Description:
--   Adds evidence review columns to audit_evidence table
--   to support proper GRC Segregation of Duties:
--   - Auditee uploads evidence
--   - Auditor reviews (Accept / Reject / Needs Revision)
-- ====================================================

-- Add evidence review columns (safe: checks column existence first)
-- Using stored procedure for safe ALTER

DELIMITER //
DROP PROCEDURE IF EXISTS add_evidence_review_columns//
CREATE PROCEDURE add_evidence_review_columns()
BEGIN
    -- evidence_status
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_evidence' AND COLUMN_NAME = 'evidence_status') THEN
        ALTER TABLE audit_evidence ADD COLUMN evidence_status ENUM('Pending Review','Accepted','Rejected','Needs Revision') DEFAULT 'Pending Review' AFTER description;
    END IF;

    -- reviewed_by
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_evidence' AND COLUMN_NAME = 'reviewed_by') THEN
        ALTER TABLE audit_evidence ADD COLUMN reviewed_by INT NULL AFTER evidence_status;
    END IF;

    -- reviewed_at
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_evidence' AND COLUMN_NAME = 'reviewed_at') THEN
        ALTER TABLE audit_evidence ADD COLUMN reviewed_at TIMESTAMP NULL AFTER reviewed_by;
    END IF;

    -- review_notes
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_evidence' AND COLUMN_NAME = 'review_notes') THEN
        ALTER TABLE audit_evidence ADD COLUMN review_notes TEXT NULL AFTER reviewed_at;
    END IF;

    -- uploaded_by (ensure it exists)
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_evidence' AND COLUMN_NAME = 'uploaded_by') THEN
        ALTER TABLE audit_evidence ADD COLUMN uploaded_by INT NULL AFTER review_notes;
    END IF;
END//
DELIMITER ;

CALL add_evidence_review_columns();
DROP PROCEDURE IF EXISTS add_evidence_review_columns;
