-- ====================================================
-- SRM-AUDIT DATABASE SCHEMA
-- Web-Based Cybersecurity GRC & Risk Management System
-- ====================================================
-- Version: 1.0
-- Date: 2026-02-22
-- ====================================================

-- Create Database
CREATE DATABASE IF NOT EXISTS audit;
USE audit;

-- ====================================================
-- 1️⃣ USERS TABLE
-- ====================================================
-- Stores auditor user accounts
-- Each user can manage multiple organizations
-- ====================================================
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    
    -- Account status and security
    is_active TINYINT(1) DEFAULT 1,
    failed_login_attempts INT DEFAULT 0,
    last_login TIMESTAMP NULL,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_email (email),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================
-- 2️⃣ PASSWORD RESET TOKENS TABLE
-- ====================================================
-- Manages forgot password functionality
-- Tokens expire after specified time (e.g., 1 hour)
-- ====================================================
CREATE TABLE password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    
    -- Token expiration
    expires_at TIMESTAMP NOT NULL,
    used TINYINT(1) DEFAULT 0,
    
    -- Request tracking
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_expires (expires_at),
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================
-- 3️⃣ ORGANIZATIONS TABLE
-- ====================================================
-- Stores organizations under audit
-- Industry stored here (stable characteristic)
-- One user can register multiple organizations
-- ====================================================
CREATE TABLE organizations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    
    organization_name VARCHAR(150) NOT NULL,
    industry ENUM('Finance','Healthcare','Education','Retail','Technology','Government','Manufacturing','Other') NOT NULL,
    
    -- Optional organization details
    contact_person VARCHAR(100),
    contact_email VARCHAR(150),
    contact_phone VARCHAR(20),
    address TEXT,
    number_of_employees INT,
    system_type VARCHAR(50),
    
    -- Status
    is_active TINYINT(1) DEFAULT 1,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================
-- 4️⃣ AUDIT SESSIONS TABLE
-- ====================================================
-- Represents periodic audit cycles
-- One organization → many audit sessions over time
-- Digital scale stored per session (can change)
-- ====================================================
CREATE TABLE audit_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    organization_id INT NOT NULL,
    
    -- Session details
    session_name VARCHAR(150),
    digital_scale ENUM('Low','Medium','High') NOT NULL,
    audit_date DATE NOT NULL,
    
    -- Calculated exposure metrics
    exposure_score DECIMAL(5,2),
    exposure_level ENUM('Low','Medium','High'),
    
    -- Aggregated risk metrics
    avg_asset_criticality DECIMAL(5,2),
    avg_risk_score DECIMAL(6,2),
    final_risk_score DECIMAL(6,2),
    final_risk_level ENUM('Low','Medium','High','Critical'),
    
    -- Compliance metrics
    compliance_percentage DECIMAL(5,2),
    nist_maturity_level ENUM('Initial','Developing','Managed','Optimized'),
    
    -- Session status
    status ENUM('Planning','In Progress','Review','Completed','Archived') DEFAULT 'Planning',
    
    -- Audit notes
    notes TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    INDEX idx_organization_id (organization_id),
    INDEX idx_audit_date (audit_date),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================
-- 5️⃣ ASSETS TABLE
-- ====================================================
-- Asset inventory per audit session
-- CIA ratings determine criticality
-- Assets can change between audit cycles
-- ====================================================
CREATE TABLE assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    audit_id INT NOT NULL,
    
    -- Asset identification
    asset_name VARCHAR(150) NOT NULL,
    ip_address VARCHAR(100),
    asset_type VARCHAR(100),
    description TEXT,
    
    -- CIA Triad ratings (1-5)
    confidentiality INT NOT NULL CHECK (confidentiality BETWEEN 1 AND 5),
    integrity INT NOT NULL CHECK (integrity BETWEEN 1 AND 5),
    availability INT NOT NULL CHECK (availability BETWEEN 1 AND 5),
    
    -- Calculated criticality
    criticality_score DECIMAL(4,2),
    criticality_level ENUM('Low','Medium','High','Critical'),
    
    -- Asset owner
    owner VARCHAR(100),
    department VARCHAR(100),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (audit_id) REFERENCES audit_sessions(id) ON DELETE CASCADE,
    INDEX idx_audit_id (audit_id),
    INDEX idx_criticality_level (criticality_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================
-- 6️⃣ FINDINGS TABLE
-- ====================================================
-- Vulnerability findings per audit session
-- Mapped to NIST CSF functions
-- Risk calculated from Likelihood × Impact
-- ====================================================
CREATE TABLE findings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    audit_id INT NOT NULL,
    asset_id INT NOT NULL,
    
    -- Finding details
    title VARCHAR(150) NOT NULL,
    description TEXT,
    
    -- Risk classification
    owasp_category VARCHAR(100),
    cwe_id VARCHAR(50),
    
    -- Risk scoring (1-5)
    likelihood INT NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
    impact INT NOT NULL CHECK (impact BETWEEN 1 AND 5),
    risk_score INT,
    risk_level ENUM('Low','Medium','High','Critical'),
    
    -- NIST CSF mapping
    nist_function ENUM('Identify','Protect','Detect','Respond','Recover') NOT NULL,
    
    -- Compliance status
    audit_status ENUM('Compliant','Partially Compliant','Non-Compliant') NOT NULL,
    
    -- Evidence and recommendations
    evidence_path VARCHAR(255),
    auditor_notes TEXT,
    recommendation TEXT,
    
    -- Remediation tracking
    remediation_status ENUM('Open','In Progress','Resolved','Accepted Risk') DEFAULT 'Open',
    remediation_deadline DATE,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (audit_id) REFERENCES audit_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    INDEX idx_audit_id (audit_id),
    INDEX idx_asset_id (asset_id),
    INDEX idx_risk_level (risk_level),
    INDEX idx_nist_function (nist_function),
    INDEX idx_audit_status (audit_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================
-- 7️⃣ AI REPORTS TABLE
-- ====================================================
-- Stores AI-generated audit reports
-- AI acts as narrative support only
-- ====================================================
CREATE TABLE ai_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    audit_session_id INT NOT NULL,
    
    -- Report type and content
    report_type ENUM('executive_summary', 'full_report', 'custom') DEFAULT 'executive_summary',
    report_content LONGTEXT NOT NULL,
    
    -- AI metadata
    tokens_used INT DEFAULT 0,
    model_used VARCHAR(50),
    generation_time_seconds DECIMAL(5,2),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (audit_session_id) REFERENCES audit_sessions(id) ON DELETE CASCADE,
    INDEX idx_audit_session_id (audit_session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================
-- 8️⃣ CHATBOT HISTORY TABLE
-- ====================================================
-- Stores educational Q&A interactions
-- For analytics and user support
-- ====================================================
CREATE TABLE chatbot_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    
    -- Conversation data
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    
    -- AI metadata
    tokens_used INT DEFAULT 0,
    model_used VARCHAR(50),
    
    -- Session tracking
    session_id VARCHAR(100),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at),
    INDEX idx_session_id (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================
-- 9️⃣ AUDIT LOGS TABLE (OPTIONAL - RECOMMENDED)
-- ====================================================
-- Tracks user actions for compliance and security
-- ====================================================
CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    
    action VARCHAR(100) NOT NULL,
    table_name VARCHAR(50),
    record_id INT,
    
    old_values TEXT,
    new_values TEXT,
    
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================
-- DATABASE SCHEMA ANALYSIS
-- ====================================================

/*
✅ NORMALIZATION ANALYSIS:
--------------------------
The database schema follows 3NF (Third Normal Form):

1️⃣ 1NF (First Normal Form):
   ✓ All columns contain atomic values
   ✓ No repeating groups
   ✓ Each table has a primary key

2️⃣ 2NF (Second Normal Form):
   ✓ All non-key attributes fully dependent on primary key
   ✓ No partial dependencies

3️⃣ 3NF (Third Normal Form):
   ✓ No transitive dependencies
   ✓ Calculated fields (risk_score, criticality_score) are stored
     for performance but can be recalculated from source data

✅ DESIGN DECISIONS:
--------------------
1. Industry in organizations table:
   - Rationale: Industry is a stable characteristic
   - Impact: Reduces redundancy across audit sessions

2. Digital_scale in audit_sessions table:
   - Rationale: Digital maturity can change over time
   - Impact: Allows tracking organization evolution

3. Calculated fields (exposure_score, risk_score, etc.):
   - Rationale: Performance optimization
   - Trade-off: Slight denormalization for query speed
   - Mitigation: Update triggers or application logic ensures consistency

4. Separate assets per audit session:
   - Rationale: Asset inventory changes over time
   - Impact: Accurate historical tracking

✅ FORGOT PASSWORD SYSTEM:
--------------------------
password_reset_tokens table includes:
- Unique token per reset request
- Expiration timestamp (recommend 1 hour)
- Used flag to prevent token reuse
- IP and user agent for security tracking
- Automatic cleanup via DELETE CASCADE

Security recommendations:
- Store hashed tokens (SHA-256)
- Implement rate limiting (max 3 requests/hour)
- Clean up expired tokens regularly
- Log all reset attempts

✅ INDEXES:
-----------
Strategic indexes added for:
- Foreign keys (JOIN performance)
- Frequently filtered columns (WHERE clauses)
- Sorting columns (ORDER BY)
- Unique constraints (email, token)

✅ SECURITY FEATURES:
---------------------
1. CASCADE DELETE: Maintains referential integrity
2. ENUM types: Prevents invalid data
3. CHECK constraints: Validates numeric ranges
4. UTF8MB4: Supports international characters
5. Audit logs: Tracks all system changes

✅ SCALABILITY CONSIDERATIONS:
------------------------------
1. INT AUTO_INCREMENT: Supports millions of records
2. Indexed foreign keys: Fast JOIN operations
3. Timestamp tracking: Enables time-series analysis
4. Soft delete option via is_active flags

✅ POTENTIAL IMPROVEMENTS:
--------------------------
1. Add document/attachment table for multiple evidence files
2. Implement user roles (Admin, Auditor, Viewer)
3. Add organization hierarchy (parent-child relationships)
4. Create materialized views for dashboard metrics
5. Implement archival strategy for old audit sessions
*/

-- ====================================================
-- 10️⃣ CONTROL CHECKLIST TABLE
-- ====================================================
-- Stores NIST CSF control audit results per audit session
-- Auditor marks each control as Compliant / Partially / Non-Compliant / N/A
-- ====================================================
CREATE TABLE IF NOT EXISTS control_checklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    audit_id INT NOT NULL,
    control_id VARCHAR(20) NOT NULL,

    -- Compliance status
    status ENUM('Not Assessed','Compliant','Partially Compliant','Non-Compliant','Not Applicable')
        DEFAULT 'Not Assessed',

    -- Auditor notes / evidence description
    notes TEXT NULL,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (audit_id) REFERENCES audit_sessions(id) ON DELETE CASCADE,
    UNIQUE KEY uq_audit_control (audit_id, control_id),
    INDEX idx_audit_id (audit_id),
    INDEX idx_control_status (audit_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================
-- INITIAL DATA (OPTIONAL)
-- ====================================================



-- ====================================================
-- MAINTENANCE QUERIES
-- ====================================================

-- Clean up expired password reset tokens (run periodically)
-- DELETE FROM password_reset_tokens WHERE expires_at < NOW() OR used = 1;

-- Archive old audit sessions (run annually)
-- UPDATE audit_sessions SET status = 'Archived' WHERE audit_date < DATE_SUB(NOW(), INTERVAL 2 YEAR);

-- Database statistics
-- SELECT 
--     TABLE_NAME, 
--     TABLE_ROWS, 
--     ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS 'Size (MB)'
-- FROM information_schema.TABLES 
-- WHERE TABLE_SCHEMA = 'srm_audit';
