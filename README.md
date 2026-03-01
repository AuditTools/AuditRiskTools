# SRM-Audit

**Web-Based Cybersecurity GRC & Risk Management System**

A comprehensive Governance, Risk, and Compliance (GRC) platform for conducting cybersecurity audits based on the **NIST Cybersecurity Framework (CSF)** and **OWASP Top 10**. Supports full audit lifecycle management — from asset inventory and vulnerability assessment to findings, remediation tracking, and AI-assisted reporting.

---

## Features

### Core Audit Workflow
- **Organization & Audit Session Management** — Create organizations, configure audit sessions with industry and digital scale context
- **Asset Inventory** — Auditees register assets; auditors set CIA triad ratings (Confidentiality, Integrity, Availability) with auto-calculated criticality scores
- **OWASP Vulnerability Assessment** — Checkbox-based vulnerability identification mapped to OWASP Top 10 categories with auto-generated risk scores
- **NIST CSF Control Checklist** — 36 controls across 5 functions (Identify, Protect, Detect, Respond, Recover) with compliance status tracking
- **Findings & Remediation** — Create findings with risk scoring (Likelihood × Impact), track remediation status, management responses, and evidence uploads
- **AI-Powered Reporting** — Generate executive summaries using Gemini AI, with full PDF report export including audit opinion, risk matrix, and compliance metrics

### Role-Based Access Control (RBAC)

| Role | Capabilities |
|------|-------------|
| **Admin** | User management, oversight of all audits and reports |
| **Auditor** | Full audit lifecycle — organizations, sessions, assessments, findings, reports |
| **Auditee** | Asset registration, finding responses, evidence uploads, activity history |

### Risk Calculation Engine
- **Exposure Score** = Industry Baseline × Digital Scale Weight
- **Asset Criticality** = (C + I + A) / 3
- **Risk Score** = Likelihood × Impact (5×5 matrix)
- **Final Risk Score** = (Exposure × Avg Criticality × Avg Risk) / 10
- **Compliance %** = Weighted blend of findings compliance (40%) + NIST checklist (60%)
- **Audit Opinion** = Secure / Acceptable Risk / Immediate Action Required

### Additional Features
- Real-time notifications for auditees on audit assignments and finding updates
- Evidence upload system (screenshots, documents, PDFs — max 10MB)
- Password reset with email verification (PHPMailer + SMTP)
- Activity history page for auditees
- Responsive sidebar navigation with role-based menu rendering
- AI chatbot for cybersecurity education (Gemini / OpenAI / Ollama)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | PHP 8.x (vanilla, no framework) |
| **Database** | MySQL / MariaDB |
| **Frontend** | Bootstrap 5, Chart.js, vanilla JavaScript |
| **PDF Export** | Dompdf |
| **AI Integration** | Google Gemini API / OpenAI / Ollama |
| **Email** | PHPMailer (SMTP) |
| **Environment** | vlucas/phpdotenv |

---

## Project Structure

```
├── api/                    # REST API endpoints
│   ├── ai_actions.php
│   ├── asset_actions.php
│   ├── audit_actions.php
│   ├── auth_actions.php
│   ├── checklist_actions.php
│   ├── evidence_actions.php
│   ├── finding_actions.php
│   ├── notification_actions.php
│   ├── organization_actions.php
│   ├── report_actions.php
│   └── vuln_actions.php
├── config/
│   └── config.php          # Environment & app configuration
├── functions/              # Business logic & helpers
│   ├── ai_api.php          # AI provider integration
│   ├── auth.php            # Authentication & RBAC
│   ├── db.php              # Database connection (PDO)
│   ├── nist.php            # NIST CSF mapping
│   ├── nist_controls.php   # 35 NIST controls library
│   ├── owasp.php           # OWASP risk mapping
│   ├── owasp_library.php   # OWASP Top 10 vulnerability library
│   ├── report.php          # Report data & HTML generation
│   └── risk.php            # Risk calculation engine
├── includes/               # Shared UI components
│   ├── header.php
│   ├── sidebar.php
│   ├── footer.php
│   └── chatbot.html
├── migrations/             # Database migration scripts
├── uploads/evidence/       # Evidence file storage
├── db/                     # Database scripts (gitignored)
│   ├── database_schema.sql
│   └── nebula_ecommerce_dummy_data.sql
├── dashboard.php           # Main dashboard
├── organizations.php       # Organization management
├── audit_sessions.php      # Audit session management
├── asset_manage.php        # Asset management / registration
├── vulnerability_assessment.php  # OWASP vulnerability assessment
├── control_checklist.php   # NIST CSF control checklist
├── findings.php            # Findings & remediation
├── report.php              # Audit report viewer
├── history.php             # Auditee activity history
├── user_management.php     # Admin user management
├── profile.php             # User profile
├── login.php               # Login page
├── register.php            # Self-registration (auditor role)
├── forgot_pw.php           # Password reset
└── index.php               # Entry point (redirect)
```

---

## Installation

### Prerequisites

- PHP 8.0 or higher
- MySQL 5.7+ or MariaDB 10.3+
- Composer
- Web server (Apache/Nginx) or [Laragon](https://laragon.org/) (recommended for Windows)

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/SRM-Audit.git
   cd SRM-Audit
   ```

2. **Install dependencies**
   ```bash
   composer install
   ```

3. **Create the database**
   ```sql
   -- Import the schema
   mysql -u root -p < db/database_schema.sql

   -- (Optional) Load demo data
   mysql -u root -p audit < db/nebula_ecommerce_dummy_data.sql
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your settings:
   ```env
   DB_HOST=localhost
   DB_PORT=3306
   DB_NAME=audit
   DB_USER=root
   DB_PASS=

   AI_PROVIDER=gemini
   GEMINI_API_KEY=your_gemini_api_key_here

   APP_ENV=development
   APP_DEBUG=true
   APP_URL=http://localhost/AuditRiskTools

   MAIL_DRIVER=smtp
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=your_email@gmail.com
   SMTP_PASS=your_app_password
   SMTP_ENCRYPTION=tls
   MAIL_FROM_ADDRESS=no-reply@yourdomain.com
   MAIL_FROM_NAME=SRM-Audit
   ```

5. **Run migration scripts** (if needed)
   ```bash
   mysql -u root -p audit < migrations/2026_02_27_evidence_review_workflow.sql
   mysql -u root -p audit < migrations/2026_02_27_password_reset_hardening.sql
   ```

6. **Set up the first admin account**
   - Register at `/register.php` (creates an auditor account)
   - Visit `/test/promote_admin.php` to promote it to admin
   - Or use the admin panel to create additional users

7. **Access the application**
   ```
   http://localhost/AuditRiskTools/
   ```

---

## Audit Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                      AUDIT LIFECYCLE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Phase 0: Setup          Admin creates user accounts            │
│       │                                                         │
│       ▼                                                         │
│  Phase 1: Initiation     Auditor creates org + audit session    │
│       │                  Auditor assigns auditee(s)             │
│       ▼                                                         │
│  Phase 2: Inventory      Auditee registers assets               │
│       │                  Auditor sets CIA ratings                │
│       │                  Auditor runs OWASP vuln assessment      │
│       ▼                                                         │
│  Phase 3: Execution      Auditor evaluates NIST CSF controls    │
│       │                  Auditee provides evidence               │
│       ▼                                                         │
│  Phase 4: Findings       Auditor creates findings               │
│       │                  Auditee responds + uploads evidence     │
│       │                  ◄── Remediation loop ──►               │
│       ▼                                                         │
│  Phase 5: Reporting      Generate AI summary                    │
│                          Review audit opinion & risk matrix      │
│                          Download PDF report                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Database Schema

The system uses **13 tables** following Third Normal Form (3NF):

| Table | Purpose |
|-------|---------|
| `users` | User accounts with RBAC |
| `password_reset_tokens` | Secure password reset flow |
| `organizations` | Audited organizations |
| `audit_sessions` | Audit cycles with calculated metrics |
| `audit_auditees` | Auditee-to-audit assignment mapping |
| `assets` | Asset inventory with CIA ratings |
| `findings` | Vulnerability findings with risk scores |
| `audit_evidence` | Evidence files linked to findings |
| `evidence_uploads` | Auditee evidence uploads |
| `control_checklist` | NIST CSF control compliance results |
| `ai_reports` | AI-generated audit summaries |
| `chatbot_history` | AI chatbot conversation logs |
| `audit_logs` | User action audit trail |
| `notifications` | In-app notification system |

---



---

## License

This project is developed for academic purposes as part of a cybersecurity audit and risk management research project.

---

## Acknowledgments

- [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Dompdf](https://github.com/dompdf/dompdf)
- [Bootstrap 5](https://getbootstrap.com/)
- [Chart.js](https://www.chartjs.org/)
