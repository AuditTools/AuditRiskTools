# SRM-Audit

**Web-Based Cybersecurity GRC & Risk Management System**

A comprehensive Governance, Risk, and Compliance (GRC) platform for conducting cybersecurity audits based on the **NIST Cybersecurity Framework (CSF)** and **OWASP Top 10**. Supports full audit lifecycle management — from asset inventory and vulnerability assessment to findings, remediation tracking, and AI-assisted reporting.

---

## Why SRM-Audit? (Problem & Solution)

### The Problem
In modern cybersecurity governance, risk management, and compliance (GRC), organizations and auditors face critical operational and analytical bottlenecks:
- **Fragmented & Manual Audit Workflows** — Traditional audits rely on disjointed spreadsheets, email threads, and static word processor documents to manage asset inventories, checklists, findings, and evidence collection. This fragmentation creates version control conflicts, communication silos, and administrative overhead between auditors and auditees.
- **Subjective & Unquantified Risk Assessment** — Risk calculation in many organizations is often ad-hoc and based on guesswork rather than a standardized mathematical model. Organizations struggle to objectively quantify how industry exposure, digital footprint scale, asset criticality (Confidentiality, Integrity, Availability), and vulnerability likelihood/impact interact to form an accurate organizational risk posture.
- **Disconnected Compliance Frameworks** — Bridging high-level governance frameworks (such as the **NIST Cybersecurity Framework**) with technical application security standards (such as **OWASP Top 10**) is complex and time-consuming. Audits often treat high-level governance controls and granular web vulnerabilities as separate, siloed exercises.
- **Inefficient Remediation Tracking & Evidence Verification** — Tracking remediation progress across numerous findings is difficult without a centralized repository for auditees to submit management responses and attach verifiable digital evidence for auditor review.
- **Complex Executive Translation & Reporting** — Converting technical security findings and compliance checklists into clear, defensible executive summaries, organizational maturity ratings, and definitive audit opinions requires extensive time and specialized writing effort.

### The Solution
**SRM-Audit** solves these challenges by providing an integrated, automated, and AI-powered web platform designed to streamline the entire cybersecurity audit lifecycle:
- **Centralized & Collaborative RBAC Platform** — Bridges administrators, auditors, and auditees into a unified workspace. Auditees register asset inventories and upload supporting verification evidence, while auditors configure sessions, evaluate controls, and issue findings with real-time notification workflows.
- **Defensible Quantitative Risk Calculation Engine** — Replaces subjective guessing with a robust mathematical engine that automatically calculates:
  - **Exposure Score:** Based on industry baseline risk and digital footprint scale.
  - **Asset Criticality:** Derived from CIA Triad ratings ((C + I + A) / 3).
  - **Vulnerability Risk Score:** Using a standard 5×5 Likelihood × Impact matrix.
  - **Composite Final Risk Score & Level:** Automatically synthesized and classified (Low, Medium, High, Critical) to provide an objective, real-time risk posture.
- **Unified Multi-Framework Harmonization** — Integrates both technical vulnerability assessments (**OWASP Top 10**) and governance control evaluations (**36 NIST CSF Controls** across Identify, Protect, Detect, Respond, and Recover). A weighted blending engine automatically combines findings compliance (40%) and NIST checklist compliance (60%) into a unified real-time compliance score and maturity level (*Initial*, *Developing*, *Managed*, *Optimized*).
- **Closed-Loop Remediation & Evidence Management** — Features a built-in evidence repository where auditees can upload supporting files (PDFs, images, documents), submit management responses, and track remediation progress until verified and resolved by auditors.
- **Automated Audit Opinion & AI-Powered Executive Reporting** — Automatically generates defensible Audit Opinions (*Secure*, *Acceptable Risk*, *Immediate Action Required*) based on compliance thresholds and open high/critical vulnerability counts. Integrates **Google Gemini AI** (as well as OpenAI and Ollama) to generate professional, natural-language executive summaries and exports publication-ready PDF reports with embedded risk matrices and compliance charts.

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
| **Deployment / Cloud** | Vercel Serverless (`vercel-php@0.7.1`), Apache/Nginx, Laragon |

---

## Project Structure

```
├── api/                    # REST API endpoints & Vercel routing
│   ├── ai_actions.php
│   ├── asset_actions.php
│   ├── audit_actions.php
│   ├── auth_actions.php
│   ├── checklist_actions.php
│   ├── evidence_actions.php
│   ├── finding_actions.php
│   ├── index.php           # Vercel serverless routing entry point
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
├── db/                     # Database schema & sample data
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
├── index.php               # Entry point (redirects to login)
├── vercel.json             # Vercel serverless deployment config
└── composer.json           # PHP dependencies & autoloader
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

### Vercel Serverless Deployment

SRM-Audit includes native support for serverless deployment on [Vercel](https://vercel.com/) using the `vercel-php` community runtime.

1. **Push your repository** to GitHub, GitLab, or Bitbucket.
2. **Import the project** into the Vercel Dashboard.
3. **Configure Environment Variables** in Vercel Project Settings (connect to a remote MySQL/MariaDB database such as Aiven, Railway, AWS RDS, or PlanetScale):
   ```env
   DB_HOST=your-cloud-db-host.com
   DB_PORT=3306
   DB_NAME=audit
   DB_USER=root
   DB_PASS=your-secure-password
   AI_PROVIDER=gemini
   GEMINI_API_KEY=your_gemini_api_key_here
   APP_ENV=production
   APP_DEBUG=false
   APP_URL=https://your-project.vercel.app
   ```
4. **Deploy**: Vercel will automatically use `vercel.json` and `vercel-php@0.7.1` to route serverless PHP requests via `api/index.php`.

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

The system uses **14 tables** following Third Normal Form (3NF):

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

## Limitations & Future Roadmap

While SRM-Audit provides a robust, rule-based GRC workflow for academic and SME environments, the platform has known technical boundaries and areas for future expansion:

### Current Limitations
- **Manual Assessment Workflow** — Vulnerability identification and risk scoring rely on auditor data entry and check-lists. The current scope does not include live automated scanning or direct log ingestion (e.g., Nmap, OpenVAS, or Burp Suite XML imports).
- **Narrative-Only AI Boundary** — Generative AI models (Gemini/OpenAI) operate strictly as narrative processing layers. AI features cannot directly alter database state, re-calculate core risk formulas, or make autonomous compliance decisions.
- **Simplified Quantitative Scoring** — The risk calculation engine uses deterministic algebraic weighting ($Exposure \times Criticality \times Risk$). It does not yet implement advanced enterprise quantitative models like FAIR (Factor Analysis of Information Risk) or ALE ($Annualized\ Loss\ Expectancy$).
- **Local Evidence Storage** — Evidence file uploads are stored on local server storage (`uploads/evidence/`). For serverless environments (like Vercel), persistent storage requires external cloud bucket integration.

### Future Roadmap
- [ ] **Automated Scanner Ingestion** — Support XML/JSON report parsing from Nmap, Nessus, and OWASP ZAP to auto-populate findings.
- [ ] **Cloud Storage Integration** — Transition evidence management to Amazon S3 or Cloudinary with SHA-256 file hashing for cryptographic non-repudiation.
- [ ] **Expanded Framework Libraries** — Add mapping support for ISO/IEC 27001:2022 Annex A controls and PCI-DSS 4.0.
- [ ] **CI/CD Compliance Pipeline Integration** — Webhook API integrations to trigger compliance checks from GitHub Actions / GitLab CI pipelines.

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
