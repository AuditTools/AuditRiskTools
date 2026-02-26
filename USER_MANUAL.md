# SRM-Audit — User Manual (Manual Testing Guide)

> **SRM-Audit** — Web-Based Cybersecurity GRC & Risk Management System  
> Version 1.0 | Last Updated: February 2026

---

## Table of Contents

1. [Overview & Roles](#1-overview--roles)
2. [Accessing the Application](#2-accessing-the-application)
3. [PHASE 0 — Setup (Admin Only)](#3-phase-0--set+up-admin-only)
4. [PHASE 1 — Audit Initiation (Auditor)](#4-phase-1--audit-initiation-auditor)
5. [PHASE 2 — Inventory (Auditee → Auditor Validates)](#5-phase-2--inventory-auditee--auditor-validates)
6. [PHASE 3 — Audit Execution (Auditor ↔ Auditee)](#6-phase-3--audit-execution-auditor--auditee)
7. [PHASE 4 — Findings & Remediation (Loop)](#7-phase-4--findings--remediation-loop)
8. [PHASE 5 — Reporting (Auditor Generates, All View)](#8-phase-5--reporting-auditor-generates-all-view)
9. [Quick Reference — Navigation by Role](#9-quick-reference--navigation-by-role)
10. [Test Data Suggestions](#10-test-data-suggestions)

---

## 1. Overview & Roles

SRM-Audit has **three roles**:

| Role | Description | Can Access |
|---|---|---|
| **Admin** | System administrator. Creates/manages user accounts. Oversight on all audits & reports. | User Management, Organizations (view all), Reports (view all) |
| **Auditor** | Performs the audit. Owns organizations, creates audit sessions, runs assessments, writes findings, generates reports. | Organizations, Audit Sessions, Asset Management, Vulnerability Assessment, Control Checklist, Findings, Reports, AI Assistant |
| **Auditee** | The person/team being audited. Registers assets, responds to findings, uploads evidence. Sees only audits assigned to them. | Dashboard (assigned audits only), Asset Registration, Findings & Response, Control Checklist (view), Reports (view) |

---

## 2. Accessing the Application

**Base URL:** `http://localhost/AuditRiskTools/`  
*(Adjust the URL based on your Laragon / web server configuration.)*

| Page | URL |
|---|---|
| Login | `/login.php` |
| Register (self-service) | `/register.php` |
| Dashboard | `/dashboard.php` |

> **Note:** Self-registration via `register.php` creates accounts with the **auditor** role by default. To create **auditee** or **admin** accounts, use the Admin's User Management page or the `test/promote_admin.php` setup script.

---

## 3. PHASE 0 — Setup (Admin Only)

> **Goal:** Create user accounts for Auditors and Auditees. This is a one-time setup.

### Step 0.1 — Log in as Admin

1. Open `http://localhost/AuditRiskTools/login.php`
2. Enter the admin email and password.
3. Click **Login**.
4. You should see the **Dashboard** page. The sidebar shows:
   - Dashboard
   - **User Management**
   - Organizations
   - Role: **Admin**
   - Logout

> **First-time setup:** If no admin account exists yet, register a normal account at `/register.php`, then run `test/promote_admin.php` in the browser to promote it to admin.

### Step 0.2 — Create an Auditor Account

1. Click **User Management** in the sidebar.
2. Scroll to the **Create New User** section.
3. Fill in the form:

| Field | Example Value |
|---|---|
| Full Name | `John Auditor` |
| Email | `auditor@test.com` |
| Password | `Password123` (min 8 characters) |
| Role | Select **auditor** |

4. Click **Create User**.
5. ✅ **Expected:** A success message appears: "User 'John Auditor' (auditor) created successfully". The user now appears in the table below.

### Step 0.3 — Create an Auditee Account

1. Still on the **User Management** page.
2. Fill in the Create New User form:

| Field | Example Value |
|---|---|
| Full Name | `Jane Auditee` |
| Email | `auditee@test.com` |
| Password | `Password123` (min 8 characters) |
| Role | Select **auditee** |

3. Click **Create User**.
4. ✅ **Expected:** A success message appears: "User 'Jane Auditee' (auditee) created successfully".

### Step 0.4 — Verify Users Table

The User Management table should now show at least three users:

| Name | Email | Role | Status |
|---|---|---|---|
| (your admin) | admin@test.com | admin | Active |
| John Auditor | auditor@test.com | auditor | Active |
| Jane Auditee | auditee@test.com | auditee | Active |

### Step 0.5 — (Optional) Change Role or Reset Password

- **Change Role:** In the user table, use the role dropdown next to any user and click the save/update button.
- **Toggle Active/Deactive:** Click the toggle status button to deactivate or reactivate a user.
- **Reset Password:** Enter a new password (min 8 chars) and click the reset button.

✅ **Admin setup is complete.** Log out (`/logout.php`).

---

## 4. PHASE 1 — Audit Initiation (Auditor)

> **Goal:** Create an organization profile, create an audit session, and assign auditee(s).

### Step 1.1 — Log in as Auditor

1. Open `http://localhost/AuditRiskTools/login.php`
2. Login with **auditor@test.com** / **Password123**
3. ✅ **Expected:** Dashboard page loads. Sidebar shows:
   - Dashboard
   - **Organizations**
   - Role: **Auditor**
   - Logout

> Note: The sidebar items for Asset Management, Vuln Assessment, Control Checklist, Findings, and Report will appear **after** you open/select an audit session.

### Step 1.2 — Create Organization Profile

1. Click **Organizations** in the sidebar.
2. Fill in the **Create Organization** form:

| Field | Example Value |
|---|---|
| Organization Name | `PT Maju Digital` |
| Industry | `Technology` |
| No. of Employees | `150` |
| System Type | `Web Application` |
| Contact Person | `Budi Santoso` (optional) |

3. Click **Create**.
4. ✅ **Expected:** The organization appears in the table below with **Audits: 0**.

### Step 1.3 — Create Audit Session

1. In the Organizations table, click the **Create Audit Sessions** button next to your organization.
2. You are redirected to the **Create Audit Session** page (`audit_sessions.php?org_id=X`).
3. Fill in the form:

| Field | Example Value |
|---|---|
| Organization | (pre-filled, disabled) — PT Maju Digital |
| Session Name | `Annual Cybersecurity Audit 2026` |
| Digital Scale | `High` |
| Audit Date | `2026-02-26` |
| Notes | `Comprehensive NIST CSF compliance audit` (optional) |

4. Click **Create Audit**.
5. ✅ **Expected:** The page reloads and the new audit session appears in the **Existing Audit Sessions** table with status **Planning**.

### Step 1.4 — Assign Auditee(s) to the Audit Session

1. In the Existing Audit Sessions table, find your audit session.
2. Click the **Assign Auditee** button (👤+ icon).
3. A modal dialog opens: **"Assign Auditee to Annual Cybersecurity Audit 2026"**
4. In the **Select Auditee** dropdown, choose `Jane Auditee (auditee@test.com)`.
5. Click **Assign**.
6. ✅ **Expected:**
   - Success message: "Auditee assigned and notified successfully"
   - Under **Currently Assigned**, you see a badge: `Jane Auditee ✕`
   - A notification is sent to the auditee's account.

7. (Optional) Assign additional auditees by repeating steps 4–5.
8. To **remove** an auditee, click the ✕ on their badge in the modal.

### Step 1.5 — Open the Audit Session

1. Still on the Audit Sessions page, click the **Open** button (👁 icon) next to the audit session.
2. ✅ **Expected:** You are redirected to `dashboard.php?audit_id=X`. The sidebar now shows the full workflow menu:
   - Dashboard
   - Organizations
   - **Asset Management**
   - **Vuln Assessment**
   - **Control Checklist**
   - **Findings**
   - **Report**

---

## 5. PHASE 2 — Inventory (Auditee → Auditor Validates)

> **Goal:** Auditee registers assets; Auditor reviews them, sets CIA ratings, and runs vulnerability assessment.

### Part A: Auditee Registers Assets

#### Step 2A.1 — Log in as Auditee

1. Log out of the auditor account.
2. Open `/login.php` and log in with **auditee@test.com** / **Password123**.
3. ✅ **Expected:** Dashboard loads. You should see:
   - A notification badge (🔴) indicating assignment notification.
   - The **Choose Organization & Audit Session** section showing the audit you were assigned to.

#### Step 2A.2 — Select the Assigned Audit

1. On the Dashboard, select the audit session from the **Audit Session** dropdown:
   - `PT Maju Digital - Annual Cybersecurity Audit 2026 (2026-02-26)`
2. Click **Open**.
3. ✅ **Expected:** Dashboard refreshes with audit overview stats. The sidebar now shows:
   - Dashboard
   - **Asset Registration**
   - **Findings & Response**
   - **Control Checklist**
   - **Report (View)**

#### Step 2A.3 — Register Assets

1. Click **Asset Registration** in the sidebar.
2. The audit session should be pre-selected. If not, select it from the dropdown and click **Open**.
3. In the **Register New Asset** form, fill in:

**Asset 1:**

| Field | Example Value |
|---|---|
| Asset Name | `Main Web Server` |
| IP Address / Location | `192.168.1.10` |
| Asset Type | `Server` |
| Owner | `IT Department` |
| Department | `Information Technology` |
| Description | `Production web server running company website` |

4. Click **Register Asset**.
5. ✅ **Expected:** Page reloads. The asset appears in the **Asset Inventory** table with CIA values of `1/1/1` (pending auditor review).

6. Register more assets:

**Asset 2:**

| Field | Example Value |
|---|---|
| Asset Name | `Employee Database` |
| IP Address / Location | `192.168.1.20` |
| Asset Type | `Database` |
| Owner | `HR Department` |
| Department | `Human Resources` |
| Description | `MySQL database containing employee records` |

**Asset 3:**

| Field | Example Value |
|---|---|
| Asset Name | `Office Firewall` |
| IP Address / Location | `192.168.1.1` |
| Asset Type | `Network Device` |
| Owner | `IT Department` |
| Department | `Information Technology` |
| Description | `Main perimeter firewall` |

**Asset 4:**

| Field | Example Value |
|---|---|
| Asset Name | `CRM Application` |
| IP Address / Location | `crm.majudigital.com` |
| Asset Type | `Application` |
| Owner | `Sales Department` |
| Department | `Sales` |
| Description | `Customer relationship management system` |

7. ✅ **Expected:** Asset Inventory table shows 4 assets, all with CIA `1/1/1` and criticality pending.

> The auditee's part is done for now. Log out.

---

### Part B: Auditor Reviews and Validates Assets

#### Step 2B.1 — Log in as Auditor

1. Open `/login.php` and log in with **auditor@test.com** / **Password123**.
2. On the **Dashboard**, select the audit session:
   - `PT Maju Digital - Annual Cybersecurity Audit 2026 (2026-02-26)`
3. Click **Open**.

#### Step 2B.2 — Review Assets & Set CIA Ratings

1. Click **Asset Management** in the sidebar.
2. You should see the 4 assets registered by the auditee, all with CIA `1/1/1`.
3. For each asset, click the **Set CIA** button (✏️ edit icon) and set appropriate CIA ratings:

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Main Web Server | 4 | 4 | 5 |
| Employee Database | 5 | 5 | 3 |
| Office Firewall | 3 | 4 | 5 |
| CRM Application | 4 | 3 | 4 |

4. For each asset:
   - Click **Set CIA** → a modal appears.
   - Enter the C, I, A values (1–5).
   - Click **Save CIA Ratings**.
   - ✅ **Expected:** Page reloads. The asset now shows updated CIA values and a calculated **Criticality Score** with a **Criticality Level** badge (Low / Medium / High / Critical).

#### Step 2B.3 — Run Vulnerability Assessment

1. Click **Vuln Assessment** in the sidebar (or the **Vulnerability Assessment** link at the bottom of the Asset Management page).
2. ✅ **Expected:** The **Vulnerability Assessment** page loads showing:
   - An **Asset** dropdown to select which asset to assess.
   - An **OWASP vulnerability checklist** grouped by category (e.g., Broken Access Control, Cryptographic Failures, Injection, etc.)

3. **Select an asset** from the dropdown (e.g., `Main Web Server`).
4. **Check the OWASP vulnerabilities** that apply to this asset. For testing, select several:
   - ☑ `A01 - Broken Access Control: Violation of least privilege`
   - ☑ `A03 - Injection: SQL Injection`
   - ☑ `A05 - Security Misconfiguration: Default accounts enabled`
   - ☑ `A07 - Identification Failures: Permits brute force attacks`

5. Click **Submit Assessment** (or the submit/save button).
6. ✅ **Expected:**
   - The system **auto-assigns likelihood and impact** values based on the OWASP library.
   - The system **calculates a risk score** for each vulnerability (Likelihood × Impact).
   - The system **auto-generates findings** for each selected vulnerability.
   - The findings appear in the **Existing Vulnerability Findings** table below with risk scores and risk level badges (Low / Medium / High / Critical).

7. Repeat for other assets as needed.
8. Navigate to the **Findings** page to see all auto-generated findings listed.

---

## 6. PHASE 3 — Audit Execution (Auditor ↔ Auditee)

> **Goal:** The system generates the NIST CSF Control Checklist. The Auditor evaluates each control, requests evidence from the Auditee, and marks compliance status.

### Step 3.1 — Open the Control Checklist (Auditor)

1. As the **Auditor**, click **Control Checklist** in the sidebar.
2. ✅ **Expected:** The checklist page loads with **35 NIST CSF controls** organized by function:

| Function | Color | Controls |
|---|---|---|
| **Identify** | 🔵 Blue | 7 controls (ID.AM-1, ID.AM-2, ID.AM-5, ID.GV-1, ID.GV-4, ID.RA-1, ID.RA-5) |
| **Protect** | 🟢 Green | 14 controls (PR.AC-1 through PR.PT-4) |
| **Detect** | 🟠 Orange | 6 controls (DE.AE-2 through DE.CM-8) |
| **Respond** | 🔴 Red | 5 controls (RS.RP-1 through RS.IM-2) |
| **Recover** | 🟣 Purple | 3 controls (RC.RP-1 through RC.CO-3) |

Each control row shows:
- **Control ID** (e.g., `ID.AM-1`)
- **Title** (e.g., "Physical Device Inventory")
- **Description** — what the control requires
- **Guidance** — how to verify compliance
- **Status dropdown** — Not Assessed / Compliant / Partially Compliant / Non-Compliant / Not Applicable
- **Notes** text field

### Step 3.2 — Evaluate Controls

For each control, follow this process:

1. Read the control **description** and **guidance**.
2. Determine if you need evidence from the auditee to verify compliance.
3. Set the **status** using the dropdown:
   - **Compliant** ✅ — Organization fully meets this control.
   - **Partially Compliant** ⚠️ — Partially implemented, improvements needed.
   - **Non-Compliant** ❌ — Control is not implemented or significantly lacking.
   - **Not Applicable** ➖ — Control does not apply to this organization/scope.
4. Add **notes** explaining your assessment rationale or evidence reference.
5. The status is saved automatically (or click Save, depending on implementation).

**Example test data for controls:**

| Control | Status | Notes |
|---|---|---|
| ID.AM-1 Physical Device Inventory | Compliant | Hardware inventory maintained in spreadsheet, verified complete |
| ID.AM-2 Software Platform Inventory | Partially Compliant | Software list exists but not updated regularly |
| ID.GV-1 Information Security Policy | Non-Compliant | No formal security policy document exists |
| PR.AC-1 Identity & Access Management | Partially Compliant | AD implemented but no MFA |
| PR.AT-1 Security Awareness Training | Non-Compliant | No training program exists |
| PR.DS-1 Data at Rest Protection | Compliant | AES-256 encryption on databases |
| DE.AE-2 Anomaly & Event Analysis | Non-Compliant | No SIEM or event correlation |
| DE.CM-1 Network Monitoring | Partially Compliant | Basic monitoring only, no IDS/IPS |
| RS.RP-1 Response Planning | Non-Compliant | No incident response plan documented |
| RC.RP-1 Recovery Planning | Non-Compliant | No disaster recovery plan |

6. ✅ **Expected:** After marking all controls:
   - A **compliance percentage** is calculated by the system.
   - A **maturity level** is determined (Initial / Developing / Managed / Optimized).
   - The compliance stats update in the audit session's metrics.

### Step 3.3 — Auditee Views Checklist (Read-Only)

1. Log out and log in as **auditee@test.com**.
2. Navigate to the assigned audit and click **Control Checklist** in the sidebar.
3. ✅ **Expected:** The auditee can **view** the checklist and see the auditor's assessments, but the controls are **view-only** (the auditee cannot change compliance status — this is the auditor's domain).

### Step 3.4 — Evidence Exchange (via Findings page)

Evidence exchange happens primarily through the **Findings** and **Evidence** system:

1. The **Auditor** creates findings for non-compliant controls (see PHASE 4).
2. The **Auditee** responds with evidence uploads on each finding.
3. Evidence types supported: Screenshots (`.jpg`, `.png`), Documents (`.pdf`, `.doc`, `.docx`), Spreadsheets (`.xls`, `.xlsx`), Text files (`.txt`). Max 10MB per file.

---

## 7. PHASE 4 — Findings & Remediation (Loop)

> **Goal:** The Auditor creates findings from non-compliant controls and vulnerability assessments. The Auditee responds with management responses and remediation evidence. This repeats until findings are resolved.

### Part A: Auditor Creates Findings

#### Step 4A.1 — Navigate to Findings

1. As the **Auditor**, click **Findings** in the sidebar.
2. ✅ **Expected:** The **Vulnerability & Risk Assessment** page loads showing:
   - The **Add New Finding** form (auditor only).
   - The **Findings List** table (showing auto-generated findings from vulnerability assessment, if any).
   - A link to the **OWASP Vulnerability Assessment** page.

#### Step 4A.2 — Create a Finding from Non-Compliant Control

1. In the **Add New Finding** form:

| Field | Example Value |
|---|---|
| Asset | `Main Web Server` |
| NIST Function | `Protect` |
| OWASP Category | (leave empty — this is from a compliance gap, not OWASP) |
| Compliance Status | `Non-Compliant` |
| Title | `No Information Security Policy Documented` |
| Description | `The organization does not have a formally documented and approved information security policy as required by NIST CSF ID.GV-1.` |
| Recommendation | `Develop and implement a comprehensive information security policy. Policy should be approved by management, distributed to all staff, and reviewed annually.` |
| Evidence Files | (optionally upload auditor screenshots) |
| Likelihood | `4` (drag slider) |
| Impact | `4` (drag slider) |

2. ✅ **Observe:** The **Risk Score** badge updates in real-time: `4 × 4 = 16` (Critical 🔴).

3. Click **Save Finding**.
4. ✅ **Expected:** Page reloads. The new finding appears in the Findings List with:
   - Status: **Open** (red badge)
   - Risk Score: **16** (red/critical badge)
   - NIST: **Protect**
   - Compliance: **Non-Compliant**

#### Step 4A.3 — Create Additional Findings

Create 2–3 more findings for testing:

**Finding 2:**

| Field | Value |
|---|---|
| Asset | `Employee Database` |
| NIST Function | `Protect` |
| Compliance Status | `Non-Compliant` |
| Title | `No Security Awareness Training Program` |
| Likelihood | 3, Impact | 4 → Risk Score: 12 (High) |
| Recommendation | `Implement mandatory security awareness training for all employees...` |

**Finding 3:**

| Field | Value |
|---|---|
| Asset | `Office Firewall` |
| NIST Function | `Detect` |
| Compliance Status | `Non-Compliant` |
| Title | `No SIEM or Event Correlation System` |
| Likelihood | 4, Impact | 3 → Risk Score: 12 (High) |
| Recommendation | `Deploy a SIEM solution for centralized log analysis...` |

#### Step 4A.4 — Set Remediation Deadlines

For each finding in the Findings List:

1. Use the **date picker** (📅 icon) in the Actions column.
2. Set a remediation deadline (e.g., `2026-04-30`).
3. Click the calendar save button.
4. ✅ **Expected:** Deadline is saved.

---

### Part B: Auditee Responds to Findings

#### Step 4B.1 — Log in as Auditee

1. Log out and log in as **auditee@test.com**.
2. Select the audit session on the Dashboard → click **Open**.
3. Click **Findings & Response** in the sidebar.

#### Step 4B.2 — View Findings

1. ✅ **Expected:** The **Findings & Management Response** page shows:
   - No "Add Finding" form (auditees cannot create findings).
   - The **Findings List** table showing all findings with their details.
   - Each finding has an expandable **Details & Evidence** section.

#### Step 4B.3 — Write Management Response

1. Click the **Details & Evidence** summary to expand a finding.
2. Under **Management Response**, you see:
   - Current response: "No management response yet."
   - A text area to enter your response.

3. Write a management response:

**For Finding 1 (No Security Policy):**
```
Action Plan: We will engage a cybersecurity consultant to develop a comprehensive 
information security policy. The policy will cover data classification, access control, 
incident response, and acceptable use.

Timeline: 
- Draft policy: March 15, 2026
- Management review: March 30, 2026  
- Approval & distribution: April 15, 2026

Responsible: IT Manager (Budi Santoso)
```

4. Click **Submit Response** (📤 paper plane icon).
5. ✅ **Expected:** Success message "Response submitted successfully!" appears. The response is saved with a timestamp. The finding status changes to **In Progress**.

#### Step 4B.4 — Upload Remediation Evidence

1. In the same expanded finding section, scroll to the **Evidence** area.
2. Click **Choose File** and select evidence files (e.g., a PDF of the draft policy, screenshots of implemented controls).
3. Click **Upload Evidence**.
4. ✅ **Expected:** The evidence file appears in the evidence table with filename, type, upload date, and View/Delete buttons.

5. Repeat for other findings.

---

### Part C: Auditor Reviews Responses & Closes Findings

#### Step 4C.1 — Log in as Auditor

1. Log out and log in as **auditor@test.com**.
2. Open the audit session → click **Findings**.

#### Step 4C.2 — Review Management Responses

1. In the Findings List, notice findings now show **"Has Response"** badge in the Details section.
2. Expand each finding to review:
   - The management response text.
   - Uploaded evidence files (click **View** to open them).

#### Step 4C.3 — Close or Keep Open

For each finding, the Auditor decides:

**If sufficient → Close the finding:**
1. Click the **Close** button (✅) in the Actions column.
2. Confirm: "Close this finding? This marks it as Resolved."
3. ✅ **Expected:** Finding status changes to **Resolved** (green badge).

**If not sufficient → Keep open:**
1. Do NOT click Close. The finding remains **Open** or **In Progress**.
2. (Optional) The opening stays open for the auditee to submit additional response/evidence — the auditee logs back in, updates their response, uploads more evidence.
3. This creates a **remediation loop** until the auditor is satisfied.

**Reopen a closed finding:**
1. If a resolved finding needs to be reopened, click the **Reopen** button (🔄).
2. ✅ **Expected:** Finding status returns to **Open**.

#### Step 4C.4 — Verify the Loop

To test the remediation loop:
1. Keep one finding **Open** after the auditee responds.
2. Switch to auditee → update the management response with additional details → upload more evidence.
3. Switch to auditor → review again → close if satisfied.
4. ✅ **Expected:** The loop works seamlessly. Responses and evidence accumulate over iterations.

---

## 8. PHASE 5 — Reporting (Auditor Generates, All View)

> **Goal:** The Auditor generates and reviews the final report with AI assistance. All roles can view the report.

### Step 5.1 — Open the Report Page (Auditor)

1. As the **Auditor**, click **Report** in the sidebar.
2. The audit session should be pre-selected. If not, select it and click **Open**.
3. ✅ **Expected:** The report page loads showing:
   - Action buttons: **Open Full Preview**, **Download PDF**, **Generate AI Summary**
   - **Audit Opinion** section
   - **Risk Matrix** (Likelihood × Impact)
   - Full report content

### Step 5.2 — Verify Audit Opinion

The **Audit Opinion** card shows one of three verdicts:

| Compliance % | Conditions | Opinion |
|---|---|---|
| ≥ 85% | AND no open High/Critical findings | 🟢 **Secure** |
| 60% – 84% | OR has open High (but not Critical) | 🟡 **Acceptable Risk** |
| < 60% | OR any open Critical findings | 🔴 **Needs Immediate Action** |

✅ **Expected:** Based on your test data (many non-compliant controls), the opinion should be **🔴 Needs Immediate Action** or **🟡 Acceptable Risk**.

### Step 5.3 — Review the Risk Matrix

The 5×5 Risk Matrix shows:
- Rows: Likelihood (L1–L5, bottom to top)
- Columns: Impact (I1–I5, left to right)
- Cell colors: 🟢 Low, 🟡 Medium, 🟠 High, 🔴 Critical
- Cell values: Count of findings at each L×I intersection

✅ **Expected:** The matrix shows counts matching your findings' likelihood and impact values.

### Step 5.4 — Generate AI Executive Summary

1. Click the **Generate AI Summary** button.
2. ✅ **Expected:** 
   - Button text changes to "Generating..."
   - After a few seconds, the AI Summary card populates with a generated executive summary.
   - The summary includes risk analysis, key findings, and recommendations.
   - The AI provider name is shown at the bottom.

> **Note:** This requires a configured AI provider (Gemini, OpenAI, or Ollama) in the `.env` file. If AI is not configured, an error message will appear.

### Step 5.5 — View Full Report Preview

1. Click **Open Full Preview**.
2. ✅ **Expected:** A new browser tab opens with the complete audit report containing:
   1. **Executive Summary** — Organization info, audit scope, methodology
   2. **Scope of Audit** — Audit session details, digital scale, date
   3. **Methodology** — NIST CSF framework description
   4. **Asset List** — All registered assets with CIA ratings and criticality
   5. **Risk Assessment Results** — Findings with risk scores, OWASP categories
   6. **Compliance % + Maturity Level** — Overall compliance percentage and NIST maturity
   7. **Audit Findings** — Detailed list of all findings with statuses
   8. **AI Recommendations** — AI-generated recommendations (if generated)
   9. **Final Audit Opinion** — Secure / Acceptable Risk / Needs Immediate Action

### Step 5.6 — Download PDF

1. Click **Download PDF**.
2. ✅ **Expected:** A PDF file downloads containing the full audit report.

### Step 5.7 — Verify Report Access by Role

**Admin views the report:**
1. Log out. Log in as **admin**.
2. On the Dashboard, select the audit session → click **Open**.
3. Click **Report (View)** in the sidebar.
4. ✅ **Expected:** Admin can see the full report (read-only). No "Generate AI Summary" or "Download PDF" buttons (admin has oversight view only).

**Auditee views the report:**
1. Log out. Log in as **auditee@test.com**.
2. On the Dashboard, select the audit session → click **Open**.
3. Click **Report (View)** in the sidebar.
4. ✅ **Expected:** Auditee can see the full report for their assigned audit only. No edit capabilities.

---

## 9. Quick Reference — Navigation by Role

### Admin Sidebar
```
Dashboard
User Management
Organizations
Report (View)        ← only when an audit is selected
Logout
```

### Auditor Sidebar
```
Dashboard
Organizations
─── (after selecting an audit) ───
Asset Management
Vuln Assessment
Control Checklist
Findings
Report
Logout
```

### Auditee Sidebar
```
Dashboard
─── (after selecting an assigned audit) ───
Asset Registration
Findings & Response
Control Checklist
Report (View)
Logout
```

---

## 10. Test Data Suggestions

Use the following test scenario to walk through the entire workflow end-to-end:

### Test Accounts

| Role | Name | Email | Password |
|---|---|---|---|
| Admin | System Admin | admin@test.com | Admin12345 |
| Auditor | John Auditor | auditor@test.com | Password123 |
| Auditee | Jane Auditee | auditee@test.com | Password123 |

### Test Organization

| Field | Value |
|---|---|
| Name | PT Maju Digital |
| Industry | Technology |
| Employees | 150 |
| System Type | Web Application |
| Contact | Budi Santoso |

### Test Audit Session

| Field | Value |
|---|---|
| Session Name | Annual Cybersecurity Audit 2026 |
| Digital Scale | High |
| Audit Date | 2026-02-26 |
| Notes | Comprehensive NIST CSF compliance audit |

### Test Assets (4 assets)

| Asset Name | Type | IP/Location | CIA (C/I/A) |
|---|---|---|---|
| Main Web Server | Server | 192.168.1.10 | 4/4/5 |
| Employee Database | Database | 192.168.1.20 | 5/5/3 |
| Office Firewall | Network Device | 192.168.1.1 | 3/4/5 |
| CRM Application | Application | crm.majudigital.com | 4/3/4 |

### Test Findings (Manual)

| Title | Asset | NIST | L×I | Status |
|---|---|---|---|---|
| No Security Policy | Web Server | Protect | 4×4=16 | Open |
| No Security Training | Database | Protect | 3×4=12 | Open |
| No SIEM System | Firewall | Detect | 4×3=12 | Open |

### Expected End Results

| Metric | Expected Range |
|---|---|
| Total Assets | 4 |
| Total Findings | 3+ (manual) + X (from vuln assessment) |
| Compliance % | 30%–60% (depending on checklist marks) |
| Maturity Level | Initial or Developing |
| Audit Opinion | 🔴 Needs Immediate Action (likely) |

---

## Troubleshooting

| Issue | Solution |
|---|---|
| Login fails | Check email/password. Admin can reset password via User Management. |
| Auditee sees no audits | Auditor must assign the auditee to the audit session first (Phase 1 Step 1.4). |
| Sidebar missing menu items | Select an audit session first from the Dashboard. Menu items appear only when `active_audit_id` is set in the session. |
| AI Summary fails | Check `.env` file for `AI_PROVIDER`, `GEMINI_API_KEY` (or equivalent). See `SETUP/AI_SETUP_GUIDE.md`. |
| Evidence upload fails | Ensure the `uploads/` directory exists and is writable. Max file size: 10MB. |
| PDF download fails | Check that the report generation library is properly installed via Composer. |
| Session expires | Sessions timeout after 30 minutes of inactivity. Re-login to continue. |

---

*End of User Manual*
