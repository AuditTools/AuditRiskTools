# 🚀 SRM-Audit - Setup & Installation Guide

## 📋 Persyaratan Sistem
- PHP 7.4 atau lebih tinggi
- MySQL 5.7 atau lebih tinggi
- Apache/Nginx Web Server
- XAMPP/WAMP (Recommended untuk Windows)

---

## 🔧 Langkah Instalasi

### 1️⃣ Setup Web Server (XAMPP)

1. **Download & Install XAMPP**
   - Download dari: https://www.apachefriends.org/
   - Install di C:\xampp (default)

2. **Start Services**
   - Buka XAMPP Control Panel
   - Klik **Start** pada Apache
   - Klik **Start** pada MySQL
   - Pastikan statusnya berubah jadi hijau

### 2️⃣ Setup Database

1. **Buka phpMyAdmin**
   - URL: http://localhost/phpmyadmin
   - Login dengan:
     - Username: `root`
     - Password: (kosong, jangan isi)

2. **Import Database**
   - Klik tab **"SQL"** di menu atas
   - Buka file `database_schema.sql` dengan text editor
   - Copy seluruh isinya
   - Paste ke kolom SQL query di phpMyAdmin
   - Klik tombol **"Go"** untuk execute
   - Database `audit` akan otomatis terbuat

### 3️⃣ Konfigurasi Koneksi Database

1. **Edit file koneksi**
   ```
   File: functions/db.php
   ```

2. **Update kredensial** (jika perlu):
   ```php
   define('DB_HOST', 'localhost');
   define('DB_PORT', '3306');
   define('DB_NAME', 'audit');
   define('DB_USER', 'root');        // Default XAMPP
   define('DB_PASS', '');            // Default XAMPP (kosong)
   ```

### 4️⃣ Copy Project ke htdocs

1. **Copy folder project**
   ```
   Dari: D:\AuditRiskTools
   Ke:   C:\xampp\htdocs\AuditRiskTools
   ```

2. **Atau buat Virtual Host** (Advanced)
   - Edit: `C:\xampp\apache\conf\extra\httpd-vhosts.conf`
   - Tambahkan:
   ```apache
   <VirtualHost *:80>
       DocumentRoot "D:/AuditRiskTools"
       ServerName srm-audit.local
       <Directory "D:/AuditRiskTools">
           AllowOverride All
           Require all granted
       </Directory>
   </VirtualHost>
   ```
   - Edit file hosts: `C:\Windows\System32\drivers\etc\hosts`
   - Tambahkan: `127.0.0.1 srm-audit.local`
   - Restart Apache

### 5️⃣ Akses Aplikasi

**Option A - Jika di htdocs:**
```
http://localhost/AuditRiskTools
```

**Option B - Jika pakai Virtual Host:**
```
http://srm-audit.local
```

**Option C - Langsung dari folder:**
```
http://localhost:3000
(atau port yang digunakan Apache)
```

---

## ✅ Testing Koneksi

### Test 1: Cek Database Connection
1. Buka browser
2. Akses: `http://localhost/AuditRiskTools/test_connection.php`
3. Jika berhasil, akan muncul: "✅ Database connected successfully!"

### Test 2: Register User Pertama
1. Akses: `http://localhost/AuditRiskTools/register.php`
2. Isi form registrasi
3. Login di: `http://localhost/AuditRiskTools/login.php`

---

## 🐛 Troubleshooting

### ❌ Error: "Database Connection Error"
**Solusi:**
- Pastikan MySQL di XAMPP sudah running (hijau)
- Cek username/password di `functions/db.php`
- Pastikan database `audit` sudah dibuat di phpMyAdmin

### ❌ Error: "Access denied for user"
**Solusi:**
- Username atau password salah
- Default XAMPP: user='root', password='' (kosong)
- Update di file `functions/db.php`

### ❌ Error: "Unknown database 'audit'"
**Solusi:**
- Database belum dibuat
- Import file `database_schema.sql` ke phpMyAdmin

### ❌ Error: "Cannot modify header information"
**Solusi:**
- Pastikan tidak ada spasi/enter sebelum `<?php`
- Cek encoding file PHP (harus UTF-8 without BOM)

### ❌ Halaman tidak muncul
**Solusi:**
- Pastikan Apache di XAMPP running
- Cek URL sudah benar
- Cek folder ada di htdocs

---

## 📁 Struktur File

```
AuditRiskTools/
├── index.php              ← Entry point
├── login.php              ← Login page
├── register.php           ← Registration
├── dashboard.php          ← Main dashboard
├── organizations.php      ← Manage orgs
├── audit_sessions.php     ← Audit sessions
├── asset_manage.php       ← Asset management
├── findings.php           ← Findings
├── report.php             ← Reports
├── database_schema.sql    ← Database structure ⚠️ IMPORT INI!
│
├── /api                   ← Backend API
│   ├── auth_actions.php
│   ├── organization_actions.php
│   ├── audit_actions.php
│   ├── asset_actions.php
│   ├── finding_actions.php
│   └── report_actions.php
│
├── /functions             ← Core functions
│   ├── db.php            ← Database connection ⚠️ CEK INI!
│   ├── auth.php          ← Authentication
│   ├── risk.php          ← Risk calculations
│   └── ai_api.php        ← AI integration
│
├── /includes             ← Layout components
│   ├── header.php
│   ├── sidebar.php
│   └── footer.php
│
└── /uploads              ← Evidence files
```

---

## 🔐 Default Login

**Setelah database di-import, user default:**
```
Email: salwanettayumna@gmail.com
Password: Sana123!
```

**⚠️ PENTING:** Ganti password default setelah login pertama kali!

---

## 📝 Fitur Aplikasi

1. ✅ User Registration & Login
2. ✅ Organization Management
3. ✅ Audit Session Creation
4. ✅ Asset Management (CIA Triad)
5. ✅ Vulnerability Findings
6. ✅ Risk Assessment (Likelihood × Impact)
7. ✅ NIST CSF Mapping
8. ✅ AI Report Generation
9. ✅ Dashboard Analytics

---

## 🆘 Butuh Bantuan?

### Quick Start Command:
```bash
# 1. Start XAMPP services
# 2. Import database_schema.sql
# 3. Access: http://localhost/AuditRiskTools
```

### Common Issues:
- **Port 80 used**: Ubah port Apache di XAMPP config
- **MySQL not starting**: Stop service MySQL Windows jika ada
- **Permission denied**: Run XAMPP as Administrator

---

## 📚 Documentation

Lihat file `SYSTEM_DOCUMENTATION.md` untuk penjelasan lengkap tentang:
- System Architecture
- Risk Calculation Formulas
- Security Implementation
- API Documentation

---

**🎉 Selamat! Aplikasi SRM-Audit sudah ready!**
