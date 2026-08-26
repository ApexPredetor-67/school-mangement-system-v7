# DAV PS KKP School Management System — Render Testing 2

This build is based on the supplied V11 ZIP and keeps the existing visual style while moving the heavy changes into the backend.

Key changes: role-specific/public announcements, registration-only student accounts, parent-child scoping, admin CRUD/reassignment, paginated people lists, admin attendance marking, JWT API authentication, retained CSRF protection, OpenAI School AI, and a precompiled `dlib-bin` face stack.

See `RENDER_TESTING_1.md` for deployment steps.

# DAV PS KKP — School Management System

> Minimal, exhibition-friendly school ERP built on Flask + PostgreSQL/SQLite, with face-attendance, academics, report cards, portals, fees, AI and a private audit system.

## Local-first demo

This bundle is designed to run locally before you connect it to Supabase or Render.

### Requirements
- Windows 10/11
- Python 3.12
- Webcam for face-attendance testing

### Fastest run

1. Extract the ZIP.
2. Open the folder in VS Code.
3. Open PowerShell/Terminal in the project root.
4. Run:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\activate
copy .env.local.example .env
pip install -r requirements.txt
python app.py
```

Open: **http://127.0.0.1:5000**

You can also run `run_local.bat` after installing Python 3.12.

## Accounts

There are no bundled demo students, teachers or parents. The initial admin account is created from `INITIAL_ADMIN_USERNAME` and `INITIAL_ADMIN_PASSWORD`; students are created only through student registration, while teachers and parents are created by an administrator.

## Main modules

- Student admissions and student information
- School logo branding using the supplied DAV PS KKP report-card logo
- Previous-school history and guardian information
- Daily attendance with manual correction and face-recognition path
- Term I / Term II / whole-year attendance analysis
- Teacher assignments
- PT-1 /40
- PT-2 /80
- PT-3 /40
- Final Examination /80
- Automatic total / percentage / grade
- Excel marks import
- Excel/PDF exports
- Printable report cards
- Student and parent portals
- Admin publishing of results to a whole class at once
- Teacher signature pad + stored signature
- Announcements 📢
- Fee ledger, payments and receipts
- Role-aware School AI using the OpenAI Responses API
- IP restrictions for staff/admin/attendance
- Private, separate audit log with chained hashes

## Access model

Students and parents are intentionally public-facing.

Admin, teacher, attendance and academic staff routes are protected by:

1. HTTPS/login
2. Role authorization
3. `STAFF_ALLOWED_IPS`

The private audit route has a separate IP allowlist and credentials.

For local development, `STAFF_ALLOWED_IPS=127.0.0.1,::1`.

## Academic subjects

### Classes IX–X
- English
- Mathematics
- Social Science
- Physics
- Chemistry
- Biology
- Information Technology
- One second language: Telugu / Hindi / Sanskrit

### Classes V–VIII
- English
- Mathematics
- Social Science
- Science
- Computers
- One second language: Telugu / Hindi / Sanskrit
- One third language: Telugu / Hindi / Sanskrit

## Grades

A1 91–100 · A2 81–90 · B1 71–80 · B2 61–70 · C1 51–60 · C2 41–50 · D 33–40 · E below 33

## Report card

The generated report card is based on the physical school report-card layout you provided as a visual template. It includes student information, attendance, all four assessments, totals, grades, co-scholastic placeholders, discipline, health placeholders and teacher signature support.

## Supabase / Render

For production, use Supabase PostgreSQL + Storage and Render for the Flask service.

Do not commit `.env`, Supabase secret keys, Gemini keys or private audit credentials.

## Latest local-debug fixes
- Fixed the Jinja `current_account` undefined error.
- Fixed the Results template formatting bug (`{{got:g}}`).
- Added a visible Sign out button in the top bar and sidebar.
- Student username is now required when registering a student.
- Student temporary password is required and must be 8+ characters.
- Restored the School Calendar with monthly view, working/non-working overrides, reset, bulk/import APIs, and a read-only teacher/student/parent view.
- Calendar API now works for any signed-in user for viewing; only admins can modify it.


## Final local-test notes
- Report cards are generated from an original school-style design, not a copy of the physical paper template.
- Teachers/admins can configure report-card remarks, co-scholastic grades, discipline, health, house, class teacher, session dates and /5 assessment components.
- Class sections are mandatory for every student.
- Timetable functionality is removed.
- Fees are admin-only.
- Scan Attendance is deliberately not shown in navigation.
- Staff routes are protected by `STAFF_ALLOWED_IPS`; audit has its own `AUDIT_LOG_ALLOWED_IPS`.
- Render web-service inbound IP restrictions are a separate edge/network control and are not available on Render Free; for production staff IP restriction, use Render inbound IP rules on a supported plan or put the staff UI behind another network control.

## Public announcements
`/announcements` is intentionally public and requires **no login**. Anonymous visitors only see `public` announcements. Signed-in users see only their role audience plus `all`.

## Local credential reset
If an old local database causes a login failure, use `reset_local_and_show.bat` to create a fresh demo database and print the current demo credentials.
