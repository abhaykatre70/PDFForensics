# A PDF Document Authenticity and Tampering Detection Tool

**Live Application:** [pdf-forensics.vercel.app](https://pdf-forensics.vercel.app/)

A **Python/Flask** web application that programmatically analyzes uploaded PDF files across **five forensic modules**, produces a weighted **Trust Score (0–100)**, generates auditable evidence reports in JSON and HTML formats, and persists all results to a **Supabase PostgreSQL database**.

---

## ✨ Features

| Module | What it Detects |
|--------|----------------|
| **Metadata Inspector** | Future timestamps, manipulation tools (ilovepdf, smallpdf, PDFtk…), XMP↔DocInfo mismatch, missing author |
| **Signature Verifier** | ByteRange coverage, cert expiry, incremental-save attacks, unsigned sig fields |
| **Structure Analyzer** | Embedded JavaScript, Launch/OpenAction, hidden OCG layers, embedded files, hybrid xref |
| **Content Stream Parser** | Invisible text (Tr=3), complex filter chains, high font counts, form-field injection |
| **Visual Forensics** | ELA anomalies, uniform region detection, JPEG count, CCITTFax scan indicators, dimension anomalies |

### Trust Score

| Score | Classification | Action |
|-------|---------------|--------|
| 80–100 | ✅ Likely Authentic | Accept with standard logging |
| 60–79 | ⚠️ Suspicious | Route to manual review |
| 35–59 | 🚨 High Risk | Escalate to senior analyst |
| 0–34 | 🛑 Compromised | Reject; initiate incident response |

---

## 🗄️ Database Integration (Supabase)

All analysis results are **permanently stored in Supabase PostgreSQL**. Every PDF upload creates:
- An **Analysis** record — filename, trust score, classification, SHA256/MD5 hashes, timestamp
- **Finding** records — each forensic flag with severity level (CRITICAL / HIGH / MEDIUM / LOW / INFO)

Results persist across deployments and are accessible via the `/history` page.

---

## 🚀 Quick Start

### Option 1 — Local Python (Development)

```bash
# 1. Clone the repository
git clone https://github.com/abhaykatre70/PDFForensics.git
cd PDFForensics

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
# Copy .env.example to .env and fill in your Supabase credentials
# (see Environment Variables section below)

# 5. Run development server
python app.py
```

Open http://localhost:5000

### Option 2 — Docker (Production)

```bash
docker-compose up --build
```

Service will be available at http://localhost:5000 within ~60 seconds.

---

## 🌐 Web UI

| Route | Description |
|-------|-------------|
| `GET /` | Drag-and-drop upload page |
| `GET /result/<id>` | Analysis dashboard with Trust Score gauge |
| `GET /history` | Paginated analysis history (pulled from Supabase DB) |
| `GET /report/<id>` | Printable forensic report |

---

## 🔌 REST API

### Single Document Analysis
```bash
curl -X POST http://localhost:5000/api/v1/analyze \
  -F "file=@contract.pdf"
```

### URL-based Analysis
```bash
curl -X POST http://localhost:5000/api/v1/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"pdf_url": "https://example.com/document.pdf"}'
```

### Batch Analysis (up to 100 files)
```bash
curl -X POST http://localhost:5000/api/v1/analyze/batch \
  -F "files[]=@doc1.pdf" \
  -F "files[]=@doc2.pdf"
```

### Get Report
```bash
curl http://localhost:5000/api/v1/report/A3F8B21C
curl http://localhost:5000/api/v1/report/A3F8B21C/html
```

### Supabase Users API
```bash
# List all users
curl http://localhost:5000/api/v1/users

# Create a user
curl -X POST http://localhost:5000/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice", "email": "alice@example.com"}'
```

---

## 🧪 Tests

```bash
pip install -r requirements.txt
pytest
```

Test coverage targets ≥ 80% as per the PRD.

---

## ⚙️ Environment Variables

> **Required for Supabase DB integration** — get these from your [Supabase Dashboard](https://supabase.com/dashboard) → Project → Settings → API

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SUPABASE_URL` | ✅ **Yes** | — | Your Supabase project URL (e.g. `https://xyz.supabase.co`) |
| `SUPABASE_ANON_KEY` | ✅ **Yes** | — | Your Supabase anon/public API key |
| `DATABASE_URL` | ✅ **Yes** | — | PostgreSQL connection string from Supabase |
| `SECRET_KEY` | ✅ **Yes** | random | Flask session signing key |
| `FLASK_ENV` | ✅ **Yes** | `development` | Set to `production` on Vercel |
| `MAX_UPLOAD_MB` | No | `100` | Max PDF upload size (MB) |
| `UPLOAD_FOLDER` | No | `/tmp/pdf_uploads` | Temp upload directory |
| `REPORT_FOLDER` | No | `/data/reports` | Persistent report storage |
| `REPORT_RETENTION_DAYS` | No | `30` | Days before records purged |
| `ENCRYPT_REPORTS` | No | `false` | Fernet encryption for reports |
| `POPPLER_PATH` | No | `None` | Override Poppler binary path |
| `RATE_LIMIT` | No | `60 per minute` | Flask-Limiter rate limit |

### Setting Up for Vercel

Go to your Vercel project → **Settings → Environment Variables** and add:

```
SUPABASE_URL      = https://<project-ref>.supabase.co
SUPABASE_ANON_KEY = <your-anon-key>
DATABASE_URL      = postgresql://postgres.<ref>:<password>@aws-1-<region>.pooler.supabase.com:6543/postgres?sslmode=require
FLASK_ENV         = production
SECRET_KEY        = <any-long-random-string>
```

> ⚠️ **Vercel file upload limit:** Vercel's free plan enforces a ~4.5 MB serverless payload limit. For large PDF uploads (up to 100 MB), use local or Docker deployment.

---

## 📁 Project Structure

```
PDFForensics/
├── app.py                  # Application factory (create_app)
├── config.py               # Dev/Prod/Test config classes
├── extensions.py           # Shared Flask extensions
├── supabase_client.py      # Supabase client factory & helpers
├── find_region.py          # Supabase region discovery utility
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── pytest.ini
├── supabase_migrations/    # SQL migration files
│   └── 001_create_users_table.sql
├── blueprints/
│   ├── api/routes.py       # REST API (/api/v1/...)
│   └── ui/routes.py        # Web UI (/, /result, /history)
├── analyzer/
│   ├── __init__.py         # PDFAnalyzer orchestrator
│   ├── metadata.py         # Module 1: Metadata Inspector
│   ├── signatures.py       # Module 2: Signature Verifier
│   ├── structure.py        # Module 3: Structure Analyzer
│   ├── content.py          # Module 4: Content Stream Parser
│   ├── visual.py           # Module 5: Visual Forensics Engine
│   └── scoring.py          # Trust Score aggregation
├── models/
│   ├── analysis.py         # Analysis SQLAlchemy model
│   └── finding.py          # Finding SQLAlchemy model
├── templates/
│   ├── base.html
│   ├── index.html          # Upload UI with drag-and-drop
│   ├── result.html         # Analysis dashboard
│   ├── history.html        # Analysis history
│   └── report.html         # Printable report (dark/light theme)
├── static/
│   ├── css/main.css        # Premium dark design system
│   └── js/upload.js        # Upload form logic
└── tests/
    ├── conftest.py         # pytest fixtures
    ├── test_metadata.py
    ├── test_structure.py
    ├── test_scoring.py
    └── test_api.py
```

---

## 👥 Contributors

| Contributor | GitHub |
|-------------|--------|
| Abhay Katre | [@abhaykatre70](https://github.com/abhaykatre70) |
| Karan Prajapati | [@KaranPrajapati15](https://github.com/KaranPrajapati15) |

---

## ⚖️ Disclaimer

> Output is **decision-support evidence only** — not a legally binding certification or authentication of any document's contents. Analysis is based on automated forensic heuristics and may produce false positives or fail to detect novel tampering techniques.
