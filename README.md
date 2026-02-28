# A PDF Document Authenticity and Tampering Detection Tool

A **Python/Flask** web application that programmatically analyzes uploaded PDF files across **five forensic modules**, produces a weighted **Trust Score (0–100)**, and generates auditable evidence reports in JSON and HTML formats.

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

## 🚀 Quick Start

### Option 1 — Local Python (Development)

```bash
# 1. Clone and enter the directory
cd CFI-TAE1

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run development server
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
| `GET /history` | Paginated analysis history table |
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

Full API docs at `GET /api/v1/docs`.

---

## 🧪 Tests

```bash
pip install -r requirements.txt
pytest
```

Test coverage targets ≥ 80% as per the PRD.

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | (random) | Flask session signing key |
| `MAX_UPLOAD_MB` | `100` | Max PDF upload size |
| `UPLOAD_FOLDER` | `/tmp/pdf_uploads` | Temp upload directory |
| `REPORT_FOLDER` | `/data/reports` | Persistent report storage |
| `DATABASE_URL` | `sqlite:///data/app.db` | SQLAlchemy DB URI |
| `REPORT_RETENTION_DAYS` | `30` | Days before records purged |
| `ENCRYPT_REPORTS` | `false` | Fernet encryption for reports |
| `POPPLER_PATH` | `None` | Override Poppler binary path |
| `RATE_LIMIT` | `60 per minute` | Flask-Limiter rate limit |

---

## 📁 Project Structure

```
CFI-TAE1/
├── app.py                  # Application factory (create_app)
├── config.py               # Dev/Prod/Test config classes
├── extensions.py           # Shared Flask extensions
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── pytest.ini
├── blueprints/
│   ├── api/routes.py       # REST API (/api/v1/...)
│   └── ui/routes.py        # Web UI (/, /upload, /result, /history)
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
│   ├── report.html         # Printable report
│   └── api_docs.html       # API reference
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

## ⚖️ Disclaimer

> Output is **decision-support evidence only** — not a legally binding certification or authentication of any document's contents. Analysis is based on automated forensic heuristics and may produce false positives or fail to detect novel tampering techniques.
