# 🛡️ AI-Driven Compliance Engine

A full-stack compliance automation platform that scans infrastructure/log data against configurable security rules, uses machine learning to catch anomalies static rules miss, and generates audit-ready reports — with role-based access control and a full audit trail.

Built as a portfolio project to demonstrate applied security engineering: rule-based detection, ML-driven risk scoring, secure API design, and compliance reporting in one working system.

## Features

- **Dynamic rule engine** — compliance rules stored in a database (not hardcoded), mapped to real frameworks (ISO 27001, PCI DSS, SOC 2, GDPR)
- **ML anomaly detection** — Isolation Forest flags statistically unusual records independent of rule-based checks
- **JWT authentication + RBAC** — Admin / Auditor / Analyst roles with different permissions
- **Audit trail** — every sensitive action (rule changes, scans, report generation) is logged with who/what/when
- **Dashboard** — compliance score, severity breakdown, recent findings, interactive charts
- **PDF report generation** — audit-ready compliance reports with preview before download
- **Automated tests** — pytest coverage for rule engine logic and API auth behavior

## Tech Stack

| Layer | Tech |
|---|---|
| Backend | Python, FastAPI |
| Database | SQLite + SQLAlchemy |
| ML | scikit-learn (Isolation Forest), Pandas |
| Auth | JWT, bcrypt (passlib) |
| Frontend | HTML, CSS, JavaScript, Chart.js |
| Reports | ReportLab (PDF generation) |
| Testing | pytest |

## Architecture
```
CSV Upload → Rule Engine (DB-driven checks) → ML Anomaly Detection
    → Results stored in DB (Scan + Violation records)
    → Dashboard / Reports / Audit Log read from DB
```


## Setup

```bash
# Clone the repo
git clone https://github.com/meowddler/ai-compliance-engine.git
cd ai-compliance-engine

# Create virtual environment
python -m venv venv
venv\Scripts\Activate.ps1      # Windows PowerShell
# source venv/bin/activate     # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Initialize database + seed sample rules and users
python -m backend.init_db
python -m backend.seed_rules
python -m backend.seed_users

# Run the backend
uvicorn backend.app:app --reload
```

Then open `frontend/login.html` in your browser.

**Default login:**
| Username | Password | Role |
|---|---|---|
| admin | admin123 | Admin |
| auditor1 | auditor123 | Auditor |
| analyst1 | analyst123 | Analyst |

## Running Tests

```bash
python -m pytest tests/ -v
```

## Why Isolation Forest?

Chosen over alternatives like One-Class SVM or Autoencoders because it requires no labeled data (unsupervised), performs well on small-to-medium tabular data, and is fast to train — a good fit for this use case where "anomalous" isn't predefined.

## Limitations (MVP scope)

- SQLite used for simplicity; swapping to PostgreSQL only requires changing the connection string in `backend/database.py`
- Sample/synthetic data used for demonstration — not tested against production-scale datasets
- Compliance scoring uses a simplified weighted formula (documented in `backend/app.py`)

## Author

Built by [meowddler](https://github.com/meowddler) as a hands-on security engineering portfolio project.