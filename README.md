# EURA 2.0

**EU Regulatory Compliance Platform** — Automated compliance scanning for EU Cyber Resilience Act (CRA) and EU AI Act.

## Overview

EURA scans software repositories and evaluates compliance against EU regulations:
- **CRA (Cyber Resilience Act)**: Security-by-design, vulnerability handling, documentation, SBOM requirements
- **AI Act**: AI system detection, risk classification, documentation requirements for high-risk AI

Returns deterministic `SHIP_ALLOWED` or `SHIP_BLOCKED` verdicts backed by evidence.

## Quick Start

### Prerequisites

- Python 3.11+ ([Download](https://www.python.org/downloads/))
- Git ([Download](https://git-scm.com/downloads))

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/eura.git
cd eura

# Create virtual environment (use Python 3.11)
py -3.11 -m venv venv

# Activate virtual environment
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Windows CMD:
venv\Scripts\activate.bat
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file in the project root:

```env
# GitHub App Authentication (required for private repos)
GITHUB_APP_ID=your-app-id
GITHUB_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----
your-private-key-content
-----END RSA PRIVATE KEY-----

# GitHub Personal Access Token (optional, for public repo scanning)
GITHUB_TOKEN=your-personal-access-token

# OpenAI API (required for LLM analysis)
OPENAI_API_KEY=sk-your-openai-key

# Supabase (required for persistence)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# CORS (optional)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
```

### Run the Server

```bash
# Start FastAPI server
uvicorn app.main:app --reload --port 8000

# Server: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Run Tests

```bash
pytest tests/ -v
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/scans/run` | Run compliance scan |
| GET | `/api/v1/scans/{scan_id}` | Get scan results |
| GET | `/api/v1/rules` | List all rules |
| GET | `/api/v1/projects` | List projects |
| POST | `/api/v1/sbom/generate` | Generate SBOM |

See full API documentation at `/docs` when server is running.

## Project Structure

```
eura/
├── app/                    # Backend application
│   ├── api/               # REST API endpoints
│   ├── core/              # Configuration, logging
│   ├── data/              # Rule definitions (rules_db.json)
│   ├── models/            # Domain models
│   ├── schemas/           # Pydantic request/response models
│   └── services/          # Business logic
├── backend/               # Backend context rules
├── frontend/              # Frontend context rules (React app TBD)
├── infrastructure/        # Infrastructure context rules
├── .github/               # CI/CD context rules
├── cli/                   # CLI tool
├── docs/                  # Architecture documentation
├── eura_knowledge/        # CRA/AI Act rule definitions
├── scripts/               # Utility scripts
└── tests/                 # Test suite
```

## Documentation

- **[PRD](EURA_2.0_PRD.md)** — Technical requirements and architecture
- **[Implementation Status](IMPLEMENTATION_STATUS.md)** — Current progress
- **[Implementation Todo](IMPLEMENTATION_TODO.md)** — Task breakdown
- **[Architecture](docs/WORKFLOW_AND_ARCHITECTURE.md)** — System design
- **[Compliance Flow](docs/EURA_FLOW.md)** — Rule evaluation logic

## Deployment

### Railway

The backend is configured for Railway deployment:

- `Procfile` — Web process definition
- `runtime.txt` — Python version (3.11)

Set environment variables in Railway dashboard.

### Database

Run `QUICK_START_DATABASE.sql` in Supabase SQL Editor to create all tables.

## Tech Stack

**Backend:**
- Python 3.11+, FastAPI, Pydantic
- PostgreSQL (Supabase), Redis (planned)
- OpenAI API for LLM analysis

**Frontend (planned):**
- React 18+, TypeScript, Vite
- Tailwind CSS, Shadcn/ui
- React Query

## License

Proprietary — All rights reserved.
