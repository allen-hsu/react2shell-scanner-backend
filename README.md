# React2Shell Scanner - Backend API

FastAPI backend for CVE-2025-55182 & CVE-2025-66478 vulnerability detection.

## Scanner Source

This tool is based on the open-source scanner from Assetnote:

- **Repository**: https://github.com/assetnote/react2shell-scanner
- **Research**: Assetnote Security Research Team

## Getting Started

```bash
pip install -r requirements.txt
python main.py
```

Or with uvicorn:

```bash
uvicorn main:app --reload --port 8000
```

API docs available at http://localhost:8000/docs

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Scan single host |
| `/api/scan/batch` | POST | Batch scan (max 100 hosts) |
| `/api/validate` | GET | Validate/normalize URL |

## Scan Modes

- **rce** - RCE PoC (executes harmless `41*271` calculation)
- **safe** - Side-channel detection (no code execution)
- **vercel-bypass** - Vercel WAF bypass variant
