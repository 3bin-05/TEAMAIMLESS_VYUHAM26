# AEGIS Backend Service

FastAPI-powered cybersecurity & phishing detection engine.

---

## Quick Start

### 1. Activate Virtual Environment
```powershell
# Windows
.\.venv\Scripts\Activate.ps1
```
```bash
# Linux / macOS
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Development Server
```powershell
.\.venv\Scripts\python.exe main.py
```
Or with Uvicorn:
```powershell
.\.venv\Scripts\uvicorn.exe main:app --host 127.0.0.1 --port 8000 --reload
```

---

## Endpoints

- **Health Check**: `GET http://127.0.0.1:8000/api/v1/health`
- **Readiness Check**: `GET http://127.0.0.1:8000/api/v1/ready`
- **Analyze Single URL**: `POST http://127.0.0.1:8000/api/v1/analyze`
  ```json
  {
    "url": "https://example.com"
  }
  ```
- **Batch Analyze**: `POST http://127.0.0.1:8000/api/v1/analyze-batch`
- **Interactive Swagger Documentation**: `http://127.0.0.1:8000/docs`

---

## Running Tests

```powershell
.\.venv\Scripts\pytest
```
