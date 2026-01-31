# Security App

Change app name in `app.config.json` to rebrand.

## Quick Start (Hour 2 Milestone)

**Backend** (mock mode):
```bash
cd backend && pip install -r requirements.txt && uvicorn main:app --reload --port 8000
```

**Dashboard**:
```bash
cd webapp && npm install && npm run dev
```
Open http://localhost:5173 and click "Run Test Scan".

**Extension** (Person A): Load `extension/` as unpacked in Chrome.

## Project Structure

- `backend/` - FastAPI orchestrator, agents, contracts
- `extension/` - Chrome extension (Person A)
- `webapp/` - React dashboard (Person D)
