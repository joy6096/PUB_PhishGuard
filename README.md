# PUB PhishGuard — Web Phase 1 Starter

A brand-new responsive web frontend + Python FastAPI backend for the PUB CSE Fest-26 A3 phishing-detection project. This is a local development prototype, not a production-ready security service.

## Stack
- Frontend: React + TypeScript + Vite
- Backend: Python + FastAPI
- Database/auth foundation: Supabase SQL migration with Row Level Security (RLS)

## Prerequisites
- Python 3.11+
- Node.js 20+ and npm
- Flutter is **not required** for this web project

## 1. Run the backend (Windows PowerShell)
Open a terminal at the project root:

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Check `http://127.0.0.1:8000/health` and `http://127.0.0.1:8000/docs`.

## 2. Run the web frontend
Open a **second** terminal at the project root:

```powershell
cd frontend
Copy-Item .env.example .env
npm install
npm run dev
```

Open the Vite URL printed in the terminal, normally `http://localhost:5173`.
The frontend calls `http://127.0.0.1:8000/api/v1` by default. Change `VITE_API_BASE_URL` in `frontend/.env` if needed; restart Vite after changing it.

## 3. Supabase setup
1. Create a separate Supabase project for PhishGuard.
2. Open SQL Editor.
3. Run `supabase/migrations/0001_initial_schema.sql`.
4. Keep the service-role key on a trusted backend only; never put it in frontend environment variables.

Phase 1 does not yet persist scans to Supabase. The migration is the database/RLS foundation for later phases.

## Phase 1 currently implemented
- Responsive web UI for URL and SMS/chat message scanning.
- FastAPI `GET /health`.
- `POST /api/v1/scans/url` passive string-based URL analysis.
- `POST /api/v1/scans/message` simple Bangla/English phrase rules.
- Rule-based 0–100 risk score, Low/Medium/High label, indicator explanation and recommendations.
- Supabase schema/RLS starting point.

## Not implemented yet (planned phases)
- Email `.eml` upload and full header analysis, SPF/DKIM/DMARC parsing.
- Trusted-domain typosquatting checks and fuller look-alike detection.
- Public dataset training, hybrid ML model, and held-out accuracy/precision/recall/F1 metrics.
- Awareness quiz and score history.
- Authenticated admin dashboard, scan persistence, allow/block list UI.

## Safety and deployment warning
- The scanner does not fetch or open submitted URLs; keep it that way for the demo.
- This prototype uses simple heuristic rules; a Low result is not proof of safety.
- The scan endpoints are currently unauthenticated and do not persist results. Do not expose this version as a public service before adding authentication, rate limits, request limits, privacy controls and production deployment hardening.
