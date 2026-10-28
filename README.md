# PUB PhishGuard — Web Phase 1 Starter

A responsive web frontend and Python FastAPI backend for the **PUB CSE Fest-26 A3 phishing-detection project**.

This is a local development prototype, not a production-ready security service.

## Stack

- **Frontend:** React + TypeScript + Vite
- **Backend:** Python + FastAPI
- **Database/Auth Foundation:** Supabase SQL migration with Row Level Security (RLS)

## Prerequisites

- Python 3.11+
- Node.js 20+ and npm
- Flutter is **not required** for this web project.

## 1. Run the Backend (Windows PowerShell)

Open PowerShell at the project root directory.

```powershell
Set-Location backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Once the backend starts, open these URLs in your browser:

- **Health Check:** http://127.0.0.1:8000/health
- **API Documentation:** http://127.0.0.1:8000/docs

Keep this terminal running while using the application.

## 2. Run the Web Frontend

Open a **second PowerShell terminal** at the project root directory.

```powershell
Set-Location frontend
Copy-Item .env.example .env
npm install
npm run dev
```

Open the Vite URL printed in the terminal. It is normally:

http://localhost:5173

The frontend uses the following API base URL by default:

```text
http://127.0.0.1:8000/api/v1
```

If needed, update `VITE_API_BASE_URL` in `frontend/.env` and restart the Vite development server.

Keep both the backend and frontend terminals running during local development.

## 3. Supabase Setup

1. Create a separate Supabase project for PhishGuard.
2. Open the Supabase SQL Editor.
3. Run the migration file:

   `supabase/migrations/0001_initial_schema.sql`

4. Keep the Supabase service-role key on a trusted backend only. Never expose it in frontend environment variables or public repositories.

**Note:** Phase 1 does not yet persist scans to Supabase. The migration provides the database schema and Row Level Security (RLS) foundation for later phases.

## Phase 1 — Currently Implemented

- Responsive web UI for URL and SMS/chat message scanning.
- FastAPI `GET /health` health-check endpoint.
- `POST /api/v1/scans/url` for passive, string-based URL analysis.
- `POST /api/v1/scans/message` for simple Bangla and English phrase-based analysis.
- Rule-based risk score from 0–100.
- Low, Medium, and High risk labels.
- Indicator explanations and recommendations.
- Supabase schema and RLS foundation.

## Planned for Future Phases

The following features are **not yet implemented** in Phase 1:

- Email `.eml` upload and full email-header analysis.
- SPF, DKIM, and DMARC parsing.
- Trusted-domain typosquatting checks and more comprehensive look-alike detection.
- Public-dataset training and a hybrid machine-learning model.
- Evaluation using held-out accuracy, precision, recall, and F1 metrics.
- Security-awareness quiz and score history.
- Authenticated admin dashboard.
- Scan-result persistence.
- Allow/block list management UI.

## Safety and Deployment Warning

- The scanner does not fetch or open submitted URLs. Keep this behavior for the demo.
- This prototype uses simple heuristic rules. A **Low** risk result is not proof that a URL is safe.
- The scan endpoints are currently unauthenticated and do not persist results.
- Do not expose this version as a public service before adding authentication, rate limiting, request-size limits, privacy controls, and production deployment hardening.
- Never submit real passwords, private tokens, or other sensitive information during testing.

## Demo Video

Watch our PUB_PhishGuard demonstration for the **PUB CSE Fest 2026 Hackathon**.

[**Watch the Demo Video on YouTube**](https://youtu.be/BRxzO6nC3_E)

## Project Repository

[**PUB_PhishGuard on GitHub**](https://github.com/joy6096/PUB_PhishGuard)