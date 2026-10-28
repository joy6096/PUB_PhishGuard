# API contract — Phase 1

Base path: `/api/v1`

## GET `/health`
`{"status":"ok","service":"pub-phishguard-api","phase":1}`

## POST `/scans/url`
Request: `{"url":"https://pub-scholarship-example.test/login"}`

## POST `/scans/message`
Request: `{"text":"আপনি পুরস্কার জিতেছেন। এখনই লগইন করুন।","language_hint":"bn"}`

Both scan routes return `input_type`, `risk_score` (0–100), `risk_level` (`low|medium|high`), `verdict`, `indicators[]`, `recommended_actions[]`, and `disclaimer`.

Phase 1 routes are unauthenticated and do not persist results. Keep them local only until JWT verification, authorization, rate limiting, and persistence are implemented.
