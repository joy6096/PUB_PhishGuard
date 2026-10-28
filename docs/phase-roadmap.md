# PUB PhishGuard — Web roadmap

1. **Phase 1: Foundation** — React web UI, FastAPI API skeleton, URL/message heuristic checks, score/explanation, Supabase schema/RLS.
2. **Phase 2: Complete detection** — email `.eml` upload, parse headers safely, sender/reply-to/display-name mismatch, SPF/DKIM/DMARC header results, risky attachment filename checks, trusted-domain typosquatting, stronger Unicode look-alike and Bangla/English rules.
3. **Phase 3: ML evaluation** — public dataset preparation, leak-resistant train/test split, baseline classifier, hybrid rules + ML score, held-out accuracy/precision/recall/F1 reporting.
4. **Phase 4: Awareness quiz** — synthetic legitimate/phishing examples, per-answer feedback, attempt history, protect answer keys behind backend policies.
5. **Phase 5: Admin & integration** — auth/roles, scan persistence, frequent indicator statistics, allow/block list management, integration/security tests, demo hardening.

Use only public/provided/synthetic datasets. Do not send phishing messages to real people, collect real credentials, reproduce real login pages, or visit suspicious links on the demo machine.
