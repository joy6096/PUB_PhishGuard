
import { useEffect, useState } from 'react';
import type { CSSProperties } from 'react';
import AwarenessQuiz from './components/AwarenessQuiz';
import AdminDashboard, { type ScanHistoryEntry } from './components/AdminDashboard';
import {
  ShieldCheck,
  ScanSearch,
  Link2,
  MessageSquareText,
  Mail,
  ArrowUpRight,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  LoaderCircle,
  LockKeyhole,
  BookOpen,
  Activity,
  Upload,
  FileText,
  X,
  Languages,
  Info,
  Landmark,
  BarChart3,
} from 'lucide-react';

type Indicator = {
  code: string;
  category: string;
  severity: string;
  weight: number;
  evidence: string;
  explanation: string;
  source?: string;
};

type EmailAttachment = {
  filename: string;
  content_type: string;
  disposition: string;
};

type EmailHeaders = {
  from: string | null;
  to: string | null;
  reply_to: string | null;
  return_path: string | null;
  subject: string | null;
  date: string | null;
  message_id: string | null;
  authentication_results: string | null;
  received_spf: string | null;
};

type EmailMetadata = {
  filename: string;
  headers: EmailHeaders;
  attachments: EmailAttachment[];
  body_extracted: boolean;
};

type ScanResult = {
  input_type: string;
  risk_score: number;
  risk_level: string;
  verdict: string;
  indicators: Indicator[];
  recommended_actions: string[];
  disclaimer: string;
  email_metadata?: EmailMetadata;
};

type Mode = 'url' | 'message' | 'email';

const MAX_EML_BYTES = 1_000_000;

const API_BASE = (
  import.meta.env.VITE_API_BASE_URL ||
  'http://127.0.0.1:8000/api/v1'
).replace(/\/$/, '');

function errorMessage(data: unknown, status: number): string {
  if (typeof data === 'object' && data !== null && 'detail' in data) {
    const detail = data.detail;

    if (typeof detail === 'string') {
      return detail;
    }

    if (Array.isArray(detail)) {
      return detail
        .map((item: { msg?: string }) => item?.msg || 'Invalid input')
        .join('; ');
    }
  }

  return `Scan failed (${status}).`;
}

export default function App() {
  const [mode, setMode] = useState<Mode>('url');
  const [url, setUrl] = useState('');
  const [message, setMessage] = useState('');
  const [email, setEmail] = useState('');
  const [emlFile, setEmlFile] = useState<File | null>(null);

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);

  const [apiStatus, setApiStatus] = useState<
    'unknown' | 'online' | 'offline'
  >('unknown');

  useEffect(() => {
    let cancelled = false;

    async function checkApiHealth() {
      try {
        const response = await fetch('http://127.0.0.1:8000/health', {
          method: 'GET',
          cache: 'no-store',
        });

        if (!response.ok) {
          throw new Error('Health check failed');
        }

        const data: { status?: string } = await response.json();

        if (!cancelled) {
          setApiStatus(data.status === 'ok' ? 'online' : 'offline');
        }
      } catch {
        if (!cancelled) {
          setApiStatus('offline');
        }
      }
    }

    void checkApiHealth();

    return () => {
      cancelled = true;
    };
  }, []);

  // Awareness Quiz navigation state
  const [quizOpen, setQuizOpen] = useState(false);
  const [adminOpen, setAdminOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>(() => {
    try {
      const saved = localStorage.getItem('phishguard_scan_history_v1');
      return saved ? (JSON.parse(saved) as ScanHistoryEntry[]) : [];
    } catch { return []; }
  });

  function goHome() { setQuizOpen(false); setAdminOpen(false); setAboutOpen(false); window.scrollTo({ top: 0, behavior: 'smooth' }); }
  function goAdmin() { setQuizOpen(false); setAboutOpen(false); setAdminOpen(true); window.scrollTo({ top: 0, behavior: 'smooth' }); }
  function goQuiz() { setAdminOpen(false); setAboutOpen(false); setQuizOpen(true); window.scrollTo({ top: 0, behavior: 'smooth' }); }
  function goAbout() { setQuizOpen(false); setAdminOpen(false); setAboutOpen(true); window.scrollTo({ top: 0, behavior: 'smooth' }); }
  function clearScanHistory() {
    setScanHistory([]);
    try { localStorage.removeItem('phishguard_scan_history_v1'); } catch { /* storage may be disabled */ }
  }

  function changeMode(nextMode: Mode) {
    setMode(nextMode);
    setError('');
    setResult(null);
  }

  function selectEmlFile(file: File | null) {
    setError('');
    setResult(null);

    if (!file) {
      setEmlFile(null);
      return;
    }

    if (!file.name.toLowerCase().endsWith('.eml')) {
      setEmlFile(null);
      setError('Please select a file with the .eml extension.');
      return;
    }

    if (file.size > MAX_EML_BYTES) {
      setEmlFile(null);
      setError('The .eml file must be 1 MB or smaller.');
      return;
    }

    setEmlFile(file);
  }

  async function scan() {
    setError('');
    setResult(null);

    const value =
      mode === 'url'
        ? url.trim()
        : mode === 'email'
          ? email.trim()
          : message.trim();

    if (mode === 'email' && emlFile) {
      if (!emlFile.name.toLowerCase().endsWith('.eml')) {
        setError('Please select a valid .eml file.');
        return;
      }

      if (emlFile.size > MAX_EML_BYTES) {
        setError('The .eml file must be 1 MB or smaller.');
        return;
      }
    } else if (!value) {
      setError(
        mode === 'url'
          ? 'Enter a URL to analyse.'
          : mode === 'email'
            ? 'Paste an email or select an .eml file.'
            : 'Paste a message to analyse.',
      );
      return;
    }

    setBusy(true);

    try {
      let response: Response;

      if (mode === 'email' && emlFile) {
        const formData = new FormData();
        formData.append('file', emlFile);

        response = await fetch(`${API_BASE}/scans/email/eml`, {
          method: 'POST',
          body: formData,
        });
      } else {
        let body: Record<string, string>;

        if (mode === 'url') {
          body = { url: value };
        } else if (mode === 'email') {
          body = { email_text: value };
        } else {
          body = {
            text: value,
            language_hint: 'auto',
          };
        }

        response = await fetch(`${API_BASE}/scans/${mode}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(body),
        });
      }

      if (!response.ok) {
        const data = await response.json().catch(() => null);
        throw new Error(errorMessage(data, response.status));
      }

      const data: ScanResult = await response.json();

      setResult(data);
      setApiStatus('online');
      let target = mode === 'url' ? value : mode === 'email' ? (emlFile?.name || 'Email content') : 'SMS / Chat message';
      if (mode === 'url') { try { target = new URL(value).hostname; } catch { /* keep supplied text if URL parsing fails */ } }
      const historyEntry: ScanHistoryEntry = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        date: new Date().toISOString(),
        type: mode === 'message' ? 'SMS / Chat' : mode.toUpperCase(),
        target: target.slice(0, 100),
        score: Math.max(0, Math.min(100, Number(data.risk_score) || 0)),
        level: data.risk_level || 'Unknown',
        verdict: data.verdict || 'Scan completed',
        indicators: (data.indicators || []).map((item) => item.code).filter(Boolean),
      };
      setScanHistory((previous) => {
        const next = [historyEntry, ...previous].slice(0, 100);
        try { localStorage.setItem('phishguard_scan_history_v1', JSON.stringify(next)); } catch { /* storage may be disabled */ }
        return next;
      });
    } catch (e) {
      setApiStatus('offline');

      setError(
        e instanceof Error
          ? `${e.message} Check that the Python API is running at ${API_BASE}.`
          : 'Could not reach the API.',
      );
    } finally {
      setBusy(false);
    }
  }

  const score = Math.max(
    0,
    Math.min(100, result?.risk_score ?? 0),
  );

  const risk = (result?.risk_level || '').toLowerCase();

  const riskClass =
    risk === 'high'
      ? 'high'
      : risk === 'medium'
        ? 'medium'
        : 'low';

  const inputLabel =
    mode === 'url'
      ? 'Suspicious URL'
      : mode === 'email'
        ? 'Email content and headers'
        : 'Message content';

  const inputHint =
    mode === 'url'
      ? 'Paste the full URL, including https://. The scanner does not open it.'
      : mode === 'email'
        ? 'Paste email text or upload an .eml file. Attachments are not opened.'
        : 'Paste a suspicious SMS or chat message. Bangla and English text are supported by the current rules.';

  const placeholder =
    mode === 'url'
      ? 'https://example.com/verify-account'
      : mode === 'email'
        ? 'From: Support <sender@example.com>\nReply-To: reply@example.net\nSubject: Verify your account\n\nPaste the email body here...'
        : 'Paste a suspicious SMS or chat message here...';

  // About opens as its own in-app page (not a new browser tab).
  if (aboutOpen) {
    return (
      <div className="app-shell">
        <header className="topbar">
          <a className="brand" href="#top" onClick={(event) => { event.preventDefault(); goHome(); }}>
            <span className="brand-icon"><ShieldCheck size={22} /></span>
            <span>PUB <b>PhishGuard</b><small>Phishing detection &amp; awareness</small></span>
          </a>
          <nav className="main-nav" aria-label="Main navigation">
            <button type="button" onClick={goHome}><ShieldCheck size={16} /> Home</button>
            <button type="button" onClick={goAdmin}><Activity size={16} /> Admin Dashboard</button>
            <button type="button" onClick={goQuiz}><BookOpen size={16} /> Awareness Quiz</button>
            <button type="button" className="active" aria-current="page" onClick={goAbout}><Info size={16} /> About</button>
          </nav>
          <div className="top-actions"><span className="demo-label">ABOUT THE PROJECT</span></div>
        </header>
        <main id="top">
        <section className="about-section about-page" aria-labelledby="about-title">
          <div className="about-heading">
            <span className="about-kicker"><Info size={15} /> ABOUT THE PROJECT</span>
            <h2 id="about-title">About <em>PUB PhishGuard</em></h2>
            <p className="about-lead">
              PUB PhishGuard is a cybersecurity awareness and phishing detection web application
              designed to help users identify potentially malicious URLs, suspicious emails, and scam messages.
            </p>
          </div>

          <div className="about-description">
            <span className="about-large-icon"><ShieldCheck size={30} /></span>
            <p>
              The platform combines rule-based detection techniques with Machine Learning to analyze
              suspicious content and provide clear, understandable explanations of potential security risks.
              It also promotes safe online behavior through cybersecurity awareness resources and educational quizzes.
            </p>
            <p>
              Developed as an academic project for <strong>PUB CSE Fest-26</strong>, PUB PhishGuard aims
              to make phishing detection and cybersecurity awareness more accessible to students and everyday internet users.
            </p>
          </div>

          <div className="about-card-grid">
            <article className="info-card about-info-card">
              <span className="about-card-icon"><ShieldCheck size={22} /></span>
              <h3>Our Mission</h3>
              <p>
                Our mission is to promote safer digital experiences by helping users recognize phishing
                threats, understand potential online risks, and make informed decisions before clicking
                suspicious links or interacting with questionable messages.
              </p>
            </article>

            <article className="info-card about-info-card">
              <span className="about-card-icon"><ScanSearch size={22} /></span>
              <h3>Key Features</h3>
              <ul>
                <li>Suspicious URL analysis</li>
                <li>Email and SMS/chat message checking</li>
                <li>Rule-based and ML-assisted URL detection</li>
                <li>Explainable results and awareness quiz</li>
              </ul>
            </article>

            <article className="info-card about-info-card">
              <span className="about-card-icon"><BookOpen size={22} /></span>
              <h3>Our Goal</h3>
              <p>
                To make cybersecurity awareness simple, accessible, and practical for everyone through
                understandable risk explanations and useful online safety education.
              </p>
            </article>
          </div>

          <div className="about-project-footer">
            <span><LockKeyhole size={17} /> Think before you click</span>
          </div>
          <p className="about-disclaimer">
            <strong>Disclaimer:</strong> Scan results are an aid to awareness, not a guarantee that a link
            or message is safe or malicious. Never submit passwords, OTPs, or other confidential information.
          </p>
        </section>

          <footer>
            <span>Think before you click</span>
          </footer>
        </main>
      </div>
    );
  }

  // Admin view shares the app shell while keeping the scanner state intact.
  if (adminOpen) {
    return (
      <div className="app-shell">
        <header className="topbar">
          <a className="brand" href="#top" onClick={(event) => { event.preventDefault(); goHome(); }}>
            <span className="brand-icon"><ShieldCheck size={22} /></span>
            <span>PUB <b>PhishGuard</b><small>Phishing detection &amp; awareness</small></span>
          </a>
          <nav className="main-nav" aria-label="Main navigation">
            <button type="button" onClick={goHome}><ShieldCheck size={16} /> Home</button>
            <button type="button" className="active" aria-current="page"><Activity size={16} /> Admin Dashboard</button>
            <button type="button" onClick={goQuiz}><BookOpen size={16} /> Awareness Quiz</button>
            <button type="button" onClick={goAbout}>About</button>
          </nav>
          <div className="top-actions"><span className={`api-pill ${apiStatus}`}><i />API {apiStatus === 'online' ? 'connected' : apiStatus === 'offline' ? 'unreachable' : 'status unknown'}</span></div>
        </header>
        <main id="top"><AdminDashboard history={scanHistory} onClearHistory={clearScanHistory} /></main>
      </div>
    );
  }

  // Show the quiz as a separate screen without removing scanner state.
  if (quizOpen) {
    return (
      <div className="app-shell">
        <header className="topbar">
          <a
            className="brand"
            href="#top"
            onClick={(event) => {
              event.preventDefault();
              setQuizOpen(false);
            }}
          >
            <span className="brand-icon">
              <ShieldCheck size={22} />
            </span>

            <span>
              PUB <b>PhishGuard</b>
              <small>Phishing detection &amp; awareness</small>
            </span>
          </a>

          <nav className="main-nav" aria-label="Main navigation">
            <button type="button" onClick={goHome}><ShieldCheck size={16} /> Home</button>
            <button type="button" onClick={goAdmin}><Activity size={16} /> Admin Dashboard</button>
            <button type="button" className="active" aria-current="page"><BookOpen size={16} /> Awareness Quiz</button>
            <button type="button" onClick={goAbout}>About</button>
          </nav>
          <div className="top-actions"><span className="demo-label">AWARENESS QUIZ</span></div>
        </header>

        <main id="top">
          <AwarenessQuiz />
        </main>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top">
          <span className="brand-icon">
            <ShieldCheck size={22} />
          </span>

          <span>
            PUB <b>PhishGuard</b>
            <small>Phishing detection &amp; awareness</small>
          </span>
        </a>

        <nav className="main-nav" aria-label="Main navigation">
          <button type="button" className={!adminOpen && !quizOpen ? 'active' : ''} aria-current={!adminOpen && !quizOpen ? 'page' : undefined} onClick={goHome}><ShieldCheck size={16} /> Home</button>
          <button type="button" onClick={goAdmin}><Activity size={16} /> Admin Dashboard</button>
          <button type="button" onClick={goQuiz}><BookOpen size={16} /> Awareness Quiz</button>
          <button type="button" onClick={goAbout}>About</button>
        </nav>

        <div className="top-actions">
          <span className={`api-pill ${apiStatus}`}>
            <i />
            API{' '}
            {apiStatus === 'online'
              ? 'connected'
              : apiStatus === 'offline'
                ? 'unreachable'
                : 'status unknown'}
          </span>

          
          <Landmark className="institution-mark" size={26} />
        </div>
      </header>

      <main id="top">
        <section className="hero">
          <div className="hero-copy">
            

            <h1 className="hero-headline">
              STAY ONE <em>STEP AHEAD</em>
            </h1>
            <h2 className="hero-subheadline">Spot the threat. <em>Stop the scam.</em></h2>
            <p>
              Check suspicious links, emails and messages with explainable signals.<br className="desktop-break" />
              Learn what looks risky before you click, reply, or share.
            </p>
          </div>

          <div className="hero-features" aria-label="PhishGuard features">
            <div className="hero-feature">
              <span className="feature-icon purple"><FileText size={27} /></span>
              <b>Explainable results</b>
              <small>Know why it looks risky</small>
            </div>
            <div className="hero-feature">
              <span className="feature-icon blue"><Languages size={28} /></span>
              <b>Bangla + English</b>
              <small>detections</small>
            </div>
            <div className="hero-feature">
              <span className="feature-icon teal"><ShieldCheck size={29} /></span>
              <b>Passive analysis</b>
              <small>Scan without<br />submitting</small>
            </div>
          </div>
        </section>

        <section className="workspace">
          <div className="scanner-panel">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">SCANNER</span>
                <h2>What would you like to check?</h2>
                <p>Submit suspicious text for passive analysis.</p>
              </div>

              <span className="lock-badge">
                <LockKeyhole size={15} /> Passive scan
              </span>
            </div>

            <div className="mode-tabs">
              <button
                className={mode === 'url' ? 'active' : ''}
                onClick={() => changeMode('url')}
                type="button"
              >
                <Link2 size={17} /> URL
              </button>

              <button
                className={mode === 'message' ? 'active' : ''}
                onClick={() => changeMode('message')}
                type="button"
              >
                <MessageSquareText size={17} /> SMS / Chat
              </button>

              <button
                className={mode === 'email' ? 'active' : ''}
                onClick={() => changeMode('email')}
                type="button"
              >
                <Mail size={17} /> Email
              </button>
            </div>

            <div className="input-area">
              <label htmlFor="scan-input">{inputLabel}</label>

              {mode === 'url' ? (
                <input
                  id="scan-input"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') void scan();
                  }}
                  placeholder={placeholder}
                  autoComplete="off"
                />
              ) : (
                <textarea
                  id="scan-input"
                  value={mode === 'email' ? email : message}
                  onChange={(e) =>
                    mode === 'email'
                      ? setEmail(e.target.value)
                      : setMessage(e.target.value)
                  }
                  placeholder={placeholder}
                  rows={mode === 'email' ? 9 : 5}
                />
              )}

              <div className="input-hint">{inputHint}</div>
            </div>

            {mode === 'email' && (
              <div className="eml-upload">
                <div className="eml-upload-title">
                  <Upload size={17} />
                  <div>
                    <b>Upload an email file</b>
                    <small>Supported format: .eml · Maximum 1 MB</small>
                  </div>
                </div>

                <label className="file-picker" htmlFor="eml-file">
                  <FileText size={17} />
                  Choose .eml file
                </label>

                <input
                  id="eml-file"
                  className="eml-file-input"
                  type="file"
                  accept=".eml,message/rfc822"
                  onChange={(e) => {
                    selectEmlFile(e.target.files?.[0] ?? null);
                    e.currentTarget.value = '';
                  }}
                />

                {emlFile && (
                  <div className="selected-file">
                    <CheckCircle2 size={16} />

                    <span>
                      <b>{emlFile.name}</b>
                      <small>{(emlFile.size / 1024).toFixed(1)} KB</small>
                    </span>

                    <button
                      type="button"
                      onClick={() => selectEmlFile(null)}
                      aria-label="Remove selected email file"
                    >
                      <X size={15} /> Remove
                    </button>
                  </div>
                )}

                {emlFile && email.trim() && (
                  <p className="file-priority-note">
                    The uploaded .eml file will be scanned instead of the
                    pasted email text.
                  </p>
                )}
              </div>
            )}

            {error && (
              <div className="error-box" role="alert">
                <AlertTriangle size={17} />
                <span>{error}</span>
              </div>
            )}

            <button
              className="scan-button"
              onClick={() => void scan()}
              disabled={busy}
              type="button"
            >
              {busy ? (
                <>
                  <LoaderCircle size={18} className="spin" />
                  Analysing…
                </>
              ) : (
                <>
                  <ScanSearch size={18} />
                  Analyse safely
                  <ArrowUpRight size={17} />
                </>
              )}
            </button>

            <div className="privacy-note">
              <LockKeyhole size={14} />
              Never open suspicious links to test them. Avoid pasting real
              passwords, OTPs, or other secrets. Uploaded email files are sent
              to your configured analysis API.
            </div>
          </div>

          <div className="result-panel">
            {result ? (
              <>
                <div className="result-top">
                  <div>
                    <span className="section-kicker">SCAN REPORT</span>
                    <h2>Your result</h2>
                    <p className="input-hint">
                      Scan type: {result.input_type}
                    </p>
                  </div>

                  <span className={`risk-pill ${riskClass}`}>
                    {result.risk_level}
                  </span>
                </div>

                <div
                  className={`score-ring ${riskClass}`}
                  style={
                    { '--score': `${score * 3.6}deg` } as CSSProperties
                  }
                >
                  <div className="score-inner">
                    <strong>{score}</strong>
                    <span>out of 100</span>
                  </div>
                </div>

                <p className="result-summary">{result.verdict}</p>

                <div className="indicators-heading">
                  <b>Indicators found</b>
                  <span>{result.indicators.length} signals</span>
                </div>

                {result.input_type === 'url' && (
                  <div className="ml-status-card">
                    <Activity size={20} />

                    <div>
                      <b>Hybrid detection enabled</b>
                      <p>
                        URL analysis combines static detection rules with a
                        Random Forest machine-learning signal when the model
                        meets its configured phishing threshold.
                      </p>
                    </div>
                  </div>
                )}

                {result.indicators.length > 0 ? (
                  <div className="indicator-list">
                    {result.indicators.map((item, i) => {
                      const isML = item.source?.toLowerCase() === 'ml';

                      return (
                        <div
                          className={`indicator ${
                            isML ? 'indicator-ml' : 'indicator-rule'
                          }`}
                          key={`${item.code}-${i}`}
                        >
                          <span className="indicator-mark">
                            <ShieldAlert size={16} />
                          </span>

                          <div className="indicator-content">
                            <b>{item.code.replace(/_/g, ' ')}</b>

                            <span
                              className={`indicator-source ${
                                isML ? 'source-ml' : 'source-rule'
                              }`}
                            >
                              {isML
                                ? 'MACHINE LEARNING'
                                : 'DETECTION RULE'}
                            </span>

                            <p>
                              {item.explanation}
                              {item.evidence
                                ? ` Evidence: ${item.evidence}`
                                : ''}
                            </p>

                            <small>
                              Severity: {item.severity} · Weight: {item.weight}
                            </small>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="empty-indicators">
                    <CheckCircle2 size={18} />
                    No suspicious indicators were detected by the current
                    prototype. This does not guarantee safety.
                  </div>
                )}

                {result.email_metadata && (
                  <section className="email-metadata">
                    <div className="metadata-heading">
                      <Mail size={17} />
                      <b>Email file details</b>
                    </div>

                    <p>
                      <strong>Filename:</strong>{' '}
                      {result.email_metadata.filename}
                    </p>

                    <p>
                      <strong>From:</strong>{' '}
                      {result.email_metadata.headers.from || 'Not provided'}
                    </p>

                    <p>
                      <strong>To:</strong>{' '}
                      {result.email_metadata.headers.to || 'Not provided'}
                    </p>

                    <p>
                      <strong>Reply-To:</strong>{' '}
                      {result.email_metadata.headers.reply_to || 'Not provided'}
                    </p>

                    <p>
                      <strong>Return-Path:</strong>{' '}
                      {result.email_metadata.headers.return_path || 'Not provided'}
                    </p>

                    <p>
                      <strong>Subject:</strong>{' '}
                      {result.email_metadata.headers.subject || 'Not provided'}
                    </p>

                    <p>
                      <strong>Authentication results:</strong>{' '}
                      {result.email_metadata.headers.authentication_results ||
                        'Not provided'}
                    </p>

                    <p>
                      <strong>Received-SPF:</strong>{' '}
                      {result.email_metadata.headers.received_spf ||
                        'Not provided'}
                    </p>

                    <p>
                      <strong>Body extracted:</strong>{' '}
                      {result.email_metadata.body_extracted ? 'Yes' : 'No'}
                    </p>

                    <div className="attachment-heading">
                      <b>
                        Attachments (
                        {result.email_metadata.attachments.length})
                      </b>
                    </div>

                    {result.email_metadata.attachments.length > 0 ? (
                      <ul className="attachment-list">
                        {result.email_metadata.attachments.map(
                          (attachment, index) => (
                            <li key={`${attachment.filename}-${index}`}>
                              <FileText size={15} />

                              <span>
                                <b>{attachment.filename}</b>
                                <small>
                                  {attachment.content_type} ·{' '}
                                  {attachment.disposition}
                                </small>
                              </span>
                            </li>
                          ),
                        )}
                      </ul>
                    ) : (
                      <p>No attachments detected.</p>
                    )}

                    <p className="metadata-note">
                      Authentication values are reported from the supplied
                      email and are not independently verified. Attachments are
                      listed as metadata only and are not opened.
                    </p>
                  </section>
                )}

                {result.recommended_actions?.length > 0 && (
                  <div className="recommendations">
                    <b>What to do next</b>

                    <ul>
                      {result.recommended_actions.map((action, i) => (
                        <li key={i}>{action}</li>
                      ))}
                    </ul>

                    <p className="disclaimer">{result.disclaimer}</p>
                  </div>
                )}
              </>
            ) : (
              <div className="empty-result">
                <div className="empty-illustration">
                  <ScanSearch size={36} />
                </div>

                <span className="section-kicker">
                  YOUR REPORT APPEARS HERE
                </span>

                <h3>Clarity before you click.</h3>

                <p>
                  Run a scan to see the risk score, detection signals, and
                  practical next steps.
                </p>

                <div className="result-steps">
                  <div>
                    <span>01</span>
                    <p>
                      <b>Paste or upload</b>
                      <small>URL, email, .eml or message</small>
                    </p>
                  </div>

                  <div>
                    <span>02</span>
                    <p>
                      <b>Analyse</b>
                      <small>Rules + ML-assisted URL detection</small>
                    </p>
                  </div>

                  <div>
                    <span>03</span>
                    <p>
                      <b>Understand</b>
                      <small>Review the explanation</small>
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>
      </main>
      <div className="home-bottom-space" aria-hidden="true" />
    </div>
  );
}

