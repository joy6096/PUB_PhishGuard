import { useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock3,
  Globe2,
  ListFilter,
  Plus,
  ShieldCheck,
  Trash2,
  TrendingUp,
} from 'lucide-react';

export type ScanHistoryEntry = {
  id: string;
  date: string;
  type: string;
  target: string;
  score: number;
  level: string;
  verdict: string;
  indicators: string[];
};

type AdminDashboardProps = {
  history: ScanHistoryEntry[];
  onClearHistory: () => void;
};

const ALLOW_KEY = 'phishguard_allow_list_v1';
const BLOCK_KEY = 'phishguard_block_list_v1';

function readList(key: string): string[] {
  try {
    const value = localStorage.getItem(key);
    const parsed: unknown = value ? JSON.parse(value) : [];
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [];
  } catch {
    return [];
  }
}

function normaliseDomain(value: string): string | null {
  const raw = value.trim().toLowerCase();
  if (!raw) return null;
  try {
    const url = new URL(raw.includes('://') ? raw : `https://${raw}`);
    const hostname = url.hostname.replace(/^www\./, '');
    if (!hostname.includes('.') || hostname.includes(' ') || hostname.length > 253) return null;
    return hostname;
  } catch {
    return null;
  }
}

function displayDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function AdminDashboard({ history, onClearHistory }: AdminDashboardProps) {
  const [allowList, setAllowList] = useState<string[]>(() => readList(ALLOW_KEY));
  const [blockList, setBlockList] = useState<string[]>(() => readList(BLOCK_KEY));
  const [allowInput, setAllowInput] = useState('');
  const [blockInput, setBlockInput] = useState('');
  const [listError, setListError] = useState('');

  const frequentIndicators = useMemo(() => {
    const counts = new Map<string, number>();
    history.forEach((entry) => entry.indicators.forEach((indicator) => counts.set(indicator, (counts.get(indicator) ?? 0) + 1)));
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [history]);

  const highRisk = history.filter((entry) => entry.level.toLowerCase() === 'high').length;
  const averageScore = history.length ? Math.round(history.reduce((sum, item) => sum + item.score, 0) / history.length) : 0;

  function persistList(key: string, list: string[]) {
    try { localStorage.setItem(key, JSON.stringify(list)); } catch { /* storage may be disabled */ }
  }

  function addDomain(kind: 'allow' | 'block') {
    const raw = kind === 'allow' ? allowInput : blockInput;
    const domain = normaliseDomain(raw);
    if (!domain) {
      setListError('Enter a valid domain, for example example.com.');
      return;
    }
    const target = kind === 'allow' ? allowList : blockList;
    const other = kind === 'allow' ? blockList : allowList;
    if (other.includes(domain)) {
      setListError(`${domain} is already on the ${kind === 'allow' ? 'block' : 'allow'}-list. Remove it there first.`);
      return;
    }
    if (target.includes(domain)) {
      setListError(`${domain} is already on this list.`);
      return;
    }
    const next = [...target, domain].sort();
    if (kind === 'allow') {
      setAllowList(next); persistList(ALLOW_KEY, next); setAllowInput('');
    } else {
      setBlockList(next); persistList(BLOCK_KEY, next); setBlockInput('');
    }
    setListError('');
  }

  function removeDomain(kind: 'allow' | 'block', domain: string) {
    if (kind === 'allow') {
      const next = allowList.filter((item) => item !== domain);
      setAllowList(next); persistList(ALLOW_KEY, next);
    } else {
      const next = blockList.filter((item) => item !== domain);
      setBlockList(next); persistList(BLOCK_KEY, next);
    }
  }

  return (
    <section className="admin-page">
      <div className="admin-heading-row">
        <div>
          <span className="admin-eyebrow"><Activity size={14} /> SECURITY OPERATIONS</span>
          <h1>Admin Dashboard</h1>
          <p>Review recent scans, spot recurring phishing signals, and maintain domain lists.</p>
        </div>
        <div className="admin-live"><span /> Local dashboard</div>
      </div>

      <div className="admin-stats-grid">
        <article className="admin-stat-card"><span className="admin-stat-icon"><Clock3 size={19} /></span><div><small>Total scans recorded</small><strong>{history.length}</strong><span>On this browser</span></div></article>
        <article className="admin-stat-card"><span className="admin-stat-icon danger"><AlertTriangle size={19} /></span><div><small>High-risk findings</small><strong>{highRisk}</strong><span>From saved scan results</span></div></article>
        <article className="admin-stat-card"><span className="admin-stat-icon blue"><TrendingUp size={19} /></span><div><small>Average risk score</small><strong>{averageScore}<em>/100</em></strong><span>Across recorded scans</span></div></article>
        <article className="admin-stat-card"><span className="admin-stat-icon"><Globe2 size={19} /></span><div><small>Managed domains</small><strong>{allowList.length + blockList.length}</strong><span>{allowList.length} trusted · {blockList.length} blocked</span></div></article>
      </div>

      <div className="admin-content-grid">
        <section className="admin-card scan-history-card">
          <div className="admin-card-header"><div><span className="admin-section-icon"><Clock3 size={17} /></span><div><h2>Scan history</h2><p>Latest successful analyses saved in this browser.</p></div></div><button className="admin-quiet-button" type="button" onClick={onClearHistory} disabled={!history.length}>Clear history</button></div>
          {history.length ? <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>Target / input</th><th>Type</th><th>Risk</th><th>Score</th><th>Date</th></tr></thead><tbody>{history.map((item) => <tr key={item.id}><td><strong className="history-target">{item.target}</strong><small>{item.verdict}</small></td><td>{item.type}</td><td><span className={`admin-risk ${item.level.toLowerCase()}`}>{item.level}</span></td><td><strong>{item.score}</strong><span className="score-outof">/100</span></td><td className="history-date">{displayDate(item.date)}</td></tr>)}</tbody></table></div> : <div className="admin-empty"><Clock3 size={24} /><strong>No scan history yet</strong><span>Successful scans will appear here after you analyse a URL, message, or email.</span></div>}
          <p className="admin-storage-note"><ShieldCheck size={14} /> History stays in this browser only; it is not a shared or server-side audit log.</p>
        </section>

        <section className="admin-card indicators-card">
          <div className="admin-card-header"><div><span className="admin-section-icon purple"><ListFilter size={17} /></span><div><h2>Most frequent indicators</h2><p>Recurring signals across saved scan results.</p></div></div></div>
          {frequentIndicators.length ? <div className="frequent-list">{frequentIndicators.map(([name, count], index) => <div className="frequent-item" key={name}><span className="frequent-rank">{String(index + 1).padStart(2, '0')}</span><div className="frequent-name"><strong>{name.replace(/_/g, ' ')}</strong><span><i style={{ width: `${Math.max(8, (count / frequentIndicators[0][1]) * 100)}%` }} /></span></div><b>{count}<small> scans</small></b></div>)}</div> : <div className="admin-empty compact"><Activity size={22} /><span>Indicators will be ranked after scan results are recorded.</span></div>}
        </section>

        <section className="admin-card list-management-card">
          <div className="admin-card-header"><div><span className="admin-section-icon"><CheckCircle2 size={17} /></span><div><h2>Allow-list</h2><p>Domains your team considers trusted.</p></div></div><span className="list-count">{allowList.length}</span></div>
          <form className="domain-add-form" onSubmit={(event) => { event.preventDefault(); addDomain('allow'); }}><input aria-label="Domain to allow" value={allowInput} onChange={(event) => setAllowInput(event.target.value)} placeholder="example.com" /><button type="submit" aria-label="Add domain to allow-list"><Plus size={17} /> Add</button></form>
          <div className="managed-domain-list">{allowList.length ? allowList.map((domain) => <div className="managed-domain" key={domain}><span><CheckCircle2 size={15} />{domain}</span><button type="button" onClick={() => removeDomain('allow', domain)} aria-label={`Remove ${domain} from allow-list`}><Trash2 size={15} /></button></div>) : <p className="list-empty">No trusted domains added yet.</p>}</div>
        </section>

        <section className="admin-card list-management-card block-card">
          <div className="admin-card-header"><div><span className="admin-section-icon danger"><Ban size={17} /></span><div><h2>Block-list</h2><p>Domains you want to flag or block.</p></div></div><span className="list-count danger-count">{blockList.length}</span></div>
          <form className="domain-add-form" onSubmit={(event) => { event.preventDefault(); addDomain('block'); }}><input aria-label="Domain to block" value={blockInput} onChange={(event) => setBlockInput(event.target.value)} placeholder="suspicious.example" /><button type="submit" aria-label="Add domain to block-list"><Plus size={17} /> Add</button></form>
          <div className="managed-domain-list">{blockList.length ? blockList.map((domain) => <div className="managed-domain blocked-domain" key={domain}><span><Ban size={15} />{domain}</span><button type="button" onClick={() => removeDomain('block', domain)} aria-label={`Remove ${domain} from block-list`}><Trash2 size={15} /></button></div>) : <p className="list-empty">No blocked domains added yet.</p>}</div>
        </section>
      </div>
      {listError && <div className="admin-list-error" role="alert"><AlertTriangle size={16} />{listError}<button type="button" onClick={() => setListError('')} aria-label="Dismiss error">×</button></div>}
      <p className="admin-disclaimer"><AlertTriangle size={15} /> Prototype note: allow-list and block-list entries are stored locally for this browser. They do not yet change the Python scanner's verdicts; server-side enforcement requires a backend endpoint and database.</p>
    </section>
  );
}
