'use client';

/**
 * TUĞRUL — RECON+ suite.
 *
 * One workspace over the in-process OSINT engine in `src/lib/recon/`:
 * dossier, passive subdomains, web fingerprint + header audit, TLS,
 * historical URLs, dorks, email intelligence, media metadata and the
 * attribution list for every upstream project.
 *
 * Design rules:
 *   • every module states its own gaps — an empty result and a failed source
 *     must never look the same on screen
 *   • nothing is uploaded: the media parser reads the file in the browser
 *   • nothing is stored: closing the panel discards the report
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import {
  Activity, AlertTriangle, ArrowUpRight, CheckCircle2, Copy, Cpu, Download, ExternalLink,
  FileSearch, Globe2, Image as ImageIcon, Layers, Link2, Loader2, Lock, Mail, MapPin,
  Radar, Search, Server, Shield, Sparkles, X, XCircle, Zap,
} from 'lucide-react';
import { INTEGRATED_PROJECTS } from '@/lib/recon/sources';
import { DORK_ENGINES, type Dork, type DorkCategory } from '@/lib/recon/dorks';
import { metadataToText, parseMetadata, type MetadataReport } from '@/lib/recon/exif';

/* ── shared types (the subset of each API response the UI reads) ─ */

interface ModuleState { id: string; label: string; status: 'ok' | 'error' | 'skipped'; ms: number; error?: string }
interface RiskFactor { label: string; weight: number; detail: string }

interface DossierResponse {
  seed: { type: string; value: string };
  generatedAt: string;
  summary: Record<string, string | number>;
  risk: { score: number; level: string; factors: RiskFactor[] };
  modules: ModuleState[];
  graph: { nodes: Array<{ id: string; label: string; type: string; risk: string | null }>; edges: Array<{ source: string; target: string; label: string }> };
  notes: string[];
  elapsedMs: number;
}

interface SubdomainHit {
  host: string; sources: string[]; ips: string[];
  firstSeen: string | null; lastSeen: string | null;
  httpStatus: number | null; title: string | null;
}
interface SubdomainResponse {
  domain: string; total: number; live: number; elapsedMs: number;
  hits: SubdomainHit[];
  sources: Array<{ id: string; label: string; status: string; ms: number; error?: string; data?: unknown[] }>;
  notes: string[];
}

interface Technology { name: string; categories: string[]; version?: string; confidence: string; evidence: string[] }
interface FingerprintResponse {
  finalUrl: string; status: number; title: string | null; server: string | null;
  technologies: Technology[];
  headerAudit: { grade: string; score: number; findings: Array<{ header: string; state: string; severity: string; value?: string; detail: string }>; missing: string[]; disclosures: string[] };
  cookies: Array<{ name: string; secure: boolean; httpOnly: boolean; sameSite: string | null; issues: string[] }>;
  favicon: { url: string; hash: number; bytes: number } | null;
  robots: { disallowed: Array<{ agent: string; path: string }>; sitemaps: string[]; blocksAll: boolean } | null;
  securityTxt: boolean;
  externalHosts: string[];
  elapsedMs: number;
  error?: string;
}

interface TlsResponse {
  host: string; port: number; connected: boolean; protocol: string | null; cipher: string | null;
  authorized: boolean | null; subject: string | null; issuer: string | null;
  validFrom: string | null; validTo: string | null; daysRemaining: number | null;
  san: string[]; grade: string; issues: string[]; chain: Array<{ subject: string; issuer: string; validTo: string | null }>;
  fingerprintSha256: string | null; error?: string;
}

interface UrlReport {
  domain: string; total?: number; elapsedMs: number; truncated?: boolean;
  urls: Array<{ url: string; sources: string[]; firstSeen: string | null }>;
  findings: Array<{ kind: string; severity: string; note: string; url: string }>;
  byExtension: Array<{ extension: string; count: number }>;
  sources: Array<{ id: string; label: string; status: string; error?: string }>;
  notes: string[];
}

interface EmailResponse {
  address: string; domain: string; provider: string; mx: string[];
  spf: { present: boolean; record: string | null; all: string | null; risk: string; note: string };
  dmarc: { present: boolean; record: string | null; policy: string | null; risk: string; note: string };
  dkim: Array<{ selector: string; found: boolean }>;
  gravatar: { exists: boolean; checked: boolean; displayName?: string; aboutMe?: string; location?: string; accounts?: Array<{ domain: string; username: string; url: string }>; avatar: string; error?: string };
  breaches: { status: string; count: number; breaches: string[]; exposedData: string[]; detail?: string };
  reputation: { status: string; reputation?: string; suspicious?: boolean; detail?: string };
  domainAge: { created: string | null; ageDays: number | null; registrar: string | null; status: string };
  flags: { disposable: boolean; freeProvider: boolean; roleAccount: boolean; subaddressing: boolean; suspiciousLocal: boolean };
  risk: { score: number; level: string; factors: RiskFactor[] };
  notes: string[];
}

interface DorksResponse { target: string; total: number; dorks: Dork[]; categories: Array<{ category: DorkCategory; count: number; high: number }>; note: string }

/* ── tiny helpers ───────────────────────────────────────────── */

const enc = encodeURIComponent;

function download(name: string, body: string, type: string) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function stamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
}

const RISK_COLOR: Record<string, string> = {
  critical: '#FF3D3D', high: '#FF6B00', medium: '#FFD700', low: '#00E676', unknown: '#8A8880',
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#FF3D3D', high: '#FF3D3D', medium: '#FF9500', low: '#FFD700', info: '#8A8880',
};

function useApi<T>() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [data, setData] = useState<T | null>(null);
  const job = useRef(0);

  const run = useCallback(async (url: string) => {
    const id = ++job.current;
    setLoading(true);
    setError('');
    setData(null);
    try {
      const res = await fetch(url);
      const body = await res.json().catch(() => ({}));
      if (id !== job.current) return null;
      if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
      setData(body as T);
      return body as T;
    } catch (e) {
      if (id !== job.current) return null;
      setError(e instanceof Error ? e.message : 'Request failed');
      return null;
    } finally {
      if (id === job.current) setLoading(false);
    }
  }, []);

  return { loading, error, data, run, reset: () => { job.current++; setData(null); setError(''); setLoading(false); } };
}

/* ── atoms ──────────────────────────────────────────────────── */

function Section({ title, icon: Icon, color = 'var(--gold-primary)', right }: {
  title: string; icon: typeof Layers; color?: string; right?: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-2 mt-4 mb-2 first:mt-0">
      <Icon className="w-3.5 h-3.5" style={{ color }} />
      <span className="text-[10px] font-mono font-bold tracking-[0.18em]" style={{ color }}>{title}</span>
      <div className="flex-1 h-px" style={{ background: `${color}30` }} />
      {right}
    </div>
  );
}

function Row({ label, value, color, mono = true }: { label: string; value: React.ReactNode; color?: string; mono?: boolean }) {
  if (value === undefined || value === null || value === '') return null;
  return (
    <div className="flex items-start gap-3 py-1 border-b border-[var(--border-secondary)]/25 last:border-0">
      <span className="text-[9px] font-mono text-[var(--text-muted)] uppercase tracking-wider w-[104px] flex-shrink-0 pt-0.5">{label}</span>
      <span className={`text-[11px] ${mono ? 'font-mono' : ''} break-all flex-1`} style={{ color: color || 'var(--text-primary)' }}>{value}</span>
    </div>
  );
}

function Badge({ children, color = '#8A8880', title }: { children: React.ReactNode; color?: string; title?: string }) {
  return (
    <span title={title} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold tracking-wider whitespace-nowrap"
      style={{ color, border: `1px solid ${color}55`, background: `${color}18` }}>
      {children}
    </span>
  );
}

function Note({ children }: { children: React.ReactNode }) {
  return <div className="mt-2 text-[10px] font-mono text-[var(--text-muted)] leading-relaxed">{children}</div>;
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="mt-3 flex items-start gap-2 px-3 py-2 rounded border border-red-500/40 bg-red-500/10">
      <AlertTriangle className="w-3.5 h-3.5 text-red-400 flex-shrink-0 mt-0.5" />
      <span className="text-[11px] font-mono text-red-300 break-all">{message}</span>
    </div>
  );
}

function RunButton({ onClick, loading, label = 'RUN' }: { onClick: () => void; loading: boolean; label?: string }) {
  return (
    <button onClick={onClick} disabled={loading}
      className="flex items-center gap-2 px-4 py-2 rounded-lg text-[10px] font-mono font-bold tracking-[0.15em] transition-all disabled:opacity-50"
      style={{ background: 'linear-gradient(135deg, rgba(91,215,186,0.22), rgba(100,174,223,0.18))', border: '1px solid rgba(91,215,186,0.45)', color: '#b7f8e4' }}>
      {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
      {loading ? 'WORKING…' : label}
    </button>
  );
}

function TargetInput({ value, onChange, onEnter, placeholder }: {
  value: string; onChange: (v: string) => void; onEnter: () => void; placeholder: string;
}) {
  return (
    <div className="relative flex-1 min-w-0">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-muted)]" />
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter') onEnter(); }}
        placeholder={placeholder}
        spellCheck={false}
        className="w-full bg-[var(--bg-primary)]/70 border border-[var(--border-primary)] rounded-lg pl-9 pr-3 py-2 text-[12px] font-mono text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 focus:outline-none focus:border-[var(--border-active)]"
      />
    </div>
  );
}

function Toggle({ on, onChange, children }: { on: boolean; onChange: (v: boolean) => void; children: React.ReactNode }) {
  return (
    <button onClick={() => onChange(!on)}
      className={`px-2.5 py-2 rounded-lg text-[9px] font-mono tracking-wider border transition-colors ${on ? 'bg-[var(--gold-primary)]/15 border-[var(--gold-primary)]/50 text-[var(--gold-light)]' : 'border-[var(--border-primary)] text-[var(--text-muted)] hover:text-[var(--text-primary)]'}`}>
      {children}
    </button>
  );
}

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard denied */
        }
      }}
      className="p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)]" title="Copy">
      {done ? <CheckCircle2 className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
    </button>
  );
}

function ExportButton({ onClick, label = 'JSON' }: { onClick: () => void; label?: string }) {
  return (
    <button onClick={onClick} className="flex items-center gap-1 px-2 py-1 rounded border border-[var(--border-primary)] text-[9px] font-mono tracking-wider text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors">
      <Download className="w-3 h-3" /> {label}
    </button>
  );
}

/* ── dossier ────────────────────────────────────────────────── */

function DossierView({ initial, onSeed }: { initial?: string; onSeed?: (value: string) => void }) {
  const [target, setTarget] = useState(initial || '');
  const [quick, setQuick] = useState(false);
  const [brute, setBrute] = useState(false);
  const api = useApi<DossierResponse>();

  const start = () => {
    if (!target.trim()) return;
    onSeed?.(target.trim());
    api.run(`/api/osint/dossier?target=${enc(target.trim())}${quick ? '&quick=1' : ''}${brute ? '&brute=1' : ''}`);
  };

  const data = api.data;
  const graphByType = useMemo(() => {
    if (!data) return [];
    const counts = new Map<string, number>();
    for (const node of data.graph.nodes) counts.set(node.type, (counts.get(node.type) || 0) + 1);
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [data]);

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <TargetInput value={target} onChange={setTarget} onEnter={start} placeholder="example.com · https://… · user@domain · 8.8.8.8 · @handle" />
        <Toggle on={quick} onChange={setQuick}>QUICK</Toggle>
        <Toggle on={brute} onChange={setBrute}>BRUTE DNS</Toggle>
        <RunButton onClick={start} loading={api.loading} label="BUILD DOSSIER" />
      </div>
      <Note>
        Runs every module that fits the seed. QUICK skips archive and subdomain tiers; BRUTE adds a DNS wordlist tier.
        A full dossier can take up to a minute — each module reports its own status.
      </Note>

      {api.error && <ErrorBox message={api.error} />}
      {api.loading && <div className="mt-4 text-[10px] font-mono text-[var(--text-muted)]">Collecting modules… this is the slow path; partial results arrive all at once.</div>}

      {data && (
        <div className="mt-4">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <div className="flex items-center gap-2 min-w-0">
              <Badge color="#5bd7ba">{data.seed.type.toUpperCase()}</Badge>
              <span className="text-[13px] font-mono text-[var(--text-primary)] truncate">{data.seed.value}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[9px] font-mono text-[var(--text-muted)]">{(data.elapsedMs / 1000).toFixed(1)}s</span>
              <ExportButton onClick={() => download(`tugrul-dossier-${data.seed.value.replace(/[^a-z0-9.-]+/gi, '_')}-${stamp()}.json`, JSON.stringify(data, null, 2), 'application/json')} />
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/50 px-3 py-2">
              <div className="text-[9px] font-mono tracking-widest text-[var(--text-muted)]">RISK</div>
              <div className="text-[20px] font-mono font-bold" style={{ color: RISK_COLOR[data.risk.level] || '#8A8880' }}>
                {data.risk.score}<span className="text-[10px] ml-1">{data.risk.level.toUpperCase()}</span>
              </div>
            </div>
            {Object.entries(data.summary).slice(0, 3).map(([key, value]) => (
              <div key={key} className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/50 px-3 py-2">
                <div className="text-[9px] font-mono tracking-widest text-[var(--text-muted)] truncate">{key.replace(/_/g, ' ').toUpperCase()}</div>
                <div className="text-[20px] font-mono font-bold text-[var(--text-primary)]">{String(value)}</div>
              </div>
            ))}
          </div>

          <div className="grid md:grid-cols-2 gap-3">
            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title="MODULES" icon={Layers} />
              {data.modules.map(m => (
                <div key={m.id} className="flex items-center gap-2 py-1 border-b border-[var(--border-secondary)]/20 last:border-0">
                  {m.status === 'ok'
                    ? <CheckCircle2 className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                    : m.status === 'skipped'
                      ? <span className="w-3 h-3 rounded-full border border-[var(--border-primary)] flex-shrink-0" />
                      : <XCircle className="w-3 h-3 text-red-400 flex-shrink-0" />}
                  <span className="text-[10px] font-mono text-[var(--text-secondary)] flex-1 truncate">{m.label}</span>
                  <span className="text-[9px] font-mono text-[var(--text-muted)]">{m.status === 'skipped' ? 'skipped' : `${m.ms}ms`}</span>
                  {m.error && <span className="text-[9px] font-mono text-red-400 truncate max-w-[120px]" title={m.error}>{m.error}</span>}
                </div>
              ))}
            </div>

            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title="RISK FACTORS" icon={AlertTriangle} color="#FF9500" />
              {data.risk.factors.length === 0 && <div className="text-[10px] font-mono text-[var(--text-muted)]">No risk factors were raised by the modules that answered.</div>}
              {data.risk.factors.slice(0, 8).map((f, i) => (
                <div key={i} className="py-1 border-b border-[var(--border-secondary)]/20 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono font-bold text-[var(--text-primary)]">{f.label}</span>
                    <span className="text-[9px] font-mono text-[var(--text-muted)]">+{f.weight}</span>
                  </div>
                  <div className="text-[10px] font-mono text-[var(--text-muted)] leading-snug">{f.detail}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-3 rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
            <Section title={`GRAPH — ${data.graph.nodes.length} NODES · ${data.graph.edges.length} EDGES`} icon={Radar} color="#64aedf" />
            <div className="flex flex-wrap gap-1.5 mb-2">
              {graphByType.map(([type, count]) => <Badge key={type} color="#64aedf">{type}: {count}</Badge>)}
            </div>
            <div className="grid md:grid-cols-2 gap-x-4">
              {data.graph.nodes.filter(n => n.type !== 'domain').slice(0, 14).map(node => (
                <div key={node.id} className="flex items-center gap-2 py-0.5">
                  <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: node.risk === 'high' ? '#FF3D3D' : node.risk === 'medium' ? '#FF9500' : '#4a6a78' }} />
                  <span className="text-[10px] font-mono text-[var(--text-secondary)] truncate flex-1" title={node.label}>{node.label}</span>
                  <span className="text-[8px] font-mono text-[var(--text-muted)] uppercase">{node.type}</span>
                </div>
              ))}
            </div>
          </div>

          {data.notes.length > 0 && (
            <div className="mt-3 rounded-lg border border-[var(--border-secondary)] bg-black/20 p-3">
              <div className="text-[9px] font-mono tracking-widest text-[var(--text-muted)] mb-1">WHAT THIS REPORT DOES NOT SAY</div>
              {data.notes.map((n, i) => <div key={i} className="text-[10px] font-mono text-[var(--text-muted)] leading-relaxed">— {n}</div>)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── subdomains ─────────────────────────────────────────────── */

function SubdomainsView({ initial }: { initial?: string }) {
  const [target, setTarget] = useState(initial || '');
  const [brute, setBrute] = useState(false);
  const [verify, setVerify] = useState(true);
  const [filter, setFilter] = useState('');
  const api = useApi<SubdomainResponse>();

  const start = () => {
    if (!target.trim()) return;
    api.run(`/api/osint/subdomains?domain=${enc(target.trim())}${brute ? '&brute=1' : ''}${verify ? '' : '&resolve=0'}`);
  };

  const data = api.data;
  const rows = useMemo(() => {
    if (!data) return [];
    const needle = filter.trim().toLowerCase();
    return needle ? data.hits.filter(h => h.host.toLowerCase().includes(needle) || h.ips.join(' ').includes(needle)) : data.hits;
  }, [data, filter]);

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <TargetInput value={target} onChange={setTarget} onEnter={start} placeholder="example.com" />
        <Toggle on={brute} onChange={setBrute}>BRUTE</Toggle>
        <Toggle on={verify} onChange={setVerify}>RESOLVE + PROBE</Toggle>
        <RunButton onClick={start} loading={api.loading} label="ENUMERATE" />
      </div>
      <Note>
        Seven passive sources: crt.sh, Cert Spotter, AlienVault OTX, HackerTarget, RapidDNS, Wayback Machine and urlscan.io.
        Each source reports its own status below — a source that failed is not evidence that no host exists.
      </Note>

      {api.error && <ErrorBox message={api.error} />}
      {api.loading && <div className="mt-4 text-[10px] font-mono text-[var(--text-muted)]">Querying passive sources…</div>}

      {data && (
        <div className="mt-4">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <div className="flex items-center gap-2">
              <Badge color="#5bd7ba">{data.total} HOSTS</Badge>
              <Badge color="#00E676">{data.live} RESOLVED</Badge>
              <span className="text-[9px] font-mono text-[var(--text-muted)]">{(data.elapsedMs / 1000).toFixed(1)}s</span>
            </div>
            <div className="flex items-center gap-2">
              <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="filter…"
                className="w-32 bg-[var(--bg-primary)]/70 border border-[var(--border-primary)] rounded px-2 py-1 text-[10px] font-mono text-[var(--text-primary)] focus:outline-none" />
              <ExportButton label="CSV" onClick={() => download(
                `tugrul-subdomains-${data.domain}-${stamp()}.csv`,
                ['host,ips,sources,http_status,title', ...data.hits.map(h => [h.host, h.ips.join(' '), h.sources.join(' '), h.httpStatus ?? '', (h.title || '').replace(/,/g, ' ')].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))].join('\n'),
                'text/csv',
              )} />
              <ExportButton onClick={() => download(`tugrul-subdomains-${data.domain}-${stamp()}.json`, JSON.stringify(data, null, 2), 'application/json')} />
            </div>
          </div>

          <div className="flex flex-wrap gap-1.5 mb-2">
            {data.sources.map(s => (
              <Badge key={s.id} color={s.status === 'ok' ? '#00E676' : s.status === 'empty' ? '#FFD700' : '#FF3D3D'}
                title={s.error || `${(s.data || []).length} records in ${s.ms}ms`}>
                {s.label} · {s.status === 'ok' ? (s.data || []).length : s.status === 'empty' ? '0' : 'FAIL'}
              </Badge>
            ))}
          </div>

          <div className="rounded-lg border border-[var(--border-primary)] overflow-hidden">
            <div className="grid grid-cols-[1fr_auto_auto] gap-2 px-3 py-1.5 bg-black/30 text-[9px] font-mono tracking-widest text-[var(--text-muted)]">
              <span>HOST</span><span className="w-24 text-right">ADDRESS</span><span className="w-16 text-right">HTTP</span>
            </div>
            <div className="max-h-[46vh] overflow-y-auto styled-scrollbar divide-y divide-[var(--border-secondary)]/25">
              {rows.map(hit => (
                <div key={hit.host} className="grid grid-cols-[1fr_auto_auto] gap-2 px-3 py-1.5 hover:bg-white/[0.03] items-center">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 min-w-0">
                      <a href={`https://${hit.host}`} target="_blank" rel="noopener noreferrer"
                        className="text-[11px] font-mono text-[var(--text-primary)] hover:text-[var(--gold-light)] truncate">{hit.host}</a>
                      {hit.sources.length > 2 && <Badge color="#64aedf">{hit.sources.length} sources</Badge>}
                    </div>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      {hit.sources.map(s => <span key={s} className="text-[8px] font-mono text-[var(--text-muted)]">{s}</span>)}
                      {hit.title && <span className="text-[9px] font-mono text-[var(--text-muted)]/70 truncate">· {hit.title}</span>}
                    </div>
                  </div>
                  <span className="text-[9px] font-mono text-[var(--cyan-primary)] w-24 text-right truncate" title={hit.ips.join(', ')}>{hit.ips[0] || '—'}</span>
                  <span className="text-[9px] font-mono w-16 text-right" style={{ color: hit.httpStatus && hit.httpStatus < 400 ? '#00E676' : 'var(--text-muted)' }}>
                    {hit.httpStatus ?? '—'}
                  </span>
                </div>
              ))}
              {rows.length === 0 && <div className="px-3 py-4 text-[10px] font-mono text-[var(--text-muted)]">No host matched the filter.</div>}
            </div>
          </div>

          {data.notes.map((note, i) => <Note key={i}>— {note}</Note>)}
        </div>
      )}
    </div>
  );
}

/* ── fingerprint ────────────────────────────────────────────── */

function FingerprintView({ initial }: { initial?: string }) {
  const [target, setTarget] = useState(initial || '');
  const api = useApi<FingerprintResponse>();

  const start = () => {
    if (!target.trim()) return;
    api.run(`/api/osint/webtech?url=${enc(target.trim())}`);
  };

  const data = api.data;

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <TargetInput value={target} onChange={setTarget} onEnter={start} placeholder="example.com or https://example.com/path" />
        <RunButton onClick={start} loading={api.loading} label="FINGERPRINT" />
      </div>
      <Note>
        One request to the target, then everything is derived locally: stack signatures, security-header audit, cookie flags,
        robots.txt, security.txt, favicon hash and third-party hosts. Private targets are refused.
      </Note>

      {api.error && <ErrorBox message={api.error} />}
      {api.loading && <div className="mt-4 text-[10px] font-mono text-[var(--text-muted)]">Fetching the page…</div>}

      {data && (
        <div className="mt-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge color={data.status < 400 ? '#00E676' : '#FF3D3D'}>HTTP {data.status}</Badge>
            {data.server && <Badge color="#64aedf">{data.server}</Badge>}
            <Badge color={(RISK_COLOR[data.headerAudit.score >= 90 ? 'low' : data.headerAudit.score >= 60 ? 'medium' : 'high'])}>
              HEADERS {data.headerAudit.grade} · {data.headerAudit.score}/100
            </Badge>
            {data.favicon && <Badge color="#FFD700">FAVICON {data.favicon.hash}</Badge>}
            <Badge color={data.securityTxt ? '#00E676' : '#8A8880'}>{data.securityTxt ? 'SECURITY.TXT' : 'NO SECURITY.TXT'}</Badge>
            <span className="text-[9px] font-mono text-[var(--text-muted)]">{(data.elapsedMs / 1000).toFixed(1)}s</span>
          </div>

          <div className="text-[11px] font-mono text-[var(--text-secondary)] truncate">{data.finalUrl}</div>
          {data.title && <div className="text-[12px] font-mono text-[var(--text-primary)]">{data.title}</div>}
          {data.error && <ErrorBox message={data.error} />}

          <div className="grid md:grid-cols-2 gap-3">
            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title={`TECHNOLOGIES (${data.technologies.length})`} icon={Cpu} color="#00E5FF" />
              {data.technologies.length === 0 && <div className="text-[10px] font-mono text-[var(--text-muted)]">No signature matched. That is not proof of a custom stack — only that nothing matched.</div>}
              <div className="flex flex-wrap gap-1.5">
                {data.technologies.map(t => (
                  <span key={t.name} title={t.evidence.join('\n')}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded border text-[10px] font-mono"
                    style={{
                      borderColor: t.confidence === 'high' ? '#00E5FF55' : t.confidence === 'medium' ? '#FFD70044' : '#8A888033',
                      color: t.confidence === 'high' ? '#9fe8ff' : t.confidence === 'medium' ? '#ffe58a' : '#b9b7ae',
                      background: t.confidence === 'high' ? '#00E5FF10' : '#ffffff05',
                    }}>
                    {t.name}{t.version ? ` ${t.version}` : ''}
                  </span>
                ))}
              </div>
              {data.technologies.some(t => t.version) && (
                <div className="mt-2">
                  <ExportButton label="VULNS"
                    onClick={() => download(`tugrul-tech-${stamp()}.json`, JSON.stringify(data.technologies, null, 2), 'application/json')} />
                </div>
              )}
            </div>

            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title="SECURITY HEADERS" icon={Shield} color="#76FF03" />
              {data.headerAudit.findings.map(f => (
                <div key={f.header} className="flex items-start gap-2 py-1 border-b border-[var(--border-secondary)]/20 last:border-0">
                  <span className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0"
                    style={{ background: f.state === 'ok' ? '#00E676' : f.state === 'missing' ? '#FF3D3D' : f.state === 'obsolete' ? '#8A8880' : '#FF9500' }} />
                  <div className="min-w-0 flex-1">
                    <div className="text-[10px] font-mono text-[var(--text-primary)]">{f.header}</div>
                    <div className="text-[9px] font-mono text-[var(--text-muted)] leading-snug break-words">{f.detail}</div>
                  </div>
                  <span className="text-[8px] font-mono uppercase flex-shrink-0" style={{ color: SEVERITY_COLOR[f.severity] || '#8A8880' }}>{f.severity}</span>
                </div>
              ))}
              {data.headerAudit.disclosures.length > 0 && (
                <div className="mt-2 text-[9px] font-mono text-[#FFD700]">Version disclosure: {data.headerAudit.disclosures.join(' · ')}</div>
              )}
            </div>
          </div>

          <div className="grid md:grid-cols-3 gap-3">
            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title="COOKIES" icon={Lock} color="#E040FB" />
              {data.cookies.length === 0 && <div className="text-[10px] font-mono text-[var(--text-muted)]">No Set-Cookie header on this response.</div>}
              {data.cookies.slice(0, 8).map(c => (
                <div key={c.name} className="py-1 border-b border-[var(--border-secondary)]/20 last:border-0">
                  <div className="text-[10px] font-mono text-[var(--text-primary)] truncate">{c.name}</div>
                  <div className="flex flex-wrap gap-1 mt-0.5">
                    <Badge color={c.secure ? '#00E676' : '#FF3D3D'}>Secure</Badge>
                    <Badge color={c.httpOnly ? '#00E676' : '#FF3D3D'}>HttpOnly</Badge>
                    <Badge color={c.sameSite ? '#00E676' : '#FF9500'}>{c.sameSite || 'no SameSite'}</Badge>
                  </div>
                </div>
              ))}
            </div>

            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title="ROBOTS.TXT" icon={FileSearch} color="#FFD700" />
              {!data.robots && <div className="text-[10px] font-mono text-[var(--text-muted)]">No robots.txt answered.</div>}
              {data.robots?.blocksAll && <div className="text-[10px] font-mono text-[#FF9500] mb-1">Crawlers are told to stay out entirely.</div>}
              {data.robots?.disallowed.slice(0, 12).map((d, i) => (
                <div key={i} className="text-[10px] font-mono text-[var(--text-secondary)] truncate">
                  <span className="text-[var(--text-muted)]">{d.agent}</span> {d.path}
                </div>
              ))}
              {data.robots && data.robots.sitemaps.length > 0 && (
                <div className="mt-1 text-[9px] font-mono text-[var(--text-muted)]">sitemaps: {data.robots.sitemaps.length}</div>
              )}
            </div>

            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title="PIVOTS" icon={Link2} color="#64aedf" />
              {data.favicon && (
                <a href={`https://www.shodan.io/search?query=http.favicon.hash%3A${data.favicon.hash}`} target="_blank" rel="noopener noreferrer"
                  className="flex items-center gap-1 text-[10px] font-mono text-[var(--cyan-primary)] hover:underline">
                  Shodan favicon hash {data.favicon.hash} <ExternalLink className="w-2.5 h-2.5" />
                </a>
              )}
              {data.robots && (
                <a href={`https://web.archive.org/web/*/${enc(data.finalUrl)}`} target="_blank" rel="noopener noreferrer"
                  className="flex items-center gap-1 text-[10px] font-mono text-[var(--cyan-primary)] hover:underline mt-1">
                  Wayback snapshots <ExternalLink className="w-2.5 h-2.5" />
                </a>
              )}
              <div className="mt-2 text-[9px] font-mono tracking-widest text-[var(--text-muted)]">THIRD-PARTY HOSTS ({data.externalHosts.length})</div>
              <div className="max-h-28 overflow-y-auto styled-scrollbar mt-1">
                {data.externalHosts.map(h => (
                  <div key={h} className="text-[10px] font-mono text-[var(--text-secondary)] truncate" title={h}>{h}</div>
                ))}
                {data.externalHosts.length === 0 && <div className="text-[10px] font-mono text-[var(--text-muted)]">None found in the page source.</div>}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── TLS ────────────────────────────────────────────────────── */

function TlsView({ initial }: { initial?: string }) {
  const [target, setTarget] = useState(initial || '');
  const api = useApi<TlsResponse>();

  const start = () => {
    if (!target.trim()) return;
    api.run(`/api/osint/tls?host=${enc(target.trim())}`);
  };

  const data = api.data;

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <TargetInput value={target} onChange={setTarget} onEnter={start} placeholder="example.com or 8.8.8.8" />
        <RunButton onClick={start} loading={api.loading} label="INSPECT TLS" />
      </div>
      <Note>
        A real handshake from this server on port 443. Certificate verification is intentionally not enforced, so an expired or
        self-signed certificate is reported instead of aborting the connection.
      </Note>

      {api.error && <ErrorBox message={api.error} />}
      {api.loading && <div className="mt-4 text-[10px] font-mono text-[var(--text-muted)]">Opening a TLS connection…</div>}

      {data && (
        <div className="mt-4">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <Badge color={data.grade === 'A' ? '#00E676' : data.grade === 'B' ? '#FFD700' : data.grade === 'U' ? '#8A8880' : '#FF3D3D'}>GRADE {data.grade}</Badge>
            {data.protocol && <Badge color="#64aedf">{data.protocol}</Badge>}
            {data.cipher && <Badge color="#8A8880">{data.cipher}</Badge>}
            {data.daysRemaining !== null && (
              <Badge color={data.daysRemaining < 0 ? '#FF3D3D' : data.daysRemaining < 30 ? '#FF9500' : '#00E676'}>
                {data.daysRemaining < 0 ? `EXPIRED ${Math.abs(data.daysRemaining)}d` : `${data.daysRemaining}d LEFT`}
              </Badge>
            )}
            <ExportButton onClick={() => download(`tugrul-tls-${data.host}-${stamp()}.json`, JSON.stringify(data, null, 2), 'application/json')} />
          </div>

          {data.error && <ErrorBox message={data.error} />}

          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
            <Row label="Subject" value={data.subject} />
            <Row label="Issuer" value={data.issuer} />
            <Row label="Valid from" value={data.validFrom} />
            <Row label="Valid to" value={data.validTo} color={data.daysRemaining !== null && data.daysRemaining < 0 ? '#FF3D3D' : undefined} />
            <Row label="Chain" value={`${data.chain.length} certificate(s)`} />
            <Row label="SHA-256" value={<span className="flex items-center gap-1">{data.fingerprintSha256} <CopyButton text={data.fingerprintSha256 || ''} /></span>} />
          </div>

          <Section title={`ISSUES (${data.issues.length})`} icon={AlertTriangle} color="#FF9500" />
          {data.issues.map((issue, i) => (
            <div key={i} className="text-[10px] font-mono text-[var(--text-secondary)] py-0.5">— {issue}</div>
          ))}

          <Section title={`SUBJECT ALT NAMES (${data.san.length})`} icon={Globe2} color="#00E5FF" />
          <div className="flex flex-wrap gap-1">
            {data.san.slice(0, 120).map(name => (
              <span key={name} className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-[9px] font-mono text-[var(--text-secondary)]">{name}</span>
            ))}
            {data.san.length === 0 && <span className="text-[10px] font-mono text-[var(--text-muted)]">No SANs on the certificate.</span>}
          </div>

          {data.chain.length > 0 && (
            <>
              <Section title="CHAIN" icon={Layers} color="#E040FB" />
              {data.chain.map((cert, i) => (
                <div key={i} className="text-[10px] font-mono text-[var(--text-secondary)] py-0.5 truncate">
                  <span className="text-[var(--text-muted)]">{i + 1}.</span> {cert.subject || '(no subject)'}
                  {cert.validTo && <span className="text-[var(--text-muted)]"> · {cert.validTo.slice(0, 10)}</span>}
                </div>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}

/* ── URLs ───────────────────────────────────────────────────── */

function UrlsView({ initial }: { initial?: string }) {
  const [target, setTarget] = useState(initial || '');
  const [quick, setQuick] = useState(true);
  const [filter, setFilter] = useState('');
  const api = useApi<UrlReport>();

  const start = () => {
    if (!target.trim()) return;
    api.run(`/api/osint/urls?domain=${enc(target.trim())}${quick ? '&quick=1' : ''}`);
  };

  const data = api.data;
  const rows = useMemo(() => {
    if (!data) return [];
    const needle = filter.trim().toLowerCase();
    return needle ? data.urls.filter(u => u.url.toLowerCase().includes(needle)) : data.urls;
  }, [data, filter]);

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <TargetInput value={target} onChange={setTarget} onEnter={start} placeholder="example.com" />
        <Toggle on={quick} onChange={setQuick}>SKIP COMMON CRAWL</Toggle>
        <RunButton onClick={start} loading={api.loading} label="HARVEST" />
      </div>
      <Note>
        Wayback CDX, Common Crawl and OTX, then each URL is classified: exposed configs, backups, keys, admin surfaces and
        credential-shaped parameters first. Historical only — a listed path may be long gone.
      </Note>

      {api.error && <ErrorBox message={api.error} />}
      {api.loading && <div className="mt-4 text-[10px] font-mono text-[var(--text-muted)]">Querying the archives…</div>}

      {data && (
        <div className="mt-4">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <div className="flex items-center gap-2">
              <Badge color="#5bd7ba">{data.urls.length} URLS</Badge>
              <Badge color="#FF3D3D">{data.findings.filter(f => f.severity === 'high').length} HIGH</Badge>
              <Badge color="#FF9500">{data.findings.filter(f => f.severity === 'medium').length} MEDIUM</Badge>
              {data.truncated && <Badge color="#8A8880">TRUNCATED</Badge>}
              <span className="text-[9px] font-mono text-[var(--text-muted)]">{(data.elapsedMs / 1000).toFixed(1)}s</span>
            </div>
            <div className="flex items-center gap-2">
              <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="filter urls…"
                className="w-40 bg-[var(--bg-primary)]/70 border border-[var(--border-primary)] rounded px-2 py-1 text-[10px] font-mono text-[var(--text-primary)] focus:outline-none" />
              <ExportButton label="TXT" onClick={() => download(`tugrul-urls-${data.domain}-${stamp()}.txt`, data.urls.map(u => u.url).join('\n'), 'text/plain')} />
              <ExportButton onClick={() => download(`tugrul-urls-${data.domain}-${stamp()}.json`, JSON.stringify(data, null, 2), 'application/json')} />
            </div>
          </div>

          <div className="flex flex-wrap gap-1.5 mb-2">
            {data.sources.map(s => (
              <Badge key={s.id} color={s.status === 'ok' ? '#00E676' : s.status === 'empty' ? '#FFD700' : '#FF3D3D'} title={s.error}>
                {s.label} · {s.status}
              </Badge>
            ))}
            {data.byExtension.slice(0, 8).map(e => <Badge key={e.extension} color="#8A8880">{e.extension} {e.count}</Badge>)}
          </div>

          {data.findings.length > 0 && (
            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3 mb-3">
              <Section title={`FINDINGS (${data.findings.length})`} icon={AlertTriangle} color="#FF3D3D" />
              <div className="max-h-[30vh] overflow-y-auto styled-scrollbar">
                {data.findings.slice(0, 60).map((f, i) => (
                  <div key={i} className="py-1 border-b border-[var(--border-secondary)]/20 last:border-0">
                    <div className="flex items-center gap-2">
                      <Badge color={SEVERITY_COLOR[f.severity]}>{f.kind}</Badge>
                      <a href={f.url} target="_blank" rel="noopener noreferrer"
                        className="text-[10px] font-mono text-[var(--text-secondary)] truncate hover:text-[var(--text-primary)] flex-1">{f.url}</a>
                    </div>
                    <div className="text-[9px] font-mono text-[var(--text-muted)] leading-snug mt-0.5">{f.note}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="rounded-lg border border-[var(--border-primary)] overflow-hidden">
            <div className="px-3 py-1.5 bg-black/30 text-[9px] font-mono tracking-widest text-[var(--text-muted)]">ARCHIVED URLS</div>
            <div className="max-h-[36vh] overflow-y-auto styled-scrollbar divide-y divide-[var(--border-secondary)]/20">
              {rows.slice(0, 400).map(u => (
                <div key={u.url} className="flex items-center gap-2 px-3 py-1 hover:bg-white/[0.03]">
                  <a href={u.url} target="_blank" rel="noopener noreferrer"
                    className="text-[10px] font-mono text-[var(--text-secondary)] truncate flex-1 hover:text-[var(--text-primary)]">{u.url}</a>
                  <span className="text-[8px] font-mono text-[var(--text-muted)] flex-shrink-0">{u.sources.join('·')}</span>
                  {u.firstSeen && <span className="text-[8px] font-mono text-[var(--text-muted)] flex-shrink-0">{u.firstSeen}</span>}
                </div>
              ))}
              {rows.length === 0 && <div className="px-3 py-4 text-[10px] font-mono text-[var(--text-muted)]">Nothing matched.</div>}
            </div>
          </div>

          {data.notes.map((note, i) => <Note key={i}>— {note}</Note>)}
        </div>
      )}
    </div>
  );
}

/* ── dorks ──────────────────────────────────────────────────── */

function DorksView({ initial }: { initial?: string }) {
  const [target, setTarget] = useState(initial || '');
  const [maxRisk, setMaxRisk] = useState<'info' | 'medium' | 'high'>('high');
  const [category, setCategory] = useState<string>('');
  const api = useApi<DorksResponse>();

  const start = () => {
    if (!target.trim()) return;
    const params = new URLSearchParams({ target: target.trim(), maxRisk });
    if (category) params.set('category', category);
    api.run(`/api/osint/dorks?${params.toString()}`);
  };

  const data = api.data;

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <TargetInput value={target} onChange={setTarget} onEnter={start} placeholder="example.com" />
        <select value={maxRisk} onChange={e => setMaxRisk(e.target.value as typeof maxRisk)}
          className="bg-[var(--bg-primary)]/70 border border-[var(--border-primary)] rounded-lg px-2 py-2 text-[9px] font-mono text-[var(--text-secondary)] focus:outline-none">
          <option value="info">INFO ONLY</option>
          <option value="medium">+ MEDIUM</option>
          <option value="high">ALL RISKS</option>
        </select>
        <RunButton onClick={start} loading={api.loading} label="BUILD DORKS" />
      </div>
      <Note>
        Query templates from the pagodo / OSINT-Framework catalogues. Nothing is scraped: each row opens a real search engine in a
        new tab, under your own session, so the engine’s terms apply to you and not to this server.
      </Note>

      {api.error && <ErrorBox message={api.error} />}

      {data && (
        <div className="mt-4">
          <div className="flex flex-wrap items-center gap-1.5 mb-3">
            <Badge color="#5bd7ba">{data.total} DORKS</Badge>
            <button onClick={() => setCategory('')}
              className={`px-2 py-0.5 rounded text-[9px] font-mono ${!category ? 'text-[var(--gold-light)] border border-[var(--gold-primary)]/50' : 'text-[var(--text-muted)] border border-transparent'}`}>all</button>
            {data.categories.map(c => (
              <button key={c.category} onClick={() => { setCategory(c.category); }}
                className={`px-2 py-0.5 rounded text-[9px] font-mono ${category === c.category ? 'text-[var(--gold-light)] border border-[var(--gold-primary)]/50' : 'text-[var(--text-muted)] border border-transparent'}`}>
                {c.category} {c.count}
              </button>
            ))}
          </div>

          <div className="space-y-1.5">
            {data.dorks.filter(d => !category || d.category === category).map(d => (
              <div key={d.title} className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-mono font-bold text-[var(--text-primary)]">{d.title}</span>
                  <Badge color={SEVERITY_COLOR[d.risk] || '#8A8880'}>{d.risk}</Badge>
                  <Badge color="#64aedf">{d.category}</Badge>
                  <div className="ml-auto flex items-center gap-1">
                    {DORK_ENGINES.map(engine => (
                      <a key={engine.id} href={d.links[engine.id]} target="_blank" rel="noopener noreferrer"
                        className="px-1.5 py-0.5 rounded border border-[var(--border-primary)] text-[8px] font-mono text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:border-[var(--border-active)]">
                        {engine.label}
                      </a>
                    ))}
                    <CopyButton text={d.resolved} />
                  </div>
                </div>
                <div className="text-[10px] font-mono text-[var(--cyan-primary)] break-all mt-1">{d.resolved}</div>
                <div className="text-[9px] font-mono text-[var(--text-muted)] leading-snug mt-0.5">{d.why}</div>
              </div>
            ))}
          </div>
          <Note>{data.note}</Note>
        </div>
      )}
    </div>
  );
}

/* ── email ──────────────────────────────────────────────────── */

function EmailView({ initial }: { initial?: string }) {
  const [target, setTarget] = useState(initial || '');
  const [quick, setQuick] = useState(false);
  const api = useApi<EmailResponse>();

  const start = () => {
    if (!target.trim()) return;
    api.run(`/api/osint/email?email=${enc(target.trim())}${quick ? '&quick=1' : ''}`);
  };

  const data = api.data;

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <TargetInput value={target} onChange={setTarget} onEnter={start} placeholder="user@example.com" />
        <Toggle on={quick} onChange={setQuick}>QUICK</Toggle>
        <RunButton onClick={start} loading={api.loading} label="INVESTIGATE" />
      </div>
      <Note>
        Public sources only: Gravatar, the XposedOrNot breach corpus, emailrep, RDAP and the domain’s own SPF/DMARC/DKIM records.
        No recovery-flow probing — that would look like credential stuffing from this server’s address.
      </Note>

      {api.error && <ErrorBox message={api.error} />}
      {api.loading && <div className="mt-4 text-[10px] font-mono text-[var(--text-muted)]">Querying identity and mail sources…</div>}

      {data && (
        <div className="mt-4">
          <div className="flex flex-wrap items-center gap-2 mb-3">
            <span className="text-[13px] font-mono text-[var(--text-primary)]">{data.address}</span>
            <Badge color={data.gravatar.exists ? '#00E676' : '#8A8880'}>{data.gravatar.exists ? 'GRAVATAR PROFILE' : 'NO GRAVATAR'}</Badge>
            <Badge color={data.breaches.status === 'ok' ? '#FF3D3D' : '#8A8880'}>
              {data.breaches.status === 'ok' ? `${data.breaches.breaches.length} BREACHES` : `BREACHES: ${data.breaches.status.toUpperCase()}`}
            </Badge>
            <Badge color={RISK_COLOR[data.risk.level]}>RISK {data.risk.score} · {data.risk.level.toUpperCase()}</Badge>
            <ExportButton onClick={() => download(`tugrul-email-${data.address.replace(/[^a-z0-9]/gi, '_')}-${stamp()}.json`, JSON.stringify(data, null, 2), 'application/json')} />
          </div>

          <div className="grid md:grid-cols-2 gap-3">
            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title="MAIL DOMAIN" icon={Mail} color="#FFD700" />
              <Row label="Provider" value={data.provider} />
              <Row label="MX" value={data.mx.join(', ') || 'none published'} />
              <Row label="SPF" value={data.spf.record || 'missing'} color={data.spf.risk === 'ok' ? undefined : '#FF9500'} />
              <Row label="DMARC" value={data.dmarc.record || 'missing'} color={data.dmarc.risk === 'ok' ? undefined : '#FF9500'} />
              <Row label="DKIM" value={data.dkim.length ? data.dkim.map(d => d.selector).join(', ') : 'no common selector found'} />
              <Row label="Domain age" value={data.domainAge.ageDays !== null ? `${data.domainAge.ageDays} days` : data.domainAge.status} color={data.domainAge.ageDays !== null && data.domainAge.ageDays < 30 ? '#FF3D3D' : undefined} />
              <Row label="Registrar" value={data.domainAge.registrar} />
              <Note>{data.spf.note}</Note>
              <Note>{data.dmarc.note}</Note>
            </div>

            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title="RISK FACTORS" icon={AlertTriangle} color="#FF9500" />
              {data.risk.factors.length === 0 && <div className="text-[10px] font-mono text-[var(--text-muted)]">No factor was raised.</div>}
              {data.risk.factors.map((f, i) => (
                <div key={i} className="py-1 border-b border-[var(--border-secondary)]/20 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono font-bold text-[var(--text-primary)]">{f.label}</span>
                    <span className="text-[9px] font-mono text-[var(--text-muted)]">+{f.weight}</span>
                  </div>
                  <div className="text-[9px] font-mono text-[var(--text-muted)] leading-snug">{f.detail}</div>
                </div>
              ))}
              <div className="flex flex-wrap gap-1 mt-2">
                {data.flags.disposable && <Badge color="#FF3D3D">disposable</Badge>}
                {data.flags.freeProvider && <Badge color="#8A8880">free provider</Badge>}
                {data.flags.roleAccount && <Badge color="#FFD700">role account</Badge>}
                {data.flags.subaddressing && <Badge color="#64aedf">subaddressed</Badge>}
                {data.flags.suspiciousLocal && <Badge color="#FF9500">generated-looking</Badge>}
              </div>
            </div>
          </div>

          <div className="grid md:grid-cols-2 gap-3 mt-3">
            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title="GRAVATAR" icon={ImageIcon} color="#3B82F6" />
              {data.gravatar.exists ? (
                <>
                  <div className="flex items-start gap-3">
                    {/* eslint-disable-next-line @next/next/no-img-element -- remote avatar, never optimized */}
                    <img src={data.gravatar.avatar} alt="" width={56} height={56} className="rounded-md border border-[var(--border-primary)]" />
                    <div className="min-w-0">
                      <div className="text-[12px] font-mono text-[var(--text-primary)]">{data.gravatar.displayName || '(no name)'}</div>
                      {data.gravatar.location && <div className="text-[10px] font-mono text-[var(--text-muted)]">{data.gravatar.location}</div>}
                      {data.gravatar.aboutMe && <div className="text-[10px] font-mono text-[var(--text-muted)] line-clamp-3">{data.gravatar.aboutMe}</div>}
                    </div>
                  </div>
                  {(data.gravatar.accounts || []).length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {(data.gravatar.accounts || []).map(a => (
                        <a key={`${a.domain}-${a.username}`} href={a.url || undefined} target="_blank" rel="noopener noreferrer"
                          className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-[9px] font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
                          {a.domain}{a.username ? ` / ${a.username}` : ''}
                        </a>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <div className="text-[10px] font-mono text-[var(--text-muted)]">
                  {data.gravatar.checked ? 'No Gravatar profile is linked to this address.' : `Not checked${data.gravatar.error ? ` — ${data.gravatar.error}` : ''}.`}
                </div>
              )}
            </div>

            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title={`BREACH EXPOSURE · ${data.breaches.status.toUpperCase()}`} icon={Shield} color="#E040FB" />
              {data.breaches.status === 'unavailable' && <div className="text-[10px] font-mono text-[var(--text-muted)]">The breach corpus did not answer; exposure was not measured. {data.breaches.detail}</div>}
              {data.breaches.breaches.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {data.breaches.breaches.slice(0, 30).map(name => (
                    <span key={name} className="px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-[9px] font-mono text-red-300">{name}</span>
                  ))}
                </div>
              )}
              {data.breaches.exposedData.length > 0 && (
                <div className="mt-2 text-[9px] font-mono text-[var(--text-muted)]">Exposed: {data.breaches.exposedData.slice(0, 12).join(', ')}</div>
              )}
              {data.breaches.status === 'not_found' && <div className="text-[10px] font-mono text-[var(--text-muted)]">Not present in the corpus. Absence here is not proof of safety — the corpus is a subset.</div>}
              <Row label="Reputation" value={data.reputation.status === 'ok' ? `${data.reputation.reputation || 'unknown'}${data.reputation.suspicious ? ' · suspicious' : ''}` : 'unavailable'} />
            </div>
          </div>

          {data.notes.map((note, i) => <Note key={i}>— {note}</Note>)}
        </div>
      )}
    </div>
  );
}

/* ── media ──────────────────────────────────────────────────── */

function MediaView() {
  const [report, setReport] = useState<MetadataReport | null>(null);
  const [filename, setFilename] = useState('');
  const [hash, setHash] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const handle = async (file: File | undefined) => {
    if (!file) return;
    setError('');
    setReport(null);
    setHash('');
    setFilename(file.name);
    if (file.size > 25 * 1024 * 1024) {
      setError('File limit is 25 MB.');
      return;
    }
    setBusy(true);
    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      setReport(parseMetadata(bytes));
      const digest = await crypto.subtle.digest('SHA-256', buffer);
      setHash(Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join(''));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not read the file');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <Note>
        The file is read in this browser and never uploaded. JPEG, PNG, TIFF and PDF are parsed for EXIF/GPS, camera, timestamps
        and document properties. A SHA-256 of the bytes is added for chain-of-custody notes.
      </Note>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button onClick={() => input.current?.click()} disabled={busy}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-[10px] font-mono font-bold tracking-[0.15em] disabled:opacity-50"
          style={{ background: 'linear-gradient(135deg, rgba(91,215,186,0.22), rgba(100,174,223,0.18))', border: '1px solid rgba(91,215,186,0.45)', color: '#b7f8e4' }}>
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ImageIcon className="w-3.5 h-3.5" />}
          {busy ? 'PARSING…' : 'SELECT FILE'}
        </button>
        <input ref={input} type="file" accept="image/*,application/pdf" className="hidden" aria-label="Media file"
          onChange={e => { handle(e.target.files?.[0]); e.target.value = ''; }} />
        {filename && <span className="text-[10px] font-mono text-[var(--text-muted)] truncate">{filename}</span>}
      </div>

      {error && <ErrorBox message={error} />}

      {report && (
        <div className="mt-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge color="#5bd7ba">{report.format.toUpperCase()}</Badge>
            <Badge color="#8A8880">{(report.byteLength / 1024).toFixed(1)} KB</Badge>
            {report.width && report.height && <Badge color="#64aedf">{report.width}×{report.height}</Badge>}
            {report.gps && <Badge color="#00E676">GPS PRESENT</Badge>}
            <span className="text-[9px] font-mono text-[var(--text-muted)]">{report.tags.length} tags</span>
            <ExportButton label="TXT" onClick={() => download(`tugrul-metadata-${stamp()}.txt`, metadataToText(report, filename), 'text/plain')} />
          </div>

          {report.gps && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3">
              <Section title="GPS LOCATION" icon={MapPin} color="#00E676" />
              <Row label="Latitude" value={report.gps.latitude} color="#00E676" />
              <Row label="Longitude" value={report.gps.longitude} color="#00E676" />
              {report.gps.altitude !== undefined && <Row label="Altitude" value={`${report.gps.altitude} m`} />}
              {report.gps.timestamp && <Row label="GPS time" value={report.gps.timestamp} />}
              <a href={report.gps.mapsUrl} target="_blank" rel="noopener noreferrer"
                className="inline-flex items-center gap-1 mt-1 text-[10px] font-mono text-emerald-300 hover:underline">
                Open in maps <ArrowUpRight className="w-3 h-3" />
              </a>
            </div>
          )}

          <div className="grid md:grid-cols-2 gap-3">
            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title="CAMERA & TIMESTAMPS" icon={Cpu} color="#00E5FF" />
              <Row label="Make" value={report.camera?.make} />
              <Row label="Model" value={report.camera?.model} />
              <Row label="Lens" value={report.camera?.lens} />
              <Row label="Software" value={report.camera?.software} />
              <Row label="Original" value={report.timestamps?.original} />
              <Row label="Digitized" value={report.timestamps?.digitized} />
              <Row label="Modified" value={report.timestamps?.modified} />
              <Row label="SHA-256" value={<span className="flex items-center gap-1">{hash} <CopyButton text={hash} /></span>} />
            </div>

            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
              <Section title="ALL TAGS" icon={FileSearch} color="#FFD700" />
              <div className="max-h-56 overflow-y-auto styled-scrollbar">
                {report.tags.map((tag, i) => (
                  <div key={`${tag.group}-${tag.tag}-${i}`} className="flex items-start gap-2 py-0.5 border-b border-[var(--border-secondary)]/20 last:border-0">
                    <span className="text-[8px] font-mono text-[var(--text-muted)] w-14 flex-shrink-0 pt-0.5">{tag.group}</span>
                    <span className="text-[10px] font-mono text-[var(--text-primary)] w-32 flex-shrink-0 truncate" title={tag.tag}>{tag.tag}</span>
                    <span className="text-[10px] font-mono text-[var(--text-secondary)] break-all flex-1">{tag.value}</span>
                  </div>
                ))}
                {report.tags.length === 0 && <div className="text-[10px] font-mono text-[var(--text-muted)]">No readable tags.</div>}
              </div>
            </div>
          </div>

          {report.warnings.length > 0 && (
            <div className="rounded-lg border border-[var(--border-secondary)] bg-black/20 p-3">
              {report.warnings.map((w, i) => <div key={i} className="text-[10px] font-mono text-[var(--text-muted)]">— {w}</div>)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── projects ───────────────────────────────────────────────── */

function ProjectsView() {
  return (
    <div>
      <Note>
        Every upstream whose method or data this suite uses, with its licence. GPL projects contribute technique only — no code
        is copied. Projects that were deliberately not integrated are listed too, with the reason.
      </Note>
      <div className="mt-3 grid md:grid-cols-2 gap-2">
        {INTEGRATED_PROJECTS.map(project => (
          <div key={project.id} className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/40 p-3">
            <div className="flex items-center gap-2 flex-wrap">
              <a href={`https://github.com/${project.repo}`} target="_blank" rel="noopener noreferrer"
                className="text-[11px] font-mono font-bold text-[var(--text-primary)] hover:text-[var(--gold-light)] flex items-center gap-1">
                {project.name} <ExternalLink className="w-2.5 h-2.5" />
              </a>
              <Badge color="#64aedf">{project.license}</Badge>
              <Badge color={project.powers === 'not enabled' ? '#8A8880' : '#00E676'}>{project.adopted}</Badge>
            </div>
            <div className="text-[9px] font-mono text-[var(--gold-primary)]/80 mt-1">{project.powers}</div>
            <div className="text-[10px] font-mono text-[var(--text-muted)] leading-snug mt-1">{project.note}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── shell ──────────────────────────────────────────────────── */

type SuiteTab = 'dossier' | 'subdomains' | 'fingerprint' | 'tls' | 'urls' | 'dorks' | 'email' | 'media' | 'projects';

const SUITE_TABS: Array<{ id: SuiteTab; label: string; icon: typeof Layers; blurb: string }> = [
  { id: 'dossier', label: 'DOSSIER', icon: Sparkles, blurb: 'One seed, every module, one report' },
  { id: 'subdomains', label: 'SUBDOMAINS', icon: Globe2, blurb: 'Seven passive sources with per-source provenance' },
  { id: 'fingerprint', label: 'FINGERPRINT', icon: Cpu, blurb: 'Stack, header audit, cookies, robots, favicon hash' },
  { id: 'tls', label: 'TLS', icon: Lock, blurb: 'Live handshake, chain, expiry and grade' },
  { id: 'urls', label: 'URL HARVEST', icon: Link2, blurb: 'Archive URLs, classified by what they expose' },
  { id: 'dorks', label: 'DORKS', icon: Search, blurb: 'Generated search-engine dorks by category' },
  { id: 'email', label: 'EMAIL', icon: Mail, blurb: 'Identity, breaches and mail-domain posture' },
  { id: 'media', label: 'MEDIA META', icon: ImageIcon, blurb: 'EXIF/GPS in the browser — the file never leaves it' },
  { id: 'projects', label: 'SOURCES', icon: Server, blurb: 'Licences and attribution for every upstream' },
];

export interface ReconSuiteProps {
  open: boolean;
  onClose: () => void;
  /** Pre-fill the active module with the value from the RECON panel. */
  initialTarget?: string;
}

export default function ReconSuite({ open, onClose, initialTarget }: ReconSuiteProps) {
  const [tab, setTab] = useState<SuiteTab>('dossier');
  const [target, setTarget] = useState(initialTarget || '');

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const active = SUITE_TABS.find(t => t.id === tab) || SUITE_TABS[0];

  const node = (
    <div className="fixed inset-0 z-[1000] flex items-center justify-center p-2 md:p-5" role="dialog" aria-modal="true" aria-label="RECON+ suite">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full h-full max-w-[1500px] glass-panel border border-[var(--gold-primary)]/35 rounded-xl flex flex-col overflow-hidden shadow-2xl">
        <div className="flex items-center gap-3 px-4 md:px-6 py-3 border-b border-[var(--border-secondary)] bg-[#0d161d]/90 flex-shrink-0">
          <Radar className="w-5 h-5 text-[var(--gold-primary)] flex-shrink-0" />
          <div className="min-w-0">
            <div className="hud-text text-[14px] text-[var(--text-primary)] leading-none">RECON+ SUITE</div>
            <div className="text-[8px] font-mono tracking-[0.2em] text-[var(--text-muted)] mt-1">
              {SUITE_TABS.length} MODULES · {INTEGRATED_PROJECTS.length} OPEN-SOURCE INTEGRATIONS
            </div>
          </div>
          <span className="ml-auto hidden md:block text-[9px] font-mono text-[var(--text-muted)] truncate max-w-[280px]">{active.blurb}</span>
          <button onClick={onClose} aria-label="Close"
            className="p-2 rounded hover:bg-white/10 text-[var(--text-muted)] hover:text-white transition-colors flex-shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex flex-1 min-h-0">
          <aside className="w-[150px] md:w-[196px] flex-shrink-0 border-r border-[var(--border-secondary)] bg-black/25 overflow-y-auto styled-scrollbar py-2">
            {SUITE_TABS.map(t => (
              <button key={t.id} onClick={() => setTab(t.id)}
                className={`w-full flex items-center gap-2 px-3 py-2 text-left transition-colors ${tab === t.id ? 'bg-[var(--gold-primary)]/10 text-[var(--gold-light)] border-l-2 border-[var(--gold-primary)]' : 'text-[var(--text-muted)] hover:text-[var(--text-primary)] border-l-2 border-transparent'}`}>
                <t.icon className="w-3.5 h-3.5 flex-shrink-0" />
                <span className="text-[9px] font-mono tracking-wider truncate">{t.label}</span>
              </button>
            ))}
          </aside>

          <main className="flex-1 min-w-0 overflow-y-auto styled-scrollbar p-3 md:p-5">
            {tab === 'dossier' && <DossierView initial={target} onSeed={setTarget} />}
            {tab === 'subdomains' && <SubdomainsView key={target} initial={target} />}
            {tab === 'fingerprint' && <FingerprintView key={target} initial={target} />}
            {tab === 'tls' && <TlsView key={target} initial={target} />}
            {tab === 'urls' && <UrlsView key={target} initial={target} />}
            {tab === 'dorks' && <DorksView key={target} initial={target} />}
            {tab === 'email' && <EmailView key={target} initial={target} />}
            {tab === 'media' && <MediaView />}
            {tab === 'projects' && <ProjectsView />}
          </main>
        </div>

        <div className="flex items-center gap-3 px-4 py-2 border-t border-[var(--border-secondary)] bg-black/30 text-[8px] font-mono text-[var(--text-muted)] flex-shrink-0">
          <Activity className="w-3 h-3 text-[var(--gold-primary)]" />
          <span>Results stay in this tab. Nothing is stored or uploaded; closing the panel discards them.</span>
          <span className="ml-auto hidden sm:block">Use only against systems you are authorised to examine.</span>
        </div>
      </div>
    </div>
  );

  // `document` only exists once the panel has been opened by a client event,
  // so the portal target is always present here.
  return createPortal(node, document.body);
}
