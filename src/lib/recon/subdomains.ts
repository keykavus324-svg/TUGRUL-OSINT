/**
 * TUĞRUL RECON+ — passive subdomain discovery.
 *
 * theHarvester (GPL-2.0), subfinder (MIT), Amass (Apache-2.0) and Sublist3r
 * (GPL-2.0) all answer the same question from overlapping public sources.
 * This module reimplements that fan-out in TypeScript and, crucially, keeps
 * *which source saw which host*. A name that appears in certificate
 * transparency and in passive DNS is a different kind of fact from a name
 * that only appeared in one scraped page.
 *
 * Sources, all keyless:
 *   crt.sh            certificate transparency log (SQL interface)
 *   Cert Spotter      certificate transparency, structured API
 *   AlienVault OTX    passive DNS
 *   HackerTarget      passive host search
 *   RapidDNS          passive DNS aggregator
 *   Wayback Machine   hosts seen in archived URLs
 *   urlscan.io        hosts seen by a public scan corpus
 *   DNS brute force   optional, DoH only — no raw sockets to third parties
 */

import { isSafeLabel, isWithinDomain, mapLimit, normaliseHost, runSource, unique, type SourceRun } from './sources';
import { resolveAddresses } from './dns';

export interface SubdomainRecord {
  host: string;
  source: string;
  firstSeen?: string | null;
  lastSeen?: string | null;
}

export interface SubdomainHit {
  host: string;
  sources: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  ips: string[];
  httpStatus: number | null;
  title: string | null;
}

export interface SubdomainReport {
  domain: string;
  hits: SubdomainHit[];
  total: number;
  /** Hosts that resolved to at least one address. */
  live: number;
  sources: Array<SourceRun<SubdomainRecord[]>>;
  brute: boolean;
  elapsedMs: number;
  notes: string[];
}

const MAX_PER_SOURCE = 3000;
const MAX_TOTAL = 5000;

/* ── parsing (pure, unit-tested) ─────────────────────────────── */

/**
 * Turn anything an upstream calls a hostname into a candidate inside the
 * target domain. Rejects wildcards, emails, IPs, and labels that could escape
 * the query if used later.
 */
export function normaliseCandidate(raw: string, domain: string): string | null {
  if (!raw) return null;
  let value = raw.trim().toLowerCase();
  value = value.replace(/^\*\./, '').replace(/\.$/, '');
  // Certificate SANs can carry a port or a URL scheme.
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split('/')[0].split(':')[0];
  if (!value || value.length > 253) return null;
  if (!isWithinDomain(value, domain)) return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return null;
  const labels = value.split('.');
  if (labels.length < 2) return null;
  if (!labels.every(isSafeLabel)) return null;
  return value;
}

function toIso(value: unknown): string | null {
  if (typeof value !== 'string' || !value) return null;
  const ts = Date.parse(value);
  return Number.isFinite(ts) ? new Date(ts).toISOString() : null;
}

/** crt.sh returns `name_value` with newline-separated SANs. */
export function parseCrtSh(json: unknown, domain: string): SubdomainRecord[] {
  if (!Array.isArray(json)) return [];
  const out: SubdomainRecord[] = [];
  for (const row of json.slice(0, MAX_PER_SOURCE)) {
    const rec = row as { name_value?: string; common_name?: string; not_before?: string; not_after?: string };
    const names = `${rec.name_value || ''}\n${rec.common_name || ''}`.split('\n');
    for (const name of names) {
      const host = normaliseCandidate(name, domain);
      if (!host) continue;
      out.push({ host, source: 'crt.sh', firstSeen: toIso(rec.not_before), lastSeen: toIso(rec.not_after) });
    }
  }
  return out;
}

export function parseCertSpotter(json: unknown, domain: string): SubdomainRecord[] {
  if (!Array.isArray(json)) return [];
  const out: SubdomainRecord[] = [];
  for (const row of json.slice(0, MAX_PER_SOURCE)) {
    const rec = row as { dns_names?: string[]; not_before?: string; not_after?: string };
    for (const name of rec.dns_names || []) {
      const host = normaliseCandidate(name, domain);
      if (!host) continue;
      out.push({ host, source: 'Cert Spotter', firstSeen: toIso(rec.not_before), lastSeen: toIso(rec.not_after) });
    }
  }
  return out;
}

export function parseOtx(json: unknown, domain: string): SubdomainRecord[] {
  const rows = (json as { passive_dns?: Array<{ hostname?: string; first?: string; last?: string }> })?.passive_dns;
  if (!Array.isArray(rows)) return [];
  const out: SubdomainRecord[] = [];
  for (const row of rows.slice(0, MAX_PER_SOURCE)) {
    const host = normaliseCandidate(row.hostname || '', domain);
    if (!host) continue;
    out.push({ host, source: 'AlienVault OTX', firstSeen: toIso(row.first), lastSeen: toIso(row.last) });
  }
  return out;
}

/** HackerTarget answers `host,ip` per line, or an error sentence. */
export function parseHackerTarget(text: string, domain: string): SubdomainRecord[] {
  const out: SubdomainRecord[] = [];
  for (const line of text.split(/\r?\n/).slice(0, MAX_PER_SOURCE)) {
    const [rawHost] = line.split(',');
    const host = normaliseCandidate(rawHost || '', domain);
    if (!host) continue;
    out.push({ host, source: 'HackerTarget' });
  }
  return out;
}

/** RapidDNS has no JSON API; hosts sit in `<td>` cells of a results table. */
export function parseRapidDns(html: string, domain: string): SubdomainRecord[] {
  const out: SubdomainRecord[] = [];
  const cell = /<td[^>]*>\s*([a-z0-9*._-]+\.[a-z0-9._-]+)\s*<\/td>/gi;
  let m: RegExpExecArray | null;
  while ((m = cell.exec(html)) !== null && out.length < MAX_PER_SOURCE) {
    const host = normaliseCandidate(m[1], domain);
    if (!host) continue;
    out.push({ host, source: 'RapidDNS' });
  }
  return out;
}

/** Extract hostnames from a list of URLs (Wayback CDX columns `original`). */
export function hostsFromUrls(urls: string[], domain: string): string[] {
  const hosts = new Set<string>();
  for (const url of urls) {
    try {
      const host = new URL(url).hostname;
      const normalised = normaliseCandidate(host, domain);
      if (normalised) hosts.add(normalised);
    } catch {
      /* not a URL */
    }
  }
  return Array.from(hosts);
}

/** Wayback CDX can answer as JSON rows; the first row may be a header. */
export function parseWaybackCdx(json: unknown, domain: string): SubdomainRecord[] {
  if (!Array.isArray(json)) return [];
  const rows = json.flat().filter((v): v is string => typeof v === 'string');
  return hostsFromUrls(rows, domain).map(host => ({ host, source: 'Wayback Machine' }));
}

export function parseUrlscan(json: unknown, domain: string): SubdomainRecord[] {
  const results = (json as { results?: Array<{ page?: { domain?: string }; task?: { url?: string } }> })?.results;
  if (!Array.isArray(results)) return [];
  const out: SubdomainRecord[] = [];
  for (const row of results.slice(0, MAX_PER_SOURCE)) {
    const host = normaliseCandidate(row.page?.domain || row.task?.url || '', domain);
    if (!host) continue;
    out.push({ host, source: 'urlscan.io' });
  }
  return out;
}

/* ── brute-force wordlist ────────────────────────────────────── */

/**
 * A short, high-yield label list. Sublist3r ships thousands; most of them
 * are noise on a modern estate, and every extra label is a DNS query the
 * resolver owner pays for.
 */
export const BRUTE_LABELS: string[] = [
  'www', 'www2', 'www3', 'web', 'web1', 'web2', 'site', 'portal', 'home',
  'mail', 'smtp', 'imap', 'pop', 'pop3', 'webmail', 'email', 'mx', 'mx1', 'mx2',
  'ns', 'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2', 'resolver',
  'api', 'api1', 'api2', 'api-v1', 'apis', 'gateway', 'gw', 'proxy', 'edge',
  'app', 'apps', 'application', 'admin', 'administrator', 'manage', 'management',
  'cpanel', 'whm', 'plesk', 'panel', 'dashboard', 'console', 'portal2',
  'dev', 'develop', 'developer', 'development', 'stage', 'staging', 'stg',
  'test', 'testing', 'qa', 'uat', 'preprod', 'prod', 'production', 'beta', 'alpha',
  'demo', 'sandbox', 'preview', 'internal', 'intranet', 'extranet', 'corp',
  'vpn', 'remote', 'rdp', 'citrix', 'jump', 'bastion', 'sso', 'auth', 'idp', 'login',
  'cdn', 'static', 'assets', 'img', 'images', 'media', 'video', 'files', 'download', 'uploads',
  'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic', 'elasticsearch',
  'grafana', 'kibana', 'prometheus', 'jenkins', 'ci', 'cd', 'gitlab', 'git', 'github',
  'jira', 'confluence', 'wiki', 'docs', 'doc', 'help', 'support', 'status', 'monitor',
  'monitoring', 'nagios', 'zabbix', 'sentry', 'logs', 'log', 'kafka', 'rabbitmq',
  'backup', 'backups', 'bak', 'old', 'legacy', 'archive', 'files2',
  'shop', 'store', 'pay', 'payment', 'payments', 'billing', 'invoice', 'crm', 'erp',
  'blog', 'news', 'forum', 'community', 'careers', 'jobs', 'hr', 'people',
  'm', 'mobile', 'wap', 'tv', 'live', 'stream', 'radio', 'meet', 'chat', 'im',
  'owa', 'exchange', 'autodiscover', 'lyncdiscover', 'sip', 'meet2', 'teams',
  's3', 'storage', 'bucket', 'objects', 'data', 'analytics', 'metrics', 'bi',
  'iot', 'devices', 'camera', 'cam', 'cams', 'scada', 'plc', 'hmi', 'vpn2',
  'tr', 'en', 'de', 'fr', 'ar', 'ru', 'az', 'eu', 'us', 'asia',
  'k8s', 'kubernetes', 'rancher', 'openshift', 'docker', 'registry', 'harbor',
  'staging2', 'dev2', 'test2', 'beta2', 'smtp2', 'mail2', 'vps', 'host', 'server',
];

/* ── collection ──────────────────────────────────────────────── */

const SOURCE_LABELS: Record<string, string> = {
  crtsh: 'crt.sh',
  certspotter: 'Cert Spotter',
  otx: 'AlienVault OTX',
  hackertarget: 'HackerTarget',
  rapiddns: 'RapidDNS',
  wayback: 'Wayback Machine',
  urlscan: 'urlscan.io',
  brute: 'DNS brute force',
};

async function getJson(url: string, timeoutMs: number): Promise<unknown> {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: { Accept: 'application/json', 'User-Agent': 'TUGRUL-OSINT/1.0' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function getText(url: string, timeoutMs: number): Promise<string> {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: { 'User-Agent': 'TUGRUL-OSINT/1.0' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

export interface EnumerateOptions {
  /** Add the wordlist tier (DNS queries through DoH). */
  brute?: boolean;
  /** Resolve A/AAAA for discovered hosts. */
  resolve?: boolean;
  /** Probe HTTP status/title for the first N resolved hosts. */
  probe?: number;
  timeoutMs?: number;
  concurrency?: number;
  /** Certificate-transparency-only mode, for a fast first pass. */
  quick?: boolean;
}

/**
 * Run every source, merge by host, then optionally resolve and probe.
 *
 * Source failures are kept in the report: “crt.sh timed out” and “no
 * subdomains exist” must never look the same to an analyst.
 */
export async function enumerateSubdomains(domainInput: string, opts: EnumerateOptions = {}): Promise<SubdomainReport> {
  const started = Date.now();
  const domain = normaliseHost(domainInput);
  if (!domain) throw new Error('Invalid domain');

  const { brute = false, resolve = true, probe = 40, timeoutMs = 12_000, concurrency = 8, quick = false } = opts;
  const notes: string[] = [];
  const tasks: Array<Promise<SourceRun<SubdomainRecord[]>>> = [];

  tasks.push(runSource('crtsh', SOURCE_LABELS.crtsh, async () => {
    const json = await getJson(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, timeoutMs + 8000);
    return parseCrtSh(json, domain);
  }));

  tasks.push(runSource('certspotter', SOURCE_LABELS.certspotter, async () => {
    const json = await getJson(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
      timeoutMs,
    );
    return parseCertSpotter(json, domain);
  }));

  if (!quick) {
    tasks.push(runSource('otx', SOURCE_LABELS.otx, async () => {
      const json = await getJson(
        `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`,
        timeoutMs,
      );
      return parseOtx(json, domain);
    }));

    tasks.push(runSource('hackertarget', SOURCE_LABELS.hackertarget, async () => {
      const text = await getText(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, timeoutMs);
      // The API answers 200 with "API count exceeded - Increase Quota with Membership".
      if (/error|exceeded|no records/i.test(text) && !text.includes(',')) return [];
      return parseHackerTarget(text, domain);
    }));

    tasks.push(runSource('rapiddns', SOURCE_LABELS.rapiddns, async () => {
      const html = await getText(`https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`, timeoutMs);
      return parseRapidDns(html, domain);
    }));

    tasks.push(runSource('wayback', SOURCE_LABELS.wayback, async () => {
      const json = await getJson(
        `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=5000`,
        timeoutMs + 8000,
      );
      return parseWaybackCdx(json, domain);
    }));

    tasks.push(runSource('urlscan', SOURCE_LABELS.urlscan, async () => {
      const json = await getJson(
        `https://urlscan.io/api/v1/search/?q=domain%3A${encodeURIComponent(domain)}&size=200`,
        timeoutMs,
      );
      return parseUrlscan(json, domain);
    }));
  }

  if (brute) {
    tasks.push(runSource('brute', SOURCE_LABELS.brute, async () => {
      const found = await mapLimit(BRUTE_LABELS, 12, async label => {
        const host = `${label}.${domain}`;
        try {
          const ips = await resolveAddresses(host, 3500);
          return ips.length ? { host, source: SOURCE_LABELS.brute } as SubdomainRecord : null;
        } catch {
          return null;
        }
      });
      return found.filter((r): r is SubdomainRecord => r !== null);
    }));
  }

  const sources = await Promise.all(tasks);

  // Merge, preserving first-seen order and collecting provenance.
  const merged = new Map<string, SubdomainHit>();
  for (const source of sources) {
    for (const rec of source.data || []) {
      if (merged.size >= MAX_TOTAL && !merged.has(rec.host)) continue;
      const existing = merged.get(rec.host);
      if (!existing) {
        merged.set(rec.host, {
          host: rec.host,
          sources: [rec.source],
          firstSeen: rec.firstSeen || null,
          lastSeen: rec.lastSeen || null,
          ips: [],
          httpStatus: null,
          title: null,
        });
        continue;
      }
      if (!existing.sources.includes(rec.source)) existing.sources.push(rec.source);
      if (rec.firstSeen && (!existing.firstSeen || rec.firstSeen < existing.firstSeen)) existing.firstSeen = rec.firstSeen;
      if (rec.lastSeen && (!existing.lastSeen || rec.lastSeen > existing.lastSeen)) existing.lastSeen = rec.lastSeen;
    }
  }

  let hits = Array.from(merged.values()).sort((a, b) => a.host.localeCompare(b.host));

  if (resolve && hits.length) {
    // Resolution is expensive; the first N are enough to establish which
    // hosts are real without spending the whole request budget on sockets.
    const toResolve = hits.slice(0, 150);
    const resolved = await mapLimit(toResolve, concurrency, async hit => {
      try {
        return await resolveAddresses(hit.host, 4000);
      } catch {
        return [];
      }
    });
    toResolve.forEach((hit, i) => { hit.ips = unique(resolved[i]); });

    const live = hits.filter(h => h.ips.length > 0);
    hits = [...live, ...hits.filter(h => h.ips.length === 0)];

    if (probe > 0 && live.length) {
      const probeTargets = live.slice(0, probe);
      await mapLimit(probeTargets, Math.min(6, concurrency), async hit => {
        for (const scheme of ['https', 'http'] as const) {
          try {
            const res = await fetch(`${scheme}://${hit.host}/`, {
              signal: AbortSignal.timeout(5000),
              redirect: 'follow',
              headers: { 'User-Agent': 'TUGRUL-OSINT/1.0', Accept: 'text/html,*/*' },
            });
            hit.httpStatus = res.status;
            const contentType = res.headers.get('content-type') || '';
            if (contentType.includes('text/html')) {
              const body = (await res.text()).slice(0, 100_000);
              hit.title = body.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i)?.[1]?.replace(/\s+/g, ' ').trim() || null;
            } else {
              await res.body?.cancel();
            }
            return;
          } catch {
            /* try the other scheme */
          }
        }
      });
    }
  }

  const failed = sources.filter(s => s.status === 'error');
  if (failed.length) {
    notes.push(
      `${failed.length} of ${sources.length} sources did not answer (${failed.map(s => s.label).join(', ')}); absence there is not evidence of absence.`,
    );
  }
  if (!sources.some(s => s.status === 'ok')) {
    notes.push('No source returned a hostname. This is an inconclusive result, not proof that no subdomains exist.');
  }
  if (brute) notes.push(`Brute-force tier queried ${BRUTE_LABELS.length} labels through DNS-over-HTTPS.`);
  notes.push('Passive sources are historical. A host that no longer resolves may still be owned by the same organisation.');

  const live = hits.filter(h => h.ips.length > 0).length;

  return {
    domain,
    hits,
    total: hits.length,
    live,
    sources,
    brute,
    elapsedMs: Date.now() - started,
    notes,
  };
}
