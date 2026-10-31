/**
 * TUĞRUL RECON+ — historical URL harvesting.
 *
 * The Wayback Machine, Common Crawl and OTX together form a public record of
 * what a domain has served. gau (MIT) and waybackurls (MIT) made the raw list
 * useful; Photon (GPL-3.0) made the point that the value is in *classifying*
 * what was found, not in printing ten thousand URLs.
 *
 * So this module does both: a deduplicated URL list, and a short list of
 * findings an analyst should look at first. Nothing is fetched from the
 * target — these are archives, so the enumeration is passive by construction.
 */

import { mapLimit, normaliseHost, runSource, type SourceRun } from './sources';

export interface UrlRecord {
  url: string;
  sources: string[];
  firstSeen: string | null;
}

export type UrlSeverity = 'high' | 'medium' | 'low';

export interface UrlFinding {
  kind: string;
  severity: UrlSeverity;
  note: string;
  url: string;
}

export interface UrlReport {
  domain: string;
  urls: UrlRecord[];
  findings: UrlFinding[];
  byExtension: Array<{ extension: string; count: number }>;
  sources: Array<SourceRun<UrlRecord[]>>;
  elapsedMs: number;
  notes: string[];
}

/* ── parsing (pure) ─────────────────────────────────────────── */

/** Remove the fragment and trailing punctuation an archive may have added. */
export function normaliseUrl(raw: string): string | null {
  const trimmed = raw.trim().replace(/[),.;]+$/, '');
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    url.hash = '';
    return url.toString();
  } catch {
    return null;
  }
}

/**
 * Wayback CDX returns `[[original, timestamp], …]` when two columns are
 * requested, and `[[original], …]` for one. Both shapes are accepted.
 */
export function parseWayback(json: unknown, domain: string): UrlRecord[] {
  if (!Array.isArray(json)) return [];
  const out: UrlRecord[] = [];
  for (const row of json.slice(0, 6000)) {
    const cells = Array.isArray(row) ? row : [row];
    const raw = cells.find((c): c is string => typeof c === 'string' && /^https?:/i.test(c));
    const stamp = cells.find((c): c is string => typeof c === 'string' && /^\d{14}$/.test(c));
    if (!raw) continue;
    const url = normaliseUrl(raw);
    if (!url || !withinDomain(url, domain)) continue;
    out.push({
      url,
      sources: ['Wayback Machine'],
      firstSeen: stamp ? `${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}` : null,
    });
  }
  return out;
}

/** Common Crawl index lines are NDJSON with a `url` field. */
export function parseCommonCrawl(ndjson: string, domain: string): UrlRecord[] {
  const out: UrlRecord[] = [];
  for (const line of ndjson.split('\n').slice(0, 6000)) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line) as { url?: string; timestamp?: string };
      const url = row.url ? normaliseUrl(row.url) : null;
      if (!url || !withinDomain(url, domain)) continue;
      out.push({
        url,
        sources: ['Common Crawl'],
        firstSeen: row.timestamp && /^\d{14}$/.test(row.timestamp)
          ? `${row.timestamp.slice(0, 4)}-${row.timestamp.slice(4, 6)}-${row.timestamp.slice(6, 8)}`
          : null,
      });
    } catch {
      /* index pages carry non-JSON banner lines */
    }
  }
  return out;
}

export function parseOtxUrls(json: unknown, domain: string): UrlRecord[] {
  const rows = (json as { url_list?: Array<{ url?: string; date?: string }> })?.url_list;
  if (!Array.isArray(rows)) return [];
  const out: UrlRecord[] = [];
  for (const row of rows.slice(0, 3000)) {
    const url = row.url ? normaliseUrl(row.url) : null;
    if (!url || !withinDomain(url, domain)) continue;
    out.push({ url, sources: ['AlienVault OTX'], firstSeen: row.date || null });
  }
  return out;
}

function withinDomain(url: string, domain: string): boolean {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return host === domain || host.endsWith(`.${domain}`);
  } catch {
    return false;
  }
}

/* ── classification (pure) ──────────────────────────────────── */

interface Rule {
  kind: string;
  severity: UrlSeverity;
  note: string;
  test: (url: URL, path: string) => boolean;
}

const SECRET_PARAMS = /^(?:key|apikey|api_key|token|access_token|auth|password|passwd|pwd|secret|sig|signature|session|sessionid)$/i;

const RULES: Rule[] = [
  {
    kind: 'env-file',
    severity: 'high',
    note: 'A served .env normally contains database and API credentials.',
    test: (_u, p) => /(?:^|\/)\.env(?:\.|$)/i.test(p),
  },
  {
    kind: 'git-metadata',
    severity: 'high',
    note: '.git objects allow full source reconstruction.',
    test: (_u, p) => /\/(?:\.git|\.svn|\.hg)\//i.test(p),
  },
  {
    kind: 'vcs-config',
    severity: 'high',
    note: 'Version-control metadata or ignore files exposed at the web root.',
    test: (_u, p) => /\/(?:\.gitignore|\.gitattributes|\.htaccess|\.htpasswd|\.DS_Store)$/i.test(p),
  },
  {
    kind: 'private-key',
    severity: 'high',
    note: 'Key material published on the public web is unrecoverable once leaked.',
    test: (_u, p) => /\.(?:pem|key|pfx|p12|jks|ppk|kdbx)$/i.test(p),
  },
  {
    kind: 'database-dump',
    severity: 'high',
    note: 'A reachable SQL dump is usually a complete copy of the dataset.',
    test: (_u, p) => /\.(?:sql|dump|sqlite|mdb|bak)$/i.test(p),
  },
  {
    kind: 'backup-archive',
    severity: 'high',
    note: 'Backup archives are rarely authenticated and often contain the live database.',
    test: (_u, p) => /(?:^|[._-])(?:backup|backups|bak|old|orig|copy)(?:[._-]|$)|\.(?:tar|tgz|tar\.gz|zip|7z|rar)$/i.test(p),
  },
  {
    kind: 'config-file',
    severity: 'high',
    note: 'Plain-text configuration often carries credentials and internal hostnames.',
    test: (_u, p) => /\.(?:ya?ml|toml|ini|conf|config|cfg|properties)$/i.test(p),
  },
  {
    kind: 'dotfile',
    severity: 'medium',
    note: 'Dotfiles leak deployment and tooling details.',
    test: (_u, p) => /\/\.[a-z][a-z0-9._-]{2,}$/i.test(p) && !/(?:apple-touch|well-known)/i.test(p),
  },
  {
    kind: 'admin-panel',
    severity: 'medium',
    note: 'Administrative surface reachable from the public web.',
    test: (_u, p) => /(?:^|\/)(?:admin|administrator|wp-admin|phpmyadmin|manager\/html|webadmin|controlpanel)(?:\/|$|\.)/i.test(p),
  },
  {
    kind: 'debug-interface',
    severity: 'medium',
    note: 'Debug or management endpoint; often unauthenticated and verbose.',
    test: (_u, p) => /(?:^|\/)(?:actuator|debug|console|phpinfo|server-status|_status|metrics|healthz?|trace)(?:\/|$|\.)/i.test(p),
  },
  {
    kind: 'api-docs',
    severity: 'low',
    note: 'Machine-readable API description; useful for mapping the surface.',
    test: (_u, p) => /(?:swagger|openapi|api-docs|graphql|redoc|\.well-known\/openid-configuration)/i.test(p),
  },
  {
    kind: 'secret-in-query',
    severity: 'high',
    note: 'Credential-shaped parameter name in a URL the archive recorded — the value may still be live.',
    test: url => Array.from(url.searchParams.keys()).some(k => SECRET_PARAMS.test(k)),
  },
  {
    kind: 'cloud-storage',
    severity: 'medium',
    note: 'Object-storage endpoint referenced by the site; check bucket authorisation.',
    test: url => /(?:s3[.-][a-z0-9-]*\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)/i.test(url.hostname),
  },
  {
    kind: 'source-map',
    severity: 'low',
    note: 'A published .map file restores original source paths and sometimes comments.',
    test: (_u, p) => /\.js\.map$/i.test(p),
  },
  {
    kind: 'archive',
    severity: 'low',
    note: 'Downloadable archive; content is worth listing manually.',
    test: (_u, p) => /\.(?:zip|rar|7z|tar|tgz|gz)$/i.test(p),
  },
  {
    kind: 'document',
    severity: 'low',
    note: 'Document metadata routinely contains author names and internal paths.',
    test: (_u, p) => /\.(?:pdf|docx?|xlsx?|pptx?|odt|ods|csv)$/i.test(p),
  },
  {
    kind: 'upload-path',
    severity: 'low',
    note: 'User-upload directory; check for listing and predictable file names.',
    test: (_u, p) => /\/(?:uploads?|files|attachments|media)\//i.test(p),
  },
  {
    kind: 'auth-endpoint',
    severity: 'low',
    note: 'Authentication endpoint; useful for mapping login flows and parameters.',
    test: (_u, p) => /(?:^|\/)(?:login|signin|sign-in|oauth|sso|auth)(?:\/|$|\.)/i.test(p),
  },
];

/**
 * Classify a URL set into findings. One URL can raise more than one finding
 * (a backup archive under /admin/ is both), which is intentional: the analyst
 * triages by kind, not by row.
 */
export function classifyUrls(urls: string[]): UrlFinding[] {
  const findings: UrlFinding[] = [];
  const seen = new Set<string>();

  for (const raw of urls) {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      continue;
    }
    const path = `${url.pathname}${url.search}`;
    for (const rule of RULES) {
      let matched = false;
      try {
        matched = rule.test(url, path);
      } catch {
        matched = false;
      }
      if (!matched) continue;
      const key = `${rule.kind}|${raw}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ kind: rule.kind, severity: rule.severity, note: rule.note, url: raw });
    }
  }

  const rank: Record<UrlSeverity, number> = { high: 0, medium: 1, low: 2 };
  return findings.sort((a, b) => rank[a.severity] - rank[b.severity] || a.kind.localeCompare(b.kind));
}

/** Extension histogram, ignoring the query string. */
export function extensionHistogram(urls: string[], limit = 15): Array<{ extension: string; count: number }> {
  const counts = new Map<string, number>();
  for (const raw of urls) {
    try {
      const path = new URL(raw).pathname;
      const match = path.match(/\.([a-z0-9]{1,8})$/i);
      const ext = match ? match[1].toLowerCase() : '(none)';
      counts.set(ext, (counts.get(ext) || 0) + 1);
    } catch {
      /* skip */
    }
  }
  return Array.from(counts.entries())
    .map(([extension, count]) => ({ extension, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

/* ── collection ─────────────────────────────────────────────── */

const MAX_URLS = 6000;

async function commonCrawlCollections(timeoutMs: number): Promise<string> {
  const res = await fetch('https://index.commoncrawl.org/collinfo.json', {
    signal: AbortSignal.timeout(timeoutMs),
    headers: { Accept: 'application/json', 'User-Agent': 'TUGRUL-OSINT/1.0' },
  });
  if (!res.ok) throw new Error(`collection list HTTP ${res.status}`);
  const list = (await res.json()) as Array<{ id?: string }>;
  const id = list.find(c => typeof c.id === 'string')?.id;
  if (!id) throw new Error('no Common Crawl collection available');
  return id;
}

export interface HarvestOptions {
  timeoutMs?: number;
  /** Skip Common Crawl (two upstream calls) when a fast answer is needed. */
  quick?: boolean;
}

/**
 * Query the three archives concurrently and merge.
 *
 * CDX and Common Crawl both answer slowly under load; they get a longer
 * budget than the JSON APIs, and a timeout is reported rather than treated as
 * “nothing archived”.
 */
export async function harvestUrls(domainInput: string, opts: HarvestOptions = {}): Promise<UrlReport> {
  const started = Date.now();
  const domain = normaliseHost(domainInput);
  if (!domain) throw new Error('Invalid domain');
  const { timeoutMs = 15_000, quick = false } = opts;

  const tasks: Array<Promise<SourceRun<UrlRecord[]>>> = [
    runSource('wayback', 'Wayback Machine', async () => {
      const res = await fetch(
        `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original,timestamp&collapse=urlkey&limit=5000`,
        { signal: AbortSignal.timeout(timeoutMs + 10_000), headers: { 'User-Agent': 'TUGRUL-OSINT/1.0' } },
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return parseWayback(JSON.parse(await res.text()), domain);
    }),
    runSource('otx', 'AlienVault OTX', async () => {
      const res = await fetch(
        `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/url_list?limit=500&page=1`,
        { signal: AbortSignal.timeout(timeoutMs), headers: { Accept: 'application/json' } },
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return parseOtxUrls(await res.json(), domain);
    }),
  ];

  if (!quick) {
    tasks.push(runSource('commoncrawl', 'Common Crawl', async () => {
      const collection = await commonCrawlCollections(timeoutMs);
      const res = await fetch(
        `https://index.commoncrawl.org/${encodeURIComponent(collection)}-index?url=*.${encodeURIComponent(domain)}/*&output=json&limit=2000`,
        { signal: AbortSignal.timeout(timeoutMs + 10_000), headers: { 'User-Agent': 'TUGRUL-OSINT/1.0' } },
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return parseCommonCrawl(await res.text(), domain);
    }));
  }

  const sources = await Promise.all(tasks);

  const merged = new Map<string, UrlRecord>();
  for (const source of sources) {
    for (const rec of source.data || []) {
      if (merged.size >= MAX_URLS && !merged.has(rec.url)) continue;
      const existing = merged.get(rec.url);
      if (!existing) {
        merged.set(rec.url, { ...rec, sources: [...rec.sources] });
        continue;
      }
      for (const s of rec.sources) if (!existing.sources.includes(s)) existing.sources.push(s);
      if (rec.firstSeen && (!existing.firstSeen || rec.firstSeen < existing.firstSeen)) existing.firstSeen = rec.firstSeen;
    }
  }

  const urls = Array.from(merged.values()).sort((a, b) => a.url.localeCompare(b.url));
  const findings = classifyUrls(urls.map(u => u.url));

  const notes: string[] = [];
  const failed = sources.filter(s => s.status === 'error');
  if (failed.length) notes.push(`Archive(s) unavailable: ${failed.map(s => s.label).join(', ')}.`);
  if (!urls.length) notes.push('No archived URLs returned. This is inconclusive — the domain may simply never have been crawled.');
  notes.push('Archived URLs are historical. A path listed here may have been removed, and absence from the archive does not mean a path never existed.');

  return {
    domain,
    urls,
    findings,
    byExtension: extensionHistogram(urls.map(u => u.url)),
    sources,
    elapsedMs: Date.now() - started,
    notes,
  };
}

/** Re-check a handful of archived URLs for liveness, politely. */
export async function checkLiveness(urls: string[], limit = 15, timeoutMs = 6000): Promise<Array<{ url: string; status: number | null }>> {
  return mapLimit(urls.slice(0, limit), 4, async url => {
    try {
      const res = await fetch(url, {
        method: 'GET',
        redirect: 'follow',
        signal: AbortSignal.timeout(timeoutMs),
        headers: { 'User-Agent': 'TUGRUL-OSINT/1.0', Range: 'bytes=0-1024' },
      });
      await res.body?.cancel();
      return { url, status: res.status };
    } catch {
      return { url, status: null };
    }
  });
}
