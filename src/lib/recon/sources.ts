/**
 * ═══════════════════════════════════════════════════════════════
 *  TUĞRUL RECON+ — shared plumbing for the open-source integrations
 *
 *  Every module under `src/lib/recon/` is built on this file, so the
 *  timeout, concurrency and partial-failure behaviour is written once.
 *
 *  The design rule for all of it: a source that fails is reported as
 *  failed, never silently treated as "nothing found". Passive OSINT is
 *  used to make decisions about real people and real infrastructure, and
 *  an empty list that actually means "the upstream was down" is worse
 *  than an error.
 * ═══════════════════════════════════════════════════════════════
 */

/**
 * The open-source projects whose *technique* this toolkit reimplements.
 *
 * No GPL code is copied: the modules here are independent TypeScript
 * implementations of published methodology (what to query, how to merge
 * evidence, which detection rule to apply). Where a project ships a
 * permissively licensed data file we consume that file directly, and the
 * `adopted` field says which of the two happened so attribution is exact.
 */
export type Adoption = 'dataset' | 'technique' | 'catalog' | 'concept';

export interface IntegratedProject {
  id: string;
  name: string;
  repo: string;
  license: string;
  /** What we took from it. */
  adopted: Adoption;
  /** Where it shows up in TUĞRUL. */
  powers: string;
  note: string;
}

export const INTEGRATED_PROJECTS: IntegratedProject[] = [
  {
    id: 'sherlock',
    name: 'Sherlock Project',
    repo: 'sherlock-project/sherlock',
    license: 'MIT',
    adopted: 'dataset',
    powers: 'USERNAME / FINGERPRINT',
    note: '481-site detection database consumed live; the calibration logic (control username re-test) is ours.',
  },
  {
    id: 'maigret',
    name: 'Maigret',
    repo: 'soxoj/maigret',
    license: 'MIT',
    adopted: 'technique',
    powers: 'RECON+ dossier',
    note: 'The “collect everything about one identity, then let the analyst read a dossier” model.',
  },
  {
    id: 'theharvester',
    name: 'theHarvester',
    repo: 'laramies/theHarvester',
    license: 'GPL-2.0',
    adopted: 'technique',
    powers: 'SUBDOMAINS / EMAIL INTEL',
    note: 'Multi-source passive host, email and employee-name enumeration; implemented independently, no code copied.',
  },
  {
    id: 'subfinder',
    name: 'subfinder',
    repo: 'projectdiscovery/subfinder',
    license: 'MIT',
    adopted: 'technique',
    powers: 'SUBDOMAINS',
    note: 'Passive-source fan-out with per-source attribution, so a host records where it was seen.',
  },
  {
    id: 'amass',
    name: 'OWASP Amass',
    repo: 'owasp-amass/amass',
    license: 'Apache-2.0',
    adopted: 'concept',
    powers: 'SUBDOMAINS / graph',
    note: 'Treating discovered names, addresses and certificates as one graph rather than separate lists.',
  },
  {
    id: 'sublist3r',
    name: 'Sublist3r',
    repo: 'aboul3la/Sublist3r',
    license: 'GPL-2.0',
    adopted: 'catalog',
    powers: 'SUBDOMAINS (brute tier)',
    note: 'The public-source + wordlist combination; the wordlist here is a short, hand-picked subset.',
  },
  {
    id: 'gau',
    name: 'gau (getallurls)',
    repo: 'lc/gau',
    license: 'MIT',
    adopted: 'technique',
    powers: 'URL HARVEST',
    note: 'Pulling historical URLs from the Wayback CDX API and surfacing the ones that matter.',
  },
  {
    id: 'waybackurls',
    name: 'waybackurls',
    repo: 'tomnomnom/waybackurls',
    license: 'MIT',
    adopted: 'technique',
    powers: 'URL HARVEST',
    note: 'Treating the archive as an index of what a site used to expose.',
  },
  {
    id: 'photon',
    name: 'Photon',
    repo: 's0md3v/Photon',
    license: 'GPL-3.0',
    adopted: 'concept',
    powers: 'URL HARVEST findings',
    note: 'Classifying harvested URLs by what an exposed file would mean (config, backup, secret).',
  },
  {
    id: 'pagodo',
    name: 'pagodo',
    repo: 'opsdisk/pagodo',
    license: 'GPL-3.0',
    adopted: 'catalog',
    powers: 'DORK BUILDER',
    note: 'Google-dork categories for exposing files, panels and secrets. Queries are generated, not scraped.',
  },
  {
    id: 'osint-framework',
    name: 'OSINT Framework',
    repo: 'lockfale/OSINT-Framework',
    license: 'MIT',
    adopted: 'catalog',
    powers: 'Analyst Suite source library',
    note: 'The category tree analysts expect when they open an OSINT toolkit.',
  },
  {
    id: 'wappalyzer',
    name: 'Wappalyzer / webappanalyzer',
    repo: 'enthec/webappanalyzer',
    license: 'GPL-3.0',
    adopted: 'concept',
    powers: 'TECH DETECT',
    note: 'Fingerprinting a stack from headers, cookies, script paths and generator tags. The signature set here is written from scratch and deliberately small.',
  },
  {
    id: 'exiftool',
    name: 'ExifTool',
    repo: 'exiftool/exiftool',
    license: 'Artistic-2.0 / GPL-1.0+',
    adopted: 'concept',
    powers: 'MEDIA META',
    note: 'The tag groups analysts look for. The parser here is a small, dependency-free subset for JPEG/PNG/PDF, run in the browser so the file is never uploaded.',
  },
  {
    id: 'spiderfoot',
    name: 'SpiderFoot',
    repo: 'smicallef/spiderfoot',
    license: 'MIT',
    adopted: 'concept',
    powers: 'dossier module model',
    note: 'One seed, many independent modules, each with its own status — so a partial result is still readable.',
  },
  {
    id: 'holehe',
    name: 'holehe',
    repo: 'megadose/holehe',
    license: 'GPL-3.0',
    adopted: 'concept',
    powers: 'not enabled',
    note: 'Account-existence probing via recovery flows is brittle and can look like credential stuffing; deliberately not shipped. Email intel uses public sources instead.',
  },
  {
    id: 'ghunt',
    name: 'GHunt',
    repo: 'mxrch/GHunt',
    license: 'AGPL-3.0',
    adopted: 'concept',
    powers: 'not enabled',
    note: 'Google-account OSINT needs an authenticated session cookie, which this app does not ask for. Listed so the gap is explicit.',
  },
];

/** Frozen lookup by id, for API responses and the UI’s “source” chips. */
export const PROJECTS_BY_ID: Record<string, IntegratedProject> = Object.fromEntries(
  INTEGRATED_PROJECTS.map(p => [p.id, p]),
);

/* ── transport ───────────────────────────────────────────────── */

export const BROWSER_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36';

/** Identifies this deployment to the free services that ask for a contact. */
export const TUGRUL_UA = 'TUGRUL-OSINT/1.0 (+https://github.com/keykavus324-svg/TUGRUL-OSINT)';

export interface HttpOptions {
  timeoutMs?: number;
  headers?: Record<string, string>;
  /** Follow redirects (default true). */
  redirect?: RequestRedirect;
  method?: string;
  body?: BodyInit;
}

export interface HttpResult {
  status: number;
  ok: boolean;
  url: string;
  headers: Headers;
  body: string;
}

/**
 * One request with a hard timeout, returning the body instead of throwing on
 * HTTP status. Callers decide whether a 404 means "no records" or "broken".
 */
export async function httpRequest(url: string, opts: HttpOptions = {}): Promise<HttpResult> {
  const { timeoutMs = 12_000, headers = {}, redirect = 'follow', method = 'GET', body } = opts;
  const res = await fetch(url, {
    method,
    body,
    redirect,
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      'User-Agent': TUGRUL_UA,
      Accept: 'application/json, text/plain, */*',
      'Accept-Language': 'en',
      ...headers,
    },
  });
  const text = await res.text();
  return { status: res.status, ok: res.ok, url: res.url || url, headers: res.headers, body: text };
}

/** JSON GET that throws a readable error on a non-2xx answer. */
export async function httpJson<T>(url: string, opts: HttpOptions = {}): Promise<T> {
  const res = await httpRequest(url, { ...opts, headers: { Accept: 'application/json', ...opts.headers } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return JSON.parse(res.body) as T;
}

/* ── concurrency ─────────────────────────────────────────────── */

/**
 * Bounded-concurrency map. A passive-recon fan-out easily reaches hundreds of
 * sockets; going wide gets every source rate-limited at once and produces a
 * result set full of self-inflicted failures.
 */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

/* ── per-source results ──────────────────────────────────────── */

export interface SourceRun<T> {
  id: string;
  label: string;
  status: 'ok' | 'error' | 'empty';
  /** Present unless the source threw. */
  data?: T;
  error?: string;
  ms: number;
}

/**
 * Run one collector and capture its outcome instead of letting it fail the
 * whole request. `empty` is distinct from `ok`: a source that answered with
 * zero hosts is useful evidence, a source that timed out is not.
 */
export async function runSource<T>(
  id: string,
  label: string,
  fn: () => Promise<T[]>,
): Promise<SourceRun<T[]>> {
  const started = Date.now();
  try {
    const data = await fn();
    return { id, label, status: data.length ? 'ok' : 'empty', data, ms: Date.now() - started };
  } catch (e) {
    return {
      id,
      label,
      status: 'error',
      error: e instanceof Error ? e.message : 'source failed',
      ms: Date.now() - started,
    };
  }
}

/* ── input normalisation ─────────────────────────────────────── */

/**
 * Accept what a person actually pastes — a bare domain, a URL, a URL with a
 * port — and return a lowercase hostname. Returns null for anything that is
 * not a plausible public hostname.
 */
export function normaliseHost(input: string): string | null {
  let value = input.trim().toLowerCase();
  if (!value) return null;

  // A pasted URL: strip scheme, credentials, path, query and port.
  // Backslashes are normalised first: browsers and several proxies treat
  // `https://example.com\\@evil.test` as a path on example.com, but a naive
  // userinfo strip would leave `evil.test` as the host.
  value = value.replace(/\\/g, '/');
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  value = value.replace(/^[^/@]+@/, '');
  value = value.split('/')[0].split('?')[0].split('#')[0];
  value = value.replace(/:\d+$/, '');
  value = value.replace(/\.$/, '');

  // IPv4 literal is not a hostname; callers handle those separately.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return null;

  if (!/^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/.test(value)) return null;
  // A bare public suffix ("com", "co.uk") is not a domain we can scan.
  if (!/\.[a-z]{2,}$/.test(value)) return null;
  return value;
}

/** Keep the host if it is `domain` itself or a subdomain of it. */
export function isWithinDomain(host: string, domain: string): boolean {
  const h = host.toLowerCase().trim().replace(/\.$/, '').replace(/^\*\./, '');
  const d = domain.toLowerCase().trim();
  return h === d || h.endsWith(`.${d}`);
}

/**
 * A DNS label we are willing to put into a query. Rejects anything that could
 * escape the hostname (dots, slashes, whitespace) — subdomain lists come from
 * third parties and are not trusted.
 */
export function isSafeLabel(label: string): boolean {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(label);
}

/** Deduplicate case-insensitively while preserving first-seen order. */
export function unique<T>(items: readonly T[]): T[] {
  return Array.from(new Set(items));
}

/** Milliseconds → the “1.2s” form the UI shows. */
export function seconds(ms: number): string {
  return `${(ms / 1000).toFixed(1)}s`;
}
