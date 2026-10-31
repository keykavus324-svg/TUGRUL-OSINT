/**
 * TUĞRUL RECON+ — one seed, every module, one report.
 *
 * This is the “full recon” entry point. It follows the model Maigret (MIT)
 * and SpiderFoot (MIT) settled on: run independent collectors against the
 * same seed, keep each one's status, then present a single dossier with the
 * evidence and the gaps side by side.
 *
 * A module that fails degrades the report; it never fails the request.
 * Nothing here is a verdict — the risk score is arithmetic over named
 * findings so an analyst can argue with it.
 */

import { scanUsername } from '../sherlock';
import { fingerprintSite, type SiteFingerprint } from './webtech';
import { inspectTls, type TlsReport } from './tls';
import { enumerateSubdomains, type SubdomainReport } from './subdomains';
import { harvestUrls, type UrlReport } from './urls';
import { buildDorks } from './dorks';
import { emailIntel, type EmailIntelReport } from './emailintel';
import { findTechCves, type CveReport } from './cve';
import { buildReconGraph, type ReconGraph } from './graph';
import { httpJson, normaliseHost } from './sources';
import { resolveDns } from './dns';

export type SeedType = 'domain' | 'email' | 'username' | 'ip' | 'url';

export interface Seed {
  type: SeedType;
  value: string;
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

/**
 * Work out what the analyst pasted.
 *
 * Order matters: an email contains a domain, and a URL contains both, so the
 * most specific shape is tested first. An IPv6 literal is accepted as an IP
 * seed without trying to parse it further.
 */
export function detectSeed(input: string): Seed {
  const value = input.trim();
  if (!value) throw new Error('Empty target');

  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
    return { type: 'email', value: value.toLowerCase() };
  }
  if (IPV4.test(value) && value.split('.').every(o => Number(o) >= 0 && Number(o) <= 255)) {
    return { type: 'ip', value };
  }
  if (/^[0-9a-f:]{2,45}$/i.test(value) && value.includes(':')) {
    return { type: 'ip', value };
  }
  if (/^https?:\/\//i.test(value)) {
    try {
      return { type: 'url', value: new URL(value).toString() };
    } catch {
      throw new Error('Invalid URL');
    }
  }
  // A bare domain may still be a handle for a username search; the caller
  // chooses the module set, so guess domain only when it has a public suffix.
  const host = normaliseHost(value);
  if (host) return { type: 'domain', value: host };

  // Four numeric labels that are not a valid IPv4 is a mistyped address, not
  // a handle — say so instead of silently scanning it as a username.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) throw new Error('Invalid IPv4 address');

  if (/^[a-z0-9._-]{1,64}$/i.test(value)) return { type: 'username', value };
  throw new Error('Unrecognised target — expected a domain, URL, email, IP or username');
}

/* ── IP profile ──────────────────────────────────────────────── */

export interface IpProfile {
  ip: string;
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  isp: string | null;
  org: string | null;
  asn: string | null;
  asName: string | null;
  isProxy: boolean | null;
  isHosting: boolean | null;
  isMobile: boolean | null;
  reverse: string | null;
  openPorts: number[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
  cpes: string[];
  notes: string[];
}

interface IpApiResponse {
  status?: string;
  country?: string;
  countryCode?: string;
  regionName?: string;
  city?: string;
  lat?: number;
  lon?: number;
  isp?: string;
  org?: string;
  as?: string;
  asname?: string;
  proxy?: boolean;
  hosting?: boolean;
  mobile?: boolean;
  reverse?: string;
  query?: string;
}

interface InternetDbResponse {
  ip?: string;
  ports?: number[];
  hostnames?: string[];
  tags?: string[];
  vulns?: string[];
  cpes?: string[];
}

/**
 * Two keyless sources: ip-api for ownership and geography, Shodan's
 * InternetDB for what is actually listening. Either can fail independently.
 */
export async function ipProfile(ip: string, timeoutMs = 10_000): Promise<IpProfile> {
  const notes: string[] = [];
  const profile: IpProfile = {
    ip,
    country: null,
    countryCode: null,
    region: null,
    city: null,
    lat: null,
    lon: null,
    isp: null,
    org: null,
    asn: null,
    asName: null,
    isProxy: null,
    isHosting: null,
    isMobile: null,
    reverse: null,
    openPorts: [],
    hostnames: [],
    tags: [],
    vulns: [],
    cpes: [],
    notes,
  };

  const [geo, internetDb] = await Promise.all([
    httpJson<IpApiResponse>(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,proxy,hosting,mobile,reverse,query`,
      { timeoutMs, headers: { Accept: 'application/json' } },
    ).catch(() => null),
    httpJson<InternetDbResponse>(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
      timeoutMs,
      headers: { Accept: 'application/json' },
    }).catch(() => null),
  ]);

  if (geo && geo.status === 'success') {
    profile.country = geo.country ?? null;
    profile.countryCode = geo.countryCode ?? null;
    profile.region = geo.regionName ?? null;
    profile.city = geo.city ?? null;
    profile.lat = typeof geo.lat === 'number' ? geo.lat : null;
    profile.lon = typeof geo.lon === 'number' ? geo.lon : null;
    profile.isp = geo.isp ?? null;
    profile.org = geo.org ?? null;
    profile.asn = geo.as ?? null;
    profile.asName = geo.asname ?? null;
    profile.isProxy = geo.proxy ?? null;
    profile.isHosting = geo.hosting ?? null;
    profile.isMobile = geo.mobile ?? null;
    profile.reverse = geo.reverse ?? null;
  } else {
    notes.push('ip-api did not answer; ownership and location are unknown.');
  }

  if (internetDb) {
    profile.openPorts = (internetDb.ports || []).slice(0, 100);
    profile.hostnames = (internetDb.hostnames || []).slice(0, 50);
    profile.tags = (internetDb.tags || []).slice(0, 20);
    profile.vulns = (internetDb.vulns || []).slice(0, 100);
    profile.cpes = (internetDb.cpes || []).slice(0, 50);
  } else {
    notes.push('Shodan InternetDB has no record for this address, or did not answer.');
  }

  if (!profile.reverse) {
    try {
      const ptr = await resolveDns(ip, 'PTR', { timeoutMs: 4000 });
      profile.reverse = ptr.records[0]?.data?.replace(/\.$/, '') || null;
    } catch {
      /* optional */
    }
  }

  return profile;
}

/* ── username profile ────────────────────────────────────────── */

export interface UsernameProfile {
  username: string;
  found: Array<{ site: string; url: string }>;
  checked: number;
  inconclusive: number;
  blocked: number;
  errors: number;
  elapsedMs: number;
  notes: string[];
}

export async function usernameProfile(username: string, limit = 40, timeoutMs = 8000): Promise<UsernameProfile> {
  const scan = await scanUsername(username, { limit, timeoutMs });
  return {
    username,
    found: scan.found.map(f => ({ site: f.site, url: f.url })),
    checked: scan.checked,
    inconclusive: scan.inconclusive.length,
    blocked: scan.blocked.length,
    errors: scan.errors.length,
    elapsedMs: scan.elapsed_ms,
    notes: [
      'Sites that answered “exists” for a random control handle are excluded from the confirmed list.',
      'A confirmed profile is an account with this handle — not proof it belongs to the person you are looking for.',
    ],
  };
}

/* ── report ──────────────────────────────────────────────────── */

export type ModuleStatus = 'ok' | 'error' | 'skipped';

export interface DossierModule<T = unknown> {
  id: string;
  label: string;
  status: ModuleStatus;
  ms: number;
  error?: string;
  data?: T;
}

export interface DossierRisk {
  score: number;
  level: 'unknown' | 'low' | 'medium' | 'high' | 'critical';
  factors: Array<{ label: string; weight: number; detail: string }>;
}

export interface Dossier {
  seed: Seed;
  generatedAt: string;
  modules: DossierModule[];
  graph: ReconGraph;
  risk: DossierRisk;
  summary: Record<string, string | number>;
  notes: string[];
  elapsedMs: number;
}

export interface DossierOptions {
  /** Skip the archive and brute-force tiers; keep certificate + page + TLS. */
  quick?: boolean;
  /** Run the wordlist tier in the subdomain module. */
  brute?: boolean;
  timeoutMs?: number;
  emailrepKey?: string;
}

async function module<T>(id: string, label: string, run: () => Promise<T>): Promise<DossierModule<T>> {
  const started = Date.now();
  try {
    const data = await run();
    return { id, label, status: 'ok', ms: Date.now() - started, data };
  } catch (e) {
    return {
      id,
      label,
      status: 'error',
      ms: Date.now() - started,
      error: e instanceof Error ? e.message : 'module failed',
    };
  }
}

/**
 * Run the dossier for any supported seed.
 *
 * Domain seeds get the full stack; URL seeds reuse the page they point at;
 * email, IP and username seeds run their own module set. The graph and the
 * risk score are derived from whatever actually returned data.
 */
export async function buildDossier(input: string, opts: DossierOptions = {}): Promise<Dossier> {
  const started = Date.now();
  const seed = detectSeed(input);
  const { quick = false, brute = false, timeoutMs = 12_000, emailrepKey } = opts;

  const modules: DossierModule[] = [];
  const notes: string[] = [];
  const summary: Record<string, string | number> = {};

  let fingerprint: SiteFingerprint | null = null;
  let tls: TlsReport | null = null;
  let subdomains: SubdomainReport | null = null;
  let urls: UrlReport | null = null;
  let email: EmailIntelReport | null = null;
  let ip: IpProfile | null = null;
  let username: UsernameProfile | null = null;
  let cves: CveReport | null = null;

  const isHostSeed = seed.type === 'domain' || seed.type === 'url';
  const host = seed.type === 'url' ? new URL(seed.value).hostname : seed.type === 'domain' ? seed.value : null;

  if (isHostSeed && host) {
    const pageUrl = seed.type === 'url' ? seed.value : host;

    const fingerprintModule = await module('fingerprint', 'Web fingerprint & headers', () =>
      fingerprintSite(pageUrl, { timeoutMs }),
    );
    modules.push(fingerprintModule);
    fingerprint = fingerprintModule.data ?? null;

    // `fetch` failing inside the fingerprint module is returned as data with
    // an `error`, not thrown — a page that does not answer has to be reported
    // as an unreachable target, never as a site with no security headers.
    const pageReached = !!fingerprint && !fingerprint.error && fingerprint.status > 0;
    if (fingerprint && !pageReached) {
      fingerprintModule.status = 'error';
      fingerprintModule.error = fingerprint.error || 'The target did not answer.';
      notes.push(
        `The page did not answer (${fingerprintModule.error}). Header, cookie and stack results were not measured — their absence is not a finding.`,
      );
    }

    const [tlsModule, subsModule, urlsModule] = await Promise.all([
      module('tls', 'TLS certificate', () => inspectTls(host, 443, timeoutMs)),
      quick
        ? Promise.resolve<DossierModule<SubdomainReport>>({ id: 'subdomains', label: 'Passive subdomains', status: 'skipped', ms: 0 })
        : module('subdomains', 'Passive subdomains', () => enumerateSubdomains(host, { brute, quick: true, probe: 20, timeoutMs })),
      quick
        ? Promise.resolve<DossierModule<UrlReport>>({ id: 'urls', label: 'Historical URLs', status: 'skipped', ms: 0 })
        : module('urls', 'Historical URLs', () => harvestUrls(host, { quick: true, timeoutMs })),
    ]);
    modules.push(tlsModule, subsModule, urlsModule);
    tls = tlsModule.data ?? null;
    if (tls && !tls.connected) {
      tlsModule.status = 'error';
      tlsModule.error = tls.error || 'No TLS handshake completed.';
    }
    subdomains = subsModule.data ?? null;
    urls = urlsModule.data ?? null;

    modules.push(await module('dorks', 'Dork catalogue', async () => buildDorks(host)));

    if (fingerprint?.technologies.length) {
      const cveModule = await module('cves', 'Technology CVEs', () =>
        findTechCves(fingerprint!.technologies, { timeoutMs }),
      );
      modules.push(cveModule);
      cves = cveModule.data ?? null;
    }

    if (subdomains) {
      summary.subdomains = subdomains.total;
      summary.resolved_hosts = subdomains.live;
      notes.push(...subdomains.notes);
    }
    if (urls) {
      summary.archived_urls = urls.urls.length;
      summary.url_findings = urls.findings.length;
      notes.push(...urls.notes);
    }
    if (pageReached && fingerprint) {
      summary.technologies = fingerprint.technologies.length;
      summary.security_grade = fingerprint.headerAudit.grade;
    }
  }

  if (seed.type === 'email') {
    const emailModule = await module('email', 'Email intelligence', () =>
      emailIntel(seed.value, { timeoutMs, quick, emailrepKey }),
    );
    modules.push(emailModule);
    email = emailModule.data ?? null;
    if (email) {
      summary.breaches = email.breaches.breaches.length;
      summary.provider = email.provider;
      notes.push(...email.notes);
    }
  }

  if (seed.type === 'ip') {
    const ipModule = await module('ip', 'IP ownership & exposure', () => ipProfile(seed.value, timeoutMs));
    modules.push(ipModule);
    ip = ipModule.data ?? null;
    if (ip) {
      summary.open_ports = ip.openPorts.length;
      summary.known_vulns = ip.vulns.length;
      notes.push(...ip.notes);
    }
  }

  if (seed.type === 'username') {
    const usernameModule = await module('username', 'Username enumeration', () =>
      usernameProfile(seed.value, quick ? 20 : 40, 8000),
    );
    modules.push(usernameModule);
    username = usernameModule.data ?? null;
    if (username) {
      summary.confirmed_accounts = username.found.length;
      notes.push(...username.notes);
    }
  }

  /* ── graph ── */
  const graphSeedType: 'domain' | 'ip' | 'email' | 'username' | 'url' = seed.type;

  const externalHosts = (fingerprint?.externalHosts || []).map(h => ({ host: h, ips: [], sources: ['page assets'] }));
  const hostNodes = [
    ...(subdomains?.hits || []).map(h => ({ host: h.host, ips: h.ips, sources: h.sources })),
    ...externalHosts,
  ];

  const graph = buildReconGraph({
    seed: seed.value,
    seedType: graphSeedType,
    hosts: hostNodes,
    technologies: fingerprint?.technologies.map(t => ({ name: t.name, version: t.version })) || [],
    emails: email ? [email.address] : [],
    findings: (urls?.findings || [])
      .filter(f => f.severity !== 'low')
      .slice(0, 30)
      .map(f => ({ url: f.url, kind: f.kind, severity: f.severity })),
    certificate: tls?.issuer ? { issuer: tls.issuer, validTo: tls.validTo, san: tls.san } : undefined,
    nameservers: [],
    addresses: seed.type === 'ip' ? [seed.value] : [],
  });

  if (ip) {
    graph.nodes.push({
      id: `organization:${(ip.org || ip.isp || ip.asn || 'unknown').toLowerCase()}`,
      label: ip.org || ip.isp || ip.asn || 'unknown owner',
      type: 'organization',
      risk: null,
      meta: { asn: ip.asn ?? '', isp: ip.isp ?? '' },
    });
    graph.edges.push({
      source: graph.rootId,
      target: `organization:${(ip.org || ip.isp || ip.asn || 'unknown').toLowerCase()}`,
      label: 'announced_by',
    });
    for (const hostname of ip.hostnames.slice(0, 20)) {
      const nodeId = `host:${hostname.toLowerCase()}`;
      graph.nodes.push({ id: nodeId, label: hostname, type: 'host', risk: null, meta: { reverse: 'true' } });
      graph.edges.push({ source: nodeId, target: graph.rootId, label: 'resolves_to' });
    }
  }

  if (username) {
    for (const account of username.found.slice(0, 40)) {
      const nodeId = `url:${account.url.toLowerCase()}`;
      graph.nodes.push({ id: nodeId, label: account.url, type: 'url', risk: null, meta: { site: account.site } });
      graph.edges.push({ source: graph.rootId, target: nodeId, label: 'account_on' });
    }
  }

  if (email) {
    for (const account of email.gravatar.accounts || []) {
      const nodeId = `username:${(account.username || account.domain).toLowerCase()}`;
      graph.nodes.push({
        id: nodeId,
        label: account.username || account.domain,
        type: 'username',
        risk: null,
        meta: { domain: account.domain, url: account.url },
      });
      graph.edges.push({ source: graph.rootId, target: nodeId, label: 'gravatar_account' });
    }
    for (const breach of email.breaches.breaches.slice(0, 20)) {
      const nodeId = `organization:${breach.toLowerCase()}`;
      graph.nodes.push({ id: nodeId, label: breach, type: 'organization', risk: null, meta: { kind: 'breach' } });
      graph.edges.push({ source: graph.rootId, target: nodeId, label: 'exposed_in' });
    }
  }

  /* ── risk ── */
  const factors: DossierRisk['factors'] = [];
  const addFactor = (label: string, weight: number, detail: string) => factors.push({ label, weight, detail });

  if (tls) {
    if (tls.grade === 'F') addFactor('Expired certificate', 25, tls.issues[0] || 'Certificate expired.');
    else if (tls.grade === 'D') addFactor('Weak TLS', 15, tls.issues[0] || 'TLS configuration is weak.');
    else if (tls.grade === 'C') addFactor('TLS needs attention', 6, tls.issues[0] || 'Certificate expires soon.');
  }
  if (fingerprint && !fingerprint.error && fingerprint.status > 0) {
    if (fingerprint.headerAudit.score < 50) addFactor('Weak security headers', 18, `Header grade ${fingerprint.headerAudit.grade} (${fingerprint.headerAudit.score}/100).`);
    else if (fingerprint.headerAudit.score < 75) addFactor('Incomplete security headers', 8, `Header grade ${fingerprint.headerAudit.grade}.`);
    if (fingerprint.technologies.some(t => t.version)) addFactor('Version disclosed', 4, 'The site volunteers software versions, which shortens an attacker’s search.');
  }
  if (urls) {
    const high = urls.findings.filter(f => f.severity === 'high').length;
    const medium = urls.findings.filter(f => f.severity === 'medium').length;
    if (high) addFactor('Exposed files in archive', Math.min(30, high * 8), `${high} high-severity URL finding(s), e.g. ${urls.findings[0]?.kind}.`);
    else if (medium) addFactor('Administrative surface in archive', Math.min(15, medium * 4), `${medium} medium-severity URL finding(s).`);
  }
  if (cves && cves.confirmed > 0) addFactor('Version-matched CVEs', Math.min(25, 5 + cves.confirmed), `${cves.confirmed} CVE(s) match the detected versions.`);
  if (ip?.vulns.length) addFactor('Shodan-reported CVEs', Math.min(25, ip.vulns.length * 3), `${ip.vulns.length} CVE(s) recorded for this address.`);
  if (ip?.openPorts.length) addFactor('Exposed services', Math.min(15, ip.openPorts.length), `${ip.openPorts.length} port(s) seen open by Shodan.`);
  if (email) {
    for (const f of email.risk.factors) addFactor(f.label, f.weight, f.detail);
  }
  if (username && username.inconclusive > 0) {
    addFactor('Unverifiable sites', 2, `${username.inconclusive} site(s) accepted a control handle; their positives were discarded.`);
  }

  const score = Math.min(100, factors.reduce((sum, f) => sum + f.weight, 0));

  // A zero score only means "low" when something was actually measured. If
  // every remote module failed, the honest answer is `unknown` — calling it
  // low would turn an offline target into a clean bill of health.
  const measured = modules.some(m => m.status === 'ok' && m.id !== 'dorks');
  const level: DossierRisk['level'] = !measured
    ? 'unknown'
    : score >= 70 ? 'critical' : score >= 45 ? 'high' : score >= 20 ? 'medium' : 'low';

  if (!modules.some(m => m.status === 'ok')) {
    notes.push('No module returned data. The result is inconclusive, not a clean bill of health.');
  }
  notes.push('This dossier is assembled from public and historical sources. Each module states its own limits; a low score is not proof of safety.');

  return {
    seed,
    generatedAt: new Date().toISOString(),
    modules,
    graph,
    risk: { score, level, factors: factors.sort((a, b) => b.weight - a.weight) },
    summary,
    notes,
    elapsedMs: Date.now() - started,
  };
}
