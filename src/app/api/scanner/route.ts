import { NextResponse } from 'next/server';
import { reverse as reverseDns } from 'node:dns/promises';
import { getClientIp, isRateLimited, validateHost } from '@/lib/ssrf-guard';
import { normaliseHost } from '@/lib/recon/sources';
import { fingerprintSite, targetUrl } from '@/lib/recon/webtech';
import { inspectTls } from '@/lib/recon/tls';
import { enumerateSubdomains } from '@/lib/recon/subdomains';
import { findTechCves } from '@/lib/recon/cve';
import { ipProfile } from '@/lib/recon/dossier';
import { httpRequest } from '@/lib/recon/sources';

/**
 * TUĞRUL — RECON scanner compatibility endpoint.
 *
 * The RECON toolkit's VULN SWEEP, SSL, HEADERS, SUBDOMAINS and TECH DETECT
 * tabs were written against an external `SCANNER_URL` service that this
 * deployment does not ship, so they returned 503. This route implements the
 * same `?target=&type=` contract in-process:
 *
 *   quick | ssl | headers | subdomains | tech | vuln | rdns | whois | geoloc
 *
 * Each branch returns the *superset* of the fields the existing renderers
 * read, so the UI keeps working without being rewritten around a new shape.
 */
export const maxDuration = 300;

const TYPES = ['quick', 'ssl', 'headers', 'subdomains', 'tech', 'vuln', 'rdns', 'whois', 'geoloc'] as const;
type ScanType = (typeof TYPES)[number];

function domainFor(target: string): string | null {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(target) ? null : normaliseHost(target);
}

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const target = (searchParams.get('target') || '').trim();
  const type = (searchParams.get('type') || 'quick').toLowerCase() as ScanType;

  if (!target) return NextResponse.json({ error: 'Missing target parameter' }, { status: 400 });
  if (!TYPES.includes(type)) {
    return NextResponse.json({ error: `Invalid type. Allowed: ${TYPES.join(', ')}` }, { status: 400 });
  }
  if (isRateLimited(getClientIp(req), 20, 60_000, 'scanner')) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  const domain = domainFor(target);
  const ip = /^(\d{1,3}\.){3}\d{1,3}$/.test(target) ? target : null;

  if (type === 'rdns') {
    if (!ip) return NextResponse.json({ error: 'Reverse DNS needs an IPv4 address' }, { status: 400 });
    try {
      const names = await reverseDns(ip);
      return NextResponse.json({ target, ip, hostnames: names, source: 'node:dns' });
    } catch {
      return NextResponse.json({ target, ip, hostnames: [], note: 'No PTR record (or the resolver refused).' });
    }
  }

  if (type === 'geoloc') {
    if (!ip) return NextResponse.json({ error: 'Geolocation needs an IPv4 address' }, { status: 400 });
    const profile = await ipProfile(ip);
    return NextResponse.json({ target, ...profile, source: 'ip-api.com + Shodan InternetDB' });
  }

  if (type === 'whois') {
    if (!domain) return NextResponse.json({ error: 'WHOIS needs a domain' }, { status: 400 });
    try {
      const res = await httpRequest(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
        timeoutMs: 10_000,
        headers: { Accept: 'application/rdap+json, application/json' },
      });
      if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
      const data = JSON.parse(res.body) as {
        ldhName?: string;
        status?: string[];
        events?: Array<{ eventAction?: string; eventDate?: string }>;
        nameservers?: Array<{ ldhName?: string }>;
        entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
      };
      const event = (name: string) => data.events?.find(e => e.eventAction === name)?.eventDate ?? null;
      const registrarEntity = data.entities?.find(e => (e.roles || []).includes('registrar'));
      const vcard = registrarEntity?.vcardArray?.[1] as Array<[string, unknown, string, string]> | undefined;
      return NextResponse.json({
        target,
        domain: data.ldhName || domain,
        registrar: vcard?.find(v => v[0] === 'fn')?.[3] || null,
        creation_date: event('registration'),
        expiration_date: event('expiration'),
        updated_date: event('last changed'),
        status: data.status || [],
        name_servers: (data.nameservers || []).map(ns => ns.ldhName).filter(Boolean),
        source: 'RDAP',
      });
    } catch (e) {
      return NextResponse.json(
        { error: 'WHOIS lookup failed', detail: e instanceof Error ? e.message : 'unknown error' },
        { status: 502 },
      );
    }
  }

  if (type === 'subdomains') {
    if (!domain) return NextResponse.json({ error: 'Subdomain enumeration needs a domain' }, { status: 400 });
    const report = await enumerateSubdomains(domain, { quick: true, probe: 25 });
    return NextResponse.json({
      target,
      domain,
      total: report.total,
      live: report.live,
      subdomains: report.hits.map(h => h.host),
      hosts: report.hits,
      sources: report.sources,
      elapsed_ms: report.elapsedMs,
      notes: report.notes,
      source: 'crt.sh, Cert Spotter, OTX, HackerTarget, RapidDNS, Wayback, urlscan',
    });
  }

  // Everything below fetches the target page.
  const url = targetUrl(target);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return NextResponse.json({ error: 'Invalid target' }, { status: 400 });
  }
  const check = await validateHost(parsed.hostname);
  if (!check.ok) {
    return NextResponse.json({ error: `Target refused: ${check.reason}` }, { status: 400 });
  }

  if (type === 'ssl') {
    const tls = await inspectTls(parsed.hostname, parsed.port ? Number(parsed.port) : 443);
    if (!tls.connected) {
      return NextResponse.json(
        { ...tls, target, valid: false, error: tls.error || 'TLS handshake failed' },
        { status: 200 },
      );
    }
    return NextResponse.json({
      target,
      protocol: tls.protocol,
      cipher: tls.cipher,
      valid: tls.authorized === true && tls.grade !== 'F',
      issuer: tls.issuer,
      subject: tls.subject,
      expires: tls.validTo,
      valid_from: tls.validFrom,
      days_remaining: tls.daysRemaining,
      sans: tls.san,
      grade: tls.grade,
      issues: tls.issues,
      chain: tls.chain,
      fingerprint_sha256: tls.fingerprintSha256,
      source: 'node:tls (live handshake)',
    });
  }

  const fingerprint = await fingerprintSite(parsed.toString());
  if (fingerprint.error) {
    // An unreachable target is a result, not a server fault: the toolkit shows
    // it inline and the analyst can tell "no answer" from "nothing found".
    return NextResponse.json(
      {
        target,
        type,
        reachable: false,
        error: fingerprint.error,
        note: 'The target did not answer. Header, technology and CVE results were not measured.',
      },
      { status: 200 },
    );
  }

  if (type === 'headers') {
    return NextResponse.json({
      target,
      url: fingerprint.finalUrl,
      status: fingerprint.status,
      title: fingerprint.title,
      score: fingerprint.headerAudit.score,
      grade: fingerprint.headerAudit.grade,
      findings: fingerprint.headerAudit.findings,
      missing: fingerprint.headerAudit.missing,
      disclosures: fingerprint.headerAudit.disclosures,
      headers: fingerprint.headers,
      cookies: fingerprint.cookies,
      source: 'live response headers',
    });
  }

  if (type === 'tech') {
    return NextResponse.json({
      target,
      url: fingerprint.finalUrl,
      status: fingerprint.status,
      title: fingerprint.title,
      server: fingerprint.server,
      favicon: fingerprint.favicon,
      robots: fingerprint.robots,
      security_txt: fingerprint.securityTxt,
      technologies: fingerprint.technologies.map(t => ({
        name: t.name,
        category: t.categories.join(', '),
        categories: t.categories,
        version: t.version || null,
        confidence: t.confidence,
        evidence: t.evidence,
      })),
      external_hosts: fingerprint.externalHosts,
      source: 'built-in signature set',
    });
  }

  if (type === 'vuln') {
    const report = await findTechCves(fingerprint.technologies);
    return NextResponse.json({
      target,
      url: fingerprint.finalUrl,
      technologies: fingerprint.technologies.map(t => ({ name: t.name, version: t.version || null })),
      vulnerabilities: report.technologies.flatMap(t =>
        t.matches.map(m => ({
          id: m.id,
          cve: m.id,
          severity: m.severity,
          cvss: m.cvss,
          description: m.summary,
          type: m.matched === 'version' ? 'version-match' : 'product-match',
          is_exploit: false,
          url: m.url,
        })),
      ),
      total: report.total,
      confirmed: report.confirmed,
      risk_level: report.riskLevel,
      notes: report.notes,
      source: 'CIRCL CVE search',
    });
  }

  // quick — the summary the toolkit shows first
  const tls = await inspectTls(parsed.hostname);
  return NextResponse.json({
    target,
    url: fingerprint.finalUrl,
    status: fingerprint.status,
    title: fingerprint.title,
    server: fingerprint.server,
    technologies: fingerprint.technologies.map(t => t.name),
    security_grade: fingerprint.headerAudit.grade,
    security_score: fingerprint.headerAudit.score,
    tls_grade: tls.grade,
    tls_protocol: tls.protocol,
    favicon: fingerprint.favicon,
    robots: fingerprint.robots,
    security_txt: fingerprint.securityTxt,
    external_hosts: fingerprint.externalHosts,
    source: 'in-process recon (no external scanner service)',
  });
}
