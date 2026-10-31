import { NextResponse } from 'next/server';
import { getClientIp, isRateLimited, validateHost } from '@/lib/ssrf-guard';
import { fingerprintSite, targetUrl, type Technology } from '@/lib/recon/webtech';
import { findTechCves, TECH_CPE } from '@/lib/recon/cve';

/**
 * TUĞRUL RECON+ — technology-based CVE correlation.
 *
 *   ?url=     fingerprint this site, then look up its stack (usual mode)
 *   ?product= look up one product by name, using its CPE mapping
 *   ?version= version for ?product= (improves confirmation, never guesses)
 *
 * This replaces the external `SCANNER_URL` service for the VULN SWEEP tab.
 * It is correlation, not scanning: no packets are sent to the target beyond
 * the single page fetch used for fingerprinting.
 */
export const maxDuration = 90;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const urlParam = (searchParams.get('url') || searchParams.get('target') || '').trim();
  const productParam = (searchParams.get('product') || '').trim();
  const version = (searchParams.get('version') || '').trim() || undefined;

  if (!urlParam && !productParam) {
    return NextResponse.json({ error: 'Provide either url or product' }, { status: 400 });
  }

  if (isRateLimited(getClientIp(req), 10, 60_000, 'osint-vulns')) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  let technologies: Technology[] = [];
  let target = productParam || urlParam;

  if (productParam) {
    const known = Object.keys(TECH_CPE).find(name => name.toLowerCase() === productParam.toLowerCase());
    if (!known) {
      return NextResponse.json(
        {
          error: `No CPE mapping for “${productParam}”`,
          mapped_products: Object.keys(TECH_CPE),
        },
        { status: 400 },
      );
    }
    technologies = [{ name: known, categories: ['framework'], confidence: 'high', evidence: ['manual product query'], ...(version ? { version } : {}) }];
  } else {
    let parsed: URL;
    try {
      parsed = new URL(targetUrl(urlParam));
    } catch {
      return NextResponse.json({ error: 'Invalid URL' }, { status: 400 });
    }
    const check = await validateHost(parsed.hostname);
    if (!check.ok) {
      return NextResponse.json({ error: `Target refused: ${check.reason}` }, { status: 400 });
    }

    const fingerprint = await fingerprintSite(parsed.toString());
    if (fingerprint.error) {
      return NextResponse.json(
        { error: 'Could not fingerprint the target', detail: fingerprint.error },
        { status: 502 },
      );
    }
    technologies = fingerprint.technologies;
    target = fingerprint.finalUrl;
  }

  if (!technologies.length) {
    return NextResponse.json({
      target,
      technologies: [],
      vulnerabilities: [],
      total: 0,
      risk_level: 'UNKNOWN',
      notes: ['No technology signatures matched, so no CVE correlation was possible. This is an inconclusive result.'],
    });
  }

  const report = await findTechCves(technologies);

  // Flat list for the toolkit's existing VULN SWEEP renderer.
  const vulnerabilities = report.technologies.flatMap(t =>
    t.matches.map(m => ({
      id: `${m.id} · ${t.technology}${t.version ? ` ${t.version}` : ''}`,
      cve: m.id,
      severity: m.severity,
      cvss: m.cvss,
      description: m.summary,
      type: m.matched === 'version' ? 'version-match' : 'product-match',
      is_exploit: false,
      url: m.url,
    })),
  );

  return NextResponse.json({
    target,
    ...report,
    technologies: technologies.map(t => ({
      name: t.name,
      version: t.version || null,
      confidence: t.confidence,
      evidence: t.evidence,
      mapped: Boolean(TECH_CPE[t.name]),
    })),
    // The toolkit's VULN SWEEP renderer reads these two legacy fields.
    vulnerabilities,
    risk_level: report.riskLevel,
  });
}
