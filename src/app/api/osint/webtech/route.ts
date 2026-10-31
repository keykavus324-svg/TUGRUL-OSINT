import { NextResponse } from 'next/server';
import { getClientIp, isRateLimited, validateHost } from '@/lib/ssrf-guard';
import { fingerprintSite, targetUrl } from '@/lib/recon/webtech';

/**
 * TUĞRUL RECON+ — page fingerprint, technology stack and security headers.
 *
 *   ?url=  absolute URL or bare hostname (required)
 *
 * Fetches one page from this server, so the target is validated against the
 * SSRF guard first: a recon tool that can be pointed at 169.254.169.254 is a
 * privilege-escalation gadget, not a feature.
 */
export const maxDuration = 60;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const target = (searchParams.get('url') || searchParams.get('target') || searchParams.get('domain') || '').trim();

  if (!target) {
    return NextResponse.json({ error: 'Missing url parameter' }, { status: 400 });
  }

  if (isRateLimited(getClientIp(req), 20, 60_000, 'osint-webtech')) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  let parsed: URL;
  try {
    parsed = new URL(targetUrl(target));
  } catch {
    return NextResponse.json({ error: 'Invalid URL' }, { status: 400 });
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return NextResponse.json({ error: 'Only http and https targets are supported' }, { status: 400 });
  }

  const check = await validateHost(parsed.hostname);
  if (!check.ok) {
    return NextResponse.json({ error: `Target refused: ${check.reason}` }, { status: 400 });
  }

  try {
    const report = await fingerprintSite(parsed.toString());
    if (report.error) {
      // A failed fetch is a finding about the target, not a bug here.
      return NextResponse.json({ ...report, warning: report.error }, { status: 200 });
    }
    return NextResponse.json(report);
  } catch (e) {
    return NextResponse.json(
      { error: 'Fingerprint failed', detail: e instanceof Error ? e.message : 'unknown error' },
      { status: 502 },
    );
  }
}
