import { NextResponse } from 'next/server';
import { getClientIp, isRateLimited } from '@/lib/ssrf-guard';
import { enumerateSubdomains } from '@/lib/recon/subdomains';
import { normaliseHost } from '@/lib/recon/sources';

/**
 * TUĞRUL RECON+ — passive subdomain enumeration.
 *
 *   ?domain=  target domain (required)
 *   ?brute=1  add the DNS wordlist tier
 *   ?quick=1  certificate transparency only (fast first pass)
 *   ?resolve=0  skip A/AAAA resolution
 *   ?probe=    how many resolved hosts to HTTP-probe (default 40, max 80)
 *
 * Every source reports its own status in `sources`, so a timeout is never
 * presented as “no hosts found”.
 */
export const maxDuration = 120;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const domain = normaliseHost(searchParams.get('domain') || searchParams.get('target') || '');

  if (!domain) {
    return NextResponse.json(
      { error: 'Missing or invalid domain parameter' },
      { status: 400 },
    );
  }

  if (domain.split('.').length < 2) {
    return NextResponse.json({ error: 'A registrable domain is required (e.g. example.com)' }, { status: 400 });
  }

  if (isRateLimited(getClientIp(req), 6, 60_000, 'osint-subdomains')) {
    return NextResponse.json({ error: 'Rate limit exceeded — subdomain enumeration is expensive' }, { status: 429 });
  }

  const probeParam = Number(searchParams.get('probe'));
  const probe = Number.isFinite(probeParam) ? Math.min(Math.max(probeParam, 0), 80) : 40;

  try {
    const report = await enumerateSubdomains(domain, {
      brute: searchParams.get('brute') === '1',
      quick: searchParams.get('quick') === '1',
      resolve: searchParams.get('resolve') !== '0',
      probe,
    });
    return NextResponse.json(report);
  } catch (e) {
    return NextResponse.json(
      { error: 'Subdomain enumeration failed', detail: e instanceof Error ? e.message : 'unknown error' },
      { status: 502 },
    );
  }
}
