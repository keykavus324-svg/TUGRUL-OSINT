import { NextResponse } from 'next/server';
import { getClientIp, isRateLimited } from '@/lib/ssrf-guard';
import { normaliseHost } from '@/lib/recon/sources';
import { buildDorks, summariseDorks, type DorkCategory, type DorkRisk } from '@/lib/recon/dorks';

/**
 * TUĞRUL RECON+ — dork builder.
 *
 *   ?target=    domain (required)
 *   ?category=  one or more comma-separated categories
 *   ?maxRisk=   info | medium | high (default high)
 *
 * Pure computation: no search engine is contacted. Links are returned for
 * the analyst to open under their own account.
 */
export const maxDuration = 15;

const RISKS: DorkRisk[] = ['info', 'medium', 'high'];
const CATEGORIES: DorkCategory[] = [
  'panels', 'exposed', 'secrets', 'directories', 'documents',
  'cameras', 'databases', 'errors', 'infrastructure', 'code', 'cloud',
];

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const target = normaliseHost(searchParams.get('target') || searchParams.get('domain') || '');

  if (!target) {
    return NextResponse.json({ error: 'Missing or invalid target domain' }, { status: 400 });
  }

  if (isRateLimited(getClientIp(req), 60, 60_000, 'osint-dorks')) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  const maxRiskParam = (searchParams.get('maxRisk') || '').toLowerCase();
  if (maxRiskParam && !RISKS.includes(maxRiskParam as DorkRisk)) {
    return NextResponse.json({ error: `Invalid maxRisk. Allowed: ${RISKS.join(', ')}` }, { status: 400 });
  }

  const requested = (searchParams.get('category') || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  const invalid = requested.filter(c => !CATEGORIES.includes(c as DorkCategory));
  if (invalid.length) {
    return NextResponse.json({ error: `Unknown category: ${invalid.join(', ')}` }, { status: 400 });
  }

  const dorks = buildDorks(target, {
    categories: requested.length ? (requested as DorkCategory[]) : undefined,
    maxRisk: (maxRiskParam as DorkRisk) || undefined,
  });

  return NextResponse.json({
    target,
    total: dorks.length,
    categories: summariseDorks(dorks),
    dorks,
    note: 'Queries are generated, not scraped. Open them in a browser; respect each engine’s terms and the target’s scope.',
  });
}
