import { NextResponse } from 'next/server';
import { getClientIp, isRateLimited } from '@/lib/ssrf-guard';
import { normaliseHost } from '@/lib/recon/sources';
import { harvestUrls } from '@/lib/recon/urls';

/**
 * TUĞRUL RECON+ — historical URL harvest.
 *
 *   ?domain=  target domain (required)
 *   ?quick=1  skip Common Crawl
 *   ?limit=   cap the URL list handed back (default 2000)
 *
 * The full list is capped server-side before serialising; an archive with
 * 50 000 entries should not become a 40 MB response.
 */
export const maxDuration = 120;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const domain = normaliseHost(searchParams.get('domain') || searchParams.get('target') || '');

  if (!domain) {
    return NextResponse.json({ error: 'Missing or invalid domain parameter' }, { status: 400 });
  }

  if (isRateLimited(getClientIp(req), 6, 60_000, 'osint-urls')) {
    return NextResponse.json({ error: 'Rate limit exceeded — archive queries are expensive' }, { status: 429 });
  }

  const limitParam = Number(searchParams.get('limit'));
  const limit = Number.isFinite(limitParam) ? Math.min(Math.max(Math.trunc(limitParam), 50), 6000) : 2000;

  try {
    const report = await harvestUrls(domain, { quick: searchParams.get('quick') === '1' });
    return NextResponse.json({
      ...report,
      urls: report.urls.slice(0, limit),
      truncated: report.urls.length > limit,
    });
  } catch (e) {
    return NextResponse.json(
      { error: 'URL harvest failed', detail: e instanceof Error ? e.message : 'unknown error' },
      { status: 502 },
    );
  }
}
