import { NextResponse } from 'next/server';
import { getClientIp, isRateLimited, validateHost } from '@/lib/ssrf-guard';
import { normaliseHost } from '@/lib/recon/sources';
import { inspectTls } from '@/lib/recon/tls';

/**
 * TUĞRUL RECON+ — TLS certificate and transport inspection.
 *
 *   ?host=  hostname or IP (required)
 *   ?port=  default 443, 1-65535
 *
 * The certificate is deliberately not required to verify: reporting an
 * expired or self-signed certificate is the point of the endpoint.
 */
export const maxDuration = 30;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const raw = (searchParams.get('host') || searchParams.get('target') || searchParams.get('domain') || '').trim();
  const host = /^(\d{1,3}\.){3}\d{1,3}$/.test(raw) ? raw : normaliseHost(raw);

  if (!host) {
    return NextResponse.json({ error: 'Missing or invalid host parameter' }, { status: 400 });
  }

  const portParam = Number(searchParams.get('port'));
  const port = Number.isInteger(portParam) && portParam > 0 && portParam <= 65535 ? portParam : 443;

  if (isRateLimited(getClientIp(req), 20, 60_000, 'osint-tls')) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  const check = await validateHost(host);
  if (!check.ok) {
    return NextResponse.json({ error: `Target refused: ${check.reason}` }, { status: 400 });
  }

  const report = await inspectTls(host, port);
  return NextResponse.json(report);
}
