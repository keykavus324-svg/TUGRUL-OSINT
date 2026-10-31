import { NextResponse } from 'next/server';
import { getClientIp, isRateLimited } from '@/lib/ssrf-guard';
import { emailIntel, parseEmail } from '@/lib/recon/emailintel';

/**
 * TUĞRUL RECON+ — email intelligence.
 *
 *   ?email=  address (required)
 *   ?quick=1 skip Gravatar, reputation, breach corpus and RDAP
 *
 * The address is personal data. Nothing is logged or stored, and the caller
 * is expected to have a lawful basis — see SECURITY.md.
 */
export const maxDuration = 90;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const address = (searchParams.get('email') || searchParams.get('query') || '').trim();

  if (!address) {
    return NextResponse.json({ error: 'Missing email parameter' }, { status: 400 });
  }
  if (address.length > 254) {
    return NextResponse.json({ error: 'Address too long' }, { status: 400 });
  }

  const parsed = parseEmail(address);
  if (!parsed.valid) {
    return NextResponse.json({ error: `Invalid email address (${parsed.reason})` }, { status: 400 });
  }

  if (isRateLimited(getClientIp(req), 10, 60_000, 'osint-email')) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  try {
    const report = await emailIntel(parsed.address, {
      quick: searchParams.get('quick') === '1',
      // Optional: brings back reputation detail without changing the keyless path.
      emailrepKey: process.env.EMAILREP_API_KEY || undefined,
    });
    return NextResponse.json(report);
  } catch (e) {
    return NextResponse.json(
      { error: 'Email intelligence failed', detail: e instanceof Error ? e.message : 'unknown error' },
      { status: 502 },
    );
  }
}
