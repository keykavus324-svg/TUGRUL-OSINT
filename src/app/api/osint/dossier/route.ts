import { NextResponse } from 'next/server';
import { getClientIp, isRateLimited, validateHost } from '@/lib/ssrf-guard';
import { buildDossier, detectSeed } from '@/lib/recon/dossier';
import { INTEGRATED_PROJECTS } from '@/lib/recon/sources';

/**
 * TUĞRUL RECON+ — full dossier for one seed.
 *
 *   ?target=  domain | URL | email | IP | username
 *   ?quick=1  page + certificate only (no archive or subdomain tiers)
 *   ?brute=1  include the DNS wordlist tier
 *
 * One request, many independent modules, each with its own status. Domain
 * and URL seeds are validated against the SSRF guard because the page
 * fingerprint fetches them from this server.
 */
export const maxDuration = 300;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const target = (searchParams.get('target') || searchParams.get('query') || '').trim();

  if (!target) {
    return NextResponse.json({ error: 'Missing target parameter' }, { status: 400 });
  }
  if (target.length > 2048) {
    return NextResponse.json({ error: 'Target too long' }, { status: 400 });
  }

  if (isRateLimited(getClientIp(req), 4, 60_000, 'osint-dossier')) {
    return NextResponse.json({ error: 'Rate limit exceeded — a full dossier runs many upstream queries' }, { status: 429 });
  }

  let seed;
  try {
    seed = detectSeed(target);
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : 'Unrecognised target' }, { status: 400 });
  }

  // Anything that will be looked up from this server must clear the SSRF
  // guard. An address seed is refused when it is private: the public
  // registries behind this module have nothing to say about RFC1918 space,
  // and silently returning an empty dossier would look like a clean result.
  if (seed.type === 'domain' || seed.type === 'url' || seed.type === 'ip') {
    let host: string;
    try {
      host = seed.type === 'url' ? new URL(seed.value).hostname : seed.value;
    } catch {
      return NextResponse.json({ error: 'Invalid URL' }, { status: 400 });
    }
    const check = await validateHost(host);
    if (!check.ok) {
      return NextResponse.json({ error: `Target refused: ${check.reason}` }, { status: 400 });
    }
  }

  try {
    const dossier = await buildDossier(target, {
      quick: searchParams.get('quick') === '1',
      brute: searchParams.get('brute') === '1',
      emailrepKey: process.env.EMAILREP_API_KEY || undefined,
    });
    return NextResponse.json({
      ...dossier,
      integrations: INTEGRATED_PROJECTS.filter(p => p.adopted !== 'concept' || p.powers !== 'not enabled').map(p => ({
        id: p.id,
        project: p.name,
        license: p.license,
        powers: p.powers,
      })),
    });
  } catch (e) {
    return NextResponse.json(
      { error: 'Dossier failed', detail: e instanceof Error ? e.message : 'unknown error' },
      { status: 502 },
    );
  }
}
