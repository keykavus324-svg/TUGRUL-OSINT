import { describe, it, expect, vi, afterEach } from 'vitest';
import { GET } from './route';

const ask = (query: string, ip = '203.0.113.70') =>
  GET(new Request(`http://localhost/api/scanner?${query}`, { headers: { 'x-forwarded-for': ip } }));

afterEach(() => vi.unstubAllGlobals());

describe('GET /api/scanner (compatibility contract)', () => {
  it('rejects a missing target and an unknown type', async () => {
    expect((await ask('')).status).toBe(400);
    expect((await ask('target=example.com&type=nope')).status).toBe(400);
  });

  it('serves the types the RECON toolkit asks for', async () => {
    for (const type of ['quick', 'ssl', 'headers', 'subdomains', 'tech', 'vuln', 'rdns', 'whois', 'geoloc']) {
      const res = await ask(`target=example.com&type=${type}`);
      // None of these may answer 404 or 500 — the tab used to show 503 here.
      expect([200, 400, 429, 502]).toContain(res.status);
    }
  });

  it('requires an IPv4 address for reverse DNS and geolocation', async () => {
    const rdns = await ask('target=example.com&type=rdns');
    expect(rdns.status).toBe(400);
    const geo = await ask('target=example.com&type=geoloc');
    expect(geo.status).toBe(400);
  });

  it('refuses private targets for the page-based scans', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    for (const type of ['quick', 'ssl', 'headers', 'tech', 'vuln']) {
      const res = await ask(`target=127.0.0.1&type=${type}`);
      expect(res.status).toBe(400);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('resolves reverse DNS through node:dns without an outbound HTTP call', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const res = await ask('target=127.0.0.1&type=rdns');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ip).toBe('127.0.0.1');
    expect(Array.isArray(body.hostnames)).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('maps a headers scan onto the fields the existing renderer reads', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (String(url).includes('/robots.txt') || String(url).includes('security.txt') || String(url).includes('favicon')) {
        return new Response('', { status: 404 });
      }
      return new Response('<html><head><title>OK</title></head><body></body></html>', {
        status: 200,
        headers: { 'content-type': 'text/html', server: 'nginx', 'x-content-type-options': 'nosniff' },
      });
    }));

    const res = await ask('target=example.com&type=headers', '203.0.113.71');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('score');
    expect(body).toHaveProperty('grade');
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.headers).toHaveProperty('server');
  });
});
