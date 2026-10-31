import { describe, it, expect, vi, afterEach } from 'vitest';
import { GET } from './route';

const ask = (query: string, ip = '203.0.113.10') =>
  GET(new Request(`http://localhost/api/osint/subdomains?${query}`, { headers: { 'x-forwarded-for': ip } }));

afterEach(() => vi.unstubAllGlobals());

describe('GET /api/osint/subdomains', () => {
  it('rejects a missing or unparseable domain', async () => {
    expect((await ask('')).status).toBe(400);
    expect((await ask('domain=not%20a%20domain')).status).toBe(400);
    expect((await ask('domain=127.0.0.1')).status).toBe(400);
  });

  it('reports every source failure instead of a clean, empty result', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('offline');
    }));
    const res = await ask('domain=example.com&resolve=0', '203.0.113.11');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.total).toBe(0);
    expect(body.sources.every((s: { status: string }) => s.status === 'error')).toBe(true);
    expect(body.notes.join(' ')).toContain('did not answer');
    expect(body.notes.join(' ')).toContain('inconclusive');
  });

  it('merges hosts from multiple sources and keeps provenance', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      const target = String(url);
      if (target.includes('crt.sh')) {
        return Response.json([
          { name_value: 'api.example.com\nwww.example.com', not_before: '2023-01-01T00:00:00' },
        ]);
      }
      if (target.includes('certspotter')) {
        return Response.json([{ dns_names: ['api.example.com', '*.example.com'] }]);
      }
      if (target.includes('hackertarget')) return new Response('vpn.example.com,1.2.3.4\n');
      return new Response('', { status: 404 });
    }));

    const res = await ask('domain=example.com&resolve=0', '203.0.113.12');
    const body = await res.json();
    const api = body.hits.find((h: { host: string }) => h.host === 'api.example.com');
    expect(api).toBeDefined();
    expect(api.sources).toEqual(expect.arrayContaining(['crt.sh', 'Cert Spotter']));
    expect(body.hits.map((h: { host: string }) => h.host)).toContain('vpn.example.com');
  });

  it('caps the probe count rather than passing an unbounded number through', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 404 })));
    const res = await ask('domain=example.com&probe=9999&resolve=0', '203.0.113.13');
    expect(res.status).toBe(200);
  });

  it('rate-limits repeated enumeration', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 404 })));
    let limited = false;
    for (let i = 0; i < 8; i++) {
      const res = await ask('domain=example.com&resolve=0', '203.0.113.99');
      if (res.status === 429) limited = true;
    }
    expect(limited).toBe(true);
  });
});
