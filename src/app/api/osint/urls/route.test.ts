import { describe, it, expect, vi, afterEach } from 'vitest';
import { GET } from './route';

const ask = (query: string, ip = '198.51.100.10') =>
  GET(new Request(`http://localhost/api/osint/urls?${query}`, { headers: { 'x-forwarded-for': ip } }));


afterEach(() => vi.unstubAllGlobals());

describe('GET /api/osint/urls', () => {
  it('rejects a missing or unparseable domain', async () => {
    expect((await ask('')).status).toBe(400);
    expect((await ask('domain=not%20a%20domain')).status).toBe(400);
    expect((await ask('domain=10.0.0.1')).status).toBe(400);
  });

  it('reports every source failure instead of an empty, authoritative result', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('offline');
    }));
    const res = await ask('domain=example.com&quick=1', '198.51.100.11');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.urls).toEqual([]);
    expect(body.sources.length).toBeGreaterThan(0);
    expect(body.sources.every((s: { status: string }) => s.status === 'error')).toBe(true);
    expect(body.notes.join(' ').toLowerCase()).toContain('inconclusive');
  });

  it('keeps archive rows and classifies what they expose', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      const target = String(url);
      if (target.includes('web.archive.org')) {
        return Response.json([
          ['urlkey', 'timestamp', 'original'],
          ['k1', '20210101000000', 'https://example.com/.env'],
          ['k2', '20210101000000', 'https://example.com/backup.zip'],
          ['k3', '20210101000000', 'https://example.com/about'],
        ]);
      }
      return new Response('', { status: 404 });
    }));

    const res = await ask('domain=example.com&quick=1', '198.51.100.12');
    const body = await res.json();
    expect(body.urls.map((u: { url: string }) => u.url)).toContain('https://example.com/.env');
    const kinds = body.findings.map((f: { kind: string }) => f.kind.toLowerCase());
    expect(kinds.join(' ')).toMatch(/env|config|backup|archive/);
    expect(body.byExtension.some((e: { extension: string }) => e.extension === 'zip')).toBe(true);
  });

  it('clamps the returned list and says the list was truncated', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (String(url).includes('web.archive.org')) {
        const rows = [['urlkey', 'timestamp', 'original']];
        for (let i = 0; i < 60; i++) {
          rows.push([`k${i}`, '20210101000000', `https://example.com/page-${i}`]);
        }
        return Response.json(rows);
      }
      return new Response('', { status: 404 });
    }));

    const res = await ask('domain=example.com&quick=1&limit=50', '198.51.100.13');
    const body = await res.json();
    expect(body.urls.length).toBeLessThanOrEqual(50);
    expect(body.truncated).toBe(true);
  });

  it('rate-limits repeated archive queries', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 404 })));
    let limited = false;
    for (let i = 0; i < 8; i++) {
      const res = await ask('domain=example.com&quick=1', '198.51.100.14');
      if (res.status === 429) {
        limited = true;
        break;
      }
    }
    expect(limited).toBe(true);
  });
});
