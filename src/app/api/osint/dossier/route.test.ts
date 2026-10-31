import { describe, it, expect, vi, afterEach } from 'vitest';
import { GET } from './route';

const ask = (query: string, ip = '192.0.2.10') =>
  GET(new Request(`http://localhost/api/osint/dossier?${query}`, { headers: { 'x-forwarded-for': ip } }));

afterEach(() => vi.unstubAllGlobals());

describe('GET /api/osint/dossier', () => {
  it('rejects an empty, oversized or unrecognised target', async () => {
    expect((await ask('')).status).toBe(400);
    expect((await ask(`target=${'a'.repeat(2100)}`)).status).toBe(400);
    // A dotted quad with an octet above 255 is a typo, not a handle to hunt.
    expect((await ask('target=999.1.1.1')).status).toBe(400);
  });

  it('refuses private targets before any module runs', async () => {
    const fetchMock = vi.fn(async () => new Response('', { status: 500 }));
    vi.stubGlobal('fetch', fetchMock);

    for (const target of ['127.0.0.1', '10.0.0.5', 'http://192.168.1.10/admin']) {
      const res = await ask(`target=${encodeURIComponent(target)}`, '192.0.2.11');
      expect(res.status).toBe(400);
      expect((await res.json()).error).toContain('refused');
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns a report shell when every upstream is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('offline');
    }));

    const res = await ask('target=example.com&quick=1', '192.0.2.12');
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.seed).toEqual({ type: 'domain', value: 'example.com' });
    expect(Array.isArray(body.modules)).toBe(true);
    expect(body.modules.length).toBeGreaterThan(0);
    expect(body.modules.every((m: { status: string }) => ['ok', 'error', 'skipped'].includes(m.status))).toBe(true);
    expect(body.modules.some((m: { status: string }) => m.status === 'error')).toBe(true);
    expect(body.modules.every((m: { ms: number }) => typeof m.ms === 'number')).toBe(true);

    // The dossier still frames the gap rather than implying "nothing found".
    expect(body.notes.length).toBeGreaterThan(0);
    expect(body.notes.join(' ').toLowerCase()).toMatch(/did not answer|could not|unavailable|failed|inconclusive/);
    expect(body.risk.level).toBe('unknown');
    expect(body.graph.nodes.some((n: { type: string }) => n.type === 'domain')).toBe(true);
    expect(body.integrations.length).toBeGreaterThan(10);
  });

  it('rate-limits repeated full dossiers', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 500 })));
    let limited = false;
    for (let i = 0; i < 6; i++) {
      const res = await ask('target=example.com&quick=1', '192.0.2.13');
      if (res.status === 429) {
        limited = true;
        break;
      }
    }
    expect(limited).toBe(true);
  });
});
