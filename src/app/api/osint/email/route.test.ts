import { describe, it, expect, vi, afterEach } from 'vitest';
import { GET } from './route';

const ask = (query: string, ip = '203.0.113.30') =>
  GET(new Request(`http://localhost/api/osint/email?${query}`, { headers: { 'x-forwarded-for': ip } }));

afterEach(() => vi.unstubAllGlobals());

describe('GET /api/osint/email', () => {
  it('rejects a malformed address before doing any work', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    for (const bad of ['', 'not-an-email', 'a@', 'a..b@example.com']) {
      const res = await ask(`email=${encodeURIComponent(bad)}`);
      expect(res.status).toBe(400);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('still returns a report when every upstream fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('offline');
    }));

    const res = await ask('email=analyst@example.com', '203.0.113.31');
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.address).toBe('analyst@example.com');
    expect(body.domain).toBe('example.com');
    expect(body.breaches.status).toBe('unavailable');
    expect(body.reputation.status).toBe('unavailable');
    expect(body.domainAge.status).toBe('unavailable');
    expect(body.notes.join(' ')).toContain('did not answer');
    // No MX was learned, so the report must not claim the domain accepts mail.
    expect(body.mx).toEqual([]);
    expect(body.risk).toBeDefined();
  });

  it('carries the rate-limit boundary for a burst on one address', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 404 })));
    let limited = false;
    for (let i = 0; i < 12; i++) {
      const res = await ask('email=a@example.com&quick=1', '203.0.113.77');
      if (res.status === 429) limited = true;
    }
    expect(limited).toBe(true);
  });
});
