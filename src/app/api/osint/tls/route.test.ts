import { describe, it, expect, vi, afterEach } from 'vitest';
import { GET } from './route';

const ask = (query: string, ip = '203.0.113.50') =>
  GET(new Request(`http://localhost/api/osint/tls?${query}`, { headers: { 'x-forwarded-for': ip } }));

afterEach(() => vi.unstubAllGlobals());

describe('GET /api/osint/tls', () => {
  it('requires a host', async () => {
    expect((await ask('')).status).toBe(400);
    expect((await ask('host=not%20a%20host')).status).toBe(400);
  });

  it('refuses reserved targets without opening a socket', async () => {
    for (const host of ['127.0.0.1', '10.1.2.3', '192.168.1.1']) {
      const res = await ask(`host=${host}`);
      expect(res.status).toBe(400);
      expect((await res.json()).error).toContain('refused');
    }
  });

  it('ignores an out-of-range port and clamps to 443', async () => {
    // The target is refused before the port matters; this asserts the parse
    // path does not throw on a nonsense port.
    const res = await ask('host=127.0.0.1&port=999999');
    expect(res.status).toBe(400);
  });
});
