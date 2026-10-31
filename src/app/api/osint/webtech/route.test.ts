import { describe, it, expect, vi, afterEach } from 'vitest';
import { GET } from './route';

const ask = (query: string, ip = '203.0.113.20') =>
  GET(new Request(`http://localhost/api/osint/webtech?${query}`, { headers: { 'x-forwarded-for': ip } }));

afterEach(() => vi.unstubAllGlobals());

describe('GET /api/osint/webtech', () => {
  it('requires a target', async () => {
    expect((await ask('')).status).toBe(400);
  });

  it('refuses a private address before any request is made', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    for (const target of ['127.0.0.1', 'http://169.254.169.254/latest/meta-data/', 'http://10.0.0.5/']) {
      const res = await ask(`url=${encodeURIComponent(target)}`, '203.0.113.21');
      expect(res.status).toBe(400);
      expect((await res.json()).error).toContain('refused');
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses a hostname that resolves into a reserved range', async () => {
    // validateHost uses node:dns, which is not stubbed here: .invalid never resolves.
    const res = await ask('url=https://does-not-exist.invalid', '203.0.113.22');
    expect(res.status).toBe(400);
  });

  it('fingerprints a page and reports the stack, headers and cookies', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      const target = String(url);
      if (target.includes('/robots.txt')) return new Response('User-agent: *\nDisallow: /admin\n');
      if (target.includes('security.txt')) return new Response('Contact: mailto:security@example.com\n');
      if (target.includes('favicon')) return new Response('', { status: 404 });
      return new Response('<html><head><title>Test Site</title></head><body><script src="/_next/static/a.js"></script></body></html>', {
        status: 200,
        headers: {
          'content-type': 'text/html',
          server: 'nginx/1.24.0',
          'x-powered-by': 'Next.js',
          'strict-transport-security': 'max-age=31536000',
          'set-cookie': 'sid=abc; Secure; HttpOnly; SameSite=Lax',
        },
      });
    }));

    const res = await ask('url=example.com', '203.0.113.23');
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.finalUrl).toContain('example.com');
    expect(body.title).toBe('Test Site');
    expect(body.technologies.map((t: { name: string }) => t.name)).toEqual(expect.arrayContaining(['Nginx', 'Next.js']));
    expect(body.headerAudit.grade).toMatch(/^[A-F]$/);
    expect(body.robots.disallowed).toEqual([{ agent: '*', path: '/admin' }]);
    expect(body.securityTxt).toBe(true);
    expect(body.warning).toBeUndefined();
  });

  it('returns the failure as data when the target cannot be fetched', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    }));
    const res = await ask('url=example.com', '203.0.113.24');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.error).toContain('ECONNREFUSED');
    expect(body.technologies).toEqual([]);
  });
});
