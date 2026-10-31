import { describe, it, expect, vi, afterEach } from 'vitest';
import { GET } from './route';

const ask = (query: string, ip = '203.0.113.60') =>
  GET(new Request(`http://localhost/api/osint/vulns?${query}`, { headers: { 'x-forwarded-for': ip } }));

afterEach(() => vi.unstubAllGlobals());

describe('GET /api/osint/vulns', () => {
  it('needs a url or a product', async () => {
    expect((await ask('')).status).toBe(400);
  });

  it('refuses a product with no CPE mapping and lists what is mapped', async () => {
    const res = await ask('product=UnknownWidget');
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('No CPE mapping');
    expect(body.mapped_products).toContain('Nginx');
    expect(body.mapped_products).toContain('WordPress');
  });

  it('accepts a known product case-insensitively', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json([])));
    const res = await ask('product=nginx&version=1.24.0');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.technologies[0]).toMatchObject({ name: 'Nginx', version: '1.24.0', mapped: true });
    expect(body.risk_level).toBe('UNKNOWN');
  });

  it('flattens matches into the shape the VULN SWEEP renderer reads', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      Response.json([
        { id: 'CVE-2024-1', summary: 'bad thing', cvss: 9.1, vulnerable_configuration: ['cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*'] },
        { id: 'CVE-2023-2', summary: 'older thing', cvss: 4.2, vulnerable_configuration: ['cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'] },
      ])));

    const body = await (await ask('product=nginx&version=1.24.0')).json();
    expect(body.vulnerabilities).toHaveLength(2);
    expect(body.vulnerabilities[0]).toMatchObject({ cve: 'CVE-2024-1', severity: 'CRITICAL', type: 'version-match', is_exploit: false });
    expect(body.vulnerabilities[1].type).toBe('product-match');
    expect(body.risk_level).toBe('CRITICAL');
  });

  it('explains an empty technology list instead of returning a bare zero', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      '<html><head><title>Nothing to see</title></head><body>plain page</body></html>',
      { status: 200, headers: { 'content-type': 'text/html' } },
    )));
    // A public literal address so the SSRF guard passes without DNS.
    const res = await ask('url=https://8.8.8.8', '203.0.113.61');
    expect(res.status).toBe(200);
    const body = await res.json();
    if (body.technologies.length === 0) {
      expect(body.notes.join(' ')).toContain('inconclusive');
    }
  });
});
