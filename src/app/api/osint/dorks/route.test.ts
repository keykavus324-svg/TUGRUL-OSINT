import { describe, it, expect } from 'vitest';
import { GET } from './route';

const ask = (query: string, ip = '203.0.113.40') =>
  GET(new Request(`http://localhost/api/osint/dorks?${query}`, { headers: { 'x-forwarded-for': ip } }));

describe('GET /api/osint/dorks', () => {
  it('requires a valid target', async () => {
    expect((await ask('')).status).toBe(400);
    expect((await ask('target=not%20a%20domain')).status).toBe(400);
    expect((await ask('target=127.0.0.1')).status).toBe(400);
  });

  it('returns the catalogue with engine links', async () => {
    const res = await ask('target=example.com');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.total).toBeGreaterThan(20);
    expect(body.dorks[0].links.google).toContain('google.com/search');
    expect(body.categories.length).toBeGreaterThan(3);
    expect(body.note).toContain('not scraped');
  });

  it('filters by category and rejects an unknown one', async () => {
    const ok = await (await ask('target=example.com&category=exposed')).json();
    expect(ok.dorks.every((d: { category: string }) => d.category === 'exposed')).toBe(true);

    const bad = await ask('target=example.com&category=nope');
    expect(bad.status).toBe(400);
    expect((await bad.json()).error).toContain('Unknown category');
  });

  it('validates maxRisk', async () => {
    expect((await ask('target=example.com&maxRisk=extreme')).status).toBe(400);
    const body = await (await ask('target=example.com&maxRisk=info')).json();
    expect(body.dorks.every((d: { risk: string }) => d.risk === 'info')).toBe(true);
  });
});
