import { describe, it, expect } from 'vitest';
import {
  DORK_TEMPLATES,
  buildDorks,
  dorkUrl,
  resolveDorkQuery,
  summariseDorks,
  type Dork,
} from './dorks';

describe('dork catalogue', () => {
  it('every template carries a reason and a risk level', () => {
    expect(DORK_TEMPLATES.length).toBeGreaterThan(25);
    for (const t of DORK_TEMPLATES) {
      expect(t.why.length).toBeGreaterThan(15);
      expect(['info', 'medium', 'high']).toContain(t.risk);
      // Most templates key on the domain; the bucket query keys on the brand name.
      expect(t.query).toMatch(/\{(d|name)\}/);
    }
  });

  it('has no duplicate titles', () => {
    const titles = DORK_TEMPLATES.map(t => t.title);
    expect(new Set(titles).size).toBe(titles.length);
  });
});

describe('resolveDorkQuery', () => {
  it('substitutes the domain and its leftmost label', () => {
    const panel = DORK_TEMPLATES.find(t => t.title === 'Login panels')!;
    expect(resolveDorkQuery(panel, 'example.com')).toContain('site:example.com');

    const bucket = DORK_TEMPLATES.find(t => t.title === 'Cloud storage buckets')!;
    expect(resolveDorkQuery(bucket, 'acme-corp.com')).toContain('"acme-corp"');
  });

  it('lowercases the target so queries are consistent', () => {
    expect(resolveDorkQuery(DORK_TEMPLATES[0], 'EXAMPLE.COM')).toContain('example.com');
  });
});

describe('buildDorks', () => {
  it('returns links for every engine', () => {
    const dorks = buildDorks('example.com');
    expect(dorks.length).toBeGreaterThan(20);
    const first = dorks[0];
    expect(first.links.google).toContain('https://www.google.com/search?q=');
    expect(first.links.bing).toContain('https://www.bing.com/search?q=');
    expect(first.links.duckduckgo).toContain('duckduckgo.com');
    expect(first.links.yandex).toContain('yandex.com');
    expect(decodeURIComponent(first.links.google)).toContain('site:example.com');
  });

  it('filters by category', () => {
    const dorks = buildDorks('example.com', { categories: ['secrets'] });
    expect(dorks.length).toBeGreaterThan(0);
    expect(dorks.every(d => d.category === 'secrets')).toBe(true);
  });

  it('never includes a query above the requested risk ceiling', () => {
    const dorks = buildDorks('example.com', { maxRisk: 'info' });
    expect(dorks.every(d => d.risk === 'info')).toBe(true);
    expect(dorks.length).toBeLessThan(buildDorks('example.com').length);
  });

  it('combines category and risk filters', () => {
    const dorks = buildDorks('example.com', { categories: ['exposed'], maxRisk: 'medium' });
    expect(dorks.every(d => d.category === 'exposed' && d.risk !== 'high')).toBe(true);
  });
});

describe('dorkUrl', () => {
  it('encodes the query rather than injecting it into the URL', () => {
    const url = dorkUrl('google', 'site:a.com "b c"&x=1');
    expect(url).toContain('%22b%20c%22');
    expect(url).toContain('%26x%3D1');
  });
});

describe('summariseDorks', () => {
  it('counts per category and ranks by count', () => {
    const dorks: Dork[] = buildDorks('example.com');
    const summary = summariseDorks(dorks);
    expect(summary.reduce((sum, s) => sum + s.count, 0)).toBe(dorks.length);
    expect(summary[0].count).toBeGreaterThanOrEqual(summary[summary.length - 1].count);
    expect(summary.every(s => s.high >= 0)).toBe(true);
  });
});
