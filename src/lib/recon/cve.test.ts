import { describe, it, expect, vi, afterEach } from 'vitest';
import { TECH_CPE, cpeMatchesVersion, findTechCves, severityFromCvss } from './cve';
import type { Technology } from './webtech';

const tech = (name: string, version?: string): Technology => ({
  name,
  categories: ['server'],
  confidence: 'high',
  evidence: ['test'],
  ...(version ? { version } : {}),
});

afterEach(() => vi.unstubAllGlobals());

describe('severityFromCvss', () => {
  it('maps the CVSS bands', () => {
    expect(severityFromCvss(9.8)).toBe('CRITICAL');
    expect(severityFromCvss(9)).toBe('CRITICAL');
    expect(severityFromCvss(7.5)).toBe('HIGH');
    expect(severityFromCvss(5.3)).toBe('MEDIUM');
    expect(severityFromCvss(2.1)).toBe('LOW');
    expect(severityFromCvss(null)).toBe('UNKNOWN');
    expect(severityFromCvss(Number.NaN)).toBe('UNKNOWN');
  });
});

describe('cpeMatchesVersion', () => {
  const cpe = (version: string) => `cpe:2.3:a:nginx:nginx:${version}:*:*:*:*:*:*:*`;

  it('matches an exact version', () => {
    expect(cpeMatchesVersion(cpe('1.24.0'), 'nginx', '1.24.0')).toBe(true);
  });

  it('matches a detected major.minor against a full version', () => {
    expect(cpeMatchesVersion(cpe('1.24.0'), 'nginx', '1.24')).toBe(true);
    expect(
      cpeMatchesVersion('cpe:2.3:a:wordpress:wordpress:6.4.3:*:*:*:*:*:*:*', 'wordpress', '6.4'),
    ).toBe(true);
  });

  it('does not match a different version that shares a prefix', () => {
    expect(cpeMatchesVersion(cpe('1.240.0'), 'nginx', '1.24')).toBe(false);
    expect(cpeMatchesVersion(cpe('7.0'), 'wordpress', '6.4')).toBe(false);
  });

  it('does not match a wildcard or an unknown product', () => {
    expect(cpeMatchesVersion(cpe('*'), 'nginx', '1.24')).toBe(false);
    expect(cpeMatchesVersion('cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*', 'nginx', '2.4.58')).toBe(false);
  });

  it('requires a detected version', () => {
    expect(cpeMatchesVersion(cpe('1.24.0'), 'nginx', null)).toBe(false);
  });
});

describe('TECH_CPE', () => {
  it('maps only unambiguous vendor/product pairs and escapes reserved characters', () => {
    for (const [name, mapping] of Object.entries(TECH_CPE)) {
      expect(name.length).toBeGreaterThan(1);
      expect(mapping.vendor).toMatch(/^[a-z0-9._!\\-]+$/);
      expect(mapping.product).toMatch(/^[a-z0-9._!\\-]+$/);
    }
  });
});

describe('findTechCves', () => {
  it('reports unmapped products instead of pretending they are clean', async () => {
    const report = await findTechCves([tech('SomeUnknownWidget', '1.0')]);
    expect(report.technologies[0].status).toBe('unmapped');
    expect(report.notes.join(' ')).toContain('no CPE mapping');
    expect(report.total).toBe(0);
  });

  it('separates version-confirmed CVEs from product-level matches', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      Response.json([
        {
          id: 'CVE-2024-0001',
          summary: 'Exact version issue',
          cvss: 9.8,
          Published: '2024-01-01',
          vulnerable_configuration: ['cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*'],
        },
        {
          id: 'CVE-2023-0002',
          summary: 'Older version issue',
          cvss: 5.0,
          Published: '2023-01-01',
          vulnerable_configuration: ['cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'],
        },
      ])));

    const report = await findTechCves([tech('Nginx', '1.24.0')]);
    const result = report.technologies[0];
    expect(result.status).toBe('ok');
    expect(result.matches[0].id).toBe('CVE-2024-0001');
    expect(result.matches[0].matched).toBe('version');
    expect(result.matches[1].matched).toBe('product');
    expect(report.confirmed).toBe(1);
    expect(report.total).toBe(2);
    expect(report.riskLevel).toBe('CRITICAL');
    expect(report.highestCvss).toBe(9.8);
  });

  it('marks an upstream error as error, not empty', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 500 })));
    const report = await findTechCves([tech('Nginx', '1.24.0')]);
    expect(report.technologies[0].status).toBe('error');
    expect(report.notes.join(' ')).toContain('failed');
  });

  it('marks a product with no published CVEs as empty', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json([])));
    const report = await findTechCves([tech('Nginx', '1.24.0')]);
    expect(report.technologies[0].status).toBe('empty');
  });

  it('caps results per technology and keeps the worst first', async () => {
    const rows = Array.from({ length: 60 }, (_, i) => ({
      id: `CVE-2024-${String(i).padStart(4, '0')}`,
      summary: `issue ${i}`,
      cvss: (i % 10) + 0.1,
      vulnerable_configuration: ['cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*'],
    }));
    vi.stubGlobal('fetch', vi.fn(async () => Response.json(rows)));
    const report = await findTechCves([tech('Nginx')], { perTech: 5 });
    expect(report.technologies[0].matches).toHaveLength(5);
    const scores = report.technologies[0].matches.map(m => m.cvss ?? 0);
    expect(scores).toEqual([...scores].sort((a, b) => b - a));
  });

  it('never guesses a version when none was detected', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      Response.json([
        { id: 'CVE-2024-1', summary: 'x', cvss: 7, vulnerable_configuration: ['cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*'] },
      ])));
    const report = await findTechCves([tech('Nginx')]);
    expect(report.confirmed).toBe(0);
    expect(report.technologies[0].matches[0].matched).toBe('product');
    expect(report.technologies[0].matches[0].note).toContain('No version was detected');
  });
});
