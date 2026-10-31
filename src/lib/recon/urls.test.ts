import { describe, it, expect } from 'vitest';
import {
  classifyUrls,
  extensionHistogram,
  normaliseUrl,
  parseCommonCrawl,
  parseOtxUrls,
  parseWayback,
} from './urls';

describe('normaliseUrl', () => {
  it('strips fragments and trailing punctuation', () => {
    expect(normaliseUrl('https://example.com/a#section')).toBe('https://example.com/a');
    expect(normaliseUrl('https://example.com/a),')).toBe('https://example.com/a');
  });

  it('rejects non-http schemes and junk', () => {
    expect(normaliseUrl('javascript:alert(1)')).toBeNull();
    expect(normaliseUrl('ftp://example.com/a')).toBeNull();
    expect(normaliseUrl('not a url')).toBeNull();
  });
});

describe('parseWayback', () => {
  it('reads [url, timestamp] rows and keeps only the target domain', () => {
    const rows = [
      ['https://www.example.com/a', '20200101120000'],
      ['https://api.example.com/b?x=1', '20210202000000'],
      ['https://other.test/c', '20200101000000'],
    ];
    const out = parseWayback(rows, 'example.com');
    expect(out).toHaveLength(2);
    expect(out[0].firstSeen).toBe('2020-01-01');
    expect(out[1].sources).toEqual(['Wayback Machine']);
  });

  it('tolerates a single-column answer and non-array input', () => {
    expect(parseWayback([['https://www.example.com/x']], 'example.com')).toHaveLength(1);
    expect(parseWayback({ error: 'rate limited' }, 'example.com')).toEqual([]);
  });
});

describe('parseCommonCrawl', () => {
  it('reads NDJSON lines and skips banner lines', () => {
    const ndjson = [
      '{"url":"https://www.example.com/a","timestamp":"20230101000000"}',
      'Reverse the list of URLs',
      '{"url":"https://evil.test/b"}',
      '{"url":"https://docs.example.com/c"}',
    ].join('\n');
    const out = parseCommonCrawl(ndjson, 'example.com');
    expect(out.map(r => r.url)).toEqual(['https://www.example.com/a', 'https://docs.example.com/c']);
    expect(out[0].firstSeen).toBe('2023-01-01');
  });
});

describe('parseOtxUrls', () => {
  it('reads the url_list array', () => {
    const out = parseOtxUrls({ url_list: [{ url: 'https://www.example.com/x', date: '2022-01-01' }] }, 'example.com');
    expect(out[0]).toMatchObject({ url: 'https://www.example.com/x', firstSeen: '2022-01-01' });
  });
});

describe('classifyUrls', () => {
  const findingsFor = (url: string) => classifyUrls([url]).map(f => f.kind);

  it('flags an environment file as high severity', () => {
    const findings = classifyUrls(['https://example.com/.env']);
    expect(findings[0]).toMatchObject({ kind: 'env-file', severity: 'high' });
  });

  it('flags git metadata', () => {
    expect(findingsFor('https://example.com/.git/config')).toContain('git-metadata');
  });

  it('flags backup archives, database dumps and key material', () => {
    expect(findingsFor('https://example.com/db-backup.sql')).toContain('database-dump');
    expect(findingsFor('https://example.com/site-backup.zip')).toContain('backup-archive');
    expect(findingsFor('https://example.com/private.pem')).toContain('private-key');
  });

  it('flags credential-shaped query parameters', () => {
    expect(findingsFor('https://example.com/api?access_token=abc')).toContain('secret-in-query');
    expect(findingsFor('https://example.com/api?id=3')).not.toContain('secret-in-query');
  });

  it('flags admin and debug surfaces as medium', () => {
    expect(classifyUrls(['https://example.com/wp-admin/']).find(f => f.kind === 'admin-panel')?.severity).toBe('medium');
    expect(findingsFor('https://example.com/actuator/env')).toContain('debug-interface');
  });

  it('flags documents and archives as low, and sorts by severity', () => {
    const findings = classifyUrls([
      'https://example.com/report.pdf',
      'https://example.com/.env',
      'https://example.com/data.zip',
    ]);
    expect(findings[0].severity).toBe('high');
    const severities = findings.map(f => f.severity);
    expect(severities).toEqual([...severities].sort((a, b) => {
      const rank = { high: 0, medium: 1, low: 2 } as Record<string, number>;
      return rank[a] - rank[b];
    }));
  });

  it('does not flag a normal content page', () => {
    expect(classifyUrls(['https://example.com/about-us'])).toEqual([]);
  });

  it('returns one finding per kind per URL', () => {
    const kinds = classifyUrls(['https://example.com/.env']).map(f => f.kind);
    expect(new Set(kinds).size).toBe(kinds.length);
  });
});

describe('extensionHistogram', () => {
  it('counts extensions and puts (none) for extensionless paths', () => {
    const hist = extensionHistogram([
      'https://example.com/a.pdf',
      'https://example.com/b.pdf',
      'https://example.com/',
      'https://example.com/c.PNG',
    ]);
    expect(hist[0]).toEqual({ extension: 'pdf', count: 2 });
    expect(hist).toEqual(expect.arrayContaining([
      { extension: '(none)', count: 1 },
      { extension: 'png', count: 1 },
    ]));
  });
});
