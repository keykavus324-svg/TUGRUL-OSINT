import { describe, it, expect } from 'vitest';
import {
  BRUTE_LABELS,
  hostsFromUrls,
  normaliseCandidate,
  parseCertSpotter,
  parseCrtSh,
  parseHackerTarget,
  parseOtx,
  parseRapidDns,
  parseUrlscan,
  parseWaybackCdx,
} from './subdomains';

describe('normaliseCandidate', () => {
  it('accepts names inside the domain and strips wildcards', () => {
    expect(normaliseCandidate('api.example.com', 'example.com')).toBe('api.example.com');
    expect(normaliseCandidate('*.dev.example.com', 'example.com')).toBe('dev.example.com');
    expect(normaliseCandidate('API.Example.COM.', 'example.com')).toBe('api.example.com');
  });

  it('rejects names outside the domain', () => {
    expect(normaliseCandidate('example.com.evil.test', 'example.com')).toBeNull();
    expect(normaliseCandidate('notexample.com', 'example.com')).toBeNull();
    expect(normaliseCandidate('evil.test', 'example.com')).toBeNull();
  });

  it('rejects wildcards that only become the domain, IPs and junk', () => {
    expect(normaliseCandidate('*.example.com', 'example.com')).toBe('example.com');
    expect(normaliseCandidate('1.2.3.4', 'example.com')).toBeNull();
    expect(normaliseCandidate('bad host.example.com', 'example.com')).toBeNull();
    expect(normaliseCandidate('', 'example.com')).toBeNull();
    expect(normaliseCandidate('a..example.com', 'example.com')).toBeNull();
  });

  it('strips a scheme and port that a SAN might carry', () => {
    expect(normaliseCandidate('https://vpn.example.com:8443/login', 'example.com')).toBe('vpn.example.com');
  });
});

describe('parseCrtSh', () => {
  it('splits newline-separated SANs and records the certificate window', () => {
    const rows = [
      { name_value: 'api.example.com\nwww.example.com', common_name: 'www.example.com', not_before: '2023-01-02T00:00:00', not_after: '2024-01-02T00:00:00' },
      { name_value: '*.example.com', common_name: '*.example.com' },
      { name_value: 'unrelated.test' },
    ];
    const out = parseCrtSh(rows, 'example.com');
    const hosts = out.map(r => r.host);
    expect(hosts).toContain('api.example.com');
    expect(hosts).toContain('www.example.com');
    expect(hosts).not.toContain('unrelated.test');
    expect(out.find(r => r.host === 'api.example.com')?.firstSeen).toBe('2023-01-02T00:00:00.000Z');
  });

  it('returns nothing for a non-array answer', () => {
    expect(parseCrtSh({ error: 'nope' }, 'example.com')).toEqual([]);
  });
});

describe('parseCertSpotter', () => {
  it('reads the dns_names array', () => {
    const out = parseCertSpotter([{ dns_names: ['mail.example.com', 'example.com', '*.example.com'] }], 'example.com');
    expect(out.map(r => r.host)).toEqual(['mail.example.com', 'example.com', 'example.com']);
    expect(out[0].source).toBe('Cert Spotter');
  });
});

describe('parseOtx', () => {
  it('reads passive_dns hostnames with their dates', () => {
    const out = parseOtx(
      { passive_dns: [{ hostname: 'ftp.example.com', first: '2020-05-01T00:00:00', last: '2021-05-01T00:00:00' }] },
      'example.com',
    );
    expect(out[0]).toMatchObject({ host: 'ftp.example.com', source: 'AlienVault OTX' });
    expect(out[0].lastSeen).toContain('2021');
  });
});

describe('parseHackerTarget', () => {
  it('reads host,ip CSV lines', () => {
    const text = 'www.example.com,93.184.216.34\nmail.example.com,93.184.216.35\n';
    const out = parseHackerTarget(text, 'example.com');
    expect(out.map(r => r.host)).toEqual(['www.example.com', 'mail.example.com']);
  });

  it('ignores an API quota sentence', () => {
    expect(parseHackerTarget('API count exceeded - Increase Quota with Membership', 'example.com')).toEqual([]);
  });
});

describe('parseRapidDns', () => {
  it('pulls hostnames out of table cells', () => {
    const html = '<table><tr><td>api.example.com</td><td>1.2.3.4</td></tr><tr><td>other.test</td></tr></table>';
    expect(parseRapidDns(html, 'example.com').map(r => r.host)).toEqual(['api.example.com']);
  });
});

describe('hostsFromUrls', () => {
  it('keeps only hosts within the domain, deduplicated', () => {
    const urls = [
      'https://a.example.com/x',
      'https://a.example.com/y',
      'http://b.example.com:8080/z',
      'https://evil.test/a',
    ];
    expect(hostsFromUrls(urls, 'example.com').sort()).toEqual(['a.example.com', 'b.example.com']);
  });
});

describe('parseWaybackCdx', () => {
  it('accepts both flat column arrays and a header row', () => {
    const rows = [
      ['original'],
      ['https://docs.example.com/a'],
      ['https://docs.example.com/b'],
      ['https://www.example.com/c'],
    ];
    expect(parseWaybackCdx(rows, 'example.com').map(r => r.host).sort()).toEqual([
      'docs.example.com',
      'www.example.com',
    ]);
  });
});

describe('parseUrlscan', () => {
  it('reads page.domain values', () => {
    const out = parseUrlscan({ results: [{ page: { domain: 'app.example.com' } }, { page: { domain: 'x.test' } }] }, 'example.com');
    expect(out.map(r => r.host)).toEqual(['app.example.com']);
  });
});

describe('BRUTE_LABELS', () => {
  it('is a bounded, unique, valid label list', () => {
    expect(BRUTE_LABELS.length).toBeGreaterThan(100);
    expect(new Set(BRUTE_LABELS).size).toBe(BRUTE_LABELS.length);
    expect(BRUTE_LABELS.every(l => /^[a-z0-9][a-z0-9-]*$/.test(l))).toBe(true);
  });
});
