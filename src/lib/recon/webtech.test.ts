import { describe, it, expect } from 'vitest';
import {
  auditSecurityHeaders,
  cookieNames,
  detectTechnologies,
  extractExternalHosts,
  extractTitle,
  faviconHash,
  headerBag,
  inspectCookies,
  murmur3_32,
  parseRobots,
  targetUrl,
} from './webtech';

describe('murmur3_32', () => {
  // Reference values from an independent implementation of MurmurHash3 x86_32.
  it('matches the published test vectors', () => {
    const enc = new TextEncoder();
    expect(murmur3_32(enc.encode(''))).toBe(0);
    expect(murmur3_32(enc.encode('foo'))).toBe(-156908512);
    expect(murmur3_32(enc.encode('hello'))).toBe(613153351);
    expect(murmur3_32(enc.encode('abcdefg'))).toBe(-2009294074);
    expect(murmur3_32(enc.encode('a'))).toBe(1009084850);
    expect(murmur3_32(new Uint8Array(Array.from({ length: 50 }, (_, i) => i)))).toBe(284514547);
  });
});

describe('faviconHash', () => {
  it('hashes the base64 form with Python-style line breaks', () => {
    // Empty base64 is "\n" — a single newline, as Python's codecs.encode emits.
    expect(faviconHash(new Uint8Array([]))).toBe(murmur3_32(new TextEncoder().encode('\n')));
    expect(typeof faviconHash(new Uint8Array([0, 1, 2, 3]))).toBe('number');
  });

  it('is stable for the same bytes and differs for different ones', () => {
    const a = faviconHash(new Uint8Array([1, 2, 3]));
    expect(faviconHash(new Uint8Array([1, 2, 3]))).toBe(a);
    expect(faviconHash(new Uint8Array([1, 2, 4]))).not.toBe(a);
  });
});

describe('headerBag', () => {
  it('lowercases keys and joins repeats', () => {
    expect(headerBag({ 'Server': 'nginx', 'Set-Cookie': ['a=1', 'b=2'] })).toEqual({
      server: 'nginx',
      'set-cookie': 'a=1, b=2',
    });
  });
});

describe('detectTechnologies', () => {
  const base = { url: 'https://example.com/', body: '', headers: {} as Record<string, string> };

  it('detects the server from its header, with the version', () => {
    const tech = detectTechnologies({ ...base, headers: { server: 'nginx/1.24.0' } });
    const nginx = tech.find(t => t.name === 'Nginx');
    expect(nginx?.version).toBe('1.24.0');
    expect(nginx?.confidence).toBe('high');
    expect(nginx?.evidence[0]).toContain('server: nginx/1.24.0');
  });

  it('detects Cloudflare from cf-ray even when the server header is masked', () => {
    const tech = detectTechnologies({ ...base, headers: { 'cf-ray': '1234', server: 'cloudflare' } });
    expect(tech.some(t => t.name === 'Cloudflare')).toBe(true);
  });

  it('detects WordPress and implies PHP', () => {
    const tech = detectTechnologies({ ...base, body: '<link rel="stylesheet" href="/wp-content/themes/x/style.css">' });
    expect(tech.some(t => t.name === 'WordPress')).toBe(true);
    expect(tech.some(t => t.name === 'PHP')).toBe(true);
    expect(tech.find(t => t.name === 'PHP')?.evidence[0]).toContain('implied by WordPress');
  });

  it('extracts the WordPress version from an asset query string', () => {
    const tech = detectTechnologies({
      ...base,
      body: '<script src="/wp-includes/js/jquery/jquery.min.js?ver=6.4.3"></script>',
    });
    expect(tech.find(t => t.name === 'WordPress')?.version).toBe('6.4.3');
  });

  it('detects Next.js and implies React', () => {
    const tech = detectTechnologies({ ...base, body: '<script src="/_next/static/chunks/main.js"></script>' });
    expect(tech.some(t => t.name === 'Next.js')).toBe(true);
    expect(tech.some(t => t.name === 'React')).toBe(true);
  });

  it('reads a generator meta tag as first-party evidence', () => {
    const tech = detectTechnologies({
      ...base,
      body: '<meta name="generator" content="Drupal 10 (https://www.drupal.org)">',
    });
    const drupal = tech.find(t => t.name === 'Drupal');
    expect(drupal).toBeDefined();
    expect(drupal?.confidence).toBe('high');
  });

  it('does not call a page React just because the word appears', () => {
    const tech = detectTechnologies({ ...base, body: '<p>We react to events and use angular momentum.</p>' });
    expect(tech.some(t => t.name === 'React')).toBe(false);
    expect(tech.some(t => t.name === 'Angular')).toBe(false);
  });

  it('uses cookies as evidence of the framework', () => {
    const tech = detectTechnologies({ ...base, cookieHeaders: ['laravel_session=abc; Path=/'] });
    expect(tech.some(t => t.name === 'Laravel')).toBe(true);
  });

  it('records Kibana from kbn-name/kbn-version headers', () => {
    const tech = detectTechnologies({ ...base, headers: { 'kbn-name': 'kibana', 'kbn-version': '8.11.1' } });
    expect(tech.find(t => t.name === 'Kibana')?.version).toBe('8.11.1');
  });
});

describe('auditSecurityHeaders', () => {
  const perfect = {
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'content-security-policy': "default-src 'self'; script-src 'nonce-abc'",
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=()',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
  };

  it('grades a complete set as A', () => {
    const audit = auditSecurityHeaders(perfect);
    expect(audit.grade).toBe('A');
    expect(audit.missing).toEqual([]);
    expect(audit.score).toBeGreaterThanOrEqual(90);
  });

  it('grades an empty set as F and names the required headers', () => {
    const audit = auditSecurityHeaders({});
    expect(audit.grade).toBe('F');
    expect(audit.missing).toEqual(
      expect.arrayContaining(['strict-transport-security', 'content-security-policy', 'x-content-type-options']),
    );
  });

  it('flags HSTS max-age=0 rather than counting it as present', () => {
    const audit = auditSecurityHeaders({ ...perfect, 'strict-transport-security': 'max-age=0' });
    const hsts = audit.findings.find(f => f.header === 'strict-transport-security');
    expect(hsts?.state).toBe('weak');
    expect(audit.grade).not.toBe('A');
  });

  it('flags an inline-script CSP as weak', () => {
    const audit = auditSecurityHeaders({ ...perfect, 'content-security-policy': "script-src 'self' 'unsafe-inline'" });
    expect(audit.findings.find(f => f.header === 'content-security-policy')?.state).toBe('weak');
  });

  it('accepts frame-ancestors as a replacement for X-Frame-Options', () => {
    const audit = auditSecurityHeaders({
      ...perfect,
      'x-frame-options': '',
      'content-security-policy': "default-src 'self'; script-src 'nonce-a'; frame-ancestors 'none'",
    });
    const frame = audit.findings.find(f => f.header === 'x-frame-options');
    expect(frame?.state).toBe('ok');
  });

  it('reports software versions as disclosures, not vulnerabilities', () => {
    const audit = auditSecurityHeaders({ ...perfect, server: 'nginx/1.18.0', 'x-powered-by': 'PHP/7.4.3' });
    expect(audit.disclosures).toEqual(expect.arrayContaining(['server: nginx/1.18.0', 'x-powered-by: PHP/7.4.3']));
  });

  it('penalises wildcard CORS', () => {
    const withCors = auditSecurityHeaders({ ...perfect, 'access-control-allow-origin': '*' });
    expect(withCors.findings.some(f => f.header === 'access-control-allow-origin' && f.state === 'weak')).toBe(true);
    expect(withCors.score).toBeLessThan(auditSecurityHeaders(perfect).score);
  });
});

describe('cookies', () => {
  it('parses names without needing the values', () => {
    expect(cookieNames(['session=abc; Path=/', 'pref=1; Secure'])).toEqual(['session', 'pref']);
  });

  it('flags missing Secure, HttpOnly and SameSite', () => {
    const [cookie] = inspectCookies(['session=abc; Path=/']);
    expect(cookie.secure).toBe(false);
    expect(cookie.httpOnly).toBe(false);
    expect(cookie.sameSite).toBeNull();
    expect(cookie.issues).toEqual(expect.arrayContaining(['no Secure flag', 'no HttpOnly flag', 'no SameSite attribute']));
    expect(cookie.session).toBe(true);
  });

  it('flags SameSite=None without Secure', () => {
    const [cookie] = inspectCookies(['track=1; SameSite=None']);
    expect(cookie.issues).toContain('SameSite=None without Secure is rejected by browsers');
  });

  it('flags a __Host- cookie that lost its Secure flag', () => {
    const [cookie] = inspectCookies(['__Host-id=1; HttpOnly']);
    expect(cookie.prefixViolation).toBe(true);
  });

  it('accepts a properly configured cookie', () => {
    const [cookie] = inspectCookies(['__Host-sid=1; Secure; HttpOnly; SameSite=Lax; Max-Age=3600']);
    expect(cookie.issues).toEqual([]);
    expect(cookie.session).toBe(false);
  });
});

describe('parseRobots', () => {
  const robots = `
# comment
User-agent: *
Disallow: /admin
Disallow: /private/
Allow: /public

User-agent: Googlebot
Disallow: /nogoogle

Sitemap: https://example.com/sitemap.xml
`;

  it('collects disallowed paths with their agent', () => {
    const info = parseRobots(robots);
    expect(info.disallowed).toEqual(
      expect.arrayContaining([
        { agent: '*', path: '/admin' },
        { agent: '*', path: '/private/' },
        { agent: 'Googlebot', path: '/nogoogle' },
      ]),
    );
    expect(info.allowed).toContain('/public');
    expect(info.sitemaps).toEqual(['https://example.com/sitemap.xml']);
    expect(info.blocksAll).toBe(false);
  });

  it('detects a blanket block', () => {
    expect(parseRobots('User-agent: *\nDisallow: /').blocksAll).toBe(true);
  });

  it('ignores comments and blank lines', () => {
    const info = parseRobots('# nothing here\n\n');
    expect(info.disallowed).toEqual([]);
    expect(info.present).toBe(true);
  });
});

describe('HTML helpers', () => {
  it('extracts a title without a parser', () => {
    expect(extractTitle('<html><head><title>  Hello   World </title>')).toBe('Hello World');
    expect(extractTitle('<html><body>no title</body>')).toBeNull();
  });

  it('lists third-party hosts and excludes the target itself', () => {
    const html = `
      <script src="https://cdn.example.com/a.js"></script>
      <script src="https://www.googletagmanager.com/gtm.js"></script>
      <a href="https://sub.example.com/page">internal</a>
      <img src="https://fonts.gstatic.com/x.woff2">
      <a href="/relative">rel</a>`;
    const hosts = extractExternalHosts(html, 'example.com');
    expect(hosts).toContain('www.googletagmanager.com');
    expect(hosts).toContain('fonts.gstatic.com');
    expect(hosts).not.toContain('cdn.example.com');
    expect(hosts).not.toContain('sub.example.com');
  });
});

describe('targetUrl', () => {
  it('defaults to https and keeps an explicit scheme', () => {
    expect(targetUrl('example.com')).toBe('https://example.com');
    expect(targetUrl('http://example.com/a')).toBe('http://example.com/a');
    expect(targetUrl('https://example.com')).toBe('https://example.com');
  });
});
