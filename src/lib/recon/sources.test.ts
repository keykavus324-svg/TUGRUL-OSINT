import { describe, it, expect } from 'vitest';
import {
  INTEGRATED_PROJECTS,
  isSafeLabel,
  isWithinDomain,
  mapLimit,
  normaliseHost,
  runSource,
  unique,
} from './sources';

describe('normaliseHost', () => {
  it('accepts a bare domain, a URL, credentials and a port', () => {
    expect(normaliseHost('example.com')).toBe('example.com');
    expect(normaliseHost('  EXAMPLE.com. ')).toBe('example.com');
    expect(normaliseHost('https://example.com/path?q=1#x')).toBe('example.com');
    expect(normaliseHost('http://user:pass@mail.example.co.uk:8443/a')).toBe('mail.example.co.uk');
  });

  it('rejects things that are not hostnames', () => {
    expect(normaliseHost('')).toBeNull();
    expect(normaliseHost('127.0.0.1')).toBeNull();
    expect(normaliseHost('localhost')).toBeNull();
    expect(normaliseHost('not a domain')).toBeNull();
    expect(normaliseHost('-bad.example.com')).toBeNull();
    expect(normaliseHost('example')).toBeNull();
  });

  it('does not allow a path to escape into the hostname', () => {
    expect(normaliseHost('https://example.com\\@evil.test')).not.toBe('evil.test');
  });
});

describe('isWithinDomain', () => {
  it('accepts the domain itself and true subdomains only', () => {
    expect(isWithinDomain('example.com', 'example.com')).toBe(true);
    expect(isWithinDomain('a.b.example.com', 'example.com')).toBe(true);
    expect(isWithinDomain('*.example.com', 'example.com')).toBe(true);
    expect(isWithinDomain('notexample.com', 'example.com')).toBe(false);
    expect(isWithinDomain('example.com.evil.test', 'example.com')).toBe(false);
  });
});

describe('isSafeLabel', () => {
  it('rejects anything that could leave the hostname', () => {
    expect(isSafeLabel('api')).toBe(true);
    expect(isSafeLabel('api-2')).toBe(true);
    expect(isSafeLabel('api.evil')).toBe(false);
    expect(isSafeLabel('a/b')).toBe(false);
    expect(isSafeLabel('-api')).toBe(false);
    expect(isSafeLabel('')).toBe(false);
  });
});

describe('mapLimit', () => {
  it('preserves order and applies the limit', async () => {
    let active = 0;
    let peak = 0;
    const out = await mapLimit([1, 2, 3, 4, 5, 6, 7], 3, async n => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise(r => setTimeout(r, 5));
      active -= 1;
      return n * 2;
    });
    expect(out).toEqual([2, 4, 6, 8, 10, 12, 14]);
    expect(peak).toBeLessThanOrEqual(3);
  });

  it('handles an empty list without starting a worker loop', async () => {
    expect(await mapLimit([], 4, async n => n)).toEqual([]);
  });
});

describe('runSource', () => {
  it('reports empty separately from failed', async () => {
    const empty = await runSource('a', 'A', async () => []);
    const failed = await runSource('b', 'B', async () => {
      throw new Error('upstream down');
    });
    const ok = await runSource('c', 'C', async () => [1]);

    expect(empty.status).toBe('empty');
    expect(empty.data).toEqual([]);
    expect(failed.status).toBe('error');
    expect(failed.error).toBe('upstream down');
    expect(ok.status).toBe('ok');
  });
});

describe('unique', () => {
  it('deduplicates case-sensitively, preserving order', () => {
    expect(unique(['a', 'b', 'a', 'A'])).toEqual(['a', 'b', 'A']);
  });
});

describe('INTEGRATED_PROJECTS', () => {
  it('names a licence and a home for every entry', () => {
    for (const project of INTEGRATED_PROJECTS) {
      expect(project.name).toBeTruthy();
      expect(project.license).toBeTruthy();
      expect(project.repo).toMatch(/^[\w.-]+\/[\w.-]+$/);
      expect(project.note.length).toBeGreaterThan(20);
    }
  });

  it('keeps the deliberately disabled integrations documented', () => {
    const disabled = INTEGRATED_PROJECTS.filter(p => p.powers === 'not enabled');
    expect(disabled.map(p => p.id).sort()).toEqual(['ghunt', 'holehe']);
  });
});
