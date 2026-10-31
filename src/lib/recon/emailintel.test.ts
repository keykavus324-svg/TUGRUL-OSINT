import { describe, it, expect } from 'vitest';
import {
  assessEmailRisk,
  avatarUrl,
  classifyAddress,
  gravatarHash,
  parseEmail,
} from './emailintel';

describe('parseEmail', () => {
  it('accepts normal addresses and normalises case', () => {
    const parsed = parseEmail('  John.Doe@Example.COM ');
    expect(parsed.valid).toBe(true);
    expect(parsed.address).toBe('john.doe@example.com');
    expect(parsed.local).toBe('john.doe');
    expect(parsed.domain).toBe('example.com');
  });

  it('strips a mailto: prefix and surrounding whitespace', () => {
    expect(parseEmail('mailto:a@b.co').address).toBe('a@b.co');
  });

  it('accepts subaddressing and plus tags', () => {
    expect(parseEmail('user+news@example.com').valid).toBe(true);
  });

  it('rejects malformed addresses with a reason', () => {
    expect(parseEmail('no-at-sign').valid).toBe(false);
    expect(parseEmail('a@').reason).toBe('missing @');
    expect(parseEmail('@example.com').valid).toBe(false);
    expect(parseEmail('a..b@example.com').valid).toBe(false);
    expect(parseEmail('a@localhost').valid).toBe(false);
    expect(parseEmail('a b@example.com').valid).toBe(false);
  });

  it('rejects an address longer than 254 characters', () => {
    const long = `${'a'.repeat(64)}@${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(63)}.com`;
    expect(parseEmail(long).valid).toBe(false);
  });
});

describe('gravatarHash', () => {
  it('matches the MD5 published in the Gravatar documentation', () => {
    expect(gravatarHash('MyEmailAddress@example.com ')).toBe('0bc83cb571cd1c50ba6f3e8a78ef1346');
  });

  it('builds an avatar URL from the hash', () => {
    expect(avatarUrl('abc', 80)).toBe('https://www.gravatar.com/avatar/abc?d=mp&s=80');
  });
});

describe('classifyAddress', () => {
  const flags = (address: string) => classifyAddress(parseEmail(address));

  it('flags disposable domains', () => {
    expect(flags('x@mailinator.com').disposable).toBe(true);
    expect(flags('x@example.com').disposable).toBe(false);
  });

  it('flags free providers', () => {
    expect(flags('x@gmail.com').freeProvider).toBe(true);
    expect(flags('x@corp.example').freeProvider).toBe(false);
  });

  it('flags role accounts', () => {
    expect(flags('security@corp.example').roleAccount).toBe(true);
    expect(flags('john@corp.example').roleAccount).toBe(false);
  });

  it('flags subaddressing and generated-looking locals', () => {
    expect(flags('a+tag@corp.example').subaddressing).toBe(true);
    expect(flags('xk3j9f2h8d7s6a5q@corp.example').suspiciousLocal).toBe(true);
    expect(flags('john@corp.example').suspiciousLocal).toBe(false);
  });
});

describe('assessEmailRisk', () => {
  const base = {
    flags: { disposable: false, freeProvider: false, roleAccount: false, subaddressing: false, suspiciousLocal: false },
    spf: { present: true, record: 'v=spf1 -all', all: 'fail' as const, lookups: 0, mechanisms: [], risk: 'ok' as const, note: '' },
    dmarc: { present: true, record: 'v=DMARC1; p=reject', policy: 'reject' as const, subdomainPolicy: null, pct: 100, reporting: [], risk: 'ok' as const, note: '' },
    hasMx: true,
    domainAgeDays: 3650,
    breachCount: 0,
    gravatarExists: false,
  };

  it('gives a clean, aged corporate address a low score', () => {
    const risk = assessEmailRisk(base);
    expect(risk.score).toBe(0);
    expect(risk.level).toBe('low');
    expect(risk.factors).toEqual([]);
  });

  it('scores a disposable domain on a new domain with no mail records as critical', () => {
    const risk = assessEmailRisk({
      ...base,
      flags: { ...base.flags, disposable: true },
      hasMx: false,
      domainAgeDays: 2,
      spf: { ...base.spf, present: false, record: null, risk: 'missing' },
      dmarc: { ...base.dmarc, present: false, record: null, policy: null, risk: 'missing' },
    });
    expect(risk.level).toBe('critical');
    expect(risk.score).toBe(100); // capped
    expect(risk.factors.map(f => f.label)).toEqual(
      expect.arrayContaining(['Disposable domain', 'No MX record', 'Newly registered domain', 'No SPF', 'No DMARC']),
    );
  });

  it('keeps breach exposure bounded regardless of breach count', () => {
    const risk = assessEmailRisk({ ...base, breachCount: 200 });
    expect(risk.score).toBeLessThanOrEqual(15);
    expect(risk.level).toBe('low');
  });

  it('sorts factors by weight', () => {
    const risk = assessEmailRisk({
      ...base,
      flags: { ...base.flags, disposable: true },
      breachCount: 3,
      gravatarExists: true,
    });
    const weights = risk.factors.map(f => f.weight);
    expect(weights).toEqual([...weights].sort((a, b) => b - a));
  });

  it('does not treat a missing DMARC on an otherwise healthy domain as critical', () => {
    const risk = assessEmailRisk({
      ...base,
      dmarc: { ...base.dmarc, present: false, record: null, policy: null, risk: 'missing' },
    });
    expect(risk.level).toBe('low');
    expect(risk.score).toBe(10);
  });
});
