import { describe, it, expect } from 'vitest';
import { analyseDmarc, analyseSpf, mailProvider } from './dns';

describe('analyseSpf', () => {
  it('marks a missing record as missing', () => {
    const result = analyseSpf(null);
    expect(result.present).toBe(false);
    expect(result.risk).toBe('missing');
    expect(result.note).toContain('anyone can forge');
  });

  it('accepts a strict -all record', () => {
    const result = analyseSpf('v=spf1 include:_spf.google.com -all');
    expect(result.present).toBe(true);
    expect(result.all).toBe('fail');
    expect(result.risk).toBe('ok');
    expect(result.lookups).toBe(1);
  });

  it('treats +all as dangerous even though a record exists', () => {
    const result = analyseSpf('v=spf1 +all');
    expect(result.all).toBe('pass');
    expect(result.risk).toBe('dangerous');
  });

  it('treats softfail and neutral as weak', () => {
    expect(analyseSpf('v=spf1 mx ~all').risk).toBe('weak');
    expect(analyseSpf('v=spf1 mx ?all').risk).toBe('weak');
  });

  it('flags a record with no all mechanism', () => {
    const result = analyseSpf('v=spf1 include:example.net');
    expect(result.all).toBeNull();
    expect(result.risk).toBe('weak');
  });

  it('flags more than ten DNS lookups', () => {
    const record = `v=spf1 ${Array.from({ length: 12 }, (_, i) => `include:spf${i}.example.net`).join(' ')} -all`;
    const result = analyseSpf(record);
    expect(result.lookups).toBe(12);
    expect(result.risk).toBe('weak');
    expect(result.note).toContain('RFC 7208');
  });
});

describe('analyseDmarc', () => {
  it('marks a missing record as missing', () => {
    expect(analyseDmarc(null).risk).toBe('missing');
  });

  it('parses a reject policy with reporting', () => {
    const result = analyseDmarc('v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@example.com');
    expect(result.policy).toBe('reject');
    expect(result.subdomainPolicy).toBe('quarantine');
    expect(result.pct).toBe(100);
    expect(result.reporting).toEqual(['mailto:dmarc@example.com']);
    expect(result.risk).toBe('ok');
  });

  it('treats p=none as monitoring only', () => {
    const result = analyseDmarc('v=DMARC1; p=none; rua=mailto:agg@example.com');
    expect(result.policy).toBe('none');
    expect(result.risk).toBe('weak');
  });

  it('flags a partial pct', () => {
    const result = analyseDmarc('v=DMARC1; p=quarantine; pct=25');
    expect(result.pct).toBe(25);
    expect(result.risk).toBe('weak');
  });

  it('flags an unusable policy', () => {
    expect(analyseDmarc('v=DMARC1; rua=mailto:a@b.c').policy).toBeNull();
    expect(analyseDmarc('v=DMARC1; rua=mailto:a@b.c').risk).toBe('weak');
  });
});

describe('mailProvider', () => {
  it('identifies the common providers from MX hostnames', () => {
    expect(mailProvider(['aspmx.l.google.com'])).toContain('Google');
    expect(mailProvider(['example-com.mail.protection.outlook.com'])).toContain('Microsoft');
    expect(mailProvider(['mx.yandex.net'])).toContain('Yandex');
    expect(mailProvider(['mail.protonmail.ch'])).toContain('Proton');
    expect(mailProvider([])).toBe('unknown');
    expect(mailProvider(['mx.some-isp.example'])).toContain('other');
  });
});
