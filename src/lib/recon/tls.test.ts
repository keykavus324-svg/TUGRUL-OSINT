import { describe, it, expect } from 'vitest';
import { daysRemaining, gradeTls } from './tls';

const NOW = Date.parse('2026-06-01T00:00:00Z');

describe('daysRemaining', () => {
  it('counts whole days ahead and goes negative after expiry', () => {
    expect(daysRemaining('2026-06-11T00:00:00Z', NOW)).toBe(10);
    expect(daysRemaining('2026-05-22T00:00:00Z', NOW)).toBe(-10);
  });

  it('returns null for missing or invalid dates', () => {
    expect(daysRemaining(null, NOW)).toBeNull();
    expect(daysRemaining('not-a-date', NOW)).toBeNull();
  });
});

describe('gradeTls', () => {
  const healthy = {
    protocol: 'TLSv1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    authorized: true,
    daysRemaining: 200,
    selfSigned: false,
    sanCount: 3,
  };

  it('gives A to a current, valid certificate', () => {
    const result = gradeTls(healthy);
    expect(result.grade).toBe('A');
    expect(result.issues).toHaveLength(1);
    expect(result.issues[0]).toContain('valid');
  });

  it('gives F to an expired certificate', () => {
    const result = gradeTls({ ...healthy, daysRemaining: -1 });
    expect(result.grade).toBe('F');
    expect(result.issues.join(' ')).toContain('expired');
  });

  it('downgrades a certificate expiring within a week, and again within a month', () => {
    expect(gradeTls({ ...healthy, daysRemaining: 3 }).grade).toBe('C');
    expect(gradeTls({ ...healthy, daysRemaining: 20 }).grade).toBe('B');
  });

  it('gives D to deprecated protocols and weak ciphers', () => {
    expect(gradeTls({ ...healthy, protocol: 'TLSv1' }).grade).toBe('D');
    expect(gradeTls({ ...healthy, cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' }).grade).toBe('D');
  });

  it('gives D to a self-signed certificate', () => {
    const result = gradeTls({ ...healthy, selfSigned: true });
    expect(result.grade).toBe('D');
    expect(result.issues.join(' ')).toContain('self-signed');
  });

  it('gives D when the chain does not validate', () => {
    const result = gradeTls({ ...healthy, authorized: false });
    expect(result.grade).toBe('D');
    expect(result.issues.join(' ')).toContain('did not validate');
  });

  it('gives U when no handshake happened', () => {
    expect(gradeTls({ ...healthy, protocol: null }).grade).toBe('U');
  });

  it('notes a certificate with no SANs', () => {
    const result = gradeTls({ ...healthy, sanCount: 0 });
    expect(result.grade).toBe('C');
    expect(result.issues.join(' ')).toContain('subject alternative names');
  });
});
