import { describe, it, expect } from 'vitest';
import { detectSeed } from './dossier';

describe('detectSeed', () => {
  it('recognises an email before treating the domain as a domain', () => {
    const seed = detectSeed('Analyst@Example.com');
    expect(seed).toEqual({ type: 'email', value: 'analyst@example.com' });
  });

  it('recognises IPv4 and IPv6 literals', () => {
    expect(detectSeed('8.8.8.8')).toEqual({ type: 'ip', value: '8.8.8.8' });
    expect(detectSeed('2001:4860:4860::8888')).toEqual({ type: 'ip', value: '2001:4860:4860::8888' });
  });

  it('normalises a bare domain and a URL', () => {
    expect(detectSeed('  Example.COM ')).toEqual({ type: 'domain', value: 'example.com' });
    expect(detectSeed('https://example.com/a?b=1')).toEqual({ type: 'url', value: 'https://example.com/a?b=1' });
  });

  it('falls back to a username for a bare handle', () => {
    expect(detectSeed('johndoe_42')).toEqual({ type: 'username', value: 'johndoe_42' });
  });

  it('rejects something that cannot be any of them', () => {
    expect(() => detectSeed('')).toThrow('Empty target');
    expect(() => detectSeed('a b c')).toThrow('Unrecognised target');
  });

  it('rejects an out-of-range dotted quad instead of scanning it as a handle', () => {
    expect(() => detectSeed('999.1.1.1')).toThrow('Invalid IPv4 address');
  });
});
