import { describe, it, expect } from 'vitest';
import { buildReconGraph, graphToRows, summariseGraph } from './graph';

describe('buildReconGraph', () => {
  const graph = buildReconGraph({
    seed: 'example.com',
    seedType: 'domain',
    addresses: ['93.184.216.34'],
    nameservers: ['ns1.example.net'],
    hosts: [
      { host: 'api.example.com', ips: ['93.184.216.35'], sources: ['crt.sh'] },
      { host: 'docs.example.com', ips: [], sources: ['Wayback Machine'] },
      { host: 'example.com', ips: [] }, // the seed itself must not be duplicated
    ],
    technologies: [{ name: 'Nginx', version: '1.24.0' }, { name: 'WordPress' }],
    emails: ['security@example.com'],
    findings: [{ url: 'https://example.com/.env', kind: 'env-file', severity: 'high' }],
    certificate: { issuer: 'CN=R3, O=Let’s Encrypt', validTo: '2026-01-01T00:00:00.000Z' },
  });

  it('namespaces node ids by type', () => {
    expect(graph.rootId).toBe('domain:example.com');
    const ids = graph.nodes.map(n => n.id);
    expect(ids).toContain('ip:93.184.216.35');
    expect(ids).toContain('host:api.example.com');
    expect(ids).toContain('technology:nginx 1.24.0');
    expect(ids).toContain('email:security@example.com');
    expect(ids).toContain('url:https://example.com/.env');
  });

  it('does not add the seed as its own subdomain', () => {
    const self = graph.edges.filter(e => e.target === 'host:example.com');
    expect(self).toEqual([]);
  });

  it('links everything back to the seed', () => {
    const counts = summariseGraph(graph);
    expect(counts.nodes).toBe(graph.nodes.length);
    expect(counts.edges).toBeGreaterThan(5);
    expect(graph.edges.find(e => e.label === 'uses')).toBeDefined();
    expect(graph.edges.find(e => e.label === 'exposes')?.target).toBe('url:https://example.com/.env');
    expect(graph.edges.find(e => e.label === 'certificate_issued_by')?.target).toContain('organization:');
  });

  it('marks high-severity URL findings with a risk', () => {
    const node = graph.nodes.find(n => n.id === 'url:https://example.com/.env');
    expect(node?.risk).toBe('high');
  });

  it('attaches evidence metadata to host nodes', () => {
    const node = graph.nodes.find(n => n.id === 'host:api.example.com');
    expect(node?.meta).toMatchObject({ ips: '93.184.216.35', sources: 'crt.sh' });
  });

  it('deduplicates repeated edges', () => {
    const keys = graph.edges.map(e => `${e.source}|${e.target}|${e.label}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('summarises node types in descending order', () => {
    const summary = summariseGraph(graph);
    expect(summary.byType.reduce((sum, t) => sum + t.count, 0)).toBe(graph.nodes.length);
    expect(summary.byType[0].count).toBeGreaterThanOrEqual(summary.byType[summary.byType.length - 1].count);
  });

  it('produces readable rows for the export', () => {
    const rows = graphToRows(graph);
    expect(rows[0]).toHaveProperty('from');
    expect(rows[0]).toHaveProperty('relation');
    expect(rows.some(r => r.relation === 'resolves_to')).toBe(true);
  });

  it('caps the graph so a huge subdomain list cannot kill the layout', () => {
    const huge = buildReconGraph({
      seed: 'example.com',
      seedType: 'domain',
      hosts: Array.from({ length: 1200 }, (_, i) => ({ host: `h${i}.example.com`, ips: [`10.0.${Math.floor(i / 250)}.${i % 250}`] })),
    });
    expect(huge.nodes.length).toBeLessThanOrEqual(500);
    expect(huge.edges.every(e => huge.nodes.some(n => n.id === e.source))).toBe(true);
    expect(huge.edges.every(e => huge.nodes.some(n => n.id === e.target))).toBe(true);
  });
});
