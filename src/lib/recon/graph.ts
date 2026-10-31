/**
 * TUĞRUL RECON+ — pivot graph.
 *
 * Amass (Apache-2.0) and SpiderFoot (MIT) both make the same point: a list of
 * subdomains is data, but “this host resolves to that address, which is
 * shared with these two names, and the certificate was issued to that
 * organisation” is intelligence. The graph layer keeps the provenance that
 * the individual modules already recorded and turns it into nodes and edges
 * the UI can draw.
 *
 * Node ids are namespaced by type (`ip:1.2.3.4`) so an address and a
 * hostname can never collide.
 */

export type NodeType = 'domain' | 'host' | 'ip' | 'email' | 'username' | 'technology' | 'certificate' | 'url' | 'organization';

export type NodeRisk = 'high' | 'medium' | 'low' | null;

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  risk: NodeRisk;
  /** Shown in the node inspector; kept small and JSON-serialisable. */
  meta?: Record<string, string | number | null>;
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

export interface ReconGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** Node id of the seed, so the UI can centre on it. */
  rootId: string;
}

export interface GraphInput {
  seed: string;
  seedType: Extract<NodeType, 'domain' | 'ip' | 'email' | 'username' | 'url'>;
  hosts?: Array<{ host: string; ips?: string[]; sources?: string[] }>;
  technologies?: Array<{ name: string; version?: string }>;
  emails?: string[];
  /** Interesting URLs, already triaged by the URL harvester. */
  findings?: Array<{ url: string; kind: string; severity: string }>;
  certificate?: { issuer?: string | null; validTo?: string | null; san?: string[] };
  nameservers?: string[];
  /** Addresses that belong to the seed itself (IP seed, or the A record). */
  addresses?: string[];
}

const MAX_NODES = 500;

const id = (type: NodeType, value: string) => `${type}:${value.toLowerCase().trim()}`;

/**
 * Build the graph.
 *
 * Capped at MAX_NODES so a domain with 4 000 passive subdomains does not
 * produce a force-directed layout that kills the browser. Everything is
 * still in the JSON report; the graph is prioritised (resolved hosts first,
 * then the rest).
 */
export function buildReconGraph(input: GraphInput): ReconGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const linked = new Set<string>();

  const addNode = (node: GraphNode): GraphNode | null => {
    if (nodes.has(node.id)) return nodes.get(node.id)!;
    if (nodes.size >= MAX_NODES) return null;
    nodes.set(node.id, node);
    return node;
  };

  const addEdge = (source: string, target: string, label: string) => {
    if (!nodes.has(source) || !nodes.has(target)) return;
    const key = `${source}|${target}|${label}`;
    if (linked.has(key)) return;
    linked.add(key);
    edges.push({ source, target, label });
  };

  const rootId = id(input.seedType, input.seed);
  addNode({
    id: rootId,
    label: input.seed,
    type: input.seedType,
    risk: null,
    meta: { seed: 'true' },
  });

  // The seed's own addresses.
  for (const ip of input.addresses || []) {
    const node = addNode({ id: id('ip', ip), label: ip, type: 'ip', risk: null });
    if (node) addEdge(rootId, node.id, 'resolves_to');
  }

  // Nameservers are infrastructure the organisation controls.
  for (const ns of input.nameservers || []) {
    const node = addNode({ id: id('host', ns), label: ns, type: 'host', risk: null, meta: { role: 'nameserver' } });
    if (node) addEdge(rootId, node.id, 'delegates_to');
  }

  // Hosts: resolved ones first so the cap keeps the most useful nodes.
  const hosts = [...(input.hosts || [])].sort((a, b) => (b.ips?.length ? 1 : 0) - (a.ips?.length ? 1 : 0));
  for (const host of hosts) {
    if (host.host.toLowerCase() === input.seed.toLowerCase()) continue;
    const node = addNode({
      id: id('host', host.host),
      label: host.host,
      type: 'host',
      risk: null,
      meta: {
        ...(host.ips?.length ? { ips: host.ips.slice(0, 8).join(', ') } : {}),
        ...(host.sources?.length ? { sources: host.sources.join(', ') } : {}),
      },
    });
    if (!node) continue;
    addEdge(rootId, node.id, 'subdomain_of');
    for (const ip of (host.ips || []).slice(0, 4)) {
      const ipNode = addNode({ id: id('ip', ip), label: ip, type: 'ip', risk: null });
      if (ipNode) addEdge(node.id, ipNode.id, 'resolves_to');
    }
  }

  for (const tech of input.technologies || []) {
    const label = tech.version ? `${tech.name} ${tech.version}` : tech.name;
    const node = addNode({ id: id('technology', label), label, type: 'technology', risk: null });
    if (node) addEdge(rootId, node.id, 'uses');
  }

  for (const email of input.emails || []) {
    const node = addNode({ id: id('email', email), label: email, type: 'email', risk: null });
    if (node) addEdge(rootId, node.id, 'mentions');
  }

  for (const finding of input.findings || []) {
    const node = addNode({
      id: id('url', finding.url),
      label: finding.url,
      type: 'url',
      risk: finding.severity === 'high' ? 'high' : finding.severity === 'medium' ? 'medium' : 'low',
      meta: { kind: finding.kind },
    });
    if (node) addEdge(rootId, node.id, 'exposes');
  }

  if (input.certificate?.issuer) {
    const issuer = input.certificate.issuer;
    const node = addNode({
      id: id('organization', issuer),
      label: issuer,
      type: 'organization',
      risk: null,
      meta: {
        role: 'certificate issuer',
        ...(input.certificate.validTo ? { validTo: input.certificate.validTo } : {}),
      },
    });
    if (node) addEdge(rootId, node.id, 'certificate_issued_by');
  }

  return { nodes: Array.from(nodes.values()), edges, rootId };
}

/** Edge and node counts by type, for the summary line in the UI. */
export function summariseGraph(graph: ReconGraph): {
  nodes: number;
  edges: number;
  byType: Array<{ type: NodeType; count: number }>;
} {
  const counts = new Map<NodeType, number>();
  for (const node of graph.nodes) counts.set(node.type, (counts.get(node.type) || 0) + 1);
  return {
    nodes: graph.nodes.length,
    edges: graph.edges.length,
    byType: Array.from(counts.entries())
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count),
  };
}

/** A flat, diffable form for the JSON export. */
export function graphToRows(graph: ReconGraph): Array<{ from: string; relation: string; to: string }> {
  const label = (nodeId: string) => graph.nodes.find(n => n.id === nodeId)?.label || nodeId;
  return graph.edges.map(e => ({ from: label(e.source), relation: e.label, to: label(e.target) }));
}
