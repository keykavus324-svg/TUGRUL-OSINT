/**
 * TUĞRUL RECON+ — TLS inspection.
 *
 * Server-side only (node:tls). Answers the questions an analyst actually
 * asks of a certificate: who signed it, what names does it cover, when does
 * it expire, is the chain complete, and is the negotiated protocol still
 * acceptable in 2026.
 *
 * The connection deliberately does not verify the certificate
 * (`rejectUnauthorized: false`): a recon tool has to *report* an expired or
 * self-signed certificate, which is impossible if the handshake aborts first.
 * Verification status is captured in `authorized` and reported instead.
 */

import tls from 'node:tls';

export interface TlsChainEntry {
  subject: string;
  issuer: string;
  validFrom: string | null;
  validTo: string | null;
  selfSigned: boolean;
}

export interface TlsReport {
  host: string;
  port: number;
  connected: boolean;
  protocol: string | null;
  cipher: string | null;
  cipherBits: number | null;
  alpn: string | null;
  authorized: boolean | null;
  authorizationError: string | null;
  subject: string | null;
  issuer: string | null;
  commonName: string | null;
  san: string[];
  /** `notBefore` / `notAfter` as ISO strings. */
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  serial: string | null;
  fingerprintSha256: string | null;
  chain: TlsChainEntry[];
  grade: 'A' | 'B' | 'C' | 'D' | 'F' | 'U';
  issues: string[];
  error?: string;
  elapsedMs: number;
}

/** `'{CN: foo, O: bar}'` → `'CN=foo, O=bar'`. */
function formatName(name: unknown): string {
  if (!name || typeof name !== 'object') return '';
  return Object.entries(name as Record<string, string | string[]>)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('/') : v}`)
    .join(', ');
}

function parseDate(value: string | undefined): string | null {
  if (!value) return null;
  const ts = Date.parse(value);
  return Number.isFinite(ts) ? new Date(ts).toISOString() : null;
}

/** Whole days between now and an ISO timestamp; negative once expired. */
export function daysRemaining(validTo: string | null, now: number = Date.now()): number | null {
  if (!validTo) return null;
  const ts = Date.parse(validTo);
  if (!Number.isFinite(ts)) return null;
  return Math.floor((ts - now) / 86_400_000);
}

const WEAK_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']);
const WEAK_CIPHER = /(RC4|3DES|DES-CBC|NULL|EXPORT|MD5)/i;

export interface GradeInput {
  protocol: string | null;
  cipher: string | null;
  authorized: boolean | null;
  daysRemaining: number | null;
  selfSigned: boolean;
  sanCount: number;
}

/**
 * A blunt letter grade, matching how reconnaissance tools rank a service.
 * It is about transport health, not about whether the site is trustworthy.
 */
export function gradeTls(input: GradeInput): { grade: TlsReport['grade']; issues: string[] } {
  const issues: string[] = [];
  let grade: TlsReport['grade'] = 'A';

  const worsen = (next: TlsReport['grade']) => {
    const rank = { A: 0, B: 1, C: 2, D: 3, F: 4, U: 5 } as const;
    if (rank[next] > rank[grade]) grade = next;
  };

  if (input.protocol === null) {
    return { grade: 'U', issues: ['No TLS handshake completed.'] };
  }

  if (WEAK_PROTOCOLS.has(input.protocol)) {
    issues.push(`${input.protocol} is deprecated and should be disabled.`);
    worsen('D');
  }

  if (input.cipher && WEAK_CIPHER.test(input.cipher)) {
    issues.push(`Weak cipher suite negotiated: ${input.cipher}.`);
    worsen('D');
  }

  if (input.selfSigned) {
    issues.push('Certificate is self-signed; no third party vouches for this host.');
    worsen('D');
  }

  if (input.authorized === false && !input.selfSigned) {
    issues.push('Certificate chain did not validate (hostname mismatch, unknown issuer or incomplete chain).');
    worsen('D');
  }

  if (input.daysRemaining !== null) {
    if (input.daysRemaining < 0) {
      issues.push(`Certificate expired ${Math.abs(input.daysRemaining)} day(s) ago.`);
      worsen('F');
    } else if (input.daysRemaining < 7) {
      issues.push(`Certificate expires in ${input.daysRemaining} day(s).`);
      worsen('C');
    } else if (input.daysRemaining < 30) {
      issues.push(`Certificate expires in ${input.daysRemaining} day(s).`);
      worsen('B');
    }
  }

  if (input.sanCount === 0) {
    issues.push('Certificate has no subject alternative names; modern clients may reject it.');
    worsen('C');
  }

  if (!issues.length) issues.push('Certificate is valid, chain verifies and the negotiated protocol is current.');

  return { grade, issues };
}

const DEFAULT_PORT = 443;

/**
 * Open one TLS connection and read everything the handshake exposes.
 *
 * Resolves rather than throws for network failures, because "port closed" is
 * a legitimate recon finding and having it land in `error` keeps the report
 * shape stable.
 */
export async function inspectTls(host: string, port: number = DEFAULT_PORT, timeoutMs = 10_000): Promise<TlsReport> {
  const started = Date.now();
  const empty: TlsReport = {
    host,
    port,
    connected: false,
    protocol: null,
    cipher: null,
    cipherBits: null,
    alpn: null,
    authorized: null,
    authorizationError: null,
    subject: null,
    issuer: null,
    commonName: null,
    san: [],
    validFrom: null,
    validTo: null,
    daysRemaining: null,
    serial: null,
    fingerprintSha256: null,
    chain: [],
    grade: 'U',
    issues: [],
    elapsedMs: 0,
  };

  return new Promise<TlsReport>(resolve => {
    let settled = false;
    // The guard timer must exist before `finish` can clear it, but it is only
    // armed after the socket exists — a holder keeps both orders valid without
    // a `let` that is assigned exactly once.
    const timer: { handle?: ReturnType<typeof setTimeout> } = {};
    const finish = (report: TlsReport) => {
      if (settled) return;
      settled = true;
      if (timer.handle) clearTimeout(timer.handle);
      try { socket.destroy(); } catch { /* already closed */ }
      resolve(report);
    };

    const socket = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      ALPNProtocols: ['h2', 'http/1.1'],
      timeout: timeoutMs,
    });

    // A second, independent timer: `timeout` on the socket covers the TCP
    // connect but not a peer that accepts and then stalls mid-handshake.
    timer.handle = setTimeout(() => {
      finish({ ...empty, error: `TLS handshake timed out after ${timeoutMs}ms`, elapsedMs: Date.now() - started });
    }, timeoutMs + 1000);

    socket.once('error', err => {
      finish({ ...empty, error: err.message, elapsedMs: Date.now() - started });
    });

    socket.once('secureConnect', () => {
      try {
        const cert = socket.getPeerCertificate(true) as tls.DetailedPeerCertificate;
        const cipher = socket.getCipher();

        if (!cert || Object.keys(cert).length === 0) {
          finish({ ...empty, error: 'Peer presented no certificate', elapsedMs: Date.now() - started });
          return;
        }

        const validTo = parseDate(cert.valid_to);
        const validFrom = parseDate(cert.valid_from);
        const subject = formatName(cert.subject);
        const issuer = formatName(cert.issuer);

        const san = (cert.subjectaltname || '')
          .split(',')
          .map(part => part.trim())
          .filter(part => part.startsWith('DNS:'))
          .map(part => part.slice(4))
          .slice(0, 200);

        // Walk the chain; Node links it as a linked list with `issuerCertificate`.
        const chain: TlsChainEntry[] = [];
        const seen = new Set<string>();
        let node: tls.DetailedPeerCertificate | undefined = cert;
        while (node && Object.keys(node).length && chain.length < 10) {
          const fingerprint = node.fingerprint256 || node.fingerprint || formatName(node.subject);
          if (seen.has(fingerprint)) break;
          seen.add(fingerprint);
          const nodeSubject = formatName(node.subject);
          const nodeIssuer = formatName(node.issuer);
          chain.push({
            subject: nodeSubject,
            issuer: nodeIssuer,
            validFrom: parseDate(node.valid_from),
            validTo: parseDate(node.valid_to),
            selfSigned: nodeSubject === nodeIssuer,
          });
          node = node.issuerCertificate;
          if (node && node.fingerprint256 === cert.fingerprint256) break;
        }

        const selfSigned = subject === issuer || chain.length === 1;
        const remaining = daysRemaining(validTo);
        const { grade, issues } = gradeTls({
          protocol: socket.getProtocol(),
          cipher: cipher?.name ?? null,
          authorized: socket.authorized,
          daysRemaining: remaining,
          selfSigned,
          sanCount: san.length,
        });

        finish({
          host,
          port,
          connected: true,
          protocol: socket.getProtocol(),
          cipher: cipher?.name ?? null,
          cipherBits: null,
          alpn: socket.alpnProtocol || null,
          authorized: socket.authorized ?? null,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
          subject,
          issuer,
          commonName: (cert.subject?.CN as string) || null,
          san,
          validFrom,
          validTo,
          daysRemaining: remaining,
          serial: cert.serialNumber || null,
          fingerprintSha256: cert.fingerprint256 || null,
          chain,
          grade,
          issues,
          elapsedMs: Date.now() - started,
        });
      } catch (e) {
        finish({
          ...empty,
          error: e instanceof Error ? e.message : 'failed to read certificate',
          elapsedMs: Date.now() - started,
        });
      }
    });

    socket.once('timeout', () => {
      finish({ ...empty, error: `Connection timed out after ${timeoutMs}ms`, elapsedMs: Date.now() - started });
    });
  });
}
