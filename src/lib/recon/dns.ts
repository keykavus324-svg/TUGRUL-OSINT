/**
 * TUĞRUL RECON+ — DNS over HTTPS.
 *
 * The rest of the app talks to Google's DoH endpoint from the browser, which
 * is fine for a single lookup but not for recon: a subdomain sweep needs
 * hundreds of short queries and a per-name cache, and the mail/SPF checks
 * need record types a browser page never asks for.
 *
 * Everything here answers `{ records, status }` rather than throwing, so a
 * NXDOMAIN and a dead resolver stay distinguishable in the report.
 */

import { httpJson } from './sources';

export type DnsType = 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' | 'CNAME' | 'SOA' | 'CAA' | 'SRV' | 'PTR';

interface DohAnswer {
  name?: string;
  type?: number;
  TTL?: number;
  data?: string;
}

interface DohResponse {
  Status?: number;
  Answer?: DohAnswer[];
  Authority?: DohAnswer[];
}

export interface DnsAnswer {
  type: string;
  name: string;
  ttl: number;
  data: string;
}

export interface DnsResult {
  name: string;
  type: DnsType;
  /** DoH status: 0 NOERROR, 3 NXDOMAIN, 2 SERVFAIL… */
  status: number;
  records: DnsAnswer[];
  /** Everything failed, as opposed to “the name has no such record”. */
  error?: string;
}

const TYPE_NAMES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  257: 'CAA',
};

const DOH_ENDPOINT = 'https://dns.google/resolve';

/** Short-lived cache: recon frequently asks the same name several times. */
const cache = new Map<string, { at: number; value: DnsResult }>();
const CACHE_TTL = 5 * 60_000;
const CACHE_MAX = 2000;

function evict() {
  if (cache.size <= CACHE_MAX) return;
  for (const key of cache.keys()) {
    if (cache.size <= CACHE_MAX) break;
    cache.delete(key);
  }
}

export async function resolveDns(
  name: string,
  type: DnsType = 'A',
  { timeoutMs = 6000, noCache = false }: { timeoutMs?: number; noCache?: boolean } = {},
): Promise<DnsResult> {
  const key = `${type}:${name.toLowerCase()}`;
  if (!noCache) {
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_TTL) return hit.value;
  }

  try {
    const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}`;
    const data = await httpJson<DohResponse>(url, { timeoutMs, headers: { Accept: 'application/json' } });
    const records = (data.Answer || [])
      .filter(a => typeof a.data === 'string')
      .map(a => ({
        type: TYPE_NAMES[a.type ?? 0] || String(a.type ?? ''),
        name: a.name || name,
        ttl: a.TTL ?? 0,
        data: a.data as string,
      }));
    const result: DnsResult = { name, type, status: data.Status ?? -1, records };
    cache.set(key, { at: Date.now(), value: result });
    evict();
    return result;
  } catch (e) {
    return {
      name,
      type,
      status: -1,
      records: [],
      error: e instanceof Error ? e.message : 'resolver unreachable',
    };
  }
}

/** A/AAAA addresses for a name, as plain strings. */
export async function resolveAddresses(name: string, timeoutMs = 6000): Promise<string[]> {
  const [a, aaaa] = await Promise.all([
    resolveDns(name, 'A', { timeoutMs }),
    resolveDns(name, 'AAAA', { timeoutMs }),
  ]);
  return [...a.records.map(r => r.data), ...aaaa.records.map(r => r.data)];
}

export interface MailDns {
  mx: string[];
  spf: string | null;
  dmarc: string | null;
  dmarcPolicy: string | null;
  dkimSelectors: Array<{ selector: string; found: boolean }>;
  provider: string;
  error?: string;
}

/** Provider detection from the MX hostnames, not from the address. */
export function mailProvider(mx: string[]): string {
  const joined = mx.join(' ').toLowerCase();
  if (!joined) return 'unknown';
  if (joined.includes('google') || joined.includes('googlemail')) return 'Google Workspace / Gmail';
  if (joined.includes('outlook') || joined.includes('protection.outlook')) return 'Microsoft 365';
  if (joined.includes('yandex')) return 'Yandex Mail';
  if (joined.includes('protonmail') || joined.includes('proton.ch')) return 'Proton Mail';
  if (joined.includes('zoho')) return 'Zoho Mail';
  if (joined.includes('icloud') || joined.includes('apple')) return 'iCloud Mail';
  if (joined.includes('qq.com') || joined.includes('tencent')) return 'Tencent Exmail';
  if (joined.includes('mail.ru') || joined.includes('mailru')) return 'Mail.ru';
  if (joined.includes('secureserver') || joined.includes('hostinger') || joined.includes('cpanel')) return 'Shared hosting mail';
  if (joined.includes('amazonaws') || joined.includes('amazonses')) return 'Amazon SES';
  if (joined.includes('mimecast')) return 'Mimecast gateway';
  if (joined.includes('pphosted') || joined.includes('proofpoint')) return 'Proofpoint gateway';
  if (joined.includes('barracuda')) return 'Barracuda gateway';
  return 'other / self-hosted';
}

const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 's1', 's2', 'mail', 'k1', 'dkim'];

/**
 * Mail-domain posture: MX, SPF, DMARC and a few common DKIM selectors.
 *
 * DMARC is looked up at `_dmarc.<domain>`; a TXT answer that does not start
 * with `v=DMARC1` is someone else's record and is ignored rather than
 * mis-parsed into an empty policy.
 */
export async function inspectMailDns(domain: string, timeoutMs = 6000): Promise<MailDns> {
  const [mx, txt, dmarc] = await Promise.all([
    resolveDns(domain, 'MX', { timeoutMs }),
    resolveDns(domain, 'TXT', { timeoutMs }),
    resolveDns(`_dmarc.${domain}`, 'TXT', { timeoutMs }),
  ]);

  const mxHosts = mx.records
    .map(r => r.data.replace(/^\d+\s+/, '').trim())
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b));

  const spf = txt.records.find(r => r.data.replace(/"/g, '').trim().startsWith('v=spf1')) ?? null;
  const dmarcRecord =
    dmarc.records.find(r => r.data.replace(/"/g, '').trim().startsWith('v=DMARC1')) ?? null;

  const policyMatch = dmarcRecord?.data.match(/\bp\s*=\s*(none|quarantine|reject)\b/i);

  // Only worth probing selectors when there is a domain to probe.
  const dkimSelectors = await Promise.all(
    DKIM_SELECTORS.map(async selector => {
      const res = await resolveDns(`${selector}._domainkey.${domain}`, 'TXT', { timeoutMs: 4000 });
      const found = res.records.some(r => /(v=DKIM1|k=|p=)/i.test(r.data));
      return { selector, found };
    }),
  );

  return {
    mx: mxHosts,
    spf: spf ? spf.data.replace(/"/g, '').replace(/\s+/g, ' ').trim() : null,
    dmarc: dmarcRecord ? dmarcRecord.data.replace(/"/g, '').replace(/\s+/g, ' ').trim() : null,
    dmarcPolicy: policyMatch ? policyMatch[1].toLowerCase() : null,
    dkimSelectors: dkimSelectors.filter(s => s.found),
    provider: mailProvider(mxHosts),
    error: mx.error || txt.error,
  };
}

export interface SpfAnalysis {
  present: boolean;
  record: string | null;
  /** `all` qualifier: what the domain says about mail from unlisted senders. */
  all: 'fail' | 'softfail' | 'neutral' | 'pass' | 'none' | null;
  lookups: number;
  mechanisms: string[];
  risk: 'ok' | 'weak' | 'dangerous' | 'missing';
  note: string;
}

/**
 * Summarise an SPF record.
 *
 * The number that matters is the `all` qualifier: `-all` rejects unlisted
 * senders, `~all` marks them, and `+all` authorises the entire internet to
 * send as this domain — a record that looks present in a checklist but
 * provides nothing.
 */
export function analyseSpf(record: string | null): SpfAnalysis {
  if (!record) {
    return {
      present: false,
      record: null,
      all: null,
      lookups: 0,
      mechanisms: [],
      risk: 'missing',
      note: 'No SPF record: anyone can forge this domain, and receivers cannot tell.',
    };
  }

  const parts = record.split(/\s+/).filter(Boolean);
  const mechanisms = parts.filter(p => !/^v=spf1$/i.test(p));
  const allMechanism = mechanisms.find(m => /^[+\-~?]?all$/i.test(m));
  const qualifier = allMechanism ? allMechanism[0] : '-';

  const all: SpfAnalysis['all'] =
    !allMechanism ? null
      : qualifier === '-' ? 'fail'
        : qualifier === '~' ? 'softfail'
          : qualifier === '?' ? 'neutral'
            : 'pass';

  const lookups = mechanisms.filter(m =>
    /^(include:|a$|a:|mx$|mx:|ptr$|ptr:|exists:|redirect=)/i.test(m),
  ).length;

  let risk: SpfAnalysis['risk'] = 'ok';
  let note = 'SPF is present and declares a policy for unlisted senders.';
  if (all === 'pass') {
    risk = 'dangerous';
    note = '`+all` authorises every host on the internet to send as this domain; effectively no protection.';
  } else if (all === null) {
    risk = 'weak';
    note = 'No `all` mechanism: receivers get no instruction for unlisted senders.';
  } else if (all === 'neutral' || all === 'softfail') {
    risk = 'weak';
    note = 'Unlisted senders are only marked, not rejected, so spoofed mail still lands in many inboxes.';
  } else if (lookups > 10) {
    risk = 'weak';
    note = `${lookups} DNS lookups exceeds the RFC 7208 limit of 10; receivers may stop evaluating and fail open.`;
  }

  return { present: true, record, all, lookups, mechanisms, risk, note };
}

export interface DmarcAnalysis {
  present: boolean;
  record: string | null;
  policy: 'none' | 'quarantine' | 'reject' | null;
  subdomainPolicy: string | null;
  pct: number | null;
  reporting: string[];
  risk: 'ok' | 'weak' | 'dangerous' | 'missing';
  note: string;
}

/** DMARC summarised the same way — `p=none` is monitoring, not enforcement. */
export function analyseDmarc(record: string | null): DmarcAnalysis {
  if (!record) {
    return {
      present: false,
      record: null,
      policy: null,
      subdomainPolicy: null,
      pct: null,
      reporting: [],
      risk: 'missing',
      note: 'No DMARC record: receivers have no instruction for mail that fails SPF/DKIM.',
    };
  }
  const tags = Object.fromEntries(
    record
      .split(';')
      .map(t => t.trim())
      .filter(Boolean)
      .map(t => {
        const [k, ...v] = t.split('=');
        return [k.trim().toLowerCase(), v.join('=').trim()];
      }),
  ) as Record<string, string>;

  const policy = (tags.p || '').toLowerCase();
  const validPolicy = policy === 'none' || policy === 'quarantine' || policy === 'reject' ? policy : null;
  const pct = tags.pct ? Number(tags.pct) : null;
  const reporting = [tags.rua, tags.ruf].filter(Boolean).flatMap(v => v.split(',').map(s => s.trim()));

  let risk: DmarcAnalysis['risk'] = 'ok';
  let note = 'DMARC is present and enforcing.';
  if (validPolicy === 'none') {
    risk = 'weak';
    note = '`p=none` only collects reports; forged mail is still delivered.';
  } else if (validPolicy === null) {
    risk = 'weak';
    note = 'The record has no usable `p=` policy.';
  } else if (pct !== null && pct < 100) {
    risk = 'weak';
    note = `Policy applies to only ${pct}% of mail.`;
  }

  return {
    present: true,
    record,
    policy: validPolicy,
    subdomainPolicy: tags.sp ? tags.sp.toLowerCase() : null,
    pct: Number.isFinite(pct) ? pct : null,
    reporting,
    risk,
    note,
  };
}
