/**
 * TUĞRUL RECON+ — email address intelligence.
 *
 * Identity side: Gravatar (a public profile keyed by the address hash) and
 * breach exposure. Infrastructure side: the mail domain's MX, SPF, DMARC and
 * DKIM posture — which is what decides whether an address can be spoofed,
 * not whether it exists.
 *
 * Deliberately *not* included: recovery-flow probing of the kind holehe
 * (GPL-3.0) popularised. Firing password-reset requests at third-party
 * services from this app would look, from the receiving side, exactly like
 * credential stuffing, and would get the deployment's IP blocked. The
 * capability gap is listed in INTEGRATED_PROJECTS instead of hidden.
 */

import { createHash } from 'node:crypto';
import { TUGRUL_UA, httpRequest } from './sources';
import { analyseDmarc, analyseSpf, inspectMailDns, type DmarcAnalysis, type MailDns, type SpfAnalysis } from './dns';

export interface ParsedEmail {
  address: string;
  local: string;
  domain: string;
  valid: boolean;
  reason?: string;
}

/** RFC-shaped local part, a single @, and a hostname with a dotted TLD. */
const LOCAL = /^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$/i;
const DOMAIN = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;

export function parseEmail(input: string): ParsedEmail {
  const address = input.trim().replace(/^mailto:/i, '').toLowerCase();
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) {
    return { address, local: '', domain: '', valid: false, reason: 'missing @' };
  }
  const local = address.slice(0, at);
  const domain = address.slice(at + 1);

  if (!LOCAL.test(local)) return { address, local, domain, valid: false, reason: 'invalid local part' };
  if (!DOMAIN.test(domain)) return { address, local, domain, valid: false, reason: 'invalid domain' };
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) {
    return { address, local, domain, valid: false, reason: 'consecutive or edge dots in local part' };
  }
  if (local.length > 64 || address.length > 254) {
    return { address, local, domain, valid: false, reason: 'address too long' };
  }
  return { address, local, domain, valid: true };
}

/** Gravatar keys on the MD5 of the lowercase, trimmed address. */
export function gravatarHash(address: string): string {
  return createHash('md5').update(address.trim().toLowerCase()).digest('hex');
}

export const DEFAULT_AVATAR = `https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&s=200`;

export function avatarUrl(hash: string, size = 200): string {
  return `https://www.gravatar.com/avatar/${hash}?d=mp&s=${size}`;
}

/** Domains that exist only to hand out throwaway addresses. */
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', '10minutemail.com', 'tempmail.com',
  'temp-mail.org', 'throwawaymail.com', 'yopmail.com', 'sharklasers.com', 'getnada.com',
  'dispostable.com', 'trashmail.com', 'maildrop.cc', 'fakeinbox.com', 'mailnesia.com',
  'spam4.me', 'grr.la', 'tempr.email', 'discard.email', 'mohmal.com', 'emailondeck.com',
]);

/** Free consumer providers — not suspicious, but relevant to attribution. */
const FREE_PROVIDERS = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'yahoo.com', 'yahoo.co.uk', 'yandex.com', 'yandex.ru', 'mail.ru', 'gmx.com', 'gmx.de',
  'protonmail.com', 'proton.me', 'icloud.com', 'me.com', 'aol.com', 'zoho.com',
  'tutanota.com', 'tuta.io', 'fastmail.com', 'hushmail.com', 'qq.com', '163.com', '126.com',
]);

const ROLE_LOCALS = new Set([
  'admin', 'administrator', 'info', 'support', 'sales', 'contact', 'help', 'billing',
  'abuse', 'postmaster', 'webmaster', 'hostmaster', 'security', 'privacy', 'legal',
  'noreply', 'no-reply', 'donotreply', 'jobs', 'careers', 'press', 'media', 'office',
]);

export interface EmailFlags {
  disposable: boolean;
  freeProvider: boolean;
  roleAccount: boolean;
  subaddressing: boolean;
  suspiciousLocal: boolean;
}

/** Heuristics on the address itself — no network needed. */
export function classifyAddress(parsed: ParsedEmail): EmailFlags {
  const domain = parsed.domain;
  const local = parsed.local;
  const suspiciousLocal =
    /^[a-z0-9]{16,}$/i.test(local) || // long random string
    /(test|fake|spam|asdf|qwerty|12345)/i.test(local);

  return {
    disposable: DISPOSABLE_DOMAINS.has(domain),
    freeProvider: FREE_PROVIDERS.has(domain),
    roleAccount: ROLE_LOCALS.has(local),
    subaddressing: local.includes('+'),
    suspiciousLocal,
  };
}

/* ── Gravatar ────────────────────────────────────────────────── */

export interface GravatarProfile {
  hash: string;
  checked: boolean;
  exists: boolean;
  displayName?: string;
  aboutMe?: string;
  location?: string;
  jobTitle?: string;
  accounts?: Array<{ domain: string; username: string; url: string }>;
  avatar: string;
  error?: string;
}

interface GravatarEntry {
  profile?: {
    displayName?: string;
    aboutMe?: string;
    currentLocation?: string;
    jobTitle?: string;
    profileUrl?: string;
  };
  accounts?: Array<{ domain?: string; username?: string; url?: string; shortname?: string }>;
}

/**
 * Gravatar's JSON endpoint. A 404 is a definitive “no profile”; anything
 * else is reported as unchecked rather than as absence.
 */
export async function lookupGravatar(address: string, timeoutMs = 8000): Promise<GravatarProfile> {
  const hash = gravatarHash(address);
  const base: GravatarProfile = { hash, checked: false, exists: false, avatar: avatarUrl(hash) };
  try {
    const res = await httpRequest(`https://gravatar.com/${hash}.json`, {
      timeoutMs,
      headers: { Accept: 'application/json', 'User-Agent': TUGRUL_UA },
    });
    if (res.status === 404) return { ...base, checked: true, exists: false };
    if (!res.ok) return { ...base, error: `Gravatar HTTP ${res.status}` };

    const data = JSON.parse(res.body) as { entry?: GravatarEntry[] };
    const entry = data.entry?.[0];
    if (!entry) return { ...base, checked: true, exists: false };

    const profile = entry.profile || {};
    return {
      hash,
      checked: true,
      exists: true,
      displayName: profile.displayName || undefined,
      aboutMe: profile.aboutMe || undefined,
      location: profile.currentLocation || undefined,
      jobTitle: profile.jobTitle || undefined,
      accounts: (entry.accounts || [])
        .filter(a => a.url || a.username)
        .slice(0, 30)
        .map(a => ({
          domain: a.domain || a.shortname || 'unknown',
          username: a.username || '',
          url: a.url || '',
        })),
      avatar: avatarUrl(hash, 200),
    };
  } catch (e) {
    return { ...base, error: e instanceof Error ? e.message : 'Gravatar lookup failed' };
  }
}

/* ── breach exposure (XposedOrNot) ───────────────────────────── */

export interface BreachResult {
  status: 'ok' | 'not_found' | 'unavailable';
  count: number;
  breaches: string[];
  exposedData: string[];
  detail?: string;
}

interface XonResponse {
  BreachesSummary?: { site?: string };
  ExposedData?: Array<{ data_classes?: string[] }>;
  breachMetrics?: { Breach_Count?: number };
}

/**
 * XposedOrNot’s public analytics endpoint — keyless, and the same source the
 * toolkit's DATA LEAKS tab already used from the browser. Moving it
 * server-side removes the CORS dependency and keeps the analyst's IP off the
 * breach service.
 */
export async function lookupBreaches(address: string, timeoutMs = 15_000): Promise<BreachResult> {
  try {
    const res = await httpRequest(
      `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(address)}`,
      { timeoutMs, headers: { Accept: 'application/json', 'User-Agent': TUGRUL_UA } },
    );
    if (res.status === 404) return { status: 'not_found', count: 0, breaches: [], exposedData: [] };
    if (!res.ok) return { status: 'unavailable', count: 0, breaches: [], exposedData: [], detail: `HTTP ${res.status}` };

    const data = JSON.parse(res.body) as XonResponse;
    const breaches = (data.BreachesSummary?.site || '')
      .split(';')
      .map(s => s.trim())
      .filter(Boolean);

    const exposed = new Set<string>();
    for (const item of data.ExposedData || []) {
      for (const cls of item.data_classes || []) exposed.add(cls);
    }

    return {
      status: breaches.length ? 'ok' : 'not_found',
      count: data.breachMetrics?.Breach_Count ?? breaches.length,
      breaches: breaches.slice(0, 100),
      exposedData: Array.from(exposed).sort(),
    };
  } catch (e) {
    return {
      status: 'unavailable',
      count: 0,
      breaches: [],
      exposedData: [],
      detail: e instanceof Error ? e.message : 'breach lookup failed',
    };
  }
}

/* ── reputation (emailrep.io) ────────────────────────────────── */

export interface ReputationResult {
  status: 'ok' | 'unavailable';
  reputation?: string;
  suspicious?: boolean;
  references?: number;
  blacklisted?: boolean;
  maliciousActivity?: boolean;
  credentialsLeaked?: number;
  profiles?: string[];
  detail?: string;
}

export async function lookupReputation(address: string, apiKey?: string, timeoutMs = 10_000): Promise<ReputationResult> {
  try {
    const res = await httpRequest(`https://emailrep.io/${encodeURIComponent(address)}`, {
      timeoutMs,
      headers: {
        Accept: 'application/json',
        'User-Agent': TUGRUL_UA,
        ...(apiKey ? { Key: apiKey } : {}),
      },
    });
    if (!res.ok) return { status: 'unavailable', detail: `HTTP ${res.status}` };
    const data = JSON.parse(res.body) as {
      reputation?: string;
      suspicious?: boolean;
      references?: number;
      details?: {
        blacklisted?: boolean;
        malicious_activity?: boolean;
        credentials_leaked?: boolean | number;
        profiles?: string[];
      };
    };
    return {
      status: 'ok',
      reputation: data.reputation,
      suspicious: data.suspicious,
      references: data.references,
      blacklisted: data.details?.blacklisted,
      maliciousActivity: data.details?.malicious_activity,
      credentialsLeaked: typeof data.details?.credentials_leaked === 'number' ? data.details.credentials_leaked : undefined,
      profiles: data.details?.profiles,
    };
  } catch (e) {
    return { status: 'unavailable', detail: e instanceof Error ? e.message : 'reputation lookup failed' };
  }
}

/* ── domain registration (RDAP) ──────────────────────────────── */

export interface DomainAge {
  created: string | null;
  ageDays: number | null;
  registrar: string | null;
  status: 'ok' | 'unavailable';
}

export async function lookupDomainAge(domain: string, timeoutMs = 10_000): Promise<DomainAge> {
  try {
    const res = await httpRequest(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      timeoutMs,
      headers: { Accept: 'application/rdap+json, application/json' },
    });
    if (!res.ok) return { created: null, ageDays: null, registrar: null, status: 'unavailable' };
    const data = JSON.parse(res.body) as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
    };
    const registration = data.events?.find(e => /registration/i.test(e.eventAction || ''));
    const created = registration?.eventDate && Number.isFinite(Date.parse(registration.eventDate))
      ? new Date(registration.eventDate).toISOString()
      : null;
    const ageDays = created ? Math.floor((Date.now() - Date.parse(created)) / 86_400_000) : null;

    const registrarEntity = data.entities?.find(e => (e.roles || []).includes('registrar'));
    const vcard = registrarEntity?.vcardArray?.[1] as Array<[string, unknown, string, string]> | undefined;
    const registrar = vcard?.find(v => v[0] === 'fn')?.[3] || null;

    return { created, ageDays, registrar, status: 'ok' };
  } catch {
    return { created: null, ageDays: null, registrar: null, status: 'unavailable' };
  }
}

/* ── risk ────────────────────────────────────────────────────── */

export interface EmailRisk {
  score: number;
  level: 'low' | 'medium' | 'high' | 'critical';
  factors: Array<{ label: string; weight: number; detail: string }>;
}

export interface RiskInput {
  flags: EmailFlags;
  spf: SpfAnalysis;
  dmarc: DmarcAnalysis;
  hasMx: boolean;
  domainAgeDays: number | null;
  breachCount: number;
  gravatarExists: boolean;
}

/**
 * A transparent score: every point is a named factor with a weight, so an
 * analyst can disagree with the arithmetic instead of a black box.
 *
 * The score describes *risk associated with the address*, not whether the
 * person behind it is malicious — a brand-new domain with no SPF is a
 * phishing indicator, while a 20-year-old corporate address in one 2013
 * breach is not.
 */
export function assessEmailRisk(input: RiskInput): EmailRisk {
  const factors: EmailRisk['factors'] = [];
  const add = (label: string, weight: number, detail: string) => factors.push({ label, weight, detail });

  if (input.flags.disposable) add('Disposable domain', 40, 'Domain exists to hand out throwaway addresses.');
  if (!input.hasMx) add('No MX record', 30, 'The domain publishes no mail exchanger and cannot receive mail.');
  if (input.domainAgeDays !== null && input.domainAgeDays < 30) {
    add('Newly registered domain', 22, `Registered ${input.domainAgeDays} day(s) ago.`);
  }
  if (input.spf.risk === 'missing') add('No SPF', 12, 'Anyone can forge this domain.');
  else if (input.spf.risk === 'dangerous') add('SPF +all', 18, 'SPF authorises every sender.');
  else if (input.spf.risk === 'weak') add('Weak SPF', 6, input.spf.note);
  if (input.dmarc.risk === 'missing') add('No DMARC', 10, 'No policy for mail failing authentication.');
  else if (input.dmarc.policy === 'none') add('DMARC not enforcing', 5, 'p=none only collects reports.');
  if (input.breachCount > 0) add('Breach exposure', Math.min(15, 4 + input.breachCount), `Address appears in ${input.breachCount} known breach(es).`);
  if (input.gravatarExists) add('Gravatar profile', 3, 'A public profile is linked to this address.');
  if (input.flags.roleAccount) add('Role account', 2, 'Shared mailbox rather than a person.');
  if (input.flags.suspiciousLocal) add('Suspicious local part', 6, 'Address looks generated or disposable.');

  const score = Math.min(100, factors.reduce((sum, f) => sum + f.weight, 0));
  const level: EmailRisk['level'] = score >= 70 ? 'critical' : score >= 45 ? 'high' : score >= 20 ? 'medium' : 'low';
  return { score, level, factors: factors.sort((a, b) => b.weight - a.weight) };
}

/* ── orchestration ───────────────────────────────────────────── */

export interface EmailIntelReport {
  address: string;
  local: string;
  domain: string;
  syntaxValid: boolean;
  syntaxError?: string;
  flags: EmailFlags;
  provider: string;
  mx: string[];
  spf: SpfAnalysis;
  dmarc: DmarcAnalysis;
  dkim: Array<{ selector: string; found: boolean }>;
  gravatar: GravatarProfile;
  breaches: BreachResult;
  reputation: ReputationResult;
  domainAge: DomainAge;
  risk: EmailRisk;
  notes: string[];
  elapsedMs: number;
}

export interface EmailIntelOptions {
  timeoutMs?: number;
  /** Skip the slower optional sources (Gravatar, reputation, RDAP). */
  quick?: boolean;
  emailrepKey?: string;
}

/**
 * Everything that can be learned about one address from public sources.
 * A source that fails leaves its own field `unavailable` — the report is
 * still returned.
 */
export async function emailIntel(input: string, opts: EmailIntelOptions = {}): Promise<EmailIntelReport> {
  const started = Date.now();
  const parsed = parseEmail(input);
  if (!parsed.valid) throw new Error(parsed.reason || 'Invalid email address');

  const { timeoutMs = 12_000, quick = false, emailrepKey } = opts;

  const [mail, gravatar, breaches, reputation, domainAge] = await Promise.all([
    inspectMailDns(parsed.domain, timeoutMs).catch((): MailDns => ({
      mx: [], spf: null, dmarc: null, dmarcPolicy: null, dkimSelectors: [], provider: 'unknown',
      error: 'mail DNS lookup failed',
    })),
    quick ? Promise.resolve<GravatarProfile>({ hash: gravatarHash(parsed.address), checked: false, exists: false, avatar: avatarUrl(gravatarHash(parsed.address)) }) : lookupGravatar(parsed.address, timeoutMs),
    quick
      ? Promise.resolve<BreachResult>({ status: 'unavailable' as const, count: 0, breaches: [], exposedData: [], detail: 'quick mode' })
      : lookupBreaches(parsed.address, timeoutMs + 5000),
    quick
      ? Promise.resolve<ReputationResult>({ status: 'unavailable' as const, detail: 'quick mode' })
      : lookupReputation(parsed.address, emailrepKey, timeoutMs),
    lookupDomainAge(parsed.domain, timeoutMs),
  ]);

  const spf = analyseSpf(mail.spf ?? null);
  const dmarc = analyseDmarc(mail.dmarc ?? null);
  const flags = classifyAddress(parsed);

  const risk = assessEmailRisk({
    flags,
    spf,
    dmarc,
    hasMx: mail.mx.length > 0,
    domainAgeDays: domainAge.ageDays,
    breachCount: breaches.breaches.length,
    gravatarExists: gravatar.exists,
  });

  const notes: string[] = [];
  if (!mail.mx.length) notes.push('No MX record was returned; the domain may not accept mail at all.');
  if (mail.error) notes.push(`Mail DNS lookup reported: ${mail.error}`);
  if (gravatar.error) notes.push(`Gravatar: ${gravatar.error}`);
  if (breaches.status === 'unavailable') notes.push('Breach corpus did not answer; exposure was not measured.');
  if (reputation.status === 'unavailable') notes.push('Reputation source did not answer (or requires a key).');
  notes.push('SPF and DMARC describe the domain, not this mailbox. A valid record does not prove the address exists.');

  return {
    address: parsed.address,
    local: parsed.local,
    domain: parsed.domain,
    syntaxValid: parsed.valid,
    syntaxError: parsed.reason,
    flags,
    provider: mail.provider,
    mx: mail.mx,
    spf,
    dmarc,
    dkim: mail.dkimSelectors,
    gravatar,
    breaches,
    reputation,
    domainAge,
    risk,
    notes,
    elapsedMs: Date.now() - started,
  };
}
