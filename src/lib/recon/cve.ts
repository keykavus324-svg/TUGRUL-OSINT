/**
 * TUĞRUL RECON+ — technology-to-CVE correlation.
 *
 * The old VULN SWEEP tab called an external scanner service. Without that
 * service the tab returned 503, so the toolkit advertised a capability it
 * did not have. This module closes the gap with public data:
 *
 *   detected stack  →  CPE vendor/product  →  CIRCL CVE search (keyless)
 *
 * What it is not: a vulnerability scanner. It reports which CVEs are
 * published against the detected product, and separates the ones whose
 * affected versions include the version we actually observed from the ones
 * we cannot confirm. A “product-level” match is a lead, not a finding.
 */

import { mapLimit, httpJson } from './sources';
import type { Technology } from './webtech';

export interface CpeMapping {
  vendor: string;
  product: string;
  note?: string;
}

/**
 * Only products whose CIRCL vendor/product pair is unambiguous are mapped.
 * Guessing a vendor produces a confident, wrong CVE list — worse than
 * admitting the product is not covered.
 */
export const TECH_CPE: Record<string, CpeMapping> = {
  'Nginx': { vendor: 'nginx', product: 'nginx' },
  'Apache HTTP Server': { vendor: 'apache', product: 'http_server' },
  'Microsoft IIS': { vendor: 'microsoft', product: 'internet_information_services' },
  'LiteSpeed': { vendor: 'litespeedtech', product: 'openlitespeed' },
  'OpenResty': { vendor: 'openresty', product: 'openresty' },
  'PHP': { vendor: 'php', product: 'php' },
  'WordPress': { vendor: 'wordpress', product: 'wordpress' },
  'Drupal': { vendor: 'drupal', product: 'drupal' },
  'Joomla': { vendor: 'joomla', product: 'joomla\\!' },
  'Magento': { vendor: 'magento', product: 'magento' },
  'WooCommerce': { vendor: 'woocommerce', product: 'woocommerce' },
  'Shopify': { vendor: 'shopify', product: 'shopify' },
  'PrestaShop': { vendor: 'prestashop', product: 'prestashop' },
  'OpenCart': { vendor: 'opencart', product: 'opencart' },
  'jQuery': { vendor: 'jquery', product: 'jquery' },
  'Bootstrap': { vendor: 'getbootstrap', product: 'bootstrap' },
  'Next.js': { vendor: 'vercel', product: 'next.js' },
  'React': { vendor: 'facebook', product: 'react' },
  'Angular': { vendor: 'google', product: 'angular' },
  'Vue.js': { vendor: 'vuejs', product: 'vue.js' },
  'Nuxt': { vendor: 'nuxt', product: 'nuxt' },
  'Laravel': { vendor: 'laravel', product: 'laravel' },
  'Django': { vendor: 'djangoproject', product: 'django' },
  'Express': { vendor: 'expressjs', product: 'express' },
  'Node.js': { vendor: 'nodejs', product: 'node.js' },
  'Grafana': { vendor: 'grafana', product: 'grafana' },
  'Kibana': { vendor: 'elastic', product: 'kibana' },
  'Jenkins': { vendor: 'jenkins', product: 'jenkins' },
  'GitLab': { vendor: 'gitlab', product: 'gitlab' },
  'phpMyAdmin': { vendor: 'phpmyadmin', product: 'phpmyadmin' },
  'Zabbix': { vendor: 'zabbix', product: 'zabbix' },
  'Drupal Commerce': { vendor: 'drupal', product: 'commerce' },
  'TYPO3': { vendor: 'typo3', product: 'typo3' },
  'Ghost': { vendor: 'ghost', product: 'ghost' },
  'Craft CMS': { vendor: 'craftcms', product: 'craft_cms' },
  'Elasticsearch': { vendor: 'elastic', product: 'elasticsearch' },
  'Jira': { vendor: 'atlassian', product: 'jira' },
  'Keycloak': { vendor: 'redhat', product: 'keycloak' },
  'Spring Boot': { vendor: 'vmware', product: 'spring_boot' },
  'ASP.NET': { vendor: 'microsoft', product: 'asp.net' },
  'Varnish': { vendor: 'varnish-cache', product: 'varnish' },
  'Traefik': { vendor: 'traefik', product: 'traefik' },
  'Caddy': { vendor: 'caddyserver', product: 'caddy' },
};

export type CveMatchKind = 'version' | 'product';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface CveMatch {
  id: string;
  summary: string;
  cvss: number | null;
  severity: Severity;
  published: string | null;
  matched: CveMatchKind;
  note: string;
  url: string;
}

export interface TechCveResult {
  technology: string;
  version: string | null;
  cpe: string | null;
  status: 'ok' | 'unmapped' | 'empty' | 'error';
  matches: CveMatch[];
  highestCvss: number | null;
  error?: string;
}

export interface CveReport {
  technologies: TechCveResult[];
  total: number;
  confirmed: number;
  highestCvss: number | null;
  riskLevel: Severity;
  notes: string[];
  elapsedMs: number;
}

interface CirclCve {
  id?: string;
  summary?: string;
  cvss?: number | null;
  Published?: string;
  Modified?: string;
  vulnerable_configuration?: string[];
  references?: string[];
}

export function severityFromCvss(score: number | null | undefined): Severity {
  if (typeof score !== 'number' || !Number.isFinite(score)) return 'UNKNOWN';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

/**
 * Does a CPE string refer to the observed version?
 *
 * CPE 2.3 puts the version in the sixth component. Match against the detected
 * version as a prefix, so `6.4` accepts `6.4.3` but not `6.40` or `7.0`.
 */
export function cpeMatchesVersion(cpe: string, product: string, version: string | null): boolean {
  if (!cpe.toLowerCase().includes(`:${product.toLowerCase()}:`)) return false;
  if (!version) return false;
  const parts = cpe.split(':');
  const cpeVersion = parts[5] || '';
  if (cpeVersion === '*' || cpeVersion === '-') return false;
  const normalised = cpeVersion.replace(/\\/g, '');
  return normalised === version || normalised.startsWith(`${version}.`) || version.startsWith(`${normalised}.`);
}

/**
 * Query CIRCL for every mapped technology.
 *
 * Products with no mapping are reported as `unmapped` rather than silently
 * omitted — an empty CVE list next to “React” would read as “React is safe”,
 * which is not what this data says.
 */
export async function findTechCves(
  technologies: Technology[],
  opts: { timeoutMs?: number; perTech?: number; concurrency?: number } = {},
): Promise<CveReport> {
  const started = Date.now();
  const { timeoutMs = 12_000, perTech = 40, concurrency = 3 } = opts;

  const results = await mapLimit(technologies, concurrency, async (tech): Promise<TechCveResult> => {
    const mapping = TECH_CPE[tech.name];
    if (!mapping) {
      return {
        technology: tech.name,
        version: tech.version || null,
        cpe: null,
        status: 'unmapped',
        matches: [],
        highestCvss: null,
      };
    }

    const cpe = `cpe:2.3:a:${mapping.vendor}:${mapping.product}`;
    try {
      const rows = await httpJson<CirclCve[]>(
        `https://cve.circl.lu/api/search/${encodeURIComponent(mapping.vendor)}/${encodeURIComponent(mapping.product)}`,
        { timeoutMs, headers: { Accept: 'application/json' } },
      );
      if (!Array.isArray(rows) || rows.length === 0) {
        return { technology: tech.name, version: tech.version || null, cpe, status: 'empty', matches: [], highestCvss: null };
      }

      const matches: CveMatch[] = rows.slice(0, 400).map(row => {
        const cves = Array.isArray(row.vulnerable_configuration) ? row.vulnerable_configuration : [];
        const confirmed = tech.version ? cves.some(c => cpeMatchesVersion(c, mapping.product.replace(/\\/g, ''), tech.version!)) : false;
        const severity = severityFromCvss(row.cvss);
        return {
          id: row.id || 'UNKNOWN',
          summary: (row.summary || '').replace(/\s+/g, ' ').slice(0, 400),
          cvss: typeof row.cvss === 'number' ? row.cvss : null,
          severity,
          published: row.Published || null,
          matched: confirmed ? 'version' : 'product',
          note: confirmed
            ? `Affected CPE includes version ${tech.version}.`
            : tech.version
              ? `Product-level match; version ${tech.version} could not be confirmed from the published CPE list.`
              : 'No version was detected, so this is a product-level match only.',
          url: `https://nvd.nist.gov/vuln/detail/${row.id || ''}`,
        };
      });

      matches.sort((a, b) => {
        if (a.matched !== b.matched) return a.matched === 'version' ? -1 : 1;
        return (b.cvss ?? 0) - (a.cvss ?? 0);
      });
      const trimmed = matches.slice(0, perTech);

      return {
        technology: tech.name,
        version: tech.version || null,
        cpe,
        status: trimmed.length ? 'ok' : 'empty',
        matches: trimmed,
        highestCvss: trimmed.reduce<number | null>((max, m) => (m.cvss !== null && (max === null || m.cvss > max) ? m.cvss : max), null),
      };
    } catch (e) {
      return {
        technology: tech.name,
        version: tech.version || null,
        cpe,
        status: 'error',
        matches: [],
        highestCvss: null,
        error: e instanceof Error ? e.message : 'CVE lookup failed',
      };
    }
  });

  const allMatches = results.flatMap(r => r.matches);
  const confirmed = allMatches.filter(m => m.matched === 'version').length;
  const highestCvss = results.reduce<number | null>(
    (max, r) => (r.highestCvss !== null && (max === null || r.highestCvss > max) ? r.highestCvss : max),
    null,
  );

  const notes = [
    'CVE correlation uses the version the site volunteered. Banners and generator tags are frequently stale or removed, so a version match can be wrong in either direction.',
    'A product-level match means a CVE exists for the product, not that this deployment runs the affected version.',
    'CIRCL aggregates NVD data; check the NVD entry before acting on a critical score.',
  ];
  if (results.some(r => r.status === 'unmapped')) {
    notes.push(`${results.filter(r => r.status === 'unmapped').length} detected product(s) have no CPE mapping and were not looked up.`);
  }
  if (results.some(r => r.status === 'error')) {
    notes.push('One or more CVE queries failed; the result is partial.');
  }

  return {
    technologies: results,
    total: allMatches.length,
    confirmed,
    highestCvss,
    riskLevel: severityFromCvss(highestCvss),
    notes,
    elapsedMs: Date.now() - started,
  };
}
