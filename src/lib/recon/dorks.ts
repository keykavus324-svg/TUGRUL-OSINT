/**
 * TUĞRUL RECON+ — dork builder (pagodo / OSINT-Framework catalogues).
 *
 * This generates *queries*, it does not scrape search engines. There is no
 * headless browser here and no attempt to defeat a captcha: the analyst gets
 * a prioritised list, clicks a link, and reads the results in a real browser
 * under their own account — which also keeps the app on the right side of
 * every engine's terms.
 *
 * Category list follows the public pagodo dork set (GPL-3.0, technique only)
 * and the OSINT Framework tree (MIT).
 */

export type DorkCategory =
  | 'panels'
  | 'exposed'
  | 'secrets'
  | 'directories'
  | 'documents'
  | 'cameras'
  | 'databases'
  | 'errors'
  | 'infrastructure'
  | 'code'
  | 'cloud';

export type DorkRisk = 'info' | 'medium' | 'high';

export interface DorkTemplate {
  category: DorkCategory;
  title: string;
  /** `{d}` is replaced with the target domain, `{name}` with its first label. */
  query: string;
  risk: DorkRisk;
  why: string;
}

export interface Dork extends DorkTemplate {
  target: string;
  resolved: string;
  links: Record<DorkEngine, string>;
}

export type DorkEngine = 'google' | 'bing' | 'duckduckgo' | 'yandex';

export const DORK_ENGINES: Array<{ id: DorkEngine; label: string }> = [
  { id: 'google', label: 'Google' },
  { id: 'bing', label: 'Bing' },
  { id: 'duckduckgo', label: 'DuckDuckGo' },
  { id: 'yandex', label: 'Yandex' },
];

/**
 * The catalogue.
 *
 * Deliberately excludes the classic “inurl:admin intext:password” style
 * strings that only produce noise — every entry here is something an analyst
 * can act on when it matches.
 */
export const DORK_TEMPLATES: DorkTemplate[] = [
  /* ── login panels ── */
  { category: 'panels', title: 'Login panels', query: 'site:{d} inurl:(login|signin|auth|admin|portal)', risk: 'info', why: 'Every entry point an attacker or a journalist would try first.' },
  { category: 'panels', title: 'Admin interfaces', query: 'site:{d} intitle:"admin" OR intitle:"dashboard" OR intitle:"control panel"', risk: 'info', why: 'Management surfaces that should not be indexed.' },
  { category: 'panels', title: 'phpMyAdmin', query: 'site:{d} intitle:phpMyAdmin', risk: 'high', why: 'A web database console on the public internet is direct data access if it answers.' },
  { category: 'panels', title: 'VPN / firewall portals', query: 'site:{d} inurl:(vpn|remote|ssl-vpn|webvpn|global-protect)', risk: 'info', why: 'Remote-access appliances carry the vulnerabilities that matter most.' },

  /* ── exposed files ── */
  { category: 'exposed', title: 'Environment files', query: 'site:{d} ext:env OR intitle:"index of" ".env"', risk: 'high', why: 'A served .env usually contains database and API credentials in clear text.' },
  { category: 'exposed', title: 'Git metadata', query: 'site:{d} inurl:.git OR ext:git', risk: 'high', why: 'An exposed .git directory allows full source-code reconstruction.' },
  { category: 'exposed', title: 'Backup archives', query: 'site:{d} ext:(bak|backup|old|orig|sql|tar|tgz|zip|7z)', risk: 'high', why: 'Backups are often unauthenticated and contain the live database.' },
  { category: 'exposed', title: 'Config files', query: 'site:{d} ext:(conf|config|cfg|ini|yaml|yml|toml)', risk: 'high', why: 'Plain-text configuration frequently carries credentials and internal hostnames.' },
  { category: 'exposed', title: 'Key material', query: 'site:{d} ext:(pem|key|pfx|p12|jks|ppk)', risk: 'high', why: 'Private keys published by mistake cannot be revoked retroactively.' },
  { category: 'exposed', title: 'Log files', query: 'site:{d} ext:(log|txt) inurl:(log|logs|debug)', risk: 'medium', why: 'Logs leak paths, usernames, tokens and internal IPs.' },

  /* ── secrets in text ── */
  { category: 'secrets', title: 'Password mentions', query: 'site:{d} intext:("password" OR "passwd" OR "pwd") filetype:txt', risk: 'high', why: 'Credentials written into notes or readme files.' },
  { category: 'secrets', title: 'API keys', query: 'site:{d} intext:("api_key" OR "apikey" OR "api-key" OR "secret_key")', risk: 'high', why: 'Keys committed in documentation or sample code.' },
  { category: 'secrets', title: 'Private tokens', query: 'site:{d} intext:("BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY")', risk: 'high', why: 'A published private key is a full impersonation risk.' },
  { category: 'secrets', title: 'Connection strings', query: 'site:{d} intext:("mongodb://" OR "postgres://" OR "mysql://" OR "redis://")', risk: 'high', why: 'Connection strings often embed user and password.' },

  /* ── directory listing / debug ── */
  { category: 'directories', title: 'Open directory indexes', query: 'site:{d} intitle:"index of /"', risk: 'medium', why: 'Directory listing turns a single misconfiguration into a file dump.' },
  { category: 'directories', title: 'Directory listing — uploads', query: 'site:{d} intitle:"index of" inurl:(uploads|files|backup|backups|tmp)', risk: 'high', why: 'User uploads served with listing enabled are a classic data leak.' },
  { category: 'errors', title: 'Stack traces', query: 'site:{d} intext:("Fatal error" OR "Warning:" OR "stack trace" OR "Traceback")', risk: 'medium', why: 'Error pages reveal framework, versions, absolute paths and sometimes credentials.' },
  { category: 'errors', title: 'Debug endpoints', query: 'site:{d} inurl:(debug|test|dev|staging|actuator|phpinfo)', risk: 'medium', why: 'Development surfaces left enabled in production.' },

  /* ── documents ── */
  { category: 'documents', title: 'PDF documents', query: 'site:{d} ext:pdf', risk: 'info', why: 'Reports and contracts carry names, emails and internal metadata.' },
  { category: 'documents', title: 'Office documents', query: 'site:{d} ext:(doc|docx|xls|xlsx|ppt|pptx)', risk: 'info', why: 'Author names and tracked changes survive in document metadata.' },
  { category: 'documents', title: 'Employee contact lists', query: 'site:{d} intext:("employee" OR "staff") ext:(xls|xlsx|csv|pdf)', risk: 'medium', why: 'Org charts and contact sheets are the starting point for social engineering.' },
  { category: 'documents', title: 'Job postings', query: 'site:{d} intext:("we are hiring" OR "careers" OR "job description")', risk: 'info', why: 'Job ads disclose the internal stack and team structure.' },

  /* ── cameras / IoT ── */
  { category: 'cameras', title: 'Camera viewers', query: 'site:{d} inurl:(viewer|view|live|stream|webcam|cam)', risk: 'medium', why: 'Publicly reachable camera interfaces with default credentials are common.' },
  { category: 'cameras', title: 'Camera index pages', query: 'site:{d} intitle:("Live View" OR "Network Camera" OR "IP Camera")', risk: 'medium', why: 'Vendor index pages identify model and firmware generation.' },

  /* ── databases / storage ── */
  { category: 'databases', title: 'Database dumps', query: 'site:{d} ext:sql intext:("INSERT INTO" OR "CREATE TABLE")', risk: 'high', why: 'A reachable SQL dump is usually the whole dataset, PII included.' },
  { category: 'databases', title: 'Elasticsearch', query: 'site:{d} intext:("cluster_name" OR "_cat/indices" OR "You Know, for Search")', risk: 'high', why: 'An unauthenticated Elasticsearch node answers with every document it holds.' },
  { category: 'databases', title: 'Kibana / Grafana', query: 'site:{d} inurl:(kibana|grafana|_plugin/kibana)', risk: 'medium', why: 'Dashboards front internal telemetry and sometimes the data store itself.' },

  /* ── cloud ── */
  { category: 'cloud', title: 'Cloud storage buckets', query: 'site:(s3.amazonaws.com|blob.core.windows.net|storage.googleapis.com) "{name}"', risk: 'medium', why: 'Buckets named after the organisation are often public by default.' },
  { category: 'cloud', title: 'Bucket listing pages', query: '"{d}" inurl:(s3.amazonaws.com|storage.googleapis.com) intitle:"index of"', risk: 'medium', why: 'Indexed bucket roots are readable without credentials.' },

  /* ── code / social ── */
  { category: 'code', title: 'Code mentioning the domain', query: '"{d}" site:github.com OR site:gitlab.com OR site:pastebin.com', risk: 'info', why: 'Code and pastes frequently contain internal hostnames, keys and configs.' },
  { category: 'code', title: 'Subdomain references', query: 'site:{d} -inurl:www intext:"{d}"', risk: 'info', why: 'Pages that mention a sibling host often reveal internal naming.' },
  { category: 'code', title: 'Email addresses', query: 'site:{d} intext:("@{d}" OR "mailto")', risk: 'info', why: 'Harvestable addresses for phishing simulation and verification.' },
  { category: 'infrastructure', title: 'Subdomains in certificates', query: 'site:{d} inurl:(ssl|cert|tls)', risk: 'info', why: 'Certificate pages and docs often list hosts the main site does not link.' },
  { category: 'infrastructure', title: 'Staging hosts', query: 'site:*.{d} inurl:(staging|stage|dev|test|uat|preprod|beta)', risk: 'medium', why: 'Non-production hosts carry weaker authentication and no monitoring.' },
  { category: 'infrastructure', title: 'Exposed CI/CD', query: 'site:{d} inurl:(jenkins|gitlab|teamcity|hudson|bamboo|drone)', risk: 'medium', why: 'Build servers hold deployment credentials.' },
];

const ENGINE_BASE: Record<DorkEngine, (q: string) => string> = {
  google: q => `https://www.google.com/search?q=${encodeURIComponent(q)}`,
  bing: q => `https://www.bing.com/search?q=${encodeURIComponent(q)}`,
  duckduckgo: q => `https://html.duckduckgo.com/html/?q=${encodeURIComponent(q)}`,
  yandex: q => `https://yandex.com/search/?text=${encodeURIComponent(q)}`,
};

/** Engine result page for a dork, ready to open in a new tab. */
export function dorkUrl(engine: DorkEngine, query: string): string {
  return ENGINE_BASE[engine](query);
}

/**
 * Fill a template for a target. `{d}` is the domain; `{name}` is its leftmost
 * label (for “bucket named after the company” style queries).
 */
export function resolveDorkQuery(template: DorkTemplate, target: string): string {
  const domain = target.trim().toLowerCase();
  const name = domain.split('.')[0] || domain;
  return template.query.replace(/\{d\}/g, domain).replace(/\{name\}/g, name);
}

export interface BuildDorkOptions {
  categories?: DorkCategory[];
  maxRisk?: DorkRisk;
}

const RISK_RANK: Record<DorkRisk, number> = { info: 0, medium: 1, high: 2 };

/**
 * Build the dork list. `maxRisk` filters *down* (an analyst who only wants
 * information-gathering can drop the credential queries), it never hides a
 * high-risk query behind a higher setting.
 */
export function buildDorks(target: string, opts: BuildDorkOptions = {}): Dork[] {
  const domain = target.trim().toLowerCase();
  const allowedRisk = opts.maxRisk ? RISK_RANK[opts.maxRisk] : RISK_RANK.high;
  const categories = opts.categories?.length ? new Set(opts.categories) : null;

  return DORK_TEMPLATES.filter(t => RISK_RANK[t.risk] <= allowedRisk)
    .filter(t => !categories || categories.has(t.category))
    .map(t => {
      const resolved = resolveDorkQuery(t, domain);
      return {
        ...t,
        target: domain,
        resolved,
        links: {
          google: dorkUrl('google', resolved),
          bing: dorkUrl('bing', resolved),
          duckduckgo: dorkUrl('duckduckgo', resolved),
          yandex: dorkUrl('yandex', resolved),
        },
      };
    });
}

/** Category counts for the UI’s filter row. */
export function summariseDorks(dorks: Dork[]): Array<{ category: DorkCategory; count: number; high: number }> {
  const map = new Map<DorkCategory, { category: DorkCategory; count: number; high: number }>();
  for (const d of dorks) {
    const entry = map.get(d.category) || { category: d.category, count: 0, high: 0 };
    entry.count += 1;
    if (d.risk === 'high') entry.high += 1;
    map.set(d.category, entry);
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count);
}
