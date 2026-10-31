/**
 * TUĞRUL RECON+ — web stack fingerprint and security-header audit.
 *
 * Replaces the external `SCANNER_URL` service the toolkit used to call for
 * HEADERS, TECH DETECT and part of SSL. Everything here runs in-process:
 *
 *   • a hand-written signature set (no GPL fingerprint database is bundled;
 *     see INTEGRATED_PROJECTS in ./sources),
 *   • a header audit scored over the controls that actually change an
 *     attacker’s options,
 *   • cookie-flag inspection,
 *   • a Shodan-compatible favicon hash for infrastructure pivoting.
 *
 * Signatures are intentionally specific. A generic `/react/` match turns
 * every third site into “React”; a `data-reactroot` attribute or a
 * `/_next/static/` asset path does not.
 */

import { BROWSER_UA, httpRequest } from './sources';

export type TechCategory =
  | 'server'
  | 'cdn'
  | 'language'
  | 'framework'
  | 'cms'
  | 'ecommerce'
  | 'javascript'
  | 'analytics'
  | 'security'
  | 'appliance'
  | 'font'
  | 'map'
  | 'media';

export interface Technology {
  name: string;
  categories: TechCategory[];
  version?: string;
  confidence: 'high' | 'medium' | 'low';
  /** Human-readable proof lines, e.g. `header server: nginx/1.24.0`. */
  evidence: string[];
}

interface Signature {
  name: string;
  categories: TechCategory[];
  /** Header name (lowercase) and value pattern. */
  headers?: Array<[string, RegExp]>;
  /** Cookie-name pattern. */
  cookie?: RegExp;
  /** Body patterns. */
  html?: RegExp[];
  /** Applied to the matched string to pull out a version. */
  version?: RegExp;
  confidence?: Technology['confidence'];
  /** Technologies this one implies (e.g. WooCommerce → WordPress). */
  implies?: string[];
}

/** `<meta name="generator" content="WordPress 6.4.3">` and friends. */
const GENERATOR = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i;

export const SIGNATURES: Signature[] = [
  /* ── servers and edges ── */
  { name: 'Nginx', categories: ['server'], headers: [['server', /\bnginx(\/[\d.]+)?/i]], version: /nginx\/([\d.]+)/i, confidence: 'high' },
  { name: 'Apache HTTP Server', categories: ['server'], headers: [['server', /\bapache(\/[\d.]+)?/i]], version: /apache\/([\d.]+)/i, confidence: 'high' },
  { name: 'Microsoft IIS', categories: ['server'], headers: [['server', /\b(?:microsoft-)?iis(\/[\d.]+)?/i]], version: /iis\/([\d.]+)/i, confidence: 'high' },
  { name: 'LiteSpeed', categories: ['server'], headers: [['server', /\blitespeed\b/i]], confidence: 'high' },
  { name: 'Caddy', categories: ['server'], headers: [['server', /\bcaddy\b/i]], confidence: 'high' },
  { name: 'OpenResty', categories: ['server'], headers: [['server', /\bopenresty\b/i]], confidence: 'high' },
  { name: 'Cloudflare', categories: ['cdn'], headers: [['cf-ray', /./], ['server', /\bcloudflare\b/i]], confidence: 'high' },
  { name: 'Akamai', categories: ['cdn'], headers: [['server', /\bakamaighost\b/i], ['x-akamai-transformed', /./]], confidence: 'high' },
  { name: 'Fastly', categories: ['cdn'], headers: [['x-served-by', /cache-/i], ['fastly-debug-digest', /./]], confidence: 'high' },
  { name: 'Amazon CloudFront', categories: ['cdn'], headers: [['x-amz-cf-id', /./], ['via', /cloudfront/i]], confidence: 'high' },
  { name: 'Varnish', categories: ['cdn'], headers: [['x-varnish', /./], ['via', /\bvarnish\b/i]], confidence: 'high' },
  { name: 'Envoy', categories: ['cdn'], headers: [['server', /\benvoy\b/i]], confidence: 'high' },
  { name: 'Traefik', categories: ['cdn'], headers: [['server', /\btraefik\b/i]], confidence: 'high' },
  { name: 'Vercel', categories: ['cdn'], headers: [['x-vercel-id', /./], ['server', /\bvercel\b/i]], confidence: 'high' },
  { name: 'Netlify', categories: ['cdn'], headers: [['x-nf-request-id', /./]], confidence: 'high' },
  { name: 'GitHub Pages', categories: ['cdn'], headers: [['server', /github\.com/i], ['x-github-request-id', /./]], confidence: 'high' },
  { name: 'Sucuri', categories: ['security'], headers: [['x-sucuri-id', /./], ['server', /sucuri/i]], confidence: 'high' },
  { name: 'Imperva', categories: ['security'], headers: [['x-iinfo', /./], ['server', /incapsula/i]], confidence: 'high' },
  { name: 'F5 BIG-IP', categories: ['appliance'], cookie: /^(BIGipServer|TS[a-f0-9]{8})$/i, confidence: 'medium' },

  /* ── languages / app servers ── */
  { name: 'PHP', categories: ['language'], headers: [['x-powered-by', /\bphp\/?([\d.]+)?/i]], version: /php\/?([\d.]+)/i, confidence: 'high', html: [/\.php(?:["'?]|$)/i] },
  { name: 'ASP.NET', categories: ['framework'], headers: [['x-aspnet-version', /([\d.]+)/], ['x-powered-by', /\basp\.?net\b/i]], version: /([\d.]+)/, confidence: 'high' },
  { name: 'Express', categories: ['framework'], headers: [['x-powered-by', /^express$/i]], confidence: 'high' },
  { name: 'Node.js', categories: ['language'], headers: [['x-powered-by', /node/i]], confidence: 'medium' },
  { name: 'Laravel', categories: ['framework'], cookie: /^laravel_session$/i, confidence: 'high' },
  { name: 'Django', categories: ['framework'], cookie: /^csrftoken$/i, html: [/csrfmiddlewaretoken/i], confidence: 'medium' },
  { name: 'Ruby on Rails', categories: ['framework'], cookie: /^_rails|_session_id$/i, headers: [['x-powered-by', /phusion|passenger/i]], confidence: 'low' },
  { name: 'Spring Boot', categories: ['framework'], headers: [['x-application-context', /./]], html: [/Whitelabel Error Page/i], confidence: 'high' },
  { name: 'Keycloak', categories: ['security'], html: [/\/realms\/[^/"']+\/protocol\/openid-connect/i, /keycloak/i], confidence: 'medium' },
  { name: 'Auth0', categories: ['security'], html: [/cdn\.auth0\.com|auth0\.com\/authorize/i], confidence: 'high' },

  /* ── CMS ── */
  { name: 'WordPress', categories: ['cms'], html: [/\/wp-(?:includes|content)\/[^"'\s>]*[?&]ver=([\d.]+)/i, /\/wp-content\//i, /\/wp-includes\//i, /wp-json/i], version: /[?&]ver=([\d.]+)/i, confidence: 'high', implies: ['PHP'] },
  { name: 'Drupal', categories: ['cms'], html: [/sites\/default\/files|drupal-settings-json|drupal\.js/i], headers: [['x-generator', /drupal/i]], version: /Drupal (\d+)/i, confidence: 'high' },
  { name: 'Joomla', categories: ['cms'], html: [/\/media\/jui\/|joomla/i], headers: [['x-content-encoded-by', /joomla/i]], confidence: 'medium' },
  { name: 'TYPO3', categories: ['cms'], html: [/typo3temp|typo3conf/i], confidence: 'high' },
  { name: 'Craft CMS', categories: ['cms'], cookie: /^CraftSessionId$/i, confidence: 'medium' },
  { name: 'Ghost', categories: ['cms'], html: [/ghost-url|ghost\/(?:v)?([\d.]+)/i], version: /ghost\/([\d.]+)/i, confidence: 'medium' },
  { name: 'Webflow', categories: ['cms'], html: [/webflow\.(?:js|css)|data-wf-page/i], confidence: 'high' },
  { name: 'Wix', categories: ['cms'], html: [/static\.parastorage\.com|wix\.com\/static/i], confidence: 'high' },
  { name: 'Squarespace', categories: ['cms'], html: [/static1\.squarespace\.com|squarespace-cdn\.com/i], confidence: 'high' },
  { name: 'Hugo', categories: ['cms'], html: [/<meta[^>]+name=["']generator["'][^>]+content=["']Hugo[^"']*["']/i], confidence: 'high' },
  { name: 'Jekyll', categories: ['cms'], html: [/<meta[^>]+name=["']generator["'][^>]+content=["']Jekyll[^"']*["']/i], confidence: 'high' },

  /* ── e-commerce ── */
  { name: 'Shopify', categories: ['ecommerce'], headers: [['x-shopid', /./], ['x-shopify-stage', /./]], html: [/cdn\.shopify\.com|Shopify\.theme/i], confidence: 'high' },
  { name: 'WooCommerce', categories: ['ecommerce'], html: [/woocommerce(?:-|\.js|\/)/i], confidence: 'high', implies: ['WordPress'] },
  { name: 'Magento', categories: ['ecommerce'], cookie: /^(frontend|adminhtml)_|^mage-cache/i, html: [/Magento_|mage\/cookies/i], confidence: 'high', implies: ['PHP'] },
  { name: 'PrestaShop', categories: ['ecommerce'], html: [/prestashop|var prestashop/i], confidence: 'high' },
  { name: 'OpenCart', categories: ['ecommerce'], html: [/catalog\/view\/theme|index\.php\?route=/i], confidence: 'low' },

  /* ── JavaScript frameworks ── */
  { name: 'Next.js', categories: ['framework', 'javascript'], html: [/\/_next\/static\//], headers: [['x-nextjs-cache', /./], ['x-powered-by', /next\.js/i]], confidence: 'high', implies: ['React'] },
  { name: 'React', categories: ['javascript'], html: [/data-reactroot|data-reactid|\/react(?:-dom)?[.@-][\d.]*|__NEXT_DATA__|_reactListening/i], confidence: 'medium' },
  { name: 'Vue.js', categories: ['javascript'], html: [/data-v-[a-f0-9]{8}|__VUE__|vue(?:\.min)?\.js/i], confidence: 'medium' },
  { name: 'Nuxt', categories: ['framework', 'javascript'], html: [/__NUXT__|\/_nuxt\//], confidence: 'high', implies: ['Vue.js'] },
  { name: 'Angular', categories: ['javascript'], html: [/ng-version=["']([\d.]+)|ng-app|angular(?:\.min)?\.js/i], version: /ng-version=["']([\d.]+)/i, confidence: 'high' },
  { name: 'Svelte', categories: ['javascript'], html: [/svelte-[a-z0-9]{6}|__sveltekit_/i], confidence: 'medium' },
  { name: 'Astro', categories: ['framework'], html: [/astro-island|data-astro-/i], confidence: 'high' },
  { name: 'Remix', categories: ['framework'], html: [/__remixContext|remix-run/i], confidence: 'medium' },
  { name: 'jQuery', categories: ['javascript'], html: [/jquery(?:-|\.)([\d.]+)?(?:\.min)?\.js|jQuery v([\d.]+)/i], version: /jquery[-.]v?([\d.]+)(?:\.min)?\.js|jQuery v([\d.]+)/i, confidence: 'high' },
  { name: 'Bootstrap', categories: ['javascript'], html: [/bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)(?:\?v=([\d.]+))?/i], version: /bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)\?v=([\d.]+)/i, confidence: 'high' },
  { name: 'Tailwind CSS', categories: ['javascript'], html: [/tailwind(?:\.min)?\.css|--tw-/], confidence: 'medium' },
  { name: 'Alpine.js', categories: ['javascript'], html: [/alpinejs|x-data=/i], confidence: 'medium' },
  { name: 'HTMX', categories: ['javascript'], html: [/htmx(?:\.min)?\.js|hx-(?:get|post|trigger)=/i], confidence: 'high' },
  { name: 'Font Awesome', categories: ['font', 'javascript'], html: [/font-?awesome|fa-solid|fa-brands/i], confidence: 'medium' },
  { name: 'Google Fonts', categories: ['font'], html: [/fonts\.googleapis\.com|fonts\.gstatic\.com/i], confidence: 'high' },
  { name: 'Webpack', categories: ['javascript'], html: [/webpackJsonp|__webpack_require__/i], confidence: 'low' },
  { name: 'Vite', categories: ['javascript'], html: [/\/@vite\/client|\/assets\/index-[a-z0-9]{8}\.js/i], confidence: 'low' },

  /* ── analytics / marketing ── */
  { name: 'Google Analytics', categories: ['analytics'], html: [/googletagmanager\.com\/gtag\/js\?id=G-|google-analytics\.com\/analytics\.js|gtag\('config'/i], confidence: 'high' },
  { name: 'Google Tag Manager', categories: ['analytics'], html: [/googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]{4,}/], confidence: 'high' },
  { name: 'Matomo', categories: ['analytics'], html: [/matomo(?:\.js|\/matomo)|piwik/i], confidence: 'medium' },
  { name: 'Plausible', categories: ['analytics'], html: [/plausible\.io\/js/i], confidence: 'high' },
  { name: 'Hotjar', categories: ['analytics'], html: [/static\.hotjar\.com|hjSiteSettings/i], confidence: 'high' },
  { name: 'Facebook Pixel', categories: ['analytics'], html: [/connect\.facebook\.net\/[^"']*fbevents\.js|fbq\('init'/i], confidence: 'high' },
  { name: 'HubSpot', categories: ['analytics'], html: [/js\.hs-scripts\.com|hs-analytics|hubspot/i], confidence: 'medium' },
  { name: 'Intercom', categories: ['analytics'], html: [/widget\.intercom\.io|intercomSettings/i], confidence: 'high' },
  { name: 'Sentry', categories: ['analytics'], html: [/browser\.sentry-cdn\.com|Sentry\.init/i], confidence: 'high' },
  { name: 'New Relic', categories: ['analytics'], html: [/js-agent\.newrelic\.com|NREUM/i], confidence: 'high' },
  { name: 'Datadog RUM', categories: ['analytics'], html: [/datadoghq-browser-agent|DD_RUM/i], confidence: 'high' },

  /* ── maps / media ── */
  { name: 'Google Maps', categories: ['map'], html: [/maps\.googleapis\.com|maps\.google\.com\/maps/i], confidence: 'high' },
  { name: 'Mapbox', categories: ['map'], html: [/api\.mapbox\.com|mapbox-gl/i], confidence: 'high' },
  { name: 'MapLibre', categories: ['map'], html: [/maplibre-gl/i], confidence: 'high' },
  { name: 'Leaflet', categories: ['map'], html: [/leaflet(?:\.min)?\.(?:js|css)|L\.map\(/i], confidence: 'high' },
  { name: 'Video.js', categories: ['media'], html: [/video(?:-js)?(?:\.min)?\.js|video-js vjs/i], confidence: 'medium' },
  { name: 'hls.js', categories: ['media'], html: [/hls(?:\.min)?\.js|new Hls\(/i], confidence: 'medium' },

  /* ── appliances / dashboards ── */
  { name: 'Grafana', categories: ['appliance'], cookie: /^grafana_session/i, html: [/grafana/i], headers: [['x-frame-options', /deny/i]], confidence: 'medium' },
  { name: 'Kibana', categories: ['appliance'], headers: [['kbn-name', /./], ['kbn-version', /([\d.]+)/]], version: /([\d.]+)/, confidence: 'high' },
  { name: 'Jenkins', categories: ['appliance'], headers: [['x-jenkins', /([\d.]+)/]], version: /([\d.]+)/, confidence: 'high' },
  { name: 'GitLab', categories: ['appliance'], cookie: /^_gitlab_session$/i, headers: [['x-gitlab-meta', /./]], confidence: 'high' },
  { name: 'Jira', categories: ['appliance'], cookie: /^(JSESSIONID|atlassian.xsrf.token)$/i, html: [/atlassian|jira/i], confidence: 'low' },
  { name: 'Zabbix', categories: ['appliance'], cookie: /^zbx_session$/i, confidence: 'high' },
  { name: 'phpMyAdmin', categories: ['appliance'], cookie: /^pmaCookieVer$/i, html: [/phpmyadmin/i], confidence: 'medium' },
  { name: 'Swagger UI', categories: ['appliance'], html: [/swagger-ui|SwaggerUIBundle/i], confidence: 'high' },
  { name: 'Elasticsearch', categories: ['appliance'], html: [/"cluster_name"\s*:|"tagline"\s*:\s*"You Know, for Search"/i], confidence: 'high' },
  { name: 'reCAPTCHA', categories: ['security'], html: [/google\.com\/recaptcha|gstatic\.com\/recaptcha/i], confidence: 'high' },
  { name: 'hCaptcha', categories: ['security'], html: [/hcaptcha\.com\/1\/api\.js|h-captcha/i], confidence: 'high' },
  { name: 'Cloudflare Turnstile', categories: ['security'], html: [/challenges\.cloudflare\.com\/turnstile/i], confidence: 'high' },
];

export interface FingerprintInput {
  url: string;
  headers: Record<string, string>;
  body: string;
  /** Raw `Set-Cookie` values, in order. */
  cookieHeaders?: string[];
  status?: number;
  title?: string;
}

export interface HeaderBag {
  [name: string]: string;
}

/**
 * A signature's version regex may contain alternation, so the version is not
 * always in group 1 (`bootstrap...css` captures the asset type first). Take
 * the last non-empty group — that is the version in every pattern here.
 */
function capturedVersion(match: RegExpMatchArray | null): string | undefined {
  if (!match) return undefined;
  for (let i = match.length - 1; i >= 1; i--) {
    if (match[i]) return match[i];
  }
  return undefined;
}

/** `Headers` or a plain object → lowercase map, joining repeated headers. */
export function headerBag(headers: Headers | Record<string, string | string[]>): HeaderBag {
  const out: HeaderBag = {};
  if (typeof (headers as Headers).forEach === 'function' && !Array.isArray(headers)) {
    (headers as Headers).forEach((value, key) => {
      const k = key.toLowerCase();
      out[k] = out[k] ? `${out[k]}, ${value}` : value;
    });
    return out;
  }
  for (const [key, value] of Object.entries(headers as Record<string, string | string[]>)) {
    out[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return out;
}

/** Cookie names from raw Set-Cookie strings; the value is never needed. */
export function cookieNames(cookieHeaders: string[]): string[] {
  return cookieHeaders
    .map(c => c.split(';')[0].split('=')[0].trim())
    .filter(Boolean);
}

/**
 * Match the signature set against one response.
 *
 * Every match keeps its evidence so the analyst can judge it: “Nginx” from a
 * Server header is a fact, “React” from a bundled filename is an inference,
 * and the UI shows which is which.
 */
export function detectTechnologies(input: FingerprintInput): Technology[] {
  const headers = input.headers;
  const body = input.body || '';
  const cookies = cookieNames(input.cookieHeaders || []);
  const generator = body.match(GENERATOR)?.[1] || null;
  const found = new Map<string, Technology>();

  const add = (name: string, categories: TechCategory[], confidence: Technology['confidence'], evidence: string, version?: string) => {
    const existing = found.get(name);
    if (existing) {
      if (!existing.evidence.includes(evidence)) existing.evidence.push(evidence);
      if (version && !existing.version) existing.version = version;
      if (confidence === 'high') existing.confidence = 'high';
      return;
    }
    found.set(name, { name, categories, confidence, evidence: [evidence], ...(version ? { version } : {}) });
  };

  for (const sig of SIGNATURES) {
    let matched = false;
    let evidence = '';
    let version: string | undefined;
    const confidence = sig.confidence || 'medium';

    const declared = sig.headers || [];
    for (const [header, pattern] of declared) {
      const value = headers[header];
      if (!value) continue;
      const m = value.match(pattern);
      if (!m) continue;
      matched = true;
      evidence = `header ${header}: ${value.slice(0, 120)}`;
      if (sig.version) {
        // Kibana matches on `kbn-name` but carries its version in
        // `kbn-version`; check every declared header, not just the one that
        // proved the product is present.
        for (const [candidate] of declared) {
          const other = headers[candidate];
          if (!other) continue;
          const found = capturedVersion(other.match(sig.version));
          if (found) { version = found; break; }
        }
        if (!version) version = capturedVersion(value.match(sig.version));
      }
      break;
    }

    if (!matched && sig.cookie) {
      const hit = cookies.find(c => sig.cookie!.test(c));
      if (hit) {
        matched = true;
        evidence = `cookie ${hit}`;
      }
    }

    if (!matched) {
      for (const pattern of sig.html || []) {
        const m = body.match(pattern);
        if (!m) continue;
        matched = true;
        evidence = `html ${m[0].slice(0, 80).replace(/\s+/g, ' ')}`;
        if (sig.version) version = capturedVersion(m[0].match(sig.version));
        break;
      }
    }

    if (!matched) continue;
    add(sig.name, sig.categories, confidence, evidence, version);
  }

  // A generator tag is first-party evidence and beats heuristic matching.
  if (generator) {
    const name = generator.split(/[\s/]/)[0];
    const version = generator.match(/\b(\d+(?:\.\d+)+)/)?.[1];
    const match = Array.from(found.values()).find(t => t.name.toLowerCase() === name.toLowerCase());
    if (match) {
      add(match.name, match.categories, 'high', `meta generator: ${generator}`, version);
    } else if (name.length > 1) {
      add(name, ['cms'], 'high', `meta generator: ${generator}`, version);
    }
  }

  // Expand `implies`, keeping the child’s own evidence.
  for (const tech of Array.from(found.values())) {
    const sig = SIGNATURES.find(s => s.name === tech.name);
    for (const implied of sig?.implies || []) {
      const known = SIGNATURES.find(s => s.name === implied);
      add(implied, known?.categories || ['framework'], 'medium', `implied by ${tech.name}`);
    }
  }

  return Array.from(found.values()).sort((a, b) => {
    const rank = (t: Technology) => (t.confidence === 'high' ? 0 : t.confidence === 'medium' ? 1 : 2);
    return rank(a) - rank(b) || a.name.localeCompare(b.name);
  });
}

/* ── security headers ───────────────────────────────────────── */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface HeaderFinding {
  header: string;
  /** `missing`, `weak` or `ok`. */
  state: 'missing' | 'weak' | 'ok' | 'obsolete';
  severity: Severity;
  value?: string;
  detail: string;
}

export interface HeaderAudit {
  findings: HeaderFinding[];
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  missing: string[];
  present: number;
  checked: number;
  /** Version strings the server volunteered — an attacker’s first search. */
  disclosures: string[];
}

interface HeaderRule {
  header: string;
  severity: Severity;
  weight: number;
  /** Absence is only a problem when this is true; otherwise it is informational. */
  required: boolean;
  check?: (value: string) => { state: HeaderFinding['state']; detail: string; penalty?: number };
  advice: string;
}

/**
 * What is scored, and why.
 *
 * HSTS, CSP, nosniff and frame-ancestors are scored: without them the browser
 * will happily do the wrong thing. COOP/CORP/Permissions-Policy matter but
 * have narrower blast radii, so they cost fewer points. Server and
 * X-Powered-By are not vulnerabilities at all — they are *disclosures*, and
 * are reported as such rather than scored as missing controls.
 */
const HEADER_RULES: HeaderRule[] = [
  {
    header: 'strict-transport-security',
    severity: 'high',
    weight: 20,
    required: true,
    check: value => {
      const maxAge = Number(value.match(/max-age=(\d+)/i)?.[1] || 0);
      if (maxAge === 0) return { state: 'weak', detail: 'HSTS is present but max-age=0 disables it.', penalty: 12 };
      if (maxAge < 15_552_000) return { state: 'weak', detail: `max-age is ${maxAge}s; below the 180-day recommendation.`, penalty: 6 };
      return { state: 'ok', detail: `HSTS enforced for ${maxAge}s.` };
    },
    advice: 'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.',
  },
  {
    header: 'content-security-policy',
    severity: 'high',
    weight: 20,
    required: true,
    check: value => {
      if (/unsafe-inline/i.test(value) && /script-src[^;]*unsafe-inline/i.test(value)) {
        return { state: 'weak', detail: 'CSP allows inline script, which removes most of the XSS protection.', penalty: 12 };
      }
      if (/\*/i.test(value.split(';').find(p => /script-src/i.test(p)) || '')) {
        return { state: 'weak', detail: 'script-src uses a wildcard.', penalty: 10 };
      }
      return { state: 'ok', detail: 'Content-Security-Policy is present and not obviously permissive.' };
    },
    advice: 'Define a CSP with nonce/hash-based script-src and no wildcards.',
  },
  {
    header: 'x-content-type-options',
    severity: 'medium',
    weight: 12,
    required: true,
    check: value =>
      /nosniff/i.test(value)
        ? { state: 'ok', detail: 'MIME sniffing disabled.' }
        : { state: 'weak', detail: `Expected \`nosniff\`, saw \`${value}\`.`, penalty: 8 },
    advice: 'Send `X-Content-Type-Options: nosniff`.',
  },
  {
    header: 'x-frame-options',
    severity: 'medium',
    weight: 10,
    required: false,
    check: value =>
      /^(deny|sameorigin)$/i.test(value.trim())
        ? { state: 'ok', detail: 'Clickjacking framing restricted.' }
        : { state: 'weak', detail: `Unexpected value \`${value}\`.`, penalty: 6 },
    advice: 'Send `X-Frame-Options: DENY` or use CSP frame-ancestors.',
  },
  {
    header: 'referrer-policy',
    severity: 'low',
    weight: 6,
    required: false,
    check: value =>
      /no-referrer|same-origin|strict-origin/i.test(value)
        ? { state: 'ok', detail: 'Referrer limited to origin.' }
        : { state: 'weak', detail: `\`${value}\` forwards full URLs to third parties.`, penalty: 4 },
    advice: 'Send `Referrer-Policy: strict-origin-when-cross-origin`.',
  },
  {
    header: 'permissions-policy',
    severity: 'low',
    weight: 5,
    required: false,
    advice: 'Deny unused browser features: camera, microphone, geolocation, payment.',
  },
  {
    header: 'cross-origin-opener-policy',
    severity: 'low',
    weight: 4,
    required: false,
    check: value =>
      /same-origin/i.test(value)
        ? { state: 'ok', detail: 'Browsing context isolated.' }
        : { state: 'weak', detail: `Value \`${value}\` does not isolate the context.`, penalty: 2 },
    advice: 'Send `Cross-Origin-Opener-Policy: same-origin` where isolation is possible.',
  },
  {
    header: 'cross-origin-resource-policy',
    severity: 'info',
    weight: 3,
    required: false,
    advice: 'Send `Cross-Origin-Resource-Policy: same-origin` for private resources.',
  },
];

/** Score the audited headers. 100 = every scored control present and sane. */
export function auditSecurityHeaders(headers: HeaderBag): HeaderAudit {
  const findings: HeaderFinding[] = [];
  const disclosures: string[] = [];
  let penalty = 0;
  let possible = 0;

  // CSP frame-ancestors substitutes for X-Frame-Options.
  const csp = headers['content-security-policy'] || '';
  const frameAncestors = /frame-ancestors[^;]*/i.test(csp);

  for (const rule of HEADER_RULES) {
    if (rule.header === 'x-frame-options' && frameAncestors) {
      findings.push({ header: rule.header, state: 'ok', severity: rule.severity, detail: 'Replaced by CSP frame-ancestors.' });
      possible += rule.weight;
      continue;
    }

    const value = headers[rule.header];
    if (!value) {
      findings.push({
        header: rule.header,
        state: 'missing',
        severity: rule.required ? rule.severity : 'low',
        detail: `${rule.header} is not sent. ${rule.advice}`,
      });
      if (rule.required) penalty += rule.weight;
      possible += rule.weight;
      continue;
    }

    possible += rule.weight;
    const checked = rule.check?.(value);
    if (checked) {
      findings.push({ header: rule.header, state: checked.state, severity: rule.severity, value, detail: checked.detail });
      penalty += checked.penalty ?? 0;
    } else {
      findings.push({ header: rule.header, state: 'ok', severity: rule.severity, value, detail: `${rule.header} is set.` });
    }
  }

  // Deprecated control: X-XSS-Protection is now harmful in some configurations.
  if (headers['x-xss-protection']) {
    findings.push({
      header: 'x-xss-protection',
      state: 'obsolete',
      severity: 'info',
      value: headers['x-xss-protection'],
      detail: 'Deprecated. Modern browsers ignore it; CSP is the replacement.',
    });
  }

  // Disclosure, not vulnerability — but worth recording.
  for (const h of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator', 'x-drupal-cache']) {
    const value = headers[h];
    if (!value) continue;
    if (/\d+\.\d+/.test(value) || /^(express|php\/[\d.]+|asp\.net)$/i.test(value.trim())) {
      disclosures.push(`${h}: ${value}`);
    }
  }

  // A wildcard CORS policy on an authenticated page is a real finding.
  const acao = headers['access-control-allow-origin'];
  if (acao === '*') {
    findings.push({
      header: 'access-control-allow-origin',
      state: 'weak',
      severity: 'medium',
      value: acao,
      detail: 'Wildcard CORS: any site can read responses. Confirm no credentials are involved.',
    });
    penalty += 6;
    possible += 6;
  }

  const score = Math.max(0, Math.min(100, Math.round(100 - (possible ? (penalty / possible) * 100 : 0))));
  const grade: HeaderAudit['grade'] =
    score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

  return {
    findings,
    score,
    grade,
    missing: findings.filter(f => f.state === 'missing' && f.severity !== 'low' && f.severity !== 'info').map(f => f.header),
    present: findings.filter(f => f.state === 'ok').length,
    checked: findings.length,
    disclosures,
  };
}

/* ── cookies ─────────────────────────────────────────────────── */

export interface CookieFlag {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  /** `__Host-` / `__Secure-` cookies lose their guarantee without the flag. */
  prefixViolation: boolean;
  session: boolean;
  issues: string[];
}

/** Parse Set-Cookie attributes and flag the mistakes that matter. */
export function inspectCookies(cookieHeaders: string[]): CookieFlag[] {
  return cookieHeaders.map(raw => {
    const [pair, ...attrs] = raw.split(';').map(s => s.trim());
    const name = pair.split('=')[0] || '(unnamed)';
    const lower = attrs.map(a => a.toLowerCase());
    const secure = lower.includes('secure');
    const httpOnly = lower.includes('httponly');
    const sameSiteAttr = attrs.find(a => /^samesite=/i.test(a));
    const sameSite = sameSiteAttr ? sameSiteAttr.split('=')[1].toLowerCase() : null;
    const session = !lower.some(a => a.startsWith('expires=') || a.startsWith('max-age='));
    const issues: string[] = [];

    if (!secure) issues.push('no Secure flag');
    if (!httpOnly) issues.push('no HttpOnly flag');
    if (sameSite === 'none' && !secure) issues.push('SameSite=None without Secure is rejected by browsers');
    if (!sameSite) issues.push('no SameSite attribute');
    if (session) issues.push('session cookie (no expiry)');

    const prefixViolation =
      (name.startsWith('__Host-') && !secure) ||
      (name.startsWith('__Secure-') && !secure);

    return { name, secure, httpOnly, sameSite, prefixViolation, session, issues };
  });
}

/* ── favicon hashing (Shodan-compatible) ─────────────────────── */

/** MurmurHash3 x86_32, the variant Shodan uses for favicon hashes. */
export function murmur3_32(bytes: Uint8Array, seed = 0): number {
  let h = seed >>> 0;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const len = bytes.length;
  const blocks = len & ~3;

  for (let i = 0; i < blocks; i += 4) {
    let k = (bytes[i] & 0xff) | ((bytes[i + 1] & 0xff) << 8) | ((bytes[i + 2] & 0xff) << 16) | ((bytes[i + 3] & 0xff) << 24);
    k = Math.imul(k, c1);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, c2);
    h ^= k;
    h = (h << 13) | (h >>> 19);
    h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }

  let k1 = 0;
  switch (len & 3) {
    case 3: k1 ^= (bytes[blocks + 2] & 0xff) << 16; // fallthrough
    case 2: k1 ^= (bytes[blocks + 1] & 0xff) << 8; // fallthrough
    case 1:
      k1 ^= bytes[blocks] & 0xff;
      k1 = Math.imul(k1, c1);
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = Math.imul(k1, c2);
      h ^= k1;
  }

  h ^= len;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;

  return h | 0;
}

/** Base64 with a newline every 76 characters, as Python's codecs.encode emits. */
function pythonBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const raw = btoa(binary);
  return raw.replace(/(.{76})/g, '$1\n') + '\n';
}

/**
 * Shodan’s favicon hash. Search `http.favicon.hash:<value>` to find every host
 * serving the same icon — the standard pivot from one box to a whole estate.
 *
 * `btoa` is a browser/Node 16+ global; the route runs in the Node runtime, so
 * this stays usable in both.
 */
export function faviconHash(bytes: Uint8Array): number {
  return murmur3_32(new TextEncoder().encode(pythonBase64(bytes)));
}

/* ── robots.txt / sitemap ───────────────────────────────────── */

export interface RobotsInfo {
  present: boolean;
  /** Disallowed paths with their user-agent, in file order. */
  disallowed: Array<{ agent: string; path: string }>;
  allowed: string[];
  sitemaps: string[];
  /** True when a crawler is told to go away entirely. */
  blocksAll: boolean;
}

/**
 * Parse robots.txt.
 *
 * Disallow entries are not a secret — they are the owner's own list of paths
 * they would rather nobody looked at, which is exactly why an analyst does.
 */
export function parseRobots(text: string): RobotsInfo {
  const disallowed: Array<{ agent: string; path: string }> = [];
  const allowed: string[] = [];
  const sitemaps: string[] = [];
  let agent = '*';
  let blocksAll = false;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const [keyRaw, ...rest] = line.split(':');
    const key = keyRaw.trim().toLowerCase();
    const value = rest.join(':').trim();
    if (key === 'user-agent') {
      agent = value || '*';
    } else if (key === 'disallow' && value) {
      disallowed.push({ agent, path: value });
      if (value === '/' && (agent === '*' || agent === '')) blocksAll = true;
    } else if (key === 'allow' && value) {
      allowed.push(value);
    } else if (key === 'sitemap' && value) {
      sitemaps.push(value);
    }
  }

  return { present: true, disallowed: disallowed.slice(0, 200), allowed: allowed.slice(0, 100), sitemaps: sitemaps.slice(0, 20), blocksAll };
}

/* ── pivots ──────────────────────────────────────────────────── */

/**
 * Third-party hosts a page loads code or media from. Each one is an
 * infrastructure dependency and often a shared-tenant lead.
 */
export function extractExternalHosts(html: string, domain: string): string[] {
  const urls = html.match(/https?:\/\/[^\s"'<>)]+/gi) || [];
  const hosts = new Set<string>();
  const suffix = `.${domain.toLowerCase()}`;
  for (const url of urls) {
    try {
      const host = new URL(url).hostname.toLowerCase();
      if (host === domain.toLowerCase() || host.endsWith(suffix)) continue;
      if (!host.includes('.')) continue;
      hosts.add(host);
    } catch {
      /* malformed href */
    }
  }
  return Array.from(hosts).sort().slice(0, 60);
}

/** `<title>` without an HTML parser, bounded so a huge page cannot stall. */
export function extractTitle(html: string): string | null {
  const m = html.slice(0, 200_000).match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim() : null;
}

export interface FetchPageOptions {
  timeoutMs?: number;
  maxBytes?: number;
}

export interface FetchedPage {
  requestedUrl: string;
  finalUrl: string;
  status: number;
  headers: HeaderBag;
  body: string;
  truncated: boolean;
  /** Raw Set-Cookie values, kept because the header bag joins them. */
  cookieHeaders: string[];
  error?: string;
}

/**
 * Fetch a page for fingerprinting.
 *
 * The body is capped: a recon target can be a multi-megabyte page, and only
 * the first slice carries the head, the asset references and the generator
 * tags the signatures look at.
 */
export async function fetchPage(url: string, opts: FetchPageOptions = {}): Promise<FetchedPage> {
  const { timeoutMs = 12_000, maxBytes = 900_000 } = opts;
  const res = await httpRequest(url, {
    timeoutMs,
    redirect: 'follow',
    headers: { 'User-Agent': BROWSER_UA, Accept: 'text/html,application/xhtml+xml,*/*;q=0.8' },
  });
  const truncated = res.body.length > maxBytes;
  return {
    requestedUrl: url,
    finalUrl: res.url,
    status: res.status,
    headers: headerBag(res.headers),
    body: truncated ? res.body.slice(0, maxBytes) : res.body,
    truncated,
    cookieHeaders: setCookieList(res.headers),
  };
}

/** All Set-Cookie values, which `headerBag` collapses into one string. */
export function setCookieList(headers: Headers): string[] {
  const anyHeaders = headers as Headers & { getSetCookie?: () => string[] };
  if (typeof anyHeaders.getSetCookie === 'function') return anyHeaders.getSetCookie();
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

/* ── whole-site fingerprint ─────────────────────────────────── */

export interface SiteFingerprint {
  requestedUrl: string;
  finalUrl: string;
  origin: string;
  status: number;
  title: string | null;
  server: string | null;
  technologies: Technology[];
  headerAudit: HeaderAudit;
  cookies: CookieFlag[];
  headers: HeaderBag;
  favicon: { url: string; hash: number; bytes: number } | null;
  robots: RobotsInfo | null;
  securityTxt: boolean;
  externalHosts: string[];
  bodyBytes: number;
  truncated: boolean;
  elapsedMs: number;
  /** Fatal problem (DNS, TLS, timeout); the rest of the fields are then empty. */
  error?: string;
}

/** Absolute URL for a target the analyst typed, defaulting to HTTPS. */
export function targetUrl(target: string): string {
  const trimmed = target.trim();
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed.replace(/^\/+/, '')}`;
}

function safeOrigin(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

async function fetchFavicon(origin: string, html: string, timeoutMs: number): Promise<SiteFingerprint['favicon']> {
  const declared = html.match(/<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']/i)?.[1];
  const candidates = declared
    ? [declared.startsWith('http') ? declared : new URL(declared, `${origin}/`).toString()]
    : [];
  candidates.push(`${origin}/favicon.ico`);

  for (const url of candidates.slice(0, 2)) {
    try {
      // Read the icon as bytes — a text round-trip would corrupt it and the
      // hash would not match Shodan's.
      const res = await fetch(url, {
        signal: AbortSignal.timeout(timeoutMs),
        headers: { 'User-Agent': BROWSER_UA, Accept: 'image/*,*/*' },
      });
      if (!res.ok) continue;
      const buffer = new Uint8Array(await res.arrayBuffer());
      if (buffer.length === 0 || buffer.length > 1_000_000) continue;
      return { url, hash: faviconHash(buffer), bytes: buffer.length };
    } catch {
      /* try the next candidate */
    }
  }
  return null;
}

/**
 * One pass over a site: fetch, fingerprint, audit, hash the icon, read
 * robots.txt and security.txt.
 *
 * Everything after the page fetch runs in parallel and is individually
 * optional — a site that blocks its favicon still produces a full report.
 */
export async function fingerprintSite(target: string, opts: { timeoutMs?: number } = {}): Promise<SiteFingerprint> {
  const started = Date.now();
  const { timeoutMs = 12_000 } = opts;
  const requestedUrl = targetUrl(target);

  let page: FetchedPage;
  try {
    page = await fetchPage(requestedUrl, { timeoutMs });
  } catch (firstError) {
    // A surprising number of hosts still only answer plain HTTP.
    const fallback = requestedUrl.replace(/^https:/i, 'http:');
    try {
      page = await fetchPage(fallback, { timeoutMs });
    } catch {
      return {
        requestedUrl,
        finalUrl: requestedUrl,
        origin: safeOrigin(requestedUrl),
        status: 0,
        title: null,
        server: null,
        technologies: [],
        headerAudit: auditSecurityHeaders({}),
        cookies: [],
        headers: {},
        favicon: null,
        robots: null,
        securityTxt: false,
        externalHosts: [],
        bodyBytes: 0,
        truncated: false,
        elapsedMs: Date.now() - started,
        error: firstError instanceof Error ? firstError.message : 'request failed',
      };
    }
  }

  const origin = new URL(page.finalUrl).origin;
  const technologies = detectTechnologies({
    url: page.finalUrl,
    headers: page.headers,
    body: page.body,
    cookieHeaders: page.cookieHeaders,
  });
  const headerAudit = auditSecurityHeaders(page.headers);

  const [robotsRes, securityTxtRes, favicon] = await Promise.all([
    httpRequest(`${origin}/robots.txt`, { timeoutMs: 6000, headers: { Accept: 'text/plain' } }).catch(() => null),
    httpRequest(`${origin}/.well-known/security.txt`, { timeoutMs: 6000, headers: { Accept: 'text/plain' } }).catch(() => null),
    fetchFavicon(origin, page.body, 6000),
  ]);

  const robots = robotsRes && robotsRes.ok && !/^\s*<(!doctype|html)/i.test(robotsRes.body)
    ? parseRobots(robotsRes.body)
    : null;

  return {
    requestedUrl,
    finalUrl: page.finalUrl,
    origin,
    status: page.status,
    title: extractTitle(page.body),
    server: page.headers.server || null,
    technologies,
    headerAudit,
    cookies: inspectCookies(page.cookieHeaders),
    headers: page.headers,
    favicon,
    robots,
    securityTxt: Boolean(securityTxtRes?.ok && /Contact:/i.test(securityTxtRes.body)),
    externalHosts: extractExternalHosts(page.body, new URL(page.finalUrl).hostname),
    bodyBytes: page.body.length,
    truncated: page.truncated,
    elapsedMs: Date.now() - started,
  };
}
