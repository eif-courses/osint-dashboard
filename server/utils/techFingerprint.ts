export type TechStack = {
  cdn?: string;
  framework?: string;
  backend?: string;
  analytics: string[];
  hosting?: string;
};

const CDN_PATTERNS: Array<{ name: string; headers: string[] }> = [
  { name: "Cloudflare", headers: ["cf-ray", "cf-cache-status"] },
  { name: "AWS CloudFront", headers: ["x-amz-cf-id", "x-amz-cf-pop"] },
  { name: "Vercel", headers: ["x-vercel-id", "x-vercel-cache"] },
  { name: "Netlify", headers: ["x-nf-request-id"] },
  { name: "Akamai", headers: ["x-check-cacheable", "akamai-grn"] },
  { name: "Fastly", headers: ["x-served-by", "x-fastly-request-id"] },
  { name: "BunnyCDN", headers: ["bunny-request-id", "cdn-requestid"] },
];

const FRAMEWORK_HTML_PATTERNS: Array<{ name: string; patterns: string[] }> = [
  { name: "Next.js", patterns: ["/_next/static/", "__next_data__", "__nextjs"] },
  { name: "Nuxt.js", patterns: ["/__nuxt/", "__nuxt__", "/_nuxt/"] },
  { name: "React", patterns: ["react.production.min.js", "data-reactroot", "react-dom"] },
  { name: "Angular", patterns: ["ng-version=", "/main.js", "angular"] },
  { name: "Vue.js", patterns: ["vue.min.js", "__vue_app__", "v-app"] },
  { name: "WordPress", patterns: ["wp-content/", "wp-includes/", "wp-json"] },
  { name: "Shopify", patterns: ["cdn.shopify.com", "shopify.shop"] },
  { name: "Wix", patterns: ["static.wixstatic.com", "wix-thunderbolt"] },
  { name: "Squarespace", patterns: ["static1.squarespace.com", "squarespace.com"] },
  { name: "Drupal", patterns: ["/sites/default/files/", "drupal.settings", "drupal.js"] },
  { name: "Joomla", patterns: ["/media/jui/", "option=com_"] },
  { name: "Ghost", patterns: ["ghost.io", "/ghost/api/"] },
];

const ANALYTICS_HTML_PATTERNS: Array<{ name: string; patterns: string[] }> = [
  { name: "Google Analytics", patterns: ["google-analytics.com/analytics.js", "gtag/js?id=ua-", "gtag/js?id=g-"] },
  { name: "Google Tag Manager", patterns: ["googletagmanager.com/gtm.js", "gtm-"] },
  { name: "Hotjar", patterns: ["hotjar.com"] },
  { name: "Segment", patterns: ["cdn.segment.com/analytics.js"] },
  { name: "Mixpanel", patterns: ["api.mixpanel.com"] },
  { name: "Intercom", patterns: ["widget.intercom.io", "intercomcdn.com"] },
  { name: "Crisp", patterns: ["client.crisp.chat"] },
  { name: "HubSpot", patterns: ["js.hs-scripts.com", "js.hsforms.net"] },
  { name: "Salesforce", patterns: ["pardot.com", "salesforceliveagent.com"] },
];

const BACKEND_HEADER_PATTERNS: Array<{ name: string; header: string; pattern: RegExp }> = [
  { name: "PHP", header: "x-powered-by", pattern: /php/i },
  { name: "ASP.NET", header: "x-powered-by", pattern: /asp\.net/i },
  { name: "Next.js", header: "x-powered-by", pattern: /next\.js/i },
  { name: "Express", header: "x-powered-by", pattern: /express/i },
  { name: "Ruby on Rails", header: "x-powered-by", pattern: /phusion passenger|ruby/i },
  { name: "Java", header: "x-powered-by", pattern: /servlet|jsp|java/i },
];

const SERVER_BACKEND_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "nginx", pattern: /nginx/i },
  { name: "Apache", pattern: /apache/i },
  { name: "IIS", pattern: /microsoft-iis/i },
  { name: "LiteSpeed", pattern: /litespeed/i },
  { name: "Caddy", pattern: /caddy/i },
];

export async function getTechFingerprint(domain: string): Promise<TechStack> {
  const result: TechStack = { analytics: [] };

  let headers: Record<string, string> = {};
  let html = "";

  try {
    const res = await fetch(`https://${domain}/`, {
      redirect: "follow",
      signal: AbortSignal.timeout(14_000),
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml",
      },
    });

    res.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val.toLowerCase();
    });

    const text = await res.text();
    html = text.slice(0, 80_000).toLowerCase();
  } catch {
    return result;
  }

  // CDN detection via headers
  for (const cdn of CDN_PATTERNS) {
    if (cdn.headers.some((h) => headers[h] !== undefined)) {
      result.cdn = cdn.name;
      break;
    }
  }

  // CDN via Server header
  if (!result.cdn && headers["server"]) {
    if (headers["server"].includes("cloudflare")) result.cdn = "Cloudflare";
  }

  // Backend from x-powered-by header
  const xpb = headers["x-powered-by"] ?? "";
  for (const bp of BACKEND_HEADER_PATTERNS) {
    if (bp.pattern.test(xpb)) {
      result.backend = bp.name;
      break;
    }
  }

  // Backend from server header
  if (!result.backend) {
    const srv = headers["server"] ?? "";
    for (const sp of SERVER_BACKEND_PATTERNS) {
      if (sp.pattern.test(srv)) {
        result.backend = sp.name;
        break;
      }
    }
  }

  // Framework from HTML
  for (const fw of FRAMEWORK_HTML_PATTERNS) {
    if (fw.patterns.some((p) => html.includes(p.toLowerCase()))) {
      result.framework = fw.name;
      break;
    }
  }

  // Hosting detection
  if (headers["x-vercel-id"]) result.hosting = "Vercel";
  else if (headers["x-nf-request-id"]) result.hosting = "Netlify";
  else if (headers["x-amz-cf-id"]) result.hosting = "AWS CloudFront";

  // Analytics from HTML
  for (const an of ANALYTICS_HTML_PATTERNS) {
    if (an.patterns.some((p) => html.includes(p.toLowerCase()))) {
      result.analytics.push(an.name);
    }
  }

  return result;
}
