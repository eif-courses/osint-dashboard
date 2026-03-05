import dns from "node:dns/promises";

const SAAS_PATTERNS: Array<{
  provider: string;
  cnameMatch: RegExp;
  fingerprints: string[];
}> = [
  {
    provider: "GitHub Pages",
    cnameMatch: /github\.io$/i,
    fingerprints: [
      "There isn't a GitHub Pages site here",
      "If you're trying to publish one",
    ],
  },
  {
    provider: "Heroku",
    cnameMatch: /herokuapp\.com$/i,
    fingerprints: ["No such app", "herokucdn.com/error-pages/no-such-app"],
  },
  {
    provider: "Azure Web Apps",
    cnameMatch: /azurewebsites\.net$/i,
    fingerprints: ["404 Web Site not found", "Microsoft Azure App Service"],
  },
  {
    provider: "AWS CloudFront",
    cnameMatch: /cloudfront\.net$/i,
    fingerprints: ["Bad request", "The request could not be satisfied"],
  },
  {
    provider: "Netlify",
    cnameMatch: /netlify\.app$/i,
    fingerprints: ["Not Found - Request ID"],
  },
  {
    provider: "Surge.sh",
    cnameMatch: /surge\.sh$/i,
    fingerprints: ["project not found"],
  },
  {
    provider: "Fastly",
    cnameMatch: /fastly\.net$/i,
    fingerprints: ["Fastly error: unknown domain"],
  },
  {
    provider: "Zendesk",
    cnameMatch: /zendesk\.com$/i,
    fingerprints: ["Help Center Closed", "Oops, this help center no longer exists"],
  },
  {
    provider: "Shopify",
    cnameMatch: /myshopify\.com$/i,
    fingerprints: ["Sorry, this shop is currently unavailable"],
  },
  {
    provider: "Ghost",
    cnameMatch: /ghost\.io$/i,
    fingerprints: ["The thing you were looking for is no longer here"],
  },
  {
    provider: "Webflow",
    cnameMatch: /webflow\.io$/i,
    fingerprints: ["The page you are looking for doesn't exist or has been moved"],
  },
  {
    provider: "Fly.io",
    cnameMatch: /fly\.dev$/i,
    fingerprints: ["404 Not Found"],
  },
];

export type TakeoverResult = {
  subdomain: string;
  cname: string;
  provider: string;
  evidence: string;
};

async function checkSubdomainTakeover(subdomain: string): Promise<TakeoverResult | null> {
  let cname: string | undefined;
  try {
    const result = await dns.resolve(subdomain, "CNAME");
    cname = result[0]?.toLowerCase();
  } catch {
    return null;
  }

  if (!cname) return null;

  const matched = SAAS_PATTERNS.find((p) => p.cnameMatch.test(cname!));
  if (!matched) return null;

  // Try HTTPS then HTTP fallback
  for (const scheme of ["https", "http"]) {
    try {
      const res = await fetch(`${scheme}://${subdomain}/`, {
        redirect: "follow",
        signal: AbortSignal.timeout(8_000),
        headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)" },
      });
      const body = await res.text();
      const evidence = matched.fingerprints.find((fp) =>
        body.toLowerCase().includes(fp.toLowerCase())
      );
      if (evidence) {
        return { subdomain, cname: cname!, provider: matched.provider, evidence };
      }
    } catch {
      // continue to next scheme
    }
  }

  return null;
}

export async function checkTakeoverRisks(subdomains: string[]): Promise<TakeoverResult[]> {
  const limited = subdomains.slice(0, 60);
  const results = await Promise.allSettled(limited.map((s) => checkSubdomainTakeover(s)));
  return results
    .filter(
      (r): r is PromiseFulfilledResult<TakeoverResult> =>
        r.status === "fulfilled" && r.value !== null
    )
    .map((r) => r.value);
}
