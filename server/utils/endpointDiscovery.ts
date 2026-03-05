export type DiscoveredEndpoint = {
  path: string;
  status: number;
  sensitive: boolean;
};

const PROBE_PATHS = [
  "/admin",
  "/administrator",
  "/login",
  "/signin",
  "/dashboard",
  "/api",
  "/api/v1",
  "/api/v2",
  "/.git/HEAD",
  "/.env",
  "/.env.local",
  "/backup",
  "/backup.zip",
  "/backup.tar.gz",
  "/config",
  "/config.json",
  "/debug",
  "/swagger",
  "/swagger-ui.html",
  "/swagger-ui/index.html",
  "/openapi.json",
  "/openapi.yaml",
  "/health",
  "/healthz",
  "/status",
  "/phpinfo.php",
  "/info.php",
  "/wp-admin",
  "/wp-login.php",
  "/phpmyadmin",
  "/.well-known/security.txt",
  "/server-status",
  "/server-info",
  "/actuator",
  "/actuator/health",
  "/actuator/env",
  "/console",
  "/metrics",
  "/graphql",
];

// Paths that would be high-severity if accessible
const SENSITIVE_PREFIXES = [
  "/.git",
  "/.env",
  "/phpinfo",
  "/info.php",
  "/debug",
  "/backup",
  "/config",
  "/phpmyadmin",
  "/server-status",
  "/server-info",
  "/actuator/env",
  "/console",
];

export async function discoverEndpoints(domain: string): Promise<DiscoveredEndpoint[]> {
  const results = await Promise.allSettled(
    PROBE_PATHS.map(async (path): Promise<DiscoveredEndpoint | null> => {
      try {
        const res = await fetch(`https://${domain}${path}`, {
          method: "GET",
          redirect: "manual", // don't follow redirects — 3xx is not "exposed"
          signal: AbortSignal.timeout(6_000),
          headers: {
            "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
          },
        });

        // Only report if endpoint actually responds (not 404/3xx)
        if (res.status === 200 || res.status === 401 || res.status === 403) {
          const sensitive = SENSITIVE_PREFIXES.some((sp) => path.startsWith(sp));
          return { path, status: res.status, sensitive };
        }
        return null;
      } catch {
        return null;
      }
    })
  );

  return results
    .filter(
      (r): r is PromiseFulfilledResult<DiscoveredEndpoint> =>
        r.status === "fulfilled" && r.value !== null
    )
    .map((r) => r.value);
}
