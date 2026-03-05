import * as tls from "node:tls";

export type WebSecurity = {
  https: {
    redirect: boolean;
    certExpiry?: string;   // ISO date string
    daysLeft?: number;
  };
  headers: {
    server?: string;
    hsts?: string;
    csp?: string;
    xContentTypeOptions?: string;
    xFrameOptions?: string;
    referrerPolicy?: string;
    permissionsPolicy?: string;
  };
  cookies: {
    count: number;
  };
  securityTxt: boolean;
  robotsTxt: boolean;
  robotsTxtPaths: string[]; // Disallow entries found in robots.txt
};

async function getTlsCertInfo(hostname: string): Promise<{ expiry: string | null; daysLeft: number | null }> {
  return new Promise((resolve) => {
    const done = (expiry: string | null, daysLeft: number | null) => {
      clearTimeout(timer);
      resolve({ expiry, daysLeft });
    };
    const timer = setTimeout(() => {
      socket.destroy();
      done(null, null);
    }, 12_000);

    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          socket.destroy();
          if (cert?.valid_to) {
            const expiry = new Date(cert.valid_to);
            const daysLeft = Math.round((expiry.getTime() - Date.now()) / 86_400_000);
            done(expiry.toISOString(), daysLeft);
          } else {
            done(null, null);
          }
        } catch {
          done(null, null);
        }
      }
    );
    socket.on("error", () => done(null, null));
  });
}

export async function getWebSecurity(domain: string): Promise<WebSecurity> {
  // HTTP → HTTPS redirect check
  let redirect = false;
  try {
    const res = await fetch(`http://${domain}/`, {
      redirect: "follow",
      signal: AbortSignal.timeout(12_000),
    });
    redirect = res.url.startsWith("https://");
  } catch { /* ignore */ }

  // Security headers from HTTPS response
  const headers: WebSecurity["headers"] = {};
  let cookieCount = 0;
  try {
    const res = await fetch(`https://${domain}/`, {
      redirect: "follow",
      signal: AbortSignal.timeout(14_000),
    });
    const h = res.headers;
    const str = (k: string) => h.get(k) ?? undefined;
    headers.server = str("server");
    headers.hsts = str("strict-transport-security");
    headers.csp = str("content-security-policy");
    headers.xContentTypeOptions = str("x-content-type-options");
    headers.xFrameOptions = str("x-frame-options");
    headers.referrerPolicy = str("referrer-policy");
    headers.permissionsPolicy = str("permissions-policy");

    // set-cookie count (Node 20 fetch/undici exposes getSetCookie())
    const setCookie = (h as any).getSetCookie?.() ?? [];
    cookieCount = Array.isArray(setCookie) ? setCookie.length : 0;
  } catch { /* ignore */ }

  // TLS cert expiry via raw socket
  const tlsCert = await getTlsCertInfo(domain);

  // security.txt (RFC 9116)
  let securityTxt = false;
  try {
    const res = await fetch(`https://${domain}/.well-known/security.txt`, {
      redirect: "follow",
      signal: AbortSignal.timeout(8_000),
    });
    securityTxt = res.ok;
  } catch { /* ignore */ }

  // robots.txt — check existence and parse Disallow paths
  let robotsTxt = false;
  let robotsTxtPaths: string[] = [];
  try {
    const res = await fetch(`https://${domain}/robots.txt`, {
      redirect: "follow",
      signal: AbortSignal.timeout(8_000),
    });
    robotsTxt = res.ok;
    if (res.ok) {
      const text = await res.text();
      robotsTxtPaths = text
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.toLowerCase().startsWith("disallow:"))
        .map((line) => line.replace(/^disallow:\s*/i, "").trim())
        .filter((p) => p && p !== "/");
    }
  } catch { /* ignore */ }

  return {
    https: {
      redirect,
      certExpiry: tlsCert.expiry ?? undefined,
      daysLeft: tlsCert.daysLeft ?? undefined,
    },
    headers,
    cookies: { count: cookieCount },
    securityTxt,
    robotsTxt,
    robotsTxtPaths,
  };
}
