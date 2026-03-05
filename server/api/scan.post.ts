import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { normalizeDomain, isAllowedDomain } from "../utils/allowlist";
import { rateLimitOrThrow } from "../utils/rateLimit";
import { parseNmapXml } from "../utils/parseNmap";
import { buildFindings } from "../utils/findings";
import { getEmailSecurity } from "../utils/emailSecurity";
import { getWebSecurity } from "../utils/webSecurity";
import { getDnsPosture } from "../utils/dnsPosture";

const execFileAsync = promisify(execFile);

type ScanRequest = { domain: string };

function isENOENT(err: any) {
  return err?.code === "ENOENT" || String(err?.message || "").includes("ENOENT");
}

function normalizeSubdomains(domain: string, raw: string) {
  return Array.from(
    new Set(
      raw
        .split("\n")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
        .filter((s) => s === domain || s.endsWith("." + domain))
    )
  );
}

// Score weights summing to 100
function calculateScore(email: any, web: any, dns: any): { score: number; riskLevel: string; breakdown: Record<string, number> } {
  const breakdown: Record<string, number> = {};
  let score = 0;

  // SPF: 10 pts (5 for present, 5 bonus for hardfail)
  if (email?.spf?.record) {
    breakdown.spf = 5;
    if (email.spf.record.includes("-all")) breakdown.spf += 5;
  } else {
    breakdown.spf = 0;
  }

  // DMARC: 15 pts (5 for present, 5 for quarantine, 5 more for reject)
  if (email?.dmarc?.record) {
    const p = (email.dmarc.policy ?? "").toLowerCase();
    breakdown.dmarc = 5;
    if (p === "quarantine") breakdown.dmarc += 5;
    else if (p === "reject") breakdown.dmarc += 10;
  } else {
    breakdown.dmarc = 0;
  }

  // DKIM: 8 pts
  breakdown.dkim = (email?.dkim?.found?.length ?? 0) > 0 ? 8 : 0;

  // HTTP → HTTPS redirect: 5 pts
  breakdown.httpsRedirect = web?.https?.redirect ? 5 : 0;

  // TLS cert valid > 30 days: 4 pts
  breakdown.tlsCert =
    web?.https?.daysLeft !== undefined && web.https.daysLeft > 30 ? 4 : 0;

  // HSTS: 10 pts
  breakdown.hsts = web?.headers?.hsts ? 10 : 0;

  // CSP: 10 pts
  breakdown.csp = web?.headers?.csp ? 10 : 0;

  // X-Content-Type-Options: 4 pts
  breakdown.xCTO = web?.headers?.xContentTypeOptions ? 4 : 0;

  // X-Frame-Options: 4 pts
  breakdown.xFO = web?.headers?.xFrameOptions ? 4 : 0;

  // Referrer-Policy: 3 pts
  breakdown.referrerPolicy = web?.headers?.referrerPolicy ? 3 : 0;

  // Permissions-Policy: 3 pts
  breakdown.permissionsPolicy = web?.headers?.permissionsPolicy ? 3 : 0;

  // CAA: 6 pts
  breakdown.caa = dns?.caa?.found ? 6 : 0;

  // DNSSEC: 6 pts
  breakdown.dnssec = dns?.dnssec?.detected ? 6 : 0;

  // MTA-STS: 5 pts
  breakdown.mtaSts = dns?.mtaSts?.found ? 5 : 0;

  // TLS-RPT: 3 pts
  breakdown.tlsRpt = dns?.tlsRpt?.found ? 3 : 0;

  // security.txt: 2 pts
  breakdown.securityTxt = web?.securityTxt ? 2 : 0;

  // robots.txt: 2 pts
  breakdown.robotsTxt = web?.robotsTxt ? 2 : 0;

  score = Object.values(breakdown).reduce((a, b) => a + b, 0);

  const riskLevel =
    score >= 70 ? "Low risk"
    : score >= 45 ? "Medium risk"
    : score >= 25 ? "High risk"
    : "Critical risk";

  return { score, riskLevel, breakdown };
}

export default defineEventHandler(async (event) => {
  // Rate limit by client IP
  const ip =
    (getRequestHeader(event, "x-forwarded-for") || "").split(",")[0].trim() ||
    (event.node.req.socket.remoteAddress ?? "unknown");

  rateLimitOrThrow(ip, { limit: 6, windowMs: 60_000 });

  // Validate domain
  const body = await readBody<ScanRequest>(event);
  const domain = normalizeDomain(body?.domain ?? "");

  if (!domain) throw createError({ statusCode: 400, statusMessage: "Domain is required" });
  if (!isAllowedDomain(domain)) {
    throw createError({ statusCode: 403, statusMessage: "Domain not allowed for scanning" });
  }

  // Get email security first (needed for MX provider detection in DNS posture)
  const email = await getEmailSecurity(domain);

  // Run web security and DNS posture in parallel using email context
  const [web, dnsPostureFull] = await Promise.all([
    getWebSecurity(domain),
    getDnsPosture(domain, email.mx, email.spf.record),
  ]);

  // AMASS (passive OSINT) — safe fallback
  let subdomains: string[] = [];
  let amassStatus: "ok" | "missing" | "error" | "crtsh" = "ok";
  let amassNote: string | undefined;

  try {
    const amass = await execFileAsync(
      "amass",
      ["enum", "-passive", "-d", domain, "-timeout", "3"],
      { timeout: 210_000, maxBuffer: 2 * 1024 * 1024 }
    );
    subdomains = normalizeSubdomains(domain, amass.stdout).filter((s) => s !== domain).slice(0, 300);
  } catch (err: any) {
    if (isENOENT(err)) {
      amassStatus = "missing";
      amassNote = "Amass not installed — trying crt.sh fallback.";
    } else {
      amassStatus = "error";
      const firstLine = (err?.message ?? "unknown error").split("\n")[0].slice(0, 120);
      amassNote = `Amass failed — trying crt.sh fallback. (${firstLine})`;
    }
    try {
      const res = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
        signal: AbortSignal.timeout(15_000),
        headers: { Accept: "application/json" },
      });
      if (res.ok) {
        const data = (await res.json()) as Array<{ name_value: string }>;
        const names = data.flatMap((r) =>
          r.name_value.split("\n").map((s) => s.trim().replace(/^\*\./, "").toLowerCase())
        );
        subdomains = normalizeSubdomains(domain, names.join("\n"))
          .filter((s) => s !== domain)
          .slice(0, 300);
        amassStatus = "crtsh";
        amassNote = "Subdomains sourced from crt.sh certificate transparency logs (Amass unavailable).";
      } else {
        amassNote = (amassNote ?? "") + " crt.sh also failed.";
      }
    } catch {
      amassNote = (amassNote ?? "") + " crt.sh also failed.";
    }
  }

  // Guardrails: don't scan too many hosts
  const targets = (subdomains.length ? subdomains : [domain]).slice(0, 30);

  // NMAP (safe TCP connect scan: -sT)
  let hosts = [];
  let nmapStatus: "ok" | "missing" | "error" = "ok";
  let nmapNote: string | undefined;

  try {
    const nmap = await execFileAsync(
      "nmap",
      ["-sT", "-sV", "-Pn", "--top-ports", "100", "--host-timeout", "20s", "-oX", "-", ...targets],
      { timeout: 120_000, maxBuffer: 6 * 1024 * 1024 }
    );
    hosts = parseNmapXml(nmap.stdout);
  } catch (err: any) {
    if (isENOENT(err)) {
      nmapStatus = "missing";
      nmapNote = "Nmap is not installed in this environment. Install it or run via Docker image.";
    } else {
      nmapStatus = "error";
      nmapNote = `Nmap failed: ${err?.message ?? "unknown error"}`;
    }
    hosts = [];
  }

  // FINDINGS (with web + DNS posture)
  const findings = buildFindings(domain, hosts as any, email, web, dnsPostureFull);

  // SCORE
  const scoreResult = calculateScore(email, web, dnsPostureFull);

  return {
    domain,
    email,
    web,
    dnsPosture: dnsPostureFull,
    score: scoreResult,
    subdomains,
    hosts,
    findings,
    meta: {
      scannedHosts: targets.length,
      scanType: "DNS(email/posture) + HTTP/TLS headers + amass(passive) + nmap(-sT -sV, top 100 ports)",
      toolStatus: {
        amass: { status: amassStatus, note: amassNote },
        nmap: { status: nmapStatus, note: nmapNote },
      },
      note: "Only scan systems you own or have explicit permission to test.",
    },
  };
});
