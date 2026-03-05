import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { normalizeDomain, isAllowedDomain } from "../utils/allowlist";
import { rateLimitOrThrow } from "../utils/rateLimit";
import { parseNmapXml } from "../utils/parseNmap";
import { buildFindings } from "../utils/findings";
import { getEmailSecurity } from "../utils/emailSecurity";

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

  // EMAIL SECURITY (DNS-based)
  const email = await getEmailSecurity(domain);

  // AMASS (passive OSINT) — safe fallback
  let subdomains: string[] = [];
  let amassStatus: "ok" | "missing" | "error" | "crtsh" = "ok";
  let amassNote: string | undefined;

  try {
    // Pass -timeout to amass (minutes) so it finishes cleanly before our hard kill.
    // Node timeout is set 30 s longer to give amass time to flush its output.
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
      // Truncate to first line to avoid verbose progress-bar spam in the note
      const firstLine = (err?.message ?? "unknown error").split("\n")[0].slice(0, 120);
      amassNote = `Amass failed — trying crt.sh fallback. (${firstLine})`;
    }
    // Fallback: query crt.sh certificate transparency logs
    try {
      const res = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
        signal: AbortSignal.timeout(15_000),
        headers: { "Accept": "application/json" }
      });
      if (res.ok) {
        const data = await res.json() as Array<{ name_value: string }>;
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
      // crt.sh also failed — subdomains stays empty
      amassNote = (amassNote ?? "") + " crt.sh also failed.";
    }
  }

  // Guardrails: don’t scan too many hosts (and always scan at least root domain)
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

  // FINDINGS
  const findings = buildFindings(domain, hosts as any, email);

  return {
    domain,
    email,
    subdomains,
    hosts,
    findings,
    meta: {
      scannedHosts: targets.length,
      scanType: "DNS(email) + amass(passive) + nmap(-sT -sV, top 100 ports)",
      toolStatus: {
        amass: { status: amassStatus, note: amassNote },
        nmap: { status: nmapStatus, note: nmapNote }
      },
      note: "Only scan systems you own or have explicit permission to test."
    }
  };
});