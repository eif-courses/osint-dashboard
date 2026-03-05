import { resolveCaa, resolveTxt, resolve4, resolve6, resolveCname } from "node:dns/promises";

export type DnsPosture = {
  caa: { found: boolean; records: string[] };
  dnssec: { detected: boolean };
  mtaSts: { found: boolean; record?: string };
  tlsRpt: { found: boolean; record?: string };
  commonSubdomains: Array<{ name: string; exists: boolean; target?: string }>;
  mxProvider: { name: string; confidence: "high" | "medium" | "low" };
};

async function safeResolveTxt(name: string): Promise<string[][] | null> {
  try { return await resolveTxt(name); } catch { return null; }
}

function findTxtByPrefix(records: string[][] | null, prefix: string): string | undefined {
  if (!records) return undefined;
  return records
    .map((parts) => parts.join(""))
    .find((s) => s.toLowerCase().startsWith(prefix.toLowerCase()));
}

async function checkCaa(domain: string): Promise<{ found: boolean; records: string[] }> {
  try {
    const recs = await resolveCaa(domain);
    if (!recs.length) return { found: false, records: [] };
    return {
      found: true,
      records: recs.map((r: any) => {
        const tag =
          r.issue !== undefined
            ? `issue "${r.issue}"`
            : r.issuewild !== undefined
            ? `issuewild "${r.issuewild}"`
            : r.iodef !== undefined
            ? `iodef "${r.iodef}"`
            : "?";
        return `${r.critical} ${tag}`;
      }),
    };
  } catch {
    return { found: false, records: [] };
  }
}

async function checkDnssec(domain: string): Promise<boolean> {
  // Use Cloudflare DoH to check for DNSKEY records (type 48)
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=DNSKEY`,
      {
        headers: { Accept: "application/dns-json" },
        signal: AbortSignal.timeout(10_000),
      }
    );
    if (!res.ok) return false;
    const data = (await res.json()) as { Answer?: Array<{ type: number }> };
    return (data.Answer ?? []).some((r) => r.type === 48);
  } catch {
    return false;
  }
}

async function checkSubdomainExists(fqdn: string): Promise<{ exists: boolean; target?: string }> {
  try { const a = await resolve4(fqdn); return { exists: true, target: a[0] }; } catch {}
  try { const a = await resolve6(fqdn); return { exists: true, target: a[0] }; } catch {}
  try { const c = await resolveCname(fqdn); return { exists: true, target: c[0] }; } catch {}
  return { exists: false };
}

export function detectMxProvider(
  mx: string[],
  spfRecord?: string
): { name: string; confidence: "high" | "medium" | "low" } {
  const mxLower = mx.join(" ").toLowerCase();
  const spfLower = (spfRecord ?? "").toLowerCase();

  if (mxLower.includes("outlook.com") || mxLower.includes("protection.outlook.com")) {
    return { name: "Microsoft 365", confidence: "high" };
  }
  if (spfLower.includes("spf.protection.outlook.com")) {
    return { name: "Microsoft 365", confidence: "medium" };
  }
  if (
    mxLower.includes("aspmx.l.google.com") ||
    mxLower.includes("googlemail.com") ||
    mxLower.includes(".google.com")
  ) {
    return { name: "Google Workspace", confidence: "high" };
  }
  if (spfLower.includes("_spf.google.com") || spfLower.includes("googlemail.com")) {
    return { name: "Google Workspace", confidence: "medium" };
  }
  if (mxLower.includes("pphosted.com")) {
    return { name: "Proofpoint", confidence: "high" };
  }
  if (mxLower.includes("mandrillapp.com") || spfLower.includes("spf.mandrillapp.com")) {
    return { name: "Mandrill (Mailchimp)", confidence: "high" };
  }
  if (spfLower.includes("sendgrid.net")) {
    return { name: "SendGrid", confidence: "medium" };
  }
  if (spfLower.includes("spf.mtasv.net") || spfLower.includes("postmarkapp.com")) {
    return { name: "Postmark", confidence: "medium" };
  }
  if (mx.length > 0) {
    return { name: "Unknown", confidence: "low" };
  }
  return { name: "No MX records", confidence: "low" };
}

const COMMON_SUBS = [
  "mail",
  "webmail",
  "smtp",
  "imap",
  "pop",
  "autodiscover",
  "autoconfig",
  "vpn",
  "admin",
  "dev",
  "staging",
  "api",
];

export async function getDnsPosture(
  domain: string,
  mx: string[],
  spfRecord?: string
): Promise<DnsPosture> {
  const [caa, dnssecDetected] = await Promise.all([checkCaa(domain), checkDnssec(domain)]);

  // MTA-STS DNS record
  const mtaStsTxt = await safeResolveTxt(`_mta-sts.${domain}`);
  const mtaStsRecord = findTxtByPrefix(mtaStsTxt, "v=STSv1");

  // TLS-RPT DNS record
  const tlsRptTxt = await safeResolveTxt(`_smtp._tls.${domain}`);
  const tlsRptRecord = findTxtByPrefix(tlsRptTxt, "v=TLSRPTv1");

  // Common subdomain existence checks (A/AAAA/CNAME)
  const subResults = await Promise.all(
    COMMON_SUBS.map(async (sub) => {
      const fqdn = `${sub}.${domain}`;
      const result = await checkSubdomainExists(fqdn);
      return { name: fqdn, ...result };
    })
  );

  const mxProvider = detectMxProvider(mx, spfRecord);

  return {
    caa,
    dnssec: { detected: dnssecDetected },
    mtaSts: { found: !!mtaStsRecord, record: mtaStsRecord },
    tlsRpt: { found: !!tlsRptRecord, record: tlsRptRecord },
    commonSubdomains: subResults,
    mxProvider,
  };
}
