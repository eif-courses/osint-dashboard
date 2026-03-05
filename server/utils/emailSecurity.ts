import { resolveMx, resolveTxt, resolveCname } from "node:dns/promises";

export type DkimSelectorResult = {
  selector: string;
  type: "TXT" | "CNAME";
};

export type EmailSecurity = {
  mx: string[];
  spf: { record?: string; lookupCount?: number };
  dmarc: { record?: string; policy?: string; subdomainPolicy?: string; ruaEmails?: string[] };
  dkim: { found: DkimSelectorResult[]; foundSelectors: string[]; note: string };
};

function findTxtStartingWith(txt: string[][], prefix: string): string | undefined {
  const joined = txt.map((parts) => parts.join("")).map((s) => s.trim());
  return joined.find((s) => s.toLowerCase().startsWith(prefix.toLowerCase()));
}

function parseDmarcPolicy(record?: string) {
  if (!record) return { policy: undefined, subdomainPolicy: undefined, ruaEmails: [] };
  const parts = record.split(";").map((p) => p.trim()).filter(Boolean);
  const p = parts.find((x) => x.toLowerCase().startsWith("p="))?.split("=", 2)[1]?.trim();
  const sp = parts.find((x) => x.toLowerCase().startsWith("sp="))?.split("=", 2)[1]?.trim();
  const rua = parts.find((x) => x.toLowerCase().startsWith("rua="))?.split("=", 2)[1]?.trim();
  const ruaEmails = rua
    ? rua.split(",").map((s) => s.trim().replace(/^mailto:/, "")).filter(Boolean)
    : [];
  return { policy: p, subdomainPolicy: sp, ruaEmails };
}

function estimateSpfLookups(record?: string): number {
  if (!record) return 0;
  // Each of these mechanisms can trigger a DNS lookup
  const lookupMechanisms = /\b(include:|a:|mx:|ptr:|exists:)/gi;
  const matches = record.match(lookupMechanisms) ?? [];
  return matches.length;
}

async function safeResolveTxt(name: string): Promise<string[][] | null> {
  try { return await resolveTxt(name); } catch { return null; }
}

async function safeResolveMx(name: string): Promise<string[]> {
  try {
    const mx = await resolveMx(name);
    return mx.sort((a, b) => a.priority - b.priority).map((x) => `${x.priority} ${x.exchange}`.trim());
  } catch {
    return [];
  }
}

// Extended DKIM check: tries CNAME first (Microsoft 365 pattern), then TXT
const DKIM_SELECTORS = [
  "default",
  "selector1",
  "selector2",
  "google",
  "smtp",
  "mail",
  "dkim",
  "s1",
  "s2",
  "k1",
  "k2",
  "em",
  "pm",
];

async function checkDkimSelector(
  selector: string,
  domain: string
): Promise<DkimSelectorResult | null> {
  const name = `${selector}._domainkey.${domain}`;

  // CNAME check first (e.g. Microsoft 365 delegates DKIM via CNAME)
  try {
    await resolveCname(name);
    return { selector, type: "CNAME" };
  } catch {}

  // TXT check
  try {
    const txt = await resolveTxt(name);
    const record = txt
      .map((p) => p.join(""))
      .find(
        (s) =>
          s.toLowerCase().includes("v=dkim1") ||
          s.toLowerCase().includes("k=rsa") ||
          s.toLowerCase().includes("k=ed25519")
      );
    if (record) return { selector, type: "TXT" };
  } catch {}

  return null;
}

export async function getEmailSecurity(domain: string): Promise<EmailSecurity> {
  const mx = await safeResolveMx(domain);

  const rootTxt = await safeResolveTxt(domain);
  const spfRecord = rootTxt ? findTxtStartingWith(rootTxt, "v=spf1") : undefined;
  const spfLookups = estimateSpfLookups(spfRecord);

  const dmarcTxt = await safeResolveTxt(`_dmarc.${domain}`);
  const dmarcRecord = dmarcTxt ? findTxtStartingWith(dmarcTxt, "v=DMARC1") : undefined;
  const { policy, subdomainPolicy, ruaEmails } = parseDmarcPolicy(dmarcRecord);

  // DKIM: best-effort selector discovery
  const dkimResults: DkimSelectorResult[] = [];
  for (const sel of DKIM_SELECTORS) {
    const result = await checkDkimSelector(sel, domain);
    if (result) dkimResults.push(result);
  }

  const note =
    dkimResults.length
      ? "DKIM appears enabled for at least one common selector (best-effort check)."
      : "DKIM selector names are not discoverable automatically. Use your email provider's selector(s) to validate DKIM precisely.";

  return {
    mx,
    spf: { record: spfRecord, lookupCount: spfLookups },
    dmarc: { record: dmarcRecord, policy, subdomainPolicy, ruaEmails },
    dkim: {
      found: dkimResults,
      foundSelectors: dkimResults.map((r) => r.selector),
      note,
    },
  };
}
