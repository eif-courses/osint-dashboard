import { resolveMx, resolveTxt } from "node:dns/promises";

export type EmailSecurity = {
  mx: string[];
  spf: { record?: string };
  dmarc: { record?: string; policy?: string; subdomainPolicy?: string };
  dkim: { foundSelectors: string[]; note: string };
};

function findTxtStartingWith(txt: string[][], prefix: string): string | undefined {
  const joined = txt.map((parts) => parts.join("")).map((s) => s.trim());
  return joined.find((s) => s.toLowerCase().startsWith(prefix.toLowerCase()));
}

function parseDmarcPolicy(record?: string) {
  if (!record) return { policy: undefined, subdomainPolicy: undefined };
  const parts = record.split(";").map((p) => p.trim()).filter(Boolean);
  const p = parts.find((x) => x.toLowerCase().startsWith("p="))?.split("=", 2)[1]?.trim();
  const sp = parts.find((x) => x.toLowerCase().startsWith("sp="))?.split("=", 2)[1]?.trim();
  return { policy: p, subdomainPolicy: sp };
}

async function safeResolveTxt(name: string): Promise<string[][] | null> {
  try {
    return await resolveTxt(name);
  } catch {
    return null;
  }
}

async function safeResolveMx(name: string): Promise<string[]> {
  try {
    const mx = await resolveMx(name);
    return mx
      .sort((a, b) => a.priority - b.priority)
      .map((x) => `${x.priority} ${x.exchange}`.trim());
  } catch {
    return [];
  }
}

export async function getEmailSecurity(domain: string): Promise<EmailSecurity> {
  const mx = await safeResolveMx(domain);

  const rootTxt = await safeResolveTxt(domain);
  const spf = rootTxt ? findTxtStartingWith(rootTxt, "v=spf1") : undefined;

  const dmarcName = `_dmarc.${domain}`;
  const dmarcTxt = await safeResolveTxt(dmarcName);
  const dmarc = dmarcTxt ? findTxtStartingWith(dmarcTxt, "v=DMARC1") : undefined;
  const { policy, subdomainPolicy } = parseDmarcPolicy(dmarc);

  // DKIM: selectors cannot be enumerated reliably; this is a best-effort heuristic.
  const commonSelectors = ["default", "selector1", "selector2", "google", "smtp", "mail", "dkim"];
  const foundSelectors: string[] = [];

  for (const sel of commonSelectors) {
    const name = `${sel}._domainkey.${domain}`;
    const txt = await safeResolveTxt(name);
    const maybe = txt ? findTxtStartingWith(txt, "v=DKIM1") : undefined;
    if (maybe) foundSelectors.push(sel);
  }

  const note =
    foundSelectors.length
      ? "DKIM appears enabled for at least one common selector (best-effort check)."
      : "DKIM selector names are not discoverable automatically. Use your email provider’s selector(s) to validate DKIM precisely.";

  return {
    mx,
    spf: { record: spf },
    dmarc: { record: dmarc, policy, subdomainPolicy },
    dkim: { foundSelectors, note }
  };
}
