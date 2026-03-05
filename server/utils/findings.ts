import type { NmapHost } from "./parseNmap";
import type { EmailSecurity } from "./emailSecurity";
import type { WebSecurity } from "./webSecurity";
import type { DnsPosture } from "./dnsPosture";

type Severity = "low" | "medium" | "high";

export type Finding = {
  severity: Severity;
  title: string;
  host?: string;
  details?: string;
  recommendation?: string;
  mitigations?: string[];
  owasp?: string;
};

function uniq(arr: string[]) {
  return Array.from(new Set(arr.filter(Boolean)));
}

export function buildFindings(
  _domain: string,
  hosts: NmapHost[],
  email?: EmailSecurity,
  web?: WebSecurity,
  dns?: DnsPosture
): Finding[] {
  const findings: Finding[] = [];

  // ── EMAIL FINDINGS ──────────────────────────────────────────────
  if (email) {
    if (!email.spf.record) {
      findings.push({
        severity: "high",
        title: "SPF record not found",
        details: "No TXT record starting with v=spf1 was found on the root domain.",
        recommendation: "Publish an SPF record for your sending providers.",
        owasp: "A05 – Security Misconfiguration",
        mitigations: [
          "Identify all authorized senders (Microsoft 365, Google, transactional providers)",
          "Publish SPF (v=spf1 ... ~all) and validate with test mail",
          "Keep SPF under 10 DNS lookups (use includes carefully)",
          "Monitor deliverability + SPF failures",
        ],
      });
    }

    if (!email.dmarc.record) {
      findings.push({
        severity: "high",
        title: "DMARC record not found",
        details: "No DMARC TXT record was found at _dmarc.<domain>.",
        recommendation: "Publish DMARC (start with p=none, then quarantine/reject).",
        owasp: "A05 – Security Misconfiguration",
        mitigations: [
          "Add DMARC record at _dmarc.<domain>",
          "Start with p=none and collect reports (rua) for 1–2 weeks",
          "Fix SPF/DKIM alignment for legitimate senders",
          "Move to p=quarantine, then p=reject",
        ],
      });
    } else {
      const p = (email.dmarc.policy || "").toLowerCase();
      if (p === "none") {
        findings.push({
          severity: "medium",
          title: "DMARC is in monitoring mode (p=none)",
          details: "DMARC will not block spoofing; it only collects reports.",
          recommendation: "Move to p=quarantine/reject after alignment is correct.",
          owasp: "A05 – Security Misconfiguration",
          mitigations: [
            "Confirm SPF passes for legitimate mail streams",
            "Enable DKIM signing for all senders",
            "Verify DMARC alignment (From domain aligns with SPF/DKIM identity)",
            "Change p=none → p=quarantine",
            "Later move p=quarantine → p=reject",
          ],
        });
      } else if (p === "quarantine") {
        findings.push({
          severity: "low",
          title: "DMARC policy is p=quarantine",
          details: "Failing messages are typically sent to spam/junk (some spoofed mail may be delivered).",
          recommendation: "If reports are clean, consider p=reject.",
          mitigations: [
            "Review DMARC reports for false positives",
            "Ensure all legitimate senders pass SPF/DKIM",
            "Move to p=reject when confident",
          ],
        });
      } else if (p === "reject") {
        findings.push({
          severity: "low",
          title: "DMARC policy is reject",
          details: "Failing messages are rejected (strong spoofing protection).",
          mitigations: [
            "Keep monitoring reports",
            "Document authorized senders",
            "Re-check after adding new email services",
          ],
        });
      } else {
        findings.push({
          severity: "medium",
          title: "DMARC policy value is unusual or missing",
          details: `Detected DMARC record but policy parsed as: ${email.dmarc.policy ?? "(none)"}`,
          recommendation: "Ensure a valid p= value exists (none/quarantine/reject).",
          owasp: "A05 – Security Misconfiguration",
          mitigations: [
            "Validate DMARC syntax with a DMARC checker",
            "Ensure record includes: v=DMARC1; p=...",
            "Add rua= mailbox to receive aggregate reports",
          ],
        });
      }

      const sp = (email.dmarc.subdomainPolicy || "").toLowerCase();
      if (!sp && (email.dmarc.policy || "").toLowerCase() !== "reject") {
        findings.push({
          severity: "low",
          title: "DMARC subdomain policy (sp=) not set",
          details: "Subdomains inherit p= by default, but sp= makes intent explicit.",
          recommendation: "Consider sp=quarantine or sp=reject.",
          mitigations: [
            "Decide how subdomains should be treated",
            "Add sp=quarantine or sp=reject",
            "Ensure subdomain mail streams are aligned",
          ],
        });
      }
    }

    if (!email.mx.length) {
      findings.push({
        severity: "low",
        title: "No MX records found",
        details: "If this domain is not used for email, this may be intentional.",
        recommendation: "If you do send/receive email, configure MX records correctly.",
        mitigations: [
          "Confirm whether the domain should receive mail",
          "If yes, add MX records for your provider",
          "If no, consider DMARC + SPF anyway",
        ],
      });
    }
  }

  // ── WEB / TLS FINDINGS ─────────────────────────────────────────
  if (web) {
    if (!web.https.redirect) {
      findings.push({
        severity: "medium",
        title: "HTTP does not redirect to HTTPS",
        details: "Requests to http:// are not being redirected to https://.",
        recommendation: "Configure your server/CDN to issue a 301 redirect from HTTP to HTTPS.",
        owasp: "A02 – Cryptographic Failures",
        mitigations: [
          "Add HTTP → HTTPS redirect in your web server config",
          "Use HSTS after redirect is stable",
          "Test with curl -I http://<domain>/",
        ],
      });
    }

    if (web.https.daysLeft !== undefined && web.https.daysLeft !== null && web.https.daysLeft < 30) {
      const sev: Severity = web.https.daysLeft < 14 ? "high" : "medium";
      findings.push({
        severity: sev,
        title: `TLS certificate expires in ${web.https.daysLeft} day${web.https.daysLeft === 1 ? "" : "s"}`,
        details: `Certificate expiry: ${web.https.certExpiry ?? "unknown"}. Expiring certificates cause browser errors.`,
        recommendation: "Renew the certificate immediately.",
        owasp: "A02 – Cryptographic Failures",
        mitigations: [
          "Renew the TLS certificate before expiry",
          "Enable auto-renewal (e.g. Let's Encrypt + certbot --renew-hook)",
          "Set up monitoring/alerts for cert expiry",
        ],
      });
    }

    if (!web.headers.hsts) {
      findings.push({
        severity: "medium",
        title: "HSTS missing",
        details: "Strict-Transport-Security header not present. Browsers may allow downgrade attacks.",
        recommendation: "Enable HSTS (Strict-Transport-Security).",
        owasp: "A05 – Security Misconfiguration",
        mitigations: [
          "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
          "Start with a short max-age while testing",
          "Consider adding to HSTS preload list (hstspreload.org) once stable",
        ],
      });
    }

    if (!web.headers.csp) {
      findings.push({
        severity: "medium",
        title: "CSP missing",
        details: "Content-Security-Policy header not present. No protection against XSS injection.",
        recommendation: "Add a Content-Security-Policy (start with report-only mode if needed).",
        owasp: "A03 – Injection",
        mitigations: [
          "Start with Content-Security-Policy-Report-Only to audit violations",
          "Restrict script sources (e.g. 'self' + explicit CDN domains)",
          "Avoid 'unsafe-inline' and 'unsafe-eval'",
          "Graduate to enforcing CSP after validation",
        ],
      });
    }

    // Collect missing security headers
    const missingHeaders: string[] = [];
    if (!web.headers.xContentTypeOptions) missingHeaders.push("x-content-type-options");
    if (!web.headers.xFrameOptions) missingHeaders.push("x-frame-options");
    if (!web.headers.referrerPolicy) missingHeaders.push("referrer-policy");
    if (!web.headers.permissionsPolicy) missingHeaders.push("permissions-policy");

    if (missingHeaders.length > 0) {
      findings.push({
        severity: "low",
        title: "Missing security headers",
        details: `Missing: ${missingHeaders.join(", ")}`,
        recommendation: "Add the missing security headers to your web server or CDN configuration.",
        owasp: "A05 – Security Misconfiguration",
        mitigations: missingHeaders.map((h) => {
          if (h === "x-content-type-options") return "Add: X-Content-Type-Options: nosniff";
          if (h === "x-frame-options") return "Add: X-Frame-Options: DENY (or SAMEORIGIN)";
          if (h === "referrer-policy") return "Add: Referrer-Policy: strict-origin-when-cross-origin";
          if (h === "permissions-policy") return "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()";
          return `Add ${h} header`;
        }),
      });
    }
  }

  // ── DNS POSTURE FINDINGS ────────────────────────────────────────
  if (dns) {
    if (!dns.caa.found) {
      findings.push({
        severity: "low",
        title: "No CAA record",
        details: "No CAA record found — any CA may issue certificates for this domain.",
        recommendation: "Add a CAA record to restrict which CAs can issue certificates.",
        owasp: "A05 – Security Misconfiguration",
        mitigations: [
          "Determine which CA(s) you use (e.g. Let's Encrypt, DigiCert)",
          "Add: <domain> CAA 0 issue \"letsencrypt.org\"",
          "Add iodef= to receive misissuance reports",
          "Validate with: dig CAA <domain>",
        ],
      });
    }

    if (!dns.dnssec.detected) {
      findings.push({
        severity: "low",
        title: "DNSSEC not detected",
        details: "No DNSKEY record found. DNS responses are not cryptographically signed.",
        recommendation: "Consider enabling DNSSEC if supported by your registrar/DNS provider.",
        owasp: "A08 – Software and Data Integrity Failures",
        mitigations: [
          "Check if your registrar supports DNSSEC",
          "Enable DNSSEC in your DNS provider dashboard",
          "Validate with: dig +dnssec DNSKEY <domain>",
          "Verify DS record is published at the registry",
        ],
      });
    }

    if (!dns.mtaSts.found) {
      findings.push({
        severity: "low",
        title: "MTA-STS not detected",
        details: "No _mta-sts TXT record found. Inbound mail TLS is not enforced.",
        recommendation: "Consider enabling MTA-STS to harden inbound mail transport security.",
        mitigations: [
          "Publish _mta-sts.<domain> TXT record: v=STSv1; id=<timestamp>",
          "Host policy at https://mta-sts.<domain>/.well-known/mta-sts.txt",
          "Set mode: enforce (or testing first)",
          "Enable TLS-RPT alongside MTA-STS for reporting",
        ],
      });
    }

    if (!dns.tlsRpt.found) {
      findings.push({
        severity: "low",
        title: "TLS-RPT not detected",
        details: "No _smtp._tls TXT record found. No reports about mail TLS failures are collected.",
        recommendation: "Enable TLS-RPT to receive reports about mail transport TLS issues.",
        mitigations: [
          "Publish _smtp._tls.<domain> TXT: v=TLSRPTv1; rua=mailto:<report-address>",
          "Use a reporting mailbox or a TLS-RPT reporting service",
          "Review reports to detect TLS delivery failures",
        ],
      });
    }
  }

  // ── NETWORK FINDINGS ───────────────────────────────────────────
  for (const h of hosts) {
    const open = h.ports.filter((p) => p.state === "open");
    const has = (port: number) => open.some((p) => p.port === port);

    if (has(22)) {
      findings.push({
        severity: "medium",
        title: "SSH exposed to the internet (port 22)",
        host: h.target,
        recommendation: "Restrict SSH and enforce strong auth.",
        owasp: "A01 – Broken Access Control",
        mitigations: [
          "Restrict SSH to VPN / allowlisted IPs",
          "Disable password auth; use SSH keys",
          "Enable MFA where possible",
          "Harden SSH config (no root login, modern ciphers)",
          "Monitor logs and add ban rules",
        ],
      });
    }

    if (has(3389)) {
      findings.push({
        severity: "high",
        title: "RDP exposed to the internet (port 3389)",
        host: h.target,
        recommendation: "Close or restrict heavily (VPN/gateway).",
        owasp: "A01 – Broken Access Control",
        mitigations: [
          "Remove public exposure (firewall)",
          "Use VPN / Remote Desktop Gateway",
          "Enable MFA",
          "Monitor brute-force attempts",
        ],
      });
    }

    if (has(80) && !has(443)) {
      findings.push({
        severity: "medium",
        title: "HTTP open without HTTPS",
        host: h.target,
        recommendation: "Enable TLS (443) and redirect 80 → 443.",
        owasp: "A02 – Cryptographic Failures",
        mitigations: [
          "Enable HTTPS with a valid certificate",
          "Redirect HTTP to HTTPS",
          "Add HSTS once stable",
          "Set secure headers (CSP, etc.)",
        ],
      });
    }

    if (has(25)) {
      findings.push({
        severity: "medium",
        title: "SMTP exposed (port 25)",
        host: h.target,
        recommendation: "Ensure it's intended and hardened.",
        mitigations: [
          "Confirm SMTP is needed publicly",
          "Patch regularly",
          "Use SPF/DKIM/DMARC",
          "Restrict relay",
          "Monitor abuse + blocklists",
        ],
      });
    }

    if (has(3306) || has(5432) || has(27017)) {
      findings.push({
        severity: "high",
        title: "Database port exposed to the internet",
        host: h.target,
        details: "Detected common DB ports (3306/5432/27017).",
        recommendation: "Databases should not be public.",
        owasp: "A01 – Broken Access Control",
        mitigations: [
          "Move DB to private network/VPC",
          "Firewall DB ports",
          "Require VPN/bastion for admin access",
          "Rotate credentials and enable TLS",
        ],
      });
    }
  }

  if (hosts.length >= 10) {
    findings.push({
      severity: "low",
      title: "Large number of discovered hosts/subdomains",
      details: `${hosts.length} hosts were scanned. Larger surface area usually increases risk.`,
      recommendation: "Decommission unused subdomains/systems.",
      mitigations: uniq([
        "Inventory subdomains and owners",
        "Remove stale dev/test/staging systems",
        "Ensure consistent TLS and auth policy",
        "Centralize DNS and certificate management",
      ]),
    });
  }

  return findings;
}
