# Domain Security Posture Analyzer
## Presentation & Technical Reference
**Version:** 1.6.0 | **Stack:** Nuxt 3 · Node.js · Amass · Nmap

---

## Slide 1 — What Is It?

**Domain Security Posture Analyzer** — an automated tool that assesses a domain's security posture using only **public signals** (DNS, HTTP/TLS, CT logs).

**This is NOT a penetration test.** It is a passive OSINT assessment tool.

### What it analyzes:
- Email authentication (SPF, DMARC, DKIM)
- DNS security (CAA, DNSSEC, MTA-STS)
- Web and TLS configuration
- Subdomain discovery and takeover risks
- Open port scanning
- Technology stack fingerprinting
- Hidden endpoint discovery

---

## Slide 2 — Architecture

```
         User enters a domain
                  │
                  ▼
     ┌────────────────────────┐
     │   POST /api/scan       │  ← Nuxt 3 Nitro server
     │   Rate limit: 6/min    │
     └────────────┬───────────┘
                  │
         ┌────────▼────────┐
         │ Email Security  │  ← SPF · DMARC · DKIM · MX
         └────────┬────────┘
                  │ (parallel)
    ┌─────────────┼──────────────┐
    ▼             ▼              ▼
┌───────┐  ┌──────────┐  ┌──────────────┐
│  Web  │  │   DNS    │  │  [continues] │
│ & TLS │  │ Posture  │  │              │
└───┬───┘  └────┬─────┘  └──────────────┘
    └───────────┘
                  │
         ┌────────▼────────┐
         │ Subdomain       │  ← Amass passive (fallback: crt.sh)
         │ Discovery       │    max 300 subdomains
         └────────┬────────┘
                  │
         ┌────────▼────────┐
         │ Nmap Port Scan  │  ← -sT -sV, top 100 ports, max 30 hosts
         └────────┬────────┘
                  │ (all parallel)
    ┌─────────────┼─────────────────────────┐
    ▼             ▼           ▼             ▼
┌────────┐ ┌──────────┐ ┌────────┐ ┌──────────────┐
│Takeover│ │   Tech   │ │  TLS   │ │  Endpoint    │
│ Check  │ │Fingerpr. │ │  Deep  │ │  Discovery   │
└────────┘ └──────────┘ └────────┘ └──────────────┘
                  │
         ┌────────▼────────┐
         │ Findings +      │
         │ Risk Score      │
         └────────┬────────┘
                  │
         ┌────────▼────────┐
         │  MD / PDF / JSON│  ← Report export
         └─────────────────┘
```

---

## Slide 3 — Module 1: Email Security

**File:** `server/utils/emailSecurity.ts`

### SPF (Sender Policy Framework)
- Checks for `v=spf1` TXT record existence
- Counts DNS lookup mechanisms (`include:`, `a:`, `mx:`, `ptr:`)
- Evaluates: `+all` (dangerous) → `~all` (softfail) → `-all` (hardfail)

### DMARC
- Checks `_dmarc.<domain>` TXT record
- Extracts fields: `p=` (policy), `sp=` (subdomain policy), `rua=` (reporting emails)
- Policies: `none` → `quarantine` → `reject`

### DKIM — 13 selectors tested
| Selector | Used by |
|----------|---------|
| `default` | Generic |
| `selector1`, `selector2` | Microsoft 365 |
| `google` | Google Workspace |
| `smtp`, `mail`, `dkim` | Various |
| `s1`, `s2`, `k1`, `k2` | Various |
| `em` | SendGrid |
| `pm` | Postmark |

Detection: CNAME check (Microsoft 365 delegation pattern) + TXT (`v=DKIM1`, `k=rsa`, `k=ed25519`)

### MX Provider Detection
| Provider | Confidence |
|----------|-----------|
| Microsoft 365 | high |
| Google Workspace | high |
| Proofpoint | high |
| Mandrill / Mailchimp | high |
| SendGrid | medium |
| Postmark | medium |

---

## Slide 4 — Module 2: DNS Security

**File:** `server/utils/dnsPosture.ts`

### Checks performed
| Check | Method | Purpose |
|---|---|---|
| **CAA** | DNS lookup | Restricts which CAs can issue certificates |
| **DNSSEC** | Cloudflare DoH API (type 48) | Cryptographic signing of DNS responses |
| **MTA-STS** | `_mta-sts.<domain>` TXT | Enforces TLS on inbound mail transport |
| **TLS-RPT** | `_smtp._tls.<domain>` TXT | Collects TLS failure reports |

### 12 Common subdomains checked for existence
```
mail · webmail · smtp · imap · pop
autodiscover · autoconfig
vpn · admin · dev · staging · api
```
Checked via: A / AAAA / CNAME records

---

## Slide 5 — Module 3: Web & HTTP Security

**File:** `server/utils/webSecurity.ts`

### Security Headers
| Header | Score | Risk if missing |
|--------|-------|----------------|
| `Strict-Transport-Security` (HSTS) | 10 | Downgrade attacks |
| `Content-Security-Policy` (CSP) | 10 | XSS injection |
| `X-Content-Type-Options` | 4 | MIME sniffing |
| `X-Frame-Options` | 4 | Clickjacking |
| `Referrer-Policy` | 3 | Information leakage |
| `Permissions-Policy` | 3 | Unauthorized API access |

### Additional checks
- HTTP → HTTPS redirect (301)
- TLS certificate expiry in days (raw socket connection)
- `Set-Cookie` header count
- `security.txt` (RFC 9116) — `/.well-known/security.txt`
- `robots.txt` existence + **Disallow** path extraction

### Robots.txt Intelligence (NEW)
All `Disallow:` entries extracted → checked for sensitive path disclosure (`/admin`, `/backup`, `/api`, `/config`, `/internal`)

---

## Slide 6 — Module 4: Subdomain Discovery

**File:** `server/api/scan.post.ts`

### Primary: Amass (passive mode)
```bash
amass enum -passive -d example.com -timeout 3
```
- Passive mode only (no active DNS bruteforce)
- Timeout: 3 minutes
- Limit: 300 subdomains

### Fallback: crt.sh Certificate Transparency
```
https://crt.sh/?q=%.example.com&output=json
```
- Automatically used when Amass is unavailable or fails
- Extracts subdomains from TLS certificate CT logs
- Deduplicated and normalized (lowercase, filtered to target domain)

---

## Slide 7 — Module 5: Port Scanning

**File:** `server/utils/parseNmap.ts`

### Nmap command
```bash
nmap -sT -sV -Pn --top-ports 100 --host-timeout 20s -oX - [targets]
```

| Flag | Meaning |
|------|---------|
| `-sT` | TCP connect scan (no root required) |
| `-sV` | Service version detection |
| `-Pn` | Skip ping (assume hosts up) |
| `--top-ports 100` | Top 100 most common ports |
| `--host-timeout 20s` | 20 second limit per host |
| `-oX -` | XML output to stdout |

**Limit:** max 30 hosts per scan
**Timeout:** 120 seconds total for all targets

### What is detected
- Open ports and protocols
- Service name (http, ssh, smtp, mysql...)
- Product and version (nginx/1.24, OpenSSH 8.9...)

---

## Slide 8 — Module 6: Subdomain Takeover Detection (NEW)

**File:** `server/utils/takeoverCheck.ts`

### What is a subdomain takeover?
When a subdomain has a CNAME pointing to a SaaS platform, but that service **no longer exists** — an attacker can claim it and control its content.

```
blog.example.com → CNAME → blog.herokuapp.com
Heroku app deleted → "No such app" error page
→ Attacker creates a new Heroku app = takeover
```

### 12 SaaS Platforms Checked
| Platform | CNAME Pattern |
|----------|--------------|
| GitHub Pages | `*.github.io` |
| Heroku | `*.herokuapp.com` |
| Azure Web Apps | `*.azurewebsites.net` |
| AWS CloudFront | `*.cloudfront.net` |
| Netlify | `*.netlify.app` |
| Surge.sh | `*.surge.sh` |
| Fastly | `*.fastly.net` |
| Zendesk | `*.zendesk.com` |
| Shopify | `*.myshopify.com` |
| Ghost | `*.ghost.io` |
| Webflow | `*.webflow.io` |
| Fly.io | `*.fly.dev` |

### Detection logic
```
1. Resolve subdomain's CNAME record (DNS)
2. Check if CNAME matches a known SaaS pattern
3. HTTP GET request to the subdomain
4. Search response body for known "takeover fingerprint"
   (e.g. "No such app", "project not found")
5. If found → Takeover possible (HIGH severity finding)
```

**Limit:** up to 60 subdomains, executed in parallel

---

## Slide 9 — Module 7: Technology Fingerprinting (NEW)

**File:** `server/utils/techFingerprint.ts`

Analyzed from: HTTP response headers + HTML body (first 80KB)

### CDNs (7 detected)
| CDN | Detection method |
|-----|-----------------|
| Cloudflare | `cf-ray`, `cf-cache-status` headers |
| AWS CloudFront | `x-amz-cf-id`, `x-amz-cf-pop` |
| Vercel | `x-vercel-id`, `x-vercel-cache` |
| Netlify | `x-nf-request-id` |
| Akamai | `x-check-cacheable`, `akamai-grn` |
| Fastly | `x-served-by`, `x-fastly-request-id` |
| BunnyCDN | `bunny-request-id` |

### Frameworks (12 detected)
`Next.js` · `Nuxt.js` · `React` · `Angular` · `Vue.js` · `WordPress` · `Shopify` · `Wix` · `Squarespace` · `Drupal` · `Joomla` · `Ghost`

### Backends / Web servers (11 detected)
PHP · ASP.NET · Express · Ruby on Rails · Java · Next.js · nginx · Apache · IIS · LiteSpeed · Caddy

### Analytics tools (9 detected)
Google Analytics · Google Tag Manager · Hotjar · Segment · Mixpanel · Intercom · Crisp · HubSpot · Salesforce

### Hosting providers (3 detected)
Vercel · Netlify · AWS CloudFront

---

## Slide 10 — Module 8: Deep TLS Analysis (NEW)

**File:** `server/utils/tlsDeep.ts`

### Collected data (raw TLS socket connection)
| Data point | What it reveals |
|------------|----------------|
| Negotiated TLS version | TLSv1.2 or TLSv1.3 |
| Cipher suite name | Which encryption combination is used |
| Weak cipher flag | Whether a dangerous algorithm is in use |
| Self-signed flag | Whether the cert is signed by itself |
| Issuer organization | Which CA issued the certificate |

### 8 Weak Cipher Keywords
```
RC4  · DES  · 3DES · NULL
EXPORT · ANON · MD5 · RC2
```

### Self-signed detection logic
```
Issuer.CN == Subject.CN  AND  Issuer.O == Subject.O
→ Certificate is self-signed → HIGH severity finding
```

### Risk table
| Finding | Severity | Score penalty |
|---------|----------|--------------|
| Weak cipher detected | MEDIUM | -10 |
| Self-signed certificate | HIGH | -10 |

---

## Slide 11 — Module 9: Hidden Endpoint Discovery (NEW)

**File:** `server/utils/endpointDiscovery.ts`

### Method
```
GET https://example.com/[path]
Timeout: 6 seconds per path
Concurrency: all 36 paths in parallel
Reported: HTTP 200, 401, 403
```

### 36 Paths Probed
**Sensitive (HIGH severity if HTTP 200):**
```
/.git/HEAD    /.env        /.env.local
/phpinfo.php  /info.php    /phpmyadmin
/debug        /backup      /backup.zip
/backup.tar.gz /config     /config.json
/server-status /server-info /actuator/env
/console
```

**Admin / Login (MEDIUM severity):**
```
/admin    /administrator    /login
/signin   /dashboard
```

**API / Documentation:**
```
/api    /api/v1    /api/v2
/swagger   /swagger-ui.html   /swagger-ui/index.html
/openapi.json   /openapi.yaml
/graphql   /metrics
/health   /healthz   /status
/actuator   /actuator/health
/.well-known/security.txt
/wp-admin   /wp-login.php
```

### HTTP Status Interpretation
| HTTP Status | Meaning |
|-------------|---------|
| 200 | Endpoint exists and is accessible |
| 401 | Exists but requires authentication |
| 403 | Exists but access is denied |
| 404 | Does not exist (not reported) |
| 3xx | Redirect (not reported) |

---

## Slide 12 — Findings and OWASP Top 10 Mapping

### All 28 Finding Types

**OWASP A01 — Broken Access Control**
| Finding | Severity |
|---------|----------|
| SSH exposed to the internet (port 22) | MEDIUM |
| RDP exposed to the internet (port 3389) | HIGH |
| Database ports exposed (3306/5432/27017) | HIGH |
| Admin/login interface publicly accessible | MEDIUM |
| Subdomain takeover possible | HIGH |

**OWASP A02 — Cryptographic Failures**
| Finding | Severity |
|---------|----------|
| HTTP does not redirect to HTTPS | MEDIUM |
| TLS certificate expires in < 30 days | MEDIUM |
| TLS certificate expires in < 14 days | HIGH |
| HSTS header missing | MEDIUM |
| Weak TLS cipher suite detected | MEDIUM |
| Self-signed TLS certificate | HIGH |
| HTTP open without HTTPS (port 80, no 443) | MEDIUM |

**OWASP A03 — Injection**
| Finding | Severity |
|---------|----------|
| Content-Security-Policy (CSP) missing | MEDIUM |

**OWASP A05 — Security Misconfiguration**
| Finding | Severity |
|---------|----------|
| SPF record not found | HIGH |
| DMARC record not found | HIGH |
| DMARC p=none (monitoring mode only) | MEDIUM |
| DMARC p=quarantine | LOW |
| DMARC p=reject | LOW |
| DMARC subdomain policy (sp=) not set | LOW |
| No MX records found | LOW |
| Missing security headers* | LOW |
| No CAA record | LOW |
| Sensitive path accessible (/.git, /.env…) | HIGH |
| Sensitive paths disclosed in robots.txt | LOW |

*Missing headers: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy

**OWASP A08 — Software and Data Integrity Failures**
| Finding | Severity |
|---------|----------|
| DNSSEC not detected | LOW |

**Other**
| Finding | Severity |
|---------|----------|
| MTA-STS not detected | LOW |
| TLS-RPT not detected | LOW |
| DMARC policy value unusual or missing | MEDIUM |
| Large number of discovered hosts (≥10) | LOW |
| SMTP exposed (port 25) | MEDIUM |

---

## Slide 13 — Scoring System

### Principle
**Start at 0** → Add points for good configurations → Deduct for critical issues

**Maximum: 100 points**

### Score breakdown table
| Component | Points | Condition |
|-----------|--------|-----------|
| SPF present | 5 | Record found |
| SPF hardfail bonus | +5 | If `-all` |
| DMARC present | 5 | Record found |
| DMARC quarantine | +5 | If `p=quarantine` |
| DMARC reject | +10 | If `p=reject` |
| DKIM found | 8 | At least one selector |
| HTTP→HTTPS redirect | 5 | Redirects correctly |
| TLS cert valid | 4 | > 30 days remaining |
| HSTS | 10 | Header present |
| CSP | 10 | Header present |
| X-Content-Type-Options | 4 | Header present |
| X-Frame-Options | 4 | Header present |
| Referrer-Policy | 3 | Header present |
| Permissions-Policy | 3 | Header present |
| CAA | 6 | DNS record found |
| DNSSEC | 6 | DNSKEY record found |
| MTA-STS | 5 | DNS record found |
| TLS-RPT | 3 | DNS record found |
| security.txt | 2 | File found |
| robots.txt | 2 | File found |
| **Total** | **100** | |

### Penalties (from new modules)
| Issue | Penalty |
|-------|---------|
| Subdomain takeover detected | **-20** |
| Weak TLS cipher suite | **-10** |
| Self-signed certificate | **-10** |

### Risk levels
| Score | Level |
|-------|-------|
| ≥ 70 | 🟢 Low risk |
| 45–69 | 🟡 Medium risk |
| 25–44 | 🔴 High risk |
| < 25 | ⛔ Critical risk |

---

## Slide 14 — Safety and Limitations

### Protection mechanisms built in
| Mechanism | Parameters |
|-----------|-----------|
| Rate limiting | 6 scans / IP / 60 seconds |
| Domain validation | Regex: `[a-z0-9-]+(\.[a-z0-9-]+)+` |
| Amass mode | Passive only (no DNS bruteforce) |
| Nmap scan type | TCP connect (`-sT`) — no root required |
| Subdomain limit | max 300 discovered, max 30 scanned |
| Endpoint probe timeout | 6 seconds per path |

### This tool does NOT:
- Perform active penetration testing
- Scan for CVEs or known vulnerabilities
- Brute-force authentication
- Test for SQL injection or payload injection
- Attempt any form of exploit

### Responsible use notice
> "Only scan systems you own or have explicit permission to test."

---

## Slide 15 — Statistics Summary

### All numbers at a glance

| Module | Count |
|--------|-------|
| SaaS platforms checked (takeover) | **12** |
| CDN fingerprint rules | **7** |
| Framework detections | **12** |
| Backend / server detections | **11** |
| Analytics tools detected | **9** |
| Endpoint paths probed | **36** |
| DKIM selectors tested | **13** |
| Weak cipher keywords | **8** |
| Common subdomains checked | **12** |
| Finding types | **28** |
| OWASP categories covered | **5** |
| Maximum security score | **100** |
| Scan pipeline stages | **9** |

---

## Slide 16 — Technology Stack

### Frontend
- **Nuxt 3** (Vue 3 + Nitro)
- **@nuxt/ui** (Tailwind CSS component library)
- **Mermaid** — subdomain graph visualization
- **pdf-lib** — PDF export

### Backend (Nuxt Nitro server routes)
- **Node.js** built-in: `dns/promises`, `tls`, `child_process`
- **fast-xml-parser** — Nmap XML output parsing
- **Amass** — passive subdomain discovery (external tool)
- **Nmap** — TCP port scanning (external tool)

### External APIs (read-only)
- **Cloudflare DoH** (`1.1.1.1/dns-query`) — DNSSEC validation
- **crt.sh** (`crt.sh/?q=%.domain&output=json`) — Certificate Transparency logs

### Export formats
- Markdown (`.md`)
- PDF (multi-page, text-wrapped)
- JSON (copy to clipboard)

---

## Slide 17 — Scan Pipeline Timeline

```
Time →    0s         10s        30s        90s       210s
          │           │          │          │          │
Email     ├───────────┤
Web+DNS   ├───────────┤
          │
Amass     ├─────────────────────────────────┤  (up to 3 min)
          │
Nmap      │           ├───────────────────┤  (up to 120s)
          │
Parallel: │                     ├──────────┤
 Takeover │                     │          │
 TechFP   │                     │          │
 TLS Deep │                     │          │
 Endpoints│                     │          │
          │
Report    │                                ├──┤
```

**Typical scan duration:** 2–3 minutes (depending on the domain)

---

## Slide 18 — Report Structure

### API Response (`POST /api/scan`)
```json
{
  "domain": "example.com",
  "score": { "score": 67, "riskLevel": "Medium risk", "breakdown": {} },
  "email": { "mx": [], "spf": {}, "dmarc": {}, "dkim": {} },
  "web": { "https": {}, "headers": {}, "cookies": {}, "robotsTxtPaths": [] },
  "dnsPosture": { "caa": {}, "dnssec": {}, "mtaSts": {}, "tlsRpt": {}, "commonSubdomains": [] },
  "subdomains": ["dev.example.com", "api.example.com"],
  "hosts": [{ "target": "...", "ports": [] }],
  "findings": [{ "severity": "high", "title": "...", "owasp": "A01", "mitigations": [] }],
  "techStack": { "cdn": "Cloudflare", "framework": "Next.js", "analytics": ["GTM"] },
  "tlsDeep": { "negotiatedVersion": "TLSv1.3", "cipher": "...", "weakCipher": false },
  "endpoints": [{ "path": "/admin", "status": 403, "sensitive": false }],
  "takeovers": [],
  "meta": { "toolStatus": { "amass": {}, "nmap": {} } }
}
```

---

## Slide 19 — Example Findings (Real Scan)

### Sample report: 39/100 — High risk

```
Score: 39/100 — High risk

[HIGH] SPF record not found
→ Anyone can spoof email from this domain

[HIGH] DMARC record not found
→ No email spoofing protection in place

[MEDIUM] HSTS missing
→ Downgrade attacks are possible

[MEDIUM] CSP missing
→ XSS attacks are not mitigated

[LOW] No CAA record
→ Any Certificate Authority may issue a cert

[LOW] DNSSEC not detected
→ DNS responses are not cryptographically signed

Score breakdown:
  SPF:           0 / 10
  DMARC:         0 / 15
  DKIM:          0 / 8
  HSTS:          0 / 10
  CSP:           0 / 10
  HTTPS redirect: 5 / 5
  TLS cert:      4 / 4
  CAA:           0 / 6
  DNSSEC:        0 / 6
```

---

## Slide 20 — Comparison with Commercial Tools

### Feature coverage matrix

| Feature | This tool | Wappalyzer | SecurityHeaders.com | Shodan | OWASP ZAP |
|---------|:---------:|:----------:|:-------------------:|:------:|:---------:|
| Technology fingerprinting | ✓ | ✓ | — | — | — |
| Security headers check | ✓ | — | ✓ | — | ✓ |
| Email security (SPF/DKIM/DMARC) | ✓ | — | — | — | — |
| Port scanning | ✓ | — | — | ✓ | — |
| Subdomain discovery | ✓ | — | — | ✓ | — |
| Subdomain takeover check | ✓ | — | — | — | — |
| Hidden endpoint discovery | ✓ | — | — | — | ✓ |
| TLS deep analysis | ✓ | — | ✓ | — | ✓ |
| Risk scoring (0–100) | ✓ | — | ✓ | — | — |
| MD / PDF report export | ✓ | — | ✓ | — | ✓ |
| Open source | ✓ | ✓ | — | — | ✓ |
| Passive scan only | ✓ | ✓ | ✓ | — | — |
| No auth required | ✓ | ✓ | ✓ | API key | — |

---

*This document was generated from `osint-dashboard` v1.6.0 source code.*
*Source files: `server/utils/` · `server/api/scan.post.ts` · `pages/index.vue`*
