# Domain Security Posture Analyzer
## Presentation & Technical Reference
**Version:** 1.6.0 | **Stack:** Nuxt 3 · Node.js · Amass · Nmap

---

## Slide 1 — Kas tai?

**Domain Security Posture Analyzer** — automatizuotas įrankis, kuris tikrina domeno saugumo būklę naudodamas tik **viešus signalus** (DNS, HTTP/TLS, CT logai).

**Tai nėra penetracijos testas.** Tai pasyvus OSINT įrankis.

### Analizuojama:
- El. pašto apsauga (SPF, DMARC, DKIM)
- DNS saugumas (CAA, DNSSEC, MTA-STS)
- Web ir TLS konfigūracija
- Subdomainų Discovery ir Takeover rizikos
- Atvirų portų skenavimas
- Technologijų atpažinimas
- Paslėptų endpoints radimas

---

## Slide 2 — Architektūra

```
         Vartotojas įveda domeną
                  │
                  ▼
     ┌────────────────────────┐
     │   POST /api/scan       │  ← Nuxt 3 Nitro serveris
     │   Rate limit: 6/min    │
     └────────────┬───────────┘
                  │
         ┌────────▼────────┐
         │ Email Security  │  ← SPF · DMARC · DKIM · MX
         └────────┬────────┘
                  │ (lygiagrečiai)
    ┌─────────────┼──────────────┐
    ▼             ▼              ▼
┌───────┐  ┌──────────┐  ┌──────────────┐
│  Web  │  │   DNS    │  │   [toliau]   │
│ & TLS │  │ Posture  │  │              │
└───┬───┘  └────┬─────┘  └──────────────┘
    └───────────┘
                  │
         ┌────────▼────────┐
         │ Subdomainų      │  ← Amass passive (fallback: crt.sh)
         │ Discovery       │    max 300 subdomainų
         └────────┬────────┘
                  │
         ┌────────▼────────┐
         │ Nmap Port Scan  │  ← -sT -sV, top 100 portų, max 30 hostų
         └────────┬────────┘
                  │ (visi lygiagrečiai)
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
         │  MD / PDF / JSON│  ← Ataskaita
         └─────────────────┘
```

---

## Slide 3 — Modulis 1: El. pašto saugumas

**Failas:** `server/utils/emailSecurity.ts`

### SPF (Sender Policy Framework)
- Tikrinama ar egzistuoja `v=spf1` TXT įrašas
- Skaičiuojamas lookup mechanizmų kiekis (`include:`, `a:`, `mx:`, `ptr:`)
- Vertinama: `+all` (pavojinga) → `~all` (softfail) → `-all` (hardfail)

### DMARC
- Tikrinama `_dmarc.<domain>` TXT įrašas
- Ištraukiami laukai: `p=` (politika), `sp=` (subdomenai), `rua=` (ataskaitos)
- Politikos: `none` → `quarantine` → `reject`

### DKIM — 13 selektorių testuojama
| Selektorius | Naudoja |
|-------------|---------|
| `default` | Bendras |
| `selector1`, `selector2` | Microsoft 365 |
| `google` | Google Workspace |
| `smtp`, `mail`, `dkim` | Įvairūs |
| `s1`, `s2`, `k1`, `k2` | Įvairūs |
| `em` | SendGrid |
| `pm` | Postmark |

Tikrinama CNAME (Microsoft 365 pattern) ir TXT (`v=DKIM1`, `k=rsa`, `k=ed25519`)

### MX Tiekėjų atpažinimas
| Tiekėjas | Pasitikėjimas |
|----------|--------------|
| Microsoft 365 | high |
| Google Workspace | high |
| Proofpoint | high |
| Mandrill/Mailchimp | high |
| SendGrid | medium |
| Postmark | medium |

---

## Slide 4 — Modulis 2: DNS Saugumas

**Failas:** `server/utils/dnsPosture.ts`

### Tikrinimai
| Patikrinimas | Metodas | Kam skirtas |
|---|---|---|
| **CAA** | DNS lookup | Apriboja, kurie CA gali išduoti sertifikatą |
| **DNSSEC** | Cloudflare DoH API (type 48) | DNS atsakymų kriptografinis pasirašymas |
| **MTA-STS** | `_mta-sts.<domain>` TXT | El. pašto transporto TLS enforcinimas |
| **TLS-RPT** | `_smtp._tls.<domain>` TXT | TLS klaidų ataskaitų surinkimas |

### 12 Bendrų subdomainų tikrinamas egzistavimas
```
mail · webmail · smtp · imap · pop
autodiscover · autoconfig
vpn · admin · dev · staging · api
```
Tikrinama: A / AAAA / CNAME įrašai

---

## Slide 5 — Modulis 3: Web ir HTTP Saugumas

**Failas:** `server/utils/webSecurity.ts`

### Saugumo antraštės
| Antraštė | Taškai | Rizika be jos |
|----------|--------|--------------|
| `Strict-Transport-Security` (HSTS) | 10 | Downgrade atakos |
| `Content-Security-Policy` (CSP) | 10 | XSS injekcija |
| `X-Content-Type-Options` | 4 | MIME sniffing |
| `X-Frame-Options` | 4 | Clickjacking |
| `Referrer-Policy` | 3 | Duomenų nutekėjimas |
| `Permissions-Policy` | 3 | Neteisėtos API prieigos |

### Papildomi tikrinimai
- HTTP → HTTPS peradresavimas (301)
- TLS sertifikato galiojimo dienos (raw socket)
- `Set-Cookie` antraščių kiekis
- `security.txt` (RFC 9116) — `/.well-known/security.txt`
- `robots.txt` egzistavimas + **Disallow** kelių ištraukimas

### Robots.txt Intelligence (NAUJAS)
Ištraukiami visi `Disallow:` įrašai → tikrinama ar neatskleidžiami jautrūs keliai (`/admin`, `/backup`, `/api`, `/config`, `/internal`)

---

## Slide 6 — Modulis 4: Subdomainų Discovery

**Failas:** `server/api/scan.post.ts`

### Pagrindinis: Amass (pasyvus)
```bash
amass enum -passive -d example.com -timeout 3
```
- Pasyvus režimas (be aktyvaus DNS bruteforce)
- Timeout: 3 sekundės
- Limitas: 300 subdomainų

### Fallback: crt.sh Certificate Transparency
```
https://crt.sh/?q=%.example.com&output=json
```
- Automatiškai naudojamas jei Amass nėra ar nepavyksta
- Ištraukia subdomainus iš TLS sertifikato CT logų
- Deduplikuojama, normalizuojama (lowercase, filtruojama pagal domeną)

---

## Slide 7 — Modulis 5: Portų Skenavimas

**Failas:** `server/utils/parseNmap.ts`

### Nmap komanda
```bash
nmap -sT -sV -Pn --top-ports 100 --host-timeout 20s -oX - [targets]
```

| Flag | Reikšmė |
|------|---------|
| `-sT` | TCP connect scan (be root teisių) |
| `-sV` | Versijų detekcija |
| `-Pn` | Skip ping (assume host up) |
| `--top-ports 100` | Top 100 dažniausiai naudojamų portų |
| `--host-timeout 20s` | 20 sekundžių limitas vienam hostui |
| `-oX -` | XML output į stdout |

**Limitas:** max 30 hostų vienu metu
**Timeout:** 120 sekundžių visiems tikslams

### Aptinkama
- Atviri portai ir jų protokolai
- Paslauga (http, ssh, smtp, mysql...)
- Produktas ir versija (nginx/1.24, OpenSSH 8.9...)

---

## Slide 8 — Modulis 6: Subdomain Takeover Detection (NAUJAS)

**Failas:** `server/utils/takeoverCheck.ts`

### Kas tai?
Kai subdomainas turi CNAME į SaaS platformą, bet ta paslauga **nebegyvena** — užpuolikas gali ją "paimti" ir valdyti turinį.

```
blog.example.com → CNAME → blog.herokuapp.com
Heroku app ištrintas → "No such app" klaida
→ Užpuolikas sukuria naują Heroku app = takeover
```

### 12 SaaS Platformų Tikrinamos
| Platforma | CNAME Pattern |
|-----------|--------------|
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

### Detekcijos logika
```
1. Gauti subdomaino CNAME įrašą (DNS)
2. Patikrinti ar CNAME atitinka žinomą SaaS pattern
3. HTTP GET į subdomainą
4. Ieškoti "fingerprint" klaidos atsakyme
   (pvz: "No such app", "project not found")
5. Jei rasta → Takeover galimas (HIGH severity)
```

**Limitas:** iki 60 subdomainų, lygiagrečiai

---

## Slide 9 — Modulis 7: Technologijų Atpažinimas (NAUJAS)

**Failas:** `server/utils/techFingerprint.ts`

Analizuojama: HTTP response antraštės + HTML body (pirmi 80KB)

### CDN (7 atpažįstami)
| CDN | Kaip aptinkama |
|-----|---------------|
| Cloudflare | `cf-ray`, `cf-cache-status` antraštės |
| AWS CloudFront | `x-amz-cf-id`, `x-amz-cf-pop` |
| Vercel | `x-vercel-id`, `x-vercel-cache` |
| Netlify | `x-nf-request-id` |
| Akamai | `x-check-cacheable`, `akamai-grn` |
| Fastly | `x-served-by`, `x-fastly-request-id` |
| BunnyCDN | `bunny-request-id` |

### Frameworks (12 atpažįstami)
`Next.js` · `Nuxt.js` · `React` · `Angular` · `Vue.js` · `WordPress` · `Shopify` · `Wix` · `Squarespace` · `Drupal` · `Joomla` · `Ghost`

### Backend / Web serveriai (11)
PHP · ASP.NET · Express · Ruby on Rails · Java · Next.js · nginx · Apache · IIS · LiteSpeed · Caddy

### Analytics (9 atpažįstami)
Google Analytics · Google Tag Manager · Hotjar · Segment · Mixpanel · Intercom · Crisp · HubSpot · Salesforce

### Hosting
Vercel · Netlify · AWS CloudFront

---

## Slide 10 — Modulis 8: TLS Giluminė Analizė (NAUJAS)

**Failas:** `server/utils/tlsDeep.ts`

### Renkama informacija (raw TLS socket)
| Duomuo | Ką rodo |
|--------|---------|
| Sutarta TLS versija | TLSv1.2 ar TLSv1.3 |
| Cipher suite pavadinimas | Kokia šifravimo kombinacija naudojama |
| Silpnas cipher | Ar naudojamas pavojingas algoritmas |
| Self-signed | Ar sertifikatas pasirašytas paties savęs |
| Issuer | Kas išdavė sertifikatą (CA organizacijos vardas) |

### 8 Silpnų Cipher Raktažodžiai
```
RC4  · DES  · 3DES · NULL
EXPORT · ANON · MD5 · RC2
```

### Self-signed detekcija
```
Issuer.CN == Subject.CN  AND  Issuer.O == Subject.O
→ Sertifikatas pasirašytas pats → HIGH severity
```

### Rizikos
| Radimas | Severity | Bausmė Score |
|---------|----------|-------------|
| Silpnas cipher | MEDIUM | -10 |
| Self-signed | HIGH | -10 |

---

## Slide 11 — Modulis 9: Paslėptų Endpoints Radimas (NAUJAS)

**Failas:** `server/utils/endpointDiscovery.ts`

### Metodas
```
GET https://example.com/[path]
Timeout: 6s per kelias
Lygiagrečiai: visi 36 keliai vienu metu
Reportuojama: HTTP 200, 401, 403
```

### 36 Tikrinami keliai
**Jautrūs (HIGH severity jei HTTP 200):**
```
/.git/HEAD    /.env        /.env.local
/phpinfo.php  /info.php    /phpmyadmin
/debug        /backup      /backup.zip
/backup.tar.gz /config     /config.json
/server-status /server-info /actuator/env
/console
```

**Admin/Login (MEDIUM severity):**
```
/admin    /administrator    /login
/signin   /dashboard
```

**API/Dokumentacija:**
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

### Interpretacija
| HTTP Status | Reikšmė |
|-------------|---------|
| 200 | Endpoint egzistuoja ir prieinamas |
| 401 | Egzistuoja, bet reikia autentikacijos |
| 403 | Egzistuoja, bet prieiga uždrausta |
| 404 | Neegzistuoja (neraportuojama) |
| 3xx | Peradresavimas (neraportuojama) |

---

## Slide 12 — Findings ir OWASP Top 10 Sąsaja

### Visi 28 Finding tipai

**OWASP A01 — Broken Access Control**
| Radinys | Severity |
|---------|----------|
| SSH atidarytas (port 22) | MEDIUM |
| RDP atidarytas (port 3389) | HIGH |
| Duomenų bazės portai (3306/5432/27017) | HIGH |
| Admin/login endpoint viešai prieinamas | MEDIUM |
| Subdomain takeover galimas | HIGH |

**OWASP A02 — Cryptographic Failures**
| Radinys | Severity |
|---------|----------|
| HTTP neperadresuoja į HTTPS | MEDIUM |
| TLS sertifikatas baigiasi < 30 dienų | MEDIUM |
| TLS sertifikatas baigiasi < 14 dienų | HIGH |
| HSTS antraštė trūksta | MEDIUM |
| Silpnas TLS cipher suite | MEDIUM |
| Self-signed TLS sertifikatas | HIGH |
| HTTP be HTTPS (port 80 be 443) | MEDIUM |

**OWASP A03 — Injection**
| Radinys | Severity |
|---------|----------|
| CSP antraštė trūksta | MEDIUM |

**OWASP A05 — Security Misconfiguration**
| Radinys | Severity |
|---------|----------|
| SPF įrašas nerastas | HIGH |
| DMARC įrašas nerastas | HIGH |
| DMARC p=none (monitoring only) | MEDIUM |
| DMARC p=quarantine | LOW |
| DMARC p=reject | LOW |
| DMARC sp= nenustatyta | LOW |
| Nėra MX įrašų | LOW |
| Trūksta saugumo antraščių* | LOW |
| CAA įrašas nerastas | LOW |
| Jautrus kelias atidarytas (/.git, /.env...) | HIGH |
| robots.txt atskleidžia jautrius kelius | LOW |

*Trūkstamos antraštės: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy

**OWASP A08 — Software and Data Integrity**
| Radinys | Severity |
|---------|----------|
| DNSSEC neaptiktas | LOW |

**Kiti**
| Radinys | Severity |
|---------|----------|
| MTA-STS neaptiktas | LOW |
| TLS-RPT neaptiktas | LOW |
| DMARC policy neįprasta/trūksta | MEDIUM |
| Daug subdomainų/hostų (≥10) | LOW |
| SMTP atidarytas (port 25) | MEDIUM |

---

## Slide 13 — Vertinimo Sistema (Score)

### Principas
**Pradedama nuo 0** → Pridedami taškai už gerus nustatymus → Atimama už kritines problemas

**Maksimumas: 100 taškų**

### Taškų lentelė
| Komponentas | Taškai | Sąlyga |
|-------------|--------|--------|
| SPF | 5 | Įrašas rastas |
| SPF hardfail | +5 | Jei `-all` |
| DMARC | 5 | Įrašas rastas |
| DMARC quarantine | +5 | Jei `p=quarantine` |
| DMARC reject | +10 | Jei `p=reject` |
| DKIM | 8 | Rastas bent vienas selektorius |
| HTTP→HTTPS redirect | 5 | Peradresuoja |
| TLS cert galioja | 4 | > 30 dienų |
| HSTS | 10 | Antraštė yra |
| CSP | 10 | Antraštė yra |
| X-Content-Type-Options | 4 | Antraštė yra |
| X-Frame-Options | 4 | Antraštė yra |
| Referrer-Policy | 3 | Antraštė yra |
| Permissions-Policy | 3 | Antraštė yra |
| CAA | 6 | DNS įrašas rastas |
| DNSSEC | 6 | DNSKEY rastas |
| MTA-STS | 5 | DNS įrašas rastas |
| TLS-RPT | 3 | DNS įrašas rastas |
| security.txt | 2 | Failas rastas |
| robots.txt | 2 | Failas rastas |
| **Viso** | **100** | |

### Baudos (nuo naujų modulių)
| Problema | Bausmė |
|----------|--------|
| Subdomain takeover | **-20** |
| Silpnas TLS cipher | **-10** |
| Self-signed sertifikatas | **-10** |

### Rizikos lygiai
| Score | Lygis |
|-------|-------|
| ≥ 70 | 🟢 Low risk |
| 45–69 | 🟡 Medium risk |
| 25–44 | 🔴 High risk |
| < 25 | ⛔ Critical risk |

---

## Slide 14 — Saugumas ir Apribojimai

### Apsaugos mechanizmai
| Mechanizmas | Parametrai |
|-------------|-----------|
| Rate limiting | 6 scan/IP/60 sekundžių |
| Domain validacija | Regex: `[a-z0-9-]+(\.[a-z0-9-]+)+` |
| Amass režimas | Pasyvus tik (be DNS bruteforce) |
| Nmap scan tipas | TCP connect (`-sT`) — nereikia root |
| Subdomainų limitas | max 300 discover, max 30 scan |
| Endpoint timeout | 6 sekundės per kelią |

### Tai **nėra** (ir neturėtų būti):
- Aktyvus penetracijos testas
- Vulnerability scanner (CVE database)
- Autentikacijos brute-force
- SQL injection testeris
- Payload injekcija

### Atsakingas naudojimas
> "Only scan systems you own or have explicit permission to test."

---

## Slide 15 — Statistikos Suvestinė

### Skaičiai viename skaidrėje

| Modulis | Kiekis |
|---------|--------|
| SaaS platformos (takeover check) | **12** |
| CDN atpažinimo taisyklės | **7** |
| Framework detekcijos | **12** |
| Backend/serverių | **11** |
| Analytics įrankių | **9** |
| Endpoint keliai tikrinami | **36** |
| DKIM selektoriai testuojami | **13** |
| Silpni cipher raktažodžiai | **8** |
| Bendrų subdomainų tikrinimas | **12** |
| Finding tipų | **28** |
| OWASP kategorijos | **5** |
| Max score | **100** |
| Scan etapų | **9** |

---

## Slide 16 — Naudojamos Technologijos

### Frontend
- **Nuxt 3** (Vue 3 + Nitro)
- **@nuxt/ui** (Tailwind CSS komponentai)
- **Mermaid** — subdomainų grafo vizualizacija
- **pdf-lib** — PDF eksportas

### Backend (Nuxt Nitro server routes)
- **Node.js** built-in: `dns/promises`, `tls`, `child_process`
- **fast-xml-parser** — Nmap XML rezultatų apdorojimas
- **Amass** — pasyvus subdomainų discovery (išorinė priemonė)
- **Nmap** — TCP portų skenavimas (išorinė priemonė)

### Išoriniai API (tik skaitymas)
- **Cloudflare DoH** (`1.1.1.1/dns-query`) — DNSSEC tikrinimui
- **crt.sh** (`crt.sh/?q=%.domain&output=json`) — CT logai

### Eksporto formatai
- Markdown (`.md`)
- PDF (multi-page, tekstinis)
- JSON (clipboard)

---

## Slide 17 — Scan Pipeline Laiko Grafikas

```
Laikas →  0s         10s        30s        90s       210s
          │           │          │          │          │
Email     ├───────────┤
Web+DNS   ├───────────┤
          │
Amass     ├─────────────────────────────────┤  (iki 3min)
          │
Nmap      │           ├───────────────────┤  (iki 120s)
          │
Parallel: │                     ├──────────┤
 Takeover │                     │          │
 TechFP   │                     │          │
 TLS Deep │                     │          │
 Endpoints│                     │          │
          │
Report    │                                ├──┤
```

**Vidutinis scan laikas:** 2–3 minutės (priklausomai nuo domeno)

---

## Slide 18 — Ataskaitos Struktūra

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

## Slide 19 — Pavyzdiniai Radiniai

### Reali ataskaita (pvz. 39/100 — High risk)

```
Score: 39/100 — High risk

[HIGH] SPF record not found
→ Kiekvienas gali siųsti el. laišką nuo šio domeno vardu

[HIGH] DMARC record not found
→ El. pašto spoofing apsaugos nėra

[MEDIUM] HSTS missing
→ Galimos downgrade atakos

[MEDIUM] CSP missing
→ XSS atakos galimos

[LOW] No CAA record
→ Bet koks CA gali išduoti sertifikatą

[LOW] DNSSEC not detected
→ DNS atsakymai nepasirašyti

Score detalės:
- SPF:      0/10
- DMARC:    0/15
- DKIM:     0/8
- HSTS:     0/10
- CSP:      0/10
- Redirect: 5/5
- TLS cert: 4/4
- CAA:      0/6
- DNSSEC:   0/6
```

---

## Slide 20 — Universitetinis Kontekstas

### Projekto taikymas

**Tai sujungia:**
- DNS protokolų žinios (SPF, DMARC, CAA, DNSSEC)
- HTTP/TLS saugumo antraštės (OWASP)
- OSINT technikos (Amass, crt.sh)
- Network scanning (Nmap)
- Pasyvus žvalgybos gathering

**Palyginimas su komerciniais įrankiais:**
| Funkcija | Mūsų įrankis | Wappalyzer | SecurityHeaders.com | Shodan |
|---------|-------------|-----------|---------------------|--------|
| Tech fingerprint | ✓ | ✓ | — | — |
| Security headers | ✓ | — | ✓ | — |
| Email security | ✓ | — | — | — |
| Port scanning | ✓ | — | — | ✓ |
| Subdomain takeover | ✓ | — | — | — |
| Endpoint discovery | ✓ | — | — | — |
| Ataskaita (MD/PDF) | ✓ | — | ✓ | — |
| Atviras kodas | ✓ | ✓ | — | — |

---

*Šis dokumentas sugeneruotas iš `osint-dashboard` v1.6.0 source kodo*
*Failai: `server/utils/` · `server/api/scan.post.ts` · `pages/index.vue`*
