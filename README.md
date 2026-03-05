# OSINT Exposure Dashboard (Nuxt 3 + Amass + Nmap + Email Security)

A teaching-friendly OSINT dashboard:
- Passive subdomain discovery via **Amass**
- Safe port/service visibility via **Nmap** (`-sT -sV`, top 100 ports)
- Email DNS checks: **SPF / DMARC / DKIM hints / MX**
- Polished UI (Nuxt UI components), graph view (Mermaid), exports (Markdown + PDF)
- Safety: allowlist + rate limit + scan limits + timeouts

## Run locally (recommended for lectures)
1. Install deps:
   ```bash
   npm install
   ```
2. Ensure **amass** and **nmap** are installed on your machine, or run via Docker (below).
3. Start:
   ```bash
   npm run dev
   ```

## Run with Docker
```bash
docker build -t osint-dashboard .
docker run -p 3000:3000 osint-dashboard
```

## Railway
Railway will build from the root `Dockerfile`. Keep the allowlist strict.

## Allowlist
Edit:
`server/utils/allowlist.ts`

Only add company domains after explicit permission.
