<script setup lang="ts">
import mermaid from "mermaid";
import { PDFDocument, StandardFonts } from "pdf-lib";

const APP_VERSION = "1.5.0";

type Severity = "low" | "medium" | "high";

interface DomainResult {
  domain: string;
  loading: boolean;
  error: string | null;
  data: any;
  mermaidSvg: string;
}

const domainsInput = ref("programuoki.lt");
const globalLoading = ref(false);
const results = ref<DomainResult[]>([]);
const showTeachingMode = ref(true);
const search = ref("");
const filterSeverity = ref<Severity | "all">("all");

// ── Helpers ─────────────────────────────────────────────────────

function sevColor(sev: Severity) {
  if (sev === "high") return "red";
  if (sev === "medium") return "amber";
  return "green";
}

function sevLabel(sev: Severity) {
  if (sev === "high") return "High";
  if (sev === "medium") return "Medium";
  return "Low";
}

function scoreColor(score: number) {
  if (score >= 70) return "green";
  if (score >= 45) return "amber";
  return "red";
}

function riskColor(riskLevel: string) {
  if (riskLevel === "Low risk") return "green";
  if (riskLevel === "Medium risk") return "amber";
  return "red";
}

function getFindings(data: any) {
  const list = (data?.findings ?? []) as any[];
  const q = search.value.trim().toLowerCase();
  return list.filter((f) => {
    const sevOk = filterSeverity.value === "all" || f.severity === filterSeverity.value;
    const text =
      `${f.title ?? ""} ${f.host ?? ""} ${f.details ?? ""} ${f.recommendation ?? ""} ${(f.mitigations ?? []).join(" ")}`.toLowerCase();
    const qOk = !q || text.includes(q);
    return sevOk && qOk;
  });
}

function getHostRows(data: any) {
  const hosts = (data?.hosts ?? []) as any[];
  const rows: any[] = [];
  for (const h of hosts) {
    const open = (h.ports ?? []).filter((p: any) => p.state === "open");
    for (const p of open) {
      rows.push({
        host: h.target,
        ip: h.address ?? "",
        port: `${p.port}/${p.protocol}`,
        service: p.service?.name ?? "unknown",
        product: `${p.service?.product ?? ""} ${p.service?.version ?? ""}`.trim(),
      });
    }
  }
  const q = search.value.trim().toLowerCase();
  return rows.filter((r) => {
    if (!q) return true;
    return `${r.host} ${r.ip} ${r.port} ${r.service} ${r.product}`.toLowerCase().includes(q);
  });
}

function getMxRows(data: any) {
  return (data?.email?.mx ?? []).map((line: string) => {
    const parts = line.split(" ");
    return { priority: parts[0] ?? "", exchange: parts.slice(1).join(" ") };
  });
}

function getSummaryCounts(data: any) {
  const list = (data?.findings ?? []) as any[];
  return {
    high: list.filter((f) => f.severity === "high").length,
    med: list.filter((f) => f.severity === "medium").length,
    low: list.filter((f) => f.severity === "low").length,
    total: list.length,
  };
}

// At-a-glance items derived from scan data
function getAtAGlance(data: any): Array<{ label: string; value: string; ok: boolean | null }> {
  const e = data?.email;
  const w = data?.web;
  const d = data?.dnsPosture;

  const spfRecord = e?.spf?.record;
  const spfValue = !spfRecord
    ? "missing"
    : spfRecord.includes("-all")
    ? "hardfail (-all)"
    : spfRecord.includes("~all")
    ? "softfail (~all)"
    : spfRecord.includes("+all")
    ? "passall (+all — dangerous)"
    : "present";
  const spfOk = !!spfRecord && !spfRecord.includes("+all");

  const dmarcPolicy = e?.dmarc?.policy;
  const dmarcValue = !e?.dmarc?.record
    ? "missing"
    : dmarcPolicy
    ? dmarcPolicy
    : "present";
  const dmarcOk = dmarcPolicy === "reject" ? true : dmarcPolicy === "quarantine" ? null : false;

  const daysLeft = w?.https?.daysLeft;
  const tlsValue =
    daysLeft === undefined || daysLeft === null
      ? "not reachable"
      : `expires in ~${daysLeft} day${daysLeft === 1 ? "" : "s"}`;
  const tlsOk = daysLeft !== undefined && daysLeft !== null && daysLeft > 30;

  return [
    { label: "SPF", value: spfValue, ok: spfOk },
    { label: "DMARC", value: dmarcValue, ok: dmarcOk },
    { label: "HTTPS/TLS", value: tlsValue, ok: tlsOk },
    { label: "HTTP→HTTPS", value: w?.https?.redirect ? "yes" : "no", ok: w?.https?.redirect ?? false },
    { label: "HSTS", value: w?.headers?.hsts ? "present" : "missing", ok: !!w?.headers?.hsts },
    { label: "CSP", value: w?.headers?.csp ? "present" : "missing", ok: !!w?.headers?.csp },
    { label: "CAA", value: d?.caa?.found ? "present" : "missing", ok: !!d?.caa?.found },
    { label: "DNSSEC", value: d?.dnssec?.detected ? "detected" : "not detected", ok: !!d?.dnssec?.detected },
    { label: "MTA-STS", value: d?.mtaSts?.found ? "detected" : "not detected", ok: !!d?.mtaSts?.found },
    { label: "TLS-RPT", value: d?.tlsRpt?.found ? "detected" : "not detected", ok: !!d?.tlsRpt?.found },
  ];
}

// Top warnings: high+medium findings titles
function getTopWarnings(data: any): string[] {
  const findings = (data?.findings ?? []) as any[];
  return findings
    .filter((f) => f.severity === "high" || f.severity === "medium")
    .map((f) => f.details ? `${f.title} — ${f.details}` : f.title)
    .slice(0, 8);
}

// Recommendations derived from findings
function getRecommendations(data: any): string[] {
  const findings = (data?.findings ?? []) as any[];
  const recs = findings
    .filter((f) => f.recommendation)
    .map((f) => f.recommendation as string);
  // Deduplicate
  return Array.from(new Set(recs));
}

// ── Scan ─────────────────────────────────────────────────────────

async function runScan() {
  const domains = domainsInput.value
    .split(/[\n,;]+/)
    .map((d) => d.trim())
    .filter(Boolean);

  if (!domains.length) return;

  globalLoading.value = true;
  results.value = domains.map((d) => ({
    domain: d,
    loading: true,
    error: null,
    data: null,
    mermaidSvg: "",
  }));

  for (let i = 0; i < results.value.length; i++) {
    try {
      const data = await $fetch("/api/scan", {
        method: "POST",
        body: { domain: results.value[i].domain },
      });
      results.value[i] = { ...results.value[i], loading: false, data };
      await nextTick();
      renderMermaidForResult(i);
    } catch (e: any) {
      const error = e?.data?.statusMessage || e?.data?.message || e?.message || "Scan failed";
      results.value[i] = { ...results.value[i], loading: false, error };
    }
  }

  globalLoading.value = false;
}

function copyText(text: string) {
  navigator.clipboard?.writeText(text);
}

function downloadFile(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Markdown / PDF Export ────────────────────────────────────────

function buildMarkdownReport(data: any) {
  const lines: string[] = [];
  const now = new Date().toISOString();
  const score = data.score;

  lines.push(`# Domain Security Posture Analyzer`);
  lines.push(`- Version: ${APP_VERSION}`);
  lines.push(`- Generated: ${now}`);
  lines.push(`- Target: **${data.domain}**`);
  lines.push("");

  if (score) {
    lines.push(`## Score`);
    lines.push(`**${score.score}/100** — ${score.riskLevel}`);
    lines.push("");
  }

  lines.push(`## At a Glance`);
  const glance = getAtAGlance(data);
  for (const item of glance) {
    const status = item.ok === true ? "✓" : item.ok === false ? "✗" : "~";
    lines.push(`- ${item.label}: ${item.value} ${status}`);
  }
  lines.push("");

  lines.push(`## Email Security`);
  const mxProvider = data.dnsPosture?.mxProvider;
  if (mxProvider) lines.push(`- MX Provider: **${mxProvider.name}** (confidence: ${mxProvider.confidence})`);
  lines.push(`- MX: ${(data.email?.mx ?? []).join(", ") || "(none)"}`);
  lines.push(`- SPF: ${data.email?.spf?.record || "Not found"}`);
  if (data.email?.spf?.lookupCount) lines.push(`- SPF lookup estimate: ${data.email.spf.lookupCount}`);
  lines.push(`- DMARC: ${data.email?.dmarc?.record || "Not found"}`);
  if (data.email?.dmarc?.policy) lines.push(`  - Policy: p=${data.email.dmarc.policy}`);
  if (data.email?.dmarc?.subdomainPolicy) lines.push(`  - Subdomains: sp=${data.email.dmarc.subdomainPolicy}`);
  if ((data.email?.dmarc?.ruaEmails ?? []).length) lines.push(`  - rua: ${data.email.dmarc.ruaEmails.join(", ")}`);
  lines.push("");
  lines.push(`### DKIM`);
  lines.push(`- ${data.email?.dkim?.note ?? "N/A"}`);
  const dkimFound = data.email?.dkim?.found ?? [];
  if (dkimFound.length) {
    for (const s of dkimFound) lines.push(`  - ${s.selector} — ${s.type}`);
  }
  lines.push("");
  lines.push(`### MTA-STS & TLS-RPT`);
  lines.push(`- MTA-STS DNS: ${data.dnsPosture?.mtaSts?.found ? "detected" : "not detected"}`);
  if (data.dnsPosture?.mtaSts?.record) lines.push(`  - ${data.dnsPosture.mtaSts.record}`);
  lines.push(`- TLS-RPT DNS: ${data.dnsPosture?.tlsRpt?.found ? "detected" : "not detected"}`);
  if (data.dnsPosture?.tlsRpt?.record) lines.push(`  - ${data.dnsPosture.tlsRpt.record}`);
  lines.push("");

  lines.push(`## Web & TLS`);
  const w = data.web;
  if (w) {
    lines.push(`- Certificate expires: ${w.https.certExpiry ?? "n/a"}`);
    lines.push(`- Days left: ${w.https.daysLeft ?? "n/a"}`);
    lines.push(`- HTTP → HTTPS redirect: ${w.https.redirect ? "yes" : "no"}`);
    lines.push(`- HSTS: ${w.headers.hsts || "missing"}`);
    lines.push(`- CSP: ${w.headers.csp || "missing"}`);
    lines.push(`- X-Content-Type-Options: ${w.headers.xContentTypeOptions || "missing"}`);
    lines.push(`- X-Frame-Options: ${w.headers.xFrameOptions || "missing"}`);
    lines.push(`- Referrer-Policy: ${w.headers.referrerPolicy || "missing"}`);
    lines.push(`- Permissions-Policy: ${w.headers.permissionsPolicy || "missing"}`);
    lines.push(`- Cookies: ${w.cookies.count}`);
    lines.push(`- security.txt: ${w.securityTxt ? "found" : "not found"}`);
    lines.push(`- robots.txt: ${w.robotsTxt ? "accessible" : "not found"}`);
  }
  lines.push("");

  lines.push(`## DNS Posture`);
  const d = data.dnsPosture;
  if (d) {
    lines.push(`- CAA: ${d.caa.found ? d.caa.records.join("; ") : "missing"}`);
    lines.push(`- DNSSEC: ${d.dnssec.detected ? "detected" : "not detected"}`);
    if (d.commonSubdomains?.length) {
      lines.push(`### Common Subdomains`);
      for (const s of d.commonSubdomains) {
        lines.push(`- ${s.name}: ${s.exists ? `yes (${s.target ?? ""})` : "no"}`);
      }
    }
  }
  lines.push("");

  lines.push(`## Findings`);
  const findings = data.findings ?? [];
  if (!findings.length) {
    lines.push(`- No findings.`);
  } else {
    for (const f of findings) {
      lines.push(`### [${String(f.severity).toUpperCase()}] ${f.title}`);
      if (f.owasp) lines.push(`- OWASP: ${f.owasp}`);
      if (f.host) lines.push(`- Host: \`${f.host}\``);
      if (f.details) lines.push(`- Details: ${f.details}`);
      if (f.recommendation) lines.push(`- Recommendation: ${f.recommendation}`);
      if ((f.mitigations ?? []).length) {
        lines.push(`- Mitigations:`);
        for (const m of f.mitigations) lines.push(`  - [ ] ${m}`);
      }
      lines.push("");
    }
  }

  lines.push(`## Recommendations`);
  const recs = getRecommendations(data);
  recs.forEach((r, i) => lines.push(`${i + 1}. ${r}`));
  lines.push("");

  lines.push(`## Open Ports by Host`);
  for (const h of data.hosts ?? []) {
    const open = (h.ports ?? []).filter((p: any) => p.state === "open");
    lines.push(`### ${h.target}${h.address ? ` (${h.address})` : ""}`);
    if (!open.length) {
      lines.push(`- No open ports detected.`);
    } else {
      for (const p of open) {
        const svc = p.service?.name ?? "unknown";
        const prod = `${p.service?.product ?? ""} ${p.service?.version ?? ""}`.trim();
        lines.push(`- ${p.port}/${p.protocol} — ${svc}${prod ? ` (${prod})` : ""}`);
      }
    }
    lines.push("");
  }

  lines.push(`## Discovered Subdomains`);
  (data.subdomains ?? []).forEach((s: string) => lines.push(`- ${s}`));
  lines.push("");

  lines.push(`## Limitations & Responsible Use`);
  lines.push(`- Public-signal posture assessment only (DNS/HTTP/TLS). Not a penetration test.`);
  lines.push(`- DKIM selector discovery is heuristic; absence does not prove DKIM is missing.`);
  lines.push(`- Some sites block automated requests or serve different headers to non-browsers.`);
  lines.push(`- Active scanning (e.g., OWASP ZAP) requires explicit written authorization.`);

  return lines.join("\n");
}

async function exportMarkdown(data: any) {
  const md = buildMarkdownReport(data);
  downloadFile(`security-posture-${data.domain}.md`, md, "text/markdown");
}

function wrapText(text: string, maxLen: number) {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = "";
  for (const w of words) {
    const next = current ? `${current} ${w}` : w;
    if (next.length > maxLen) {
      if (current) lines.push(current);
      current = w;
    } else {
      current = next;
    }
  }
  if (current) lines.push(current);
  return lines;
}

async function exportPDF(data: any) {
  const md = buildMarkdownReport(data);
  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const pageSize = { width: 595.28, height: 841.89 };
  const margin = 40;
  const fontSize = 10;
  const lineHeight = 14;
  let page = pdfDoc.addPage([pageSize.width, pageSize.height]);
  let y = pageSize.height - margin;
  const lines = md.split("\n").flatMap((line) => wrapText(line, 95));
  for (const line of lines) {
    if (y < margin) {
      page = pdfDoc.addPage([pageSize.width, pageSize.height]);
      y = pageSize.height - margin;
    }
    page.drawText(line, { x: margin, y, size: fontSize, font });
    y -= lineHeight;
  }
  const bytes = await pdfDoc.save();
  const blob = new Blob([bytes], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `security-posture-${data.domain}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Mermaid Graph ────────────────────────────────────────────────

function buildMermaidGraph(data: any) {
  const root = data.domain;
  const subs = (data.subdomains ?? []).slice(0, 80);
  const idFor = (s: string) =>
    "n_" + btoa(unescape(encodeURIComponent(s))).replace(/=|\+|\//g, "").slice(0, 24);
  const lines: string[] = [];
  lines.push("flowchart TD");
  lines.push(`${idFor(root)}["${root}"]`);
  for (const s of subs) {
    const sid = idFor(s);
    lines.push(`${sid}["${s}"]`);
    lines.push(`${idFor(root)} --> ${sid}`);
  }
  lines.push("");
  lines.push("classDef root fill:#eef,stroke:#88a,stroke-width:1px;");
  lines.push(`class ${idFor(root)} root;`);
  return lines.join("\n");
}

async function renderMermaidForResult(index: number) {
  const r = results.value[index];
  if (!r?.data) return;
  mermaid.initialize({ startOnLoad: false, theme: "default", securityLevel: "strict" });
  const code = buildMermaidGraph(r.data);
  try {
    const { svg } = await mermaid.render(`graph-${index}-${Date.now()}`, code);
    results.value[index] = { ...results.value[index], mermaidSvg: svg };
  } catch (_) {
    // ignore render errors
  }
}
</script>

<template>
  <div class="max-w-6xl mx-auto p-4 md:p-6 space-y-4">

    <!-- ── Header ── -->
    <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
      <div>
        <h1 class="text-xl font-bold tracking-tight">Domain Security Posture Analyzer</h1>
        <p class="text-xs opacity-50 mt-0.5">
          Version {{ APP_VERSION }} · DNS · HTTP/TLS headers · Email security · Amass (passive) · Nmap (-sT)
        </p>
      </div>
      <UButton size="xs" color="gray" variant="soft" icon="i-heroicons-academic-cap" @click="showTeachingMode = !showTeachingMode">
        Teaching mode: {{ showTeachingMode ? "On" : "Off" }}
      </UButton>
    </div>

    <!-- ── Input card ── -->
    <UCard :ui="{ body: { padding: 'p-3 sm:p-4' }, header: { padding: 'px-3 py-2 sm:px-4' } }">
      <template #header>
        <div class="flex items-center gap-2">
          <UIcon name="i-heroicons-globe-alt" class="w-4 h-4 opacity-60" />
          <span class="text-sm font-medium">Targets</span>
        </div>
      </template>

      <div class="space-y-3">
        <div class="flex flex-col md:flex-row gap-3">
          <div class="flex-1">
            <label class="text-xs font-medium opacity-70 mb-1 block">Domains (one per line or comma-separated)</label>
            <UTextarea
              v-model="domainsInput"
              placeholder="example.com&#10;another.org"
              :rows="3"
              class="font-mono text-sm w-full"
            />
          </div>

          <div class="flex flex-col gap-2 md:w-52">
            <div>
              <label class="text-xs font-medium opacity-70 mb-1 block">Search findings / hosts</label>
              <UInput v-model="search" placeholder="ssh, dmarc, 443…" icon="i-heroicons-magnifying-glass" size="sm" />
            </div>
            <div>
              <label class="text-xs font-medium opacity-70 mb-1 block">Severity</label>
              <USelect
                v-model="filterSeverity"
                size="sm"
                :options="[
                  { label: 'All severities', value: 'all' },
                  { label: 'High', value: 'high' },
                  { label: 'Medium', value: 'medium' },
                  { label: 'Low', value: 'low' }
                ]"
              />
            </div>
            <UButton :loading="globalLoading" icon="i-heroicons-play" size="sm" class="w-full mt-auto" @click="runScan">
              Run scan
            </UButton>
          </div>
        </div>

        <UAlert
          v-if="showTeachingMode"
          color="blue"
          variant="soft"
          icon="i-heroicons-light-bulb"
          title="Teaching mode"
          description="This report uses public signals only (DNS, HTTPS/TLS, HTTP response headers). It is a posture assessment, not a penetration test."
          :ui="{ description: 'text-xs', title: 'text-sm font-medium' }"
        />
      </div>
    </UCard>

    <!-- ── Empty state ── -->
    <div v-if="!results.length" class="text-sm opacity-50 text-center py-6">
      Enter one or more domains above and click "Run scan".
    </div>

    <!-- ── Results per domain ── -->
    <div v-for="(sr, idx) in results" :key="sr.domain" class="space-y-3">

      <!-- Domain header bar -->
      <div class="flex items-center justify-between gap-3 pt-1 border-t-2 border-gray-200 dark:border-gray-700">
        <div class="flex flex-wrap items-center gap-2 min-w-0">
          <h2 class="text-base font-bold font-mono truncate">{{ sr.domain }}</h2>
          <template v-if="sr.data">
            <UBadge size="xs" :color="getSummaryCounts(sr.data).high ? 'red' : 'gray'" variant="subtle">
              High: {{ getSummaryCounts(sr.data).high }}
            </UBadge>
            <UBadge size="xs" :color="getSummaryCounts(sr.data).med ? 'amber' : 'gray'" variant="subtle">
              Med: {{ getSummaryCounts(sr.data).med }}
            </UBadge>
            <UBadge size="xs" :color="getSummaryCounts(sr.data).low ? 'green' : 'gray'" variant="subtle">
              Low: {{ getSummaryCounts(sr.data).low }}
            </UBadge>
          </template>
        </div>
        <div v-if="sr.data" class="flex items-center gap-1 shrink-0">
          <UButton size="xs" color="gray" variant="ghost" icon="i-heroicons-arrow-down-tray" @click="exportMarkdown(sr.data)">MD</UButton>
          <UButton size="xs" color="gray" variant="ghost" icon="i-heroicons-document-arrow-down" @click="exportPDF(sr.data)">PDF</UButton>
          <UButton size="xs" color="gray" variant="ghost" icon="i-heroicons-clipboard" @click="copyText(JSON.stringify(sr.data, null, 2))">JSON</UButton>
        </div>
      </div>

      <!-- Scanning spinner -->
      <div v-if="sr.loading" class="flex items-center gap-2 py-3 px-4 rounded-xl bg-gray-50 dark:bg-gray-900/40">
        <UIcon name="i-heroicons-arrow-path" class="w-4 h-4 animate-spin opacity-60 shrink-0" />
        <span class="text-sm opacity-70">Scanning <span class="font-mono">{{ sr.domain }}</span>… up to 2–3 min (DNS + TLS + Amass + Nmap).</span>
      </div>

      <!-- Error -->
      <UAlert v-else-if="sr.error" color="red" variant="soft" icon="i-heroicons-exclamation-triangle" :title="sr.error" />

      <!-- Results -->
      <template v-else-if="sr.data">

        <!-- ── Score Banner ── -->
        <div class="flex flex-col sm:flex-row items-start sm:items-center gap-3 rounded-xl border border-gray-200 dark:border-gray-800 px-4 py-3">
          <!-- Score circle -->
          <div class="flex items-center gap-3 shrink-0">
            <div class="flex flex-col items-center justify-center w-16 h-16 rounded-full border-4"
              :class="{
                'border-green-400 bg-green-50 dark:bg-green-900/20': scoreColor(sr.data.score?.score ?? 0) === 'green',
                'border-amber-400 bg-amber-50 dark:bg-amber-900/20': scoreColor(sr.data.score?.score ?? 0) === 'amber',
                'border-red-400 bg-red-50 dark:bg-red-900/20': scoreColor(sr.data.score?.score ?? 0) === 'red',
              }"
            >
              <span class="text-xl font-bold leading-none">{{ sr.data.score?.score ?? 0 }}</span>
              <span class="text-[10px] opacity-60">/100</span>
            </div>
            <div>
              <UBadge :color="riskColor(sr.data.score?.riskLevel ?? '')" variant="subtle" size="sm">
                {{ sr.data.score?.riskLevel ?? "Unknown" }}
              </UBadge>
              <p class="text-xs opacity-50 mt-1">Posture score</p>
            </div>
          </div>
          <!-- Quick meta -->
          <div class="flex-1 text-xs opacity-60 space-y-0.5">
            <p>Target: <span class="font-mono font-medium opacity-100">{{ sr.data.domain }}</span></p>
            <p>Generated: {{ new Date().toISOString() }} (UTC)</p>
            <p class="text-[11px]">Public-signal assessment only (DNS, HTTPS/TLS, HTTP headers). Not a penetration test.</p>
          </div>
          <!-- Jump-to nav -->
          <div class="flex flex-wrap gap-1.5 shrink-0">
            <span class="text-[10px] opacity-40 self-center">Jump to:</span>
            <a :href="`#email-${idx}`" class="text-[11px] text-blue-500 hover:underline">Email</a>
            <span class="text-[10px] opacity-30">·</span>
            <a :href="`#web-${idx}`" class="text-[11px] text-blue-500 hover:underline">Web & TLS</a>
            <span class="text-[10px] opacity-30">·</span>
            <a :href="`#dns-${idx}`" class="text-[11px] text-blue-500 hover:underline">DNS</a>
            <span class="text-[10px] opacity-30">·</span>
            <a :href="`#recs-${idx}`" class="text-[11px] text-blue-500 hover:underline">Recommendations</a>
          </div>
        </div>

        <!-- ── At a Glance ── -->
        <UCard :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
          <template #header>
            <div class="flex items-center gap-2">
              <UIcon name="i-heroicons-eye" class="w-4 h-4 opacity-60" />
              <span class="text-sm font-medium">At a glance</span>
              <span class="text-xs opacity-40">· Public signals only (DNS, HTTPS/TLS, HTTP headers)</span>
            </div>
          </template>
          <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
            <div
              v-for="item in getAtAGlance(sr.data)"
              :key="item.label"
              class="rounded-lg border px-2.5 py-2"
              :class="{
                'border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-900/20': item.ok === true,
                'border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-900/20': item.ok === null,
                'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-900/20': item.ok === false,
              }"
            >
              <p class="text-[10px] font-semibold opacity-60 uppercase tracking-wide">{{ item.label }}</p>
              <p class="text-xs font-medium mt-0.5 break-words">{{ item.value }}</p>
            </div>
          </div>
        </UCard>

        <!-- ── Top Warnings ── -->
        <UCard v-if="getTopWarnings(sr.data).length" :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
          <template #header>
            <div class="flex items-center gap-2">
              <UIcon name="i-heroicons-exclamation-triangle" class="w-4 h-4 text-amber-500" />
              <span class="text-sm font-medium">Top warnings</span>
            </div>
          </template>
          <ul class="space-y-1">
            <li v-for="(w, wi) in getTopWarnings(sr.data)" :key="wi" class="flex items-start gap-2 text-xs">
              <span class="text-amber-500 mt-0.5 shrink-0">▲</span>
              <span class="opacity-80">{{ w }}</span>
            </li>
          </ul>
          <p v-if="sr.data.findings?.some((f: any) => f.owasp)" class="mt-2 text-xs opacity-50">
            OWASP mapping (high-level):
            {{ [...new Set((sr.data.findings ?? []).filter((f: any) => f.owasp).map((f: any) => f.owasp))].join(" · ") }}
          </p>
        </UCard>

        <!-- ── Top row: Findings + Email Security ── -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">

          <!-- ── Findings ── -->
          <UCard :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
            <template #header>
              <div class="flex items-center gap-2">
                <UIcon name="i-heroicons-shield-exclamation" class="w-4 h-4 opacity-60" />
                <span class="text-sm font-medium">Findings</span>
                <UBadge size="xs" color="gray" variant="subtle">{{ getFindings(sr.data).length }}</UBadge>
              </div>
            </template>

            <div class="space-y-2">
              <div v-if="!getFindings(sr.data).length" class="text-sm opacity-50 py-2">
                No findings match your filters.
              </div>

              <div
                v-for="(f, fi) in getFindings(sr.data)"
                :key="fi"
                class="rounded-lg border border-gray-200 dark:border-gray-800 p-3 space-y-1.5"
              >
                <div class="flex items-start justify-between gap-2">
                  <div class="flex items-center gap-1.5 flex-wrap min-w-0">
                    <UBadge size="xs" :color="sevColor(f.severity)" variant="subtle">{{ sevLabel(f.severity) }}</UBadge>
                    <span class="text-sm font-semibold">{{ f.title }}</span>
                  </div>
                  <UButton
                    size="xs" color="gray" variant="ghost" icon="i-heroicons-clipboard" class="shrink-0"
                    @click="copyText(`${f.title}\n${f.host ? 'Host: '+f.host+'\n' : ''}${f.details ?? ''}\n${f.recommendation ?? ''}\nMitigations:\n- ${(f.mitigations ?? []).join('\n- ')}`)"
                  />
                </div>

                <p v-if="f.host" class="text-xs opacity-50 font-mono">{{ f.host }}</p>
                <p v-if="f.details" class="text-xs opacity-70">{{ f.details }}</p>
                <p v-if="f.owasp" class="text-xs opacity-40 italic">OWASP: {{ f.owasp }}</p>

                <div v-if="f.recommendation" class="text-xs rounded-lg bg-gray-50 dark:bg-gray-900/40 px-2 py-1.5">
                  <span class="font-medium">Rec:</span> <span class="opacity-70">{{ f.recommendation }}</span>
                </div>

                <div v-if="(f.mitigations ?? []).length" class="space-y-1 pt-0.5">
                  <p class="text-xs font-medium opacity-60">Mitigations</p>
                  <div v-for="(m, mi) in f.mitigations" :key="mi" class="flex items-start gap-2">
                    <input type="checkbox" class="mt-0.5 shrink-0" />
                    <p class="text-xs opacity-70 leading-relaxed">{{ m }}</p>
                  </div>
                </div>

                <p v-if="showTeachingMode" class="text-xs opacity-40 italic pt-0.5">
                  Discussion: "Do we need this exposure? Which mitigations are mandatory?"
                </p>
              </div>
            </div>
          </UCard>

          <!-- ── Email Security ── -->
          <UCard :id="`email-${idx}`" :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
            <template #header>
              <div class="flex items-center gap-2">
                <UIcon name="i-heroicons-envelope" class="w-4 h-4 opacity-60" />
                <span class="text-sm font-medium">Email security</span>
              </div>
            </template>

            <div class="space-y-2">
              <!-- MX Provider -->
              <div v-if="sr.data.dnsPosture?.mxProvider" class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-semibold">MX provider</span>
                  <UBadge size="xs" :color="sr.data.dnsPosture.mxProvider.confidence === 'high' ? 'green' : 'gray'" variant="subtle">
                    {{ sr.data.dnsPosture.mxProvider.confidence }}
                  </UBadge>
                </div>
                <p class="text-xs font-medium opacity-80">{{ sr.data.dnsPosture.mxProvider.name }}</p>
                <div class="mt-1 flex flex-wrap gap-1">
                  <span v-for="mx in getMxRows(sr.data)" :key="mx.exchange" class="text-[10px] font-mono opacity-50">{{ mx.exchange }}</span>
                </div>
              </div>

              <!-- SPF -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-semibold">SPF</span>
                  <UBadge size="xs" :color="sr.data.email?.spf?.record ? (sr.data.email.spf.record.includes('-all') ? 'green' : 'amber') : 'red'" variant="subtle">
                    {{ !sr.data.email?.spf?.record ? 'missing' : sr.data.email.spf.record.includes('-all') ? 'hardfail' : sr.data.email.spf.record.includes('~all') ? 'softfail' : 'present' }}
                  </UBadge>
                </div>
                <p class="text-xs opacity-60 break-all">{{ sr.data.email?.spf?.record || "No SPF TXT record found." }}</p>
                <p v-if="sr.data.email?.spf?.lookupCount !== undefined" class="text-xs opacity-40 mt-0.5">
                  Lookup estimate: {{ sr.data.email.spf.lookupCount }}
                </p>
              </div>

              <!-- DKIM -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-semibold">DKIM — best-effort discovery</span>
                  <UBadge size="xs" :color="(sr.data.email?.dkim?.found?.length ?? 0) ? 'green' : 'amber'" variant="subtle">
                    {{ (sr.data.email?.dkim?.found?.length ?? 0) ? 'found' : 'unknown' }}
                  </UBadge>
                </div>
                <p class="text-xs opacity-50 mb-1">{{ sr.data.email?.dkim?.note }}</p>
                <div v-if="sr.data.email?.dkim?.found?.length" class="space-y-0.5">
                  <div v-for="s in sr.data.email.dkim.found" :key="s.selector" class="flex items-center gap-2 text-xs">
                    <span class="font-mono opacity-70">{{ s.selector }}</span>
                    <span class="opacity-40">—</span>
                    <UBadge size="xs" :color="s.type === 'CNAME' ? 'blue' : 'green'" variant="subtle">{{ s.type }}</UBadge>
                  </div>
                </div>
              </div>

              <!-- DMARC -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-semibold">DMARC</span>
                  <UBadge
                    size="xs"
                    :color="!sr.data.email?.dmarc?.record ? 'red' : (String(sr.data.email?.dmarc?.policy).toLowerCase() === 'none' ? 'amber' : 'green')"
                    variant="subtle"
                  >
                    {{ !sr.data.email?.dmarc?.record ? "missing" : (sr.data.email?.dmarc?.policy ? `p=${sr.data.email.dmarc.policy}` : "present") }}
                  </UBadge>
                </div>
                <div class="space-y-0.5">
                  <div class="flex gap-2 text-xs">
                    <span class="opacity-50 w-24 shrink-0">Main domain</span>
                    <span class="opacity-70">{{ sr.data.email?.dmarc?.policy ? `p=${sr.data.email.dmarc.policy}` : "—" }}</span>
                  </div>
                  <div class="flex gap-2 text-xs">
                    <span class="opacity-50 w-24 shrink-0">Subdomains (sp=)</span>
                    <span class="opacity-70">{{ sr.data.email?.dmarc?.subdomainPolicy ? `sp=${sr.data.email.dmarc.subdomainPolicy}` : "—" }}</span>
                  </div>
                  <div v-if="(sr.data.email?.dmarc?.ruaEmails ?? []).length" class="flex gap-2 text-xs">
                    <span class="opacity-50 w-24 shrink-0">Aggregate rua</span>
                    <span class="opacity-70">{{ sr.data.email.dmarc.ruaEmails.join(", ") }}</span>
                  </div>
                </div>
                <p class="text-xs opacity-50 break-all mt-1.5 font-mono text-[10px]">{{ sr.data.email?.dmarc?.record }}</p>
              </div>

              <!-- MTA-STS & TLS-RPT -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1.5">
                  <span class="text-xs font-semibold">MTA-STS & TLS-RPT</span>
                  <UBadge size="xs" color="gray" variant="subtle">info</UBadge>
                </div>
                <div class="space-y-1">
                  <div class="flex items-center justify-between text-xs">
                    <span class="opacity-60">MTA-STS DNS</span>
                    <UBadge size="xs" :color="sr.data.dnsPosture?.mtaSts?.found ? 'green' : 'gray'" variant="subtle">
                      {{ sr.data.dnsPosture?.mtaSts?.found ? "detected" : "not detected" }}
                    </UBadge>
                  </div>
                  <div class="flex items-center justify-between text-xs">
                    <span class="opacity-60">TLS-RPT DNS</span>
                    <UBadge size="xs" :color="sr.data.dnsPosture?.tlsRpt?.found ? 'green' : 'gray'" variant="subtle">
                      {{ sr.data.dnsPosture?.tlsRpt?.found ? "detected" : "not detected" }}
                    </UBadge>
                  </div>
                  <p class="text-[10px] opacity-40 pt-0.5">Optional hardening features for mail transport security.</p>
                </div>
              </div>
            </div>
          </UCard>
        </div>

        <!-- ── Web & TLS + DNS Posture row ── -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">

          <!-- ── Web & TLS ── -->
          <UCard :id="`web-${idx}`" :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
            <template #header>
              <div class="flex items-center gap-2">
                <UIcon name="i-heroicons-lock-closed" class="w-4 h-4 opacity-60" />
                <span class="text-sm font-medium">Web & TLS</span>
              </div>
            </template>

            <div class="space-y-2">
              <!-- HTTPS & Certificate -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1.5">
                  <span class="text-xs font-semibold">HTTPS & Certificate</span>
                  <UBadge
                    size="xs"
                    :color="sr.data.web?.https?.daysLeft > 30 ? 'green' : sr.data.web?.https?.daysLeft > 0 ? 'amber' : 'red'"
                    variant="subtle"
                  >
                    {{ sr.data.web?.https?.daysLeft !== undefined ? (sr.data.web.https.daysLeft > 30 ? 'good' : 'expiring') : 'n/a' }}
                  </UBadge>
                </div>
                <div class="space-y-0.5 text-xs">
                  <div class="flex justify-between">
                    <span class="opacity-50">Certificate expires</span>
                    <span class="opacity-70 font-mono text-[10px]">{{ sr.data.web?.https?.certExpiry ?? "n/a" }}</span>
                  </div>
                  <div class="flex justify-between">
                    <span class="opacity-50">Days left</span>
                    <span :class="sr.data.web?.https?.daysLeft > 30 ? 'text-green-600 dark:text-green-400' : 'text-amber-600 dark:text-amber-400'" class="font-semibold">
                      {{ sr.data.web?.https?.daysLeft ?? "n/a" }}
                    </span>
                  </div>
                  <div class="flex justify-between">
                    <span class="opacity-50">HTTP → HTTPS redirect</span>
                    <UBadge size="xs" :color="sr.data.web?.https?.redirect ? 'green' : 'red'" variant="subtle">
                      {{ sr.data.web?.https?.redirect ? "yes" : "no" }}
                    </UBadge>
                  </div>
                </div>
              </div>

              <!-- Security Headers -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1.5">
                  <span class="text-xs font-semibold">Security Headers</span>
                  <UBadge
                    size="xs"
                    :color="sr.data.web?.headers?.hsts && sr.data.web?.headers?.csp ? 'green' : 'amber'"
                    variant="subtle"
                  >
                    {{ sr.data.web?.headers?.hsts && sr.data.web?.headers?.csp ? 'good' : 'warn' }}
                  </UBadge>
                </div>
                <table class="w-full text-xs">
                  <tbody>
                    <tr v-for="[key, label] in [
                      ['server', 'server'],
                      ['hsts', 'HSTS'],
                      ['csp', 'CSP'],
                      ['xContentTypeOptions', 'x-content-type-options'],
                      ['xFrameOptions', 'x-frame-options'],
                      ['referrerPolicy', 'referrer-policy'],
                      ['permissionsPolicy', 'permissions-policy'],
                    ]" :key="key" class="border-b border-gray-100 dark:border-gray-900 last:border-0">
                      <td class="py-1 pr-2 opacity-50 w-36 shrink-0">{{ label }}</td>
                      <td class="py-1 opacity-70 font-mono text-[10px] truncate max-w-[160px]"
                        :class="!sr.data.web?.headers?.[key] && key !== 'server' ? 'text-red-500 dark:text-red-400' : ''"
                      >
                        {{ sr.data.web?.headers?.[key] || (key === 'server' ? '—' : 'missing') }}
                      </td>
                    </tr>
                  </tbody>
                </table>
                <div class="mt-1.5 space-y-0.5">
                  <p v-if="!sr.data.web?.headers?.hsts" class="text-[10px] text-amber-600 dark:text-amber-400">
                    HSTS missing — consider enabling Strict-Transport-Security.
                  </p>
                  <p v-if="!sr.data.web?.headers?.csp" class="text-[10px] text-amber-600 dark:text-amber-400">
                    CSP missing — add Content-Security-Policy (start with report-only mode).
                  </p>
                </div>
              </div>

              <!-- Cookies -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-semibold">Cookies</span>
                  <UBadge size="xs" color="green" variant="subtle">good</UBadge>
                </div>
                <p class="text-xs opacity-60">
                  Cookies seen: <span class="font-semibold">{{ sr.data.web?.cookies?.count ?? 0 }}</span>
                </p>
                <p class="text-xs opacity-40 mt-0.5">
                  {{ (sr.data.web?.cookies?.count ?? 0) === 0 ? "No cookie issues detected (or no cookies set)." : "Review cookies for Secure, HttpOnly, SameSite flags." }}
                </p>
              </div>

              <!-- security.txt & robots.txt -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5 space-y-1.5">
                <div class="flex items-center justify-between text-xs">
                  <span class="font-semibold">security.txt <span class="font-normal opacity-50">(RFC 9116)</span></span>
                  <UBadge size="xs" :color="sr.data.web?.securityTxt ? 'green' : 'gray'" variant="subtle">
                    {{ sr.data.web?.securityTxt ? "found" : "not found" }}
                  </UBadge>
                </div>
                <p v-if="!sr.data.web?.securityTxt" class="text-[10px] opacity-40">
                  security.txt not found — consider publishing /.well-known/security.txt so researchers can report vulnerabilities responsibly.
                </p>
                <div class="flex items-center justify-between text-xs pt-1 border-t border-gray-100 dark:border-gray-900">
                  <span class="font-semibold">robots.txt</span>
                  <UBadge size="xs" :color="sr.data.web?.robotsTxt ? 'green' : 'gray'" variant="subtle">
                    {{ sr.data.web?.robotsTxt ? "accessible" : "not found" }}
                  </UBadge>
                </div>
              </div>
            </div>
          </UCard>

          <!-- ── DNS Posture ── -->
          <UCard :id="`dns-${idx}`" :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
            <template #header>
              <div class="flex items-center gap-2">
                <UIcon name="i-heroicons-server-stack" class="w-4 h-4 opacity-60" />
                <span class="text-sm font-medium">DNS posture</span>
              </div>
            </template>

            <div class="space-y-2">
              <!-- CAA -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-semibold">CAA Records</span>
                  <UBadge size="xs" :color="sr.data.dnsPosture?.caa?.found ? 'green' : 'amber'" variant="subtle">
                    {{ sr.data.dnsPosture?.caa?.found ? "present" : "warn" }}
                  </UBadge>
                </div>
                <p v-if="!sr.data.dnsPosture?.caa?.found" class="text-xs opacity-60">
                  CAA missing — any CA may issue certificates for this domain.
                </p>
                <div v-else class="space-y-0.5">
                  <p v-for="r in sr.data.dnsPosture.caa.records" :key="r" class="text-xs font-mono opacity-60">{{ r }}</p>
                </div>
              </div>

              <!-- DNSSEC -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-semibold">DNSSEC</span>
                  <UBadge size="xs" :color="sr.data.dnsPosture?.dnssec?.detected ? 'green' : 'amber'" variant="subtle">
                    {{ sr.data.dnsPosture?.dnssec?.detected ? "detected" : "warn" }}
                  </UBadge>
                </div>
                <p class="text-xs opacity-60">
                  {{ sr.data.dnsPosture?.dnssec?.detected
                    ? "DNSSEC detected (DNSKEY record found)."
                    : "DNSSEC not detected — consider enabling if supported by your registrar/DNS provider." }}
                </p>
              </div>

              <!-- Common Subdomains -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1.5">
                  <span class="text-xs font-semibold">Common subdomains</span>
                  <span class="text-[10px] opacity-40">Existence checks only (A/AAAA/CNAME)</span>
                </div>
                <table class="w-full text-xs">
                  <thead>
                    <tr class="border-b border-gray-100 dark:border-gray-900">
                      <th class="text-left py-1 pr-2 opacity-50 font-medium">Name</th>
                      <th class="text-left py-1 pr-2 opacity-50 font-medium">Exists</th>
                      <th class="text-left py-1 opacity-50 font-medium">Target</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="sub in (sr.data.dnsPosture?.commonSubdomains ?? [])"
                      :key="sub.name"
                      class="border-b border-gray-100 dark:border-gray-900 last:border-0"
                    >
                      <td class="py-0.5 pr-2 font-mono opacity-70">{{ sub.name }}</td>
                      <td class="py-0.5 pr-2">
                        <UBadge size="xs" :color="sub.exists ? 'amber' : 'gray'" variant="subtle">
                          {{ sub.exists ? "yes" : "no" }}
                        </UBadge>
                      </td>
                      <td class="py-0.5 font-mono opacity-50 text-[10px] truncate max-w-[100px]">{{ sub.target ?? "" }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </UCard>
        </div>

        <!-- ── Hosts & Ports + Subdomains ── -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">

          <!-- ── Hosts & Ports ── -->
          <UCard :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
            <template #header>
              <div class="flex items-center gap-2">
                <UIcon name="i-heroicons-server" class="w-4 h-4 opacity-60" />
                <span class="text-sm font-medium">Hosts & Ports</span>
                <UBadge size="xs" color="gray" variant="subtle">{{ getHostRows(sr.data).length }}</UBadge>
              </div>
            </template>
            <div v-if="!getHostRows(sr.data).length" class="text-sm opacity-50 py-1">No open ports found.</div>
            <div v-else class="overflow-x-auto">
              <table class="w-full text-xs">
                <thead>
                  <tr class="border-b border-gray-200 dark:border-gray-800">
                    <th class="text-left py-1.5 pr-3 opacity-50 font-medium">Host</th>
                    <th class="text-left py-1.5 pr-3 opacity-50 font-medium">IP</th>
                    <th class="text-left py-1.5 pr-3 opacity-50 font-medium">Port</th>
                    <th class="text-left py-1.5 pr-3 opacity-50 font-medium">Service</th>
                    <th class="text-left py-1.5 opacity-50 font-medium">Version</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="(row, ri) in getHostRows(sr.data)"
                    :key="ri"
                    class="border-b border-gray-100 dark:border-gray-900 last:border-0"
                  >
                    <td class="py-1 pr-3 font-mono truncate max-w-[120px]">{{ row.host }}</td>
                    <td class="py-1 pr-3 font-mono opacity-60">{{ row.ip }}</td>
                    <td class="py-1 pr-3 font-mono">{{ row.port }}</td>
                    <td class="py-1 pr-3 opacity-80">{{ row.service }}</td>
                    <td class="py-1 opacity-60 truncate max-w-[100px]">{{ row.product }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </UCard>

          <!-- ── Subdomains ── -->
          <UCard :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
            <template #header>
              <div class="flex items-center gap-2">
                <UIcon name="i-heroicons-list-bullet" class="w-4 h-4 opacity-60" />
                <span class="text-sm font-medium">Subdomains</span>
                <UBadge size="xs" color="gray" variant="subtle">{{ sr.data.subdomains?.length ?? 0 }}</UBadge>
              </div>
            </template>
            <div
              v-if="sr.data.meta?.toolStatus?.amass?.status === 'crtsh'"
              class="flex items-start gap-1.5 text-xs text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 rounded px-2 py-1.5 mb-2"
            >
              <UIcon name="i-heroicons-information-circle" class="w-3.5 h-3.5 mt-0.5 shrink-0" />
              <span>{{ sr.data.meta.toolStatus.amass.note }}</span>
            </div>
            <div
              v-else-if="sr.data.meta?.toolStatus?.amass?.status === 'missing' || sr.data.meta?.toolStatus?.amass?.status === 'error'"
              class="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 rounded px-2 py-1.5 mb-2"
            >
              <UIcon name="i-heroicons-exclamation-triangle" class="w-3.5 h-3.5 mt-0.5 shrink-0" />
              <span>{{ sr.data.meta.toolStatus.amass.note }}</span>
            </div>
            <div v-if="!(sr.data.subdomains?.length)" class="text-sm opacity-50 py-1">No subdomains discovered.</div>
            <div v-else class="grid grid-cols-1 gap-0.5 max-h-64 overflow-y-auto">
              <div
                v-for="s in (sr.data.subdomains ?? [])"
                :key="s"
                class="flex items-center justify-between gap-2 px-2 py-1 rounded hover:bg-gray-50 dark:hover:bg-gray-900/40 group"
              >
                <span class="font-mono text-xs truncate opacity-80">{{ s }}</span>
                <UButton
                  size="xs" color="gray" variant="ghost" icon="i-heroicons-clipboard"
                  class="opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                  @click="copyText(s)"
                />
              </div>
            </div>
          </UCard>
        </div>

        <!-- ── Domain Graph ── -->
        <UCard :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
          <template #header>
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <UIcon name="i-heroicons-share" class="w-4 h-4 opacity-60" />
                <span class="text-sm font-medium">Domain graph</span>
              </div>
              <UButton size="xs" color="gray" variant="ghost" icon="i-heroicons-arrow-path" @click="renderMermaidForResult(idx)">
                Re-render
              </UButton>
            </div>
          </template>
          <div v-if="!sr.mermaidSvg" class="text-xs opacity-50">Rendering graph…</div>
          <div v-html="sr.mermaidSvg" class="overflow-auto" />
        </UCard>

        <!-- ── Recommendations ── -->
        <UCard :id="`recs-${idx}`" :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
          <template #header>
            <div class="flex items-center gap-2">
              <UIcon name="i-heroicons-clipboard-document-list" class="w-4 h-4 opacity-60" />
              <span class="text-sm font-medium">Recommendations</span>
            </div>
          </template>
          <ol v-if="getRecommendations(sr.data).length" class="space-y-1.5 list-none">
            <li v-for="(rec, ri) in getRecommendations(sr.data)" :key="ri" class="flex items-start gap-2 text-xs">
              <span class="text-blue-500 font-semibold shrink-0 w-5 text-right">{{ ri + 1 }}.</span>
              <span class="opacity-80">{{ rec }}</span>
            </li>
          </ol>
          <p v-else class="text-sm opacity-50">No recommendations generated.</p>
        </UCard>

        <!-- ── Limitations ── -->
        <UCard :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
          <template #header>
            <div class="flex items-center gap-2">
              <UIcon name="i-heroicons-information-circle" class="w-4 h-4 opacity-60" />
              <span class="text-sm font-medium">Limitations & responsible use</span>
            </div>
          </template>
          <ul class="space-y-1">
            <li v-for="lim in [
              'Public-signal posture assessment only (DNS/HTTP/TLS). Not a penetration test.',
              'DKIM selector discovery is heuristic; absence does not prove DKIM is missing.',
              'Some sites block automated requests or serve different headers to non-browsers.',
              'Active scanning (e.g., OWASP ZAP active scan) requires explicit written authorization and should be run on staging/lab targets.',
            ]" :key="lim" class="flex items-start gap-2 text-xs">
              <span class="opacity-40 shrink-0 mt-0.5">·</span>
              <span class="opacity-60">{{ lim }}</span>
            </li>
          </ul>
        </UCard>

      </template>
    </div>
  </div>
</template>
