<script setup lang="ts">
import mermaid from "mermaid";
import { PDFDocument, StandardFonts } from "pdf-lib";

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
        product: `${p.service?.product ?? ""} ${p.service?.version ?? ""}`.trim()
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
    total: list.length
  };
}

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
    mermaidSvg: ""
  }));

  for (let i = 0; i < results.value.length; i++) {
    try {
      const data = await $fetch("/api/scan", {
        method: "POST",
        body: { domain: results.value[i].domain }
      });
      results.value[i] = { ...results.value[i], loading: false, data };
      await nextTick();
      renderMermaidForResult(i); // fire-and-forget – must NOT be awaited or it can stall globalLoading
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

function buildMarkdownReport(data: any) {
  const lines: string[] = [];
  const now = new Date().toISOString();

  lines.push(`# OSINT Exposure Report`);
  lines.push(`- Domain: **${data.domain}**`);
  lines.push(`- Generated: ${now}`);
  lines.push("");

  lines.push(`## Summary`);
  lines.push(`- Findings: ${data.findings?.length ?? 0}`);
  lines.push(`- Scanned hosts: ${data.meta?.scannedHosts ?? 0}`);
  lines.push(`- Scan type: ${data.meta?.scanType ?? ""}`);
  lines.push("");

  lines.push(`## Email Security`);
  lines.push(`### MX`);
  const mx = data.email?.mx ?? [];
  if (!mx.length) lines.push(`- (none found)`);
  else mx.forEach((m: string) => lines.push(`- ${m}`));
  lines.push("");

  lines.push(`### SPF`);
  lines.push(data.email?.spf?.record ? `\`${data.email.spf.record}\`` : `- Not found`);
  lines.push("");

  lines.push(`### DMARC`);
  lines.push(data.email?.dmarc?.record ? `\`${data.email.dmarc.record}\`` : `- Not found`);
  if (data.email?.dmarc?.policy) lines.push(`- Policy: **p=${data.email.dmarc.policy}**`);
  if (data.email?.dmarc?.subdomainPolicy) lines.push(`- Subdomains: **sp=${data.email.dmarc.subdomainPolicy}**`);
  lines.push("");

  lines.push(`### DKIM`);
  lines.push(`- ${data.email?.dkim?.note ?? "N/A"}`);
  if ((data.email?.dkim?.foundSelectors ?? []).length) {
    lines.push(`- Found selectors: ${data.email.dkim.foundSelectors.join(", ")}`);
  }
  lines.push("");

  lines.push(`## Findings`);
  const findings = data.findings ?? [];
  if (!findings.length) {
    lines.push(`- No findings.`);
  } else {
    for (const f of findings) {
      lines.push(`### [${String(f.severity).toUpperCase()}] ${f.title}`);
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

  lines.push(`## Open Ports by Host`);
  for (const h of data.hosts ?? []) {
    const open = (h.ports ?? []).filter((p: any) => p.state === "open");
    lines.push(`### ${h.target}${h.address ? ` (${h.address})` : ""}`);
    if (!open.length) {
      lines.push(`- No open ports detected (or host unreachable).`);
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
  const subs = data.subdomains ?? [];
  subs.forEach((s: string) => lines.push(`- ${s}`));
  lines.push("");

  return lines.join("\n");
}

async function exportMarkdown(data: any) {
  const md = buildMarkdownReport(data);
  downloadFile(`osint-report-${data.domain}.md`, md, "text/markdown");
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
  a.download = `osint-report-${data.domain}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}

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
        <h1 class="text-xl font-bold tracking-tight">OSINT Exposure Dashboard</h1>
        <p class="text-xs opacity-50 mt-0.5">Amass (passive) + Nmap (-sT) + Email DNS · exports · graph · mitigation checklist</p>
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
          <!-- Domain input -->
          <div class="flex-1">
            <label class="text-xs font-medium opacity-70 mb-1 block">Domains (one per line or comma-separated)</label>
            <UTextarea
              v-model="domainsInput"
              placeholder="example.com&#10;another.org"
              :rows="3"
              class="font-mono text-sm w-full"
            />
          </div>

          <!-- Controls column -->
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
          description="Use findings as prompts: what is exposed, why it matters, and which mitigations developers should apply."
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
        <span class="text-sm opacity-70">Scanning <span class="font-mono">{{ sr.domain }}</span>… up to 2 min.</span>
      </div>

      <!-- Error -->
      <UAlert v-else-if="sr.error" color="red" variant="soft" icon="i-heroicons-exclamation-triangle" :title="sr.error" />

      <!-- Results grid -->
      <template v-else-if="sr.data">

        <!-- Top row: Findings + Email Security side by side on wide screens -->
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
                <!-- Finding header -->
                <div class="flex items-start justify-between gap-2">
                  <div class="flex items-center gap-1.5 flex-wrap min-w-0">
                    <UBadge size="xs" :color="sevColor(f.severity)" variant="subtle">{{ sevLabel(f.severity) }}</UBadge>
                    <span class="text-sm font-semibold">{{ f.title }}</span>
                  </div>
                  <UButton
                    size="xs"
                    color="gray"
                    variant="ghost"
                    icon="i-heroicons-clipboard"
                    class="shrink-0"
                    @click="copyText(`${f.title}\n${f.host ? 'Host: '+f.host+'\n' : ''}${f.details ?? ''}\n${f.recommendation ?? ''}\nMitigations:\n- ${(f.mitigations ?? []).join('\n- ')}`)"
                  />
                </div>

                <p v-if="f.host" class="text-xs opacity-50 font-mono">{{ f.host }}</p>
                <p v-if="f.details" class="text-xs opacity-70">{{ f.details }}</p>

                <div v-if="f.recommendation" class="text-xs rounded-lg bg-gray-50 dark:bg-gray-900/40 px-2 py-1.5">
                  <span class="font-medium">Rec:</span> <span class="opacity-70">{{ f.recommendation }}</span>
                </div>

                <!-- Mitigations – always visible, no accordion -->
                <div v-if="(f.mitigations ?? []).length" class="space-y-1 pt-0.5">
                  <p class="text-xs font-medium opacity-60">Mitigations</p>
                  <div
                    v-for="(m, mi) in f.mitigations"
                    :key="mi"
                    class="flex items-start gap-2"
                  >
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
          <UCard :ui="{ body: { padding: 'p-3' }, header: { padding: 'px-3 py-2' } }">
            <template #header>
              <div class="flex items-center gap-2">
                <UIcon name="i-heroicons-envelope" class="w-4 h-4 opacity-60" />
                <span class="text-sm font-medium">Email Security</span>
              </div>
            </template>

            <div class="space-y-2">
              <!-- SPF -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-semibold">SPF</span>
                  <UBadge size="xs" :color="sr.data.email?.spf?.record ? 'green' : 'red'" variant="subtle">
                    {{ sr.data.email?.spf?.record ? 'Found' : 'Missing' }}
                  </UBadge>
                </div>
                <p class="text-xs opacity-60 break-all">{{ sr.data.email?.spf?.record || "No SPF TXT record found." }}</p>
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
                    {{ !sr.data.email?.dmarc?.record ? "Missing" : (sr.data.email?.dmarc?.policy ? `p=${sr.data.email.dmarc.policy}` : "Present") }}
                  </UBadge>
                </div>
                <p class="text-xs opacity-60 break-all">{{ sr.data.email?.dmarc?.record || "No DMARC record found." }}</p>
                <p v-if="sr.data.email?.dmarc?.subdomainPolicy" class="text-xs opacity-50 mt-0.5">
                  sp={{ sr.data.email.dmarc.subdomainPolicy }}
                </p>
              </div>

              <!-- DKIM -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-semibold">DKIM</span>
                  <UBadge size="xs" :color="(sr.data.email?.dkim?.foundSelectors?.length ?? 0) ? 'green' : 'amber'" variant="subtle">
                    {{ (sr.data.email?.dkim?.foundSelectors?.length ?? 0) ? "Likely enabled" : "Unknown" }}
                  </UBadge>
                </div>
                <p class="text-xs opacity-60">{{ sr.data.email?.dkim?.note }}</p>
                <div v-if="sr.data.email?.dkim?.foundSelectors?.length" class="mt-1 flex flex-wrap gap-1">
                  <UBadge v-for="s in sr.data.email.dkim.foundSelectors" :key="s" size="xs" color="blue" variant="subtle">{{ s }}</UBadge>
                </div>
              </div>

              <!-- MX -->
              <div class="rounded-lg border border-gray-200 dark:border-gray-800 p-2.5">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-semibold">MX Records</span>
                  <UBadge size="xs" color="gray" variant="subtle">{{ getMxRows(sr.data).length }}</UBadge>
                </div>
                <div class="space-y-0.5">
                  <div v-if="!getMxRows(sr.data).length" class="text-xs opacity-50">None found.</div>
                  <div v-for="row in getMxRows(sr.data)" :key="row.exchange" class="flex items-center gap-2 text-xs">
                    <span class="opacity-40 w-6 text-right shrink-0">{{ row.priority }}</span>
                    <span class="font-mono opacity-70 truncate">{{ row.exchange }}</span>
                  </div>
                </div>
              </div>
            </div>
          </UCard>
        </div>

        <!-- Bottom row: Hosts & Ports + Subdomains + Graph -->
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
            <div v-if="!(sr.data.subdomains?.length)" class="text-sm opacity-50 py-1">No subdomains discovered.</div>
            <div v-else class="grid grid-cols-1 gap-0.5 max-h-64 overflow-y-auto">
              <div
                v-for="s in (sr.data.subdomains ?? [])"
                :key="s"
                class="flex items-center justify-between gap-2 px-2 py-1 rounded hover:bg-gray-50 dark:hover:bg-gray-900/40 group"
              >
                <span class="font-mono text-xs truncate opacity-80">{{ s }}</span>
                <UButton
                  size="xs"
                  color="gray"
                  variant="ghost"
                  icon="i-heroicons-clipboard"
                  class="opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                  @click="copyText(s)"
                />
              </div>
            </div>
          </UCard>
        </div>

        <!-- ── Domain Graph (full width) ── -->
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

      </template>
    </div>
  </div>
</template>
