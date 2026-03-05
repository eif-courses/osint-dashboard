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
      await renderMermaidForResult(i);
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
    <!-- Header -->
    <div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
      <div>
        <h1 class="text-2xl md:text-3xl font-semibold tracking-tight">OSINT Exposure Dashboard</h1>
        <p class="text-sm opacity-70 mt-1">
          Amass (passive) + Nmap (-sT) + Email DNS checks · exports + graph + mitigation checklist.
        </p>
      </div>
      <UButton
        color="gray"
        variant="soft"
        icon="i-heroicons-academic-cap"
        @click="showTeachingMode = !showTeachingMode"
      >
        Teaching mode: {{ showTeachingMode ? "On" : "Off" }}
      </UButton>
    </div>

    <!-- Input Card -->
    <UCard>
      <template #header>
        <div class="flex items-center gap-2">
          <UIcon name="i-heroicons-globe-alt" class="w-5 h-5 opacity-70" />
          <span class="font-medium">Targets</span>
        </div>
      </template>

      <div class="space-y-3">
        <UFormField label="Domains (one per line, or comma-separated)">
          <UTextarea
            v-model="domainsInput"
            placeholder="example.com&#10;another-domain.org&#10;third-domain.net"
            :rows="4"
            class="font-mono w-full"
          />
        </UFormField>

        <div class="flex flex-col md:flex-row gap-3">
          <div class="flex-1">
            <UFormField label="Search (findings / hosts)">
              <UInput v-model="search" placeholder="ssh, dmarc, 443..." icon="i-heroicons-magnifying-glass" />
            </UFormField>
          </div>

          <div class="md:w-40">
            <UFormField label="Severity">
              <USelect
                v-model="filterSeverity"
                :options="[
                  { label: 'All', value: 'all' },
                  { label: 'High', value: 'high' },
                  { label: 'Medium', value: 'medium' },
                  { label: 'Low', value: 'low' }
                ]"
              />
            </UFormField>
          </div>

          <div class="md:w-36 flex items-end">
            <UButton :loading="globalLoading" icon="i-heroicons-play" class="w-full" @click="runScan">
              Run scan
            </UButton>
          </div>
        </div>

        <div v-if="showTeachingMode">
          <UAlert
            color="blue"
            variant="soft"
            icon="i-heroicons-light-bulb"
            title="Teaching mode"
            description="Use findings as prompts: what is exposed, why it matters, and which mitigations developers should apply."
          />
        </div>
      </div>
    </UCard>

    <!-- Empty state -->
    <UCard v-if="!results.length">
      <div class="text-sm opacity-70">
        Enter one or more domains above and click "Run scan". All findings, email security, open ports, subdomains and graphs will appear here.
      </div>
    </UCard>

    <!-- Results for each domain -->
    <div v-for="(sr, idx) in results" :key="sr.domain" class="space-y-4">
      <!-- Domain header bar -->
      <div class="flex items-center justify-between gap-3 pt-2 border-t-2 border-gray-200 dark:border-gray-700">
        <div class="flex flex-wrap items-center gap-3">
          <h2 class="text-lg font-semibold font-mono">{{ sr.domain }}</h2>
          <template v-if="sr.data">
            <UBadge :color="getSummaryCounts(sr.data).high ? 'red' : 'gray'" variant="subtle">
              High: {{ getSummaryCounts(sr.data).high }}
            </UBadge>
            <UBadge :color="getSummaryCounts(sr.data).med ? 'amber' : 'gray'" variant="subtle">
              Medium: {{ getSummaryCounts(sr.data).med }}
            </UBadge>
            <UBadge :color="getSummaryCounts(sr.data).low ? 'green' : 'gray'" variant="subtle">
              Low: {{ getSummaryCounts(sr.data).low }}
            </UBadge>
          </template>
        </div>

        <div v-if="sr.data" class="flex items-center gap-2 shrink-0">
          <UButton size="xs" color="gray" variant="soft" icon="i-heroicons-arrow-down-tray" @click="exportMarkdown(sr.data)">
            MD
          </UButton>
          <UButton size="xs" color="gray" variant="soft" icon="i-heroicons-document-arrow-down" @click="exportPDF(sr.data)">
            PDF
          </UButton>
          <UButton size="xs" color="gray" variant="soft" icon="i-heroicons-clipboard" @click="copyText(JSON.stringify(sr.data, null, 2))">
            JSON
          </UButton>
        </div>
      </div>

      <!-- Scanning indicator -->
      <div v-if="sr.loading" class="flex items-center gap-3 p-4">
        <UIcon name="i-heroicons-arrow-path" class="w-5 h-5 animate-spin opacity-70" />
        <span class="text-sm opacity-70">Scanning {{ sr.domain }}… this may take up to 2 minutes.</span>
      </div>

      <!-- Error -->
      <UAlert
        v-else-if="sr.error"
        color="red"
        variant="soft"
        icon="i-heroicons-exclamation-triangle"
        :title="sr.error"
      />

      <!-- All result sections expanded on same page -->
      <template v-else-if="sr.data">

        <!-- ── Findings ── -->
        <UCard>
          <template #header>
            <div class="flex items-center gap-2">
              <UIcon name="i-heroicons-shield-exclamation" class="w-5 h-5 opacity-70" />
              <span class="font-medium">Findings</span>
              <UBadge color="gray" variant="subtle">{{ getFindings(sr.data).length }}</UBadge>
            </div>
          </template>

          <div class="space-y-3">
            <div v-if="!getFindings(sr.data).length" class="text-sm opacity-70">
              No findings match your filters/search.
            </div>

            <div v-for="(f, fi) in getFindings(sr.data)" :key="fi">
              <UCard class="shadow-sm">
                <template #header>
                  <div class="flex items-start justify-between gap-3">
                    <div class="min-w-0">
                      <div class="flex items-center gap-2">
                        <UBadge :color="sevColor(f.severity)" variant="subtle">{{ sevLabel(f.severity) }}</UBadge>
                        <p class="font-semibold truncate">{{ f.title }}</p>
                      </div>
                      <p v-if="f.host" class="text-xs opacity-70 mt-1">
                        Host: <span class="font-mono">{{ f.host }}</span>
                      </p>
                    </div>
                    <UButton
                      size="xs"
                      color="gray"
                      variant="ghost"
                      icon="i-heroicons-clipboard"
                      @click="copyText(`${f.title}\n${f.host ? 'Host: '+f.host+'\n' : ''}${f.details ?? ''}\n${f.recommendation ?? ''}\nMitigations:\n- ${(f.mitigations ?? []).join('\n- ')}`)"
                    >
                      Copy
                    </UButton>
                  </div>
                </template>

                <div class="space-y-2">
                  <p v-if="f.details" class="text-sm opacity-80">{{ f.details }}</p>

                  <div v-if="f.recommendation" class="rounded-xl p-3 bg-gray-50 dark:bg-gray-900/40">
                    <p class="text-sm">
                      <span class="font-medium">Recommendation:</span>
                      <span class="opacity-80"> {{ f.recommendation }}</span>
                    </p>
                  </div>

                  <div v-if="(f.mitigations ?? []).length">
                    <UAccordion :items="[{ label: `Mitigation checklist (${f.mitigations.length})`, content: 'checklist' }]">
                      <template #item="{ item: accItem }">
                        <div v-if="accItem.content === 'checklist'" class="space-y-2">
                          <div
                            v-for="(m, mi) in f.mitigations"
                            :key="mi"
                            class="flex items-start gap-2 rounded-xl border border-gray-200 dark:border-gray-800 px-3 py-2"
                          >
                            <input type="checkbox" class="mt-1" />
                            <p class="text-sm opacity-80">{{ m }}</p>
                          </div>
                        </div>
                      </template>
                    </UAccordion>
                  </div>

                  <div v-if="showTeachingMode" class="text-xs opacity-70">
                    Discussion idea: "Do we need this exposure? If yes, which mitigations are mandatory?"
                  </div>
                </div>
              </UCard>
            </div>
          </div>
        </UCard>

        <!-- ── Email Security ── -->
        <UCard>
          <template #header>
            <div class="flex items-center gap-2">
              <UIcon name="i-heroicons-envelope" class="w-5 h-5 opacity-70" />
              <span class="font-medium">Email Security</span>
            </div>
          </template>

          <div class="space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <UCard>
                <template #header>
                  <div class="flex items-center justify-between">
                    <span class="font-medium">SPF</span>
                    <UBadge :color="sr.data.email?.spf?.record ? 'green' : 'red'" variant="subtle">
                      {{ sr.data.email?.spf?.record ? 'Found' : 'Missing' }}
                    </UBadge>
                  </div>
                </template>
                <p class="text-sm opacity-80 break-words">
                  {{ sr.data.email?.spf?.record || "No SPF TXT record found." }}
                </p>
              </UCard>

              <UCard>
                <template #header>
                  <div class="flex items-center justify-between">
                    <span class="font-medium">DMARC</span>
                    <UBadge
                      :color="
                        !sr.data.email?.dmarc?.record ? 'red' :
                        (String(sr.data.email?.dmarc?.policy).toLowerCase() === 'none' ? 'amber' : 'green')
                      "
                      variant="subtle"
                    >
                      {{
                        !sr.data.email?.dmarc?.record ? "Missing" :
                          (sr.data.email?.dmarc?.policy ? `p=${sr.data.email.dmarc.policy}` : "Present")
                      }}
                    </UBadge>
                  </div>
                </template>
                <p class="text-sm opacity-80 break-words">
                  {{ sr.data.email?.dmarc?.record || "No DMARC record found at _dmarc.<domain>." }}
                </p>
                <div class="text-sm opacity-80 mt-2" v-if="sr.data.email?.dmarc?.record">
                  <span class="font-medium">Policy:</span> {{ sr.data.email?.dmarc?.policy || "unknown" }}
                  <span v-if="sr.data.email?.dmarc?.subdomainPolicy">
                    · <span class="font-medium">Subdomains:</span> {{ sr.data.email?.dmarc?.subdomainPolicy }}
                  </span>
                </div>
              </UCard>
            </div>

            <UCard>
              <template #header>
                <div class="flex items-center justify-between">
                  <span class="font-medium">MX Records</span>
                  <UBadge color="gray" variant="subtle">{{ getMxRows(sr.data).length }}</UBadge>
                </div>
              </template>
              <UTable
                :rows="getMxRows(sr.data)"
                :columns="[
                  { key: 'priority', label: 'Priority' },
                  { key: 'exchange', label: 'Mail server' }
                ]"
              />
            </UCard>

            <UCard>
              <template #header>
                <div class="flex items-center justify-between">
                  <span class="font-medium">DKIM</span>
                  <UBadge :color="(sr.data.email?.dkim?.foundSelectors?.length ?? 0) ? 'green' : 'amber'" variant="subtle">
                    {{ (sr.data.email?.dkim?.foundSelectors?.length ?? 0) ? "Likely enabled" : "Unknown" }}
                  </UBadge>
                </div>
              </template>
              <p class="text-sm opacity-80">{{ sr.data.email?.dkim?.note }}</p>
              <div v-if="sr.data.email?.dkim?.foundSelectors?.length" class="mt-3 flex flex-wrap gap-2">
                <UBadge v-for="s in sr.data.email.dkim.foundSelectors" :key="s" color="blue" variant="subtle">
                  {{ s }}
                </UBadge>
              </div>
            </UCard>
          </div>
        </UCard>

        <!-- ── Hosts & Ports ── -->
        <UCard>
          <template #header>
            <div class="flex items-center gap-2">
              <UIcon name="i-heroicons-server" class="w-5 h-5 opacity-70" />
              <span class="font-medium">Hosts & Ports</span>
              <UBadge color="gray" variant="subtle">{{ getHostRows(sr.data).length }}</UBadge>
            </div>
          </template>
          <UTable
            :rows="getHostRows(sr.data)"
            :columns="[
              { key: 'host', label: 'Host' },
              { key: 'ip', label: 'IP' },
              { key: 'port', label: 'Port' },
              { key: 'service', label: 'Service' },
              { key: 'product', label: 'Product/Version' }
            ]"
          />
        </UCard>

        <!-- ── Subdomains ── -->
        <UCard>
          <template #header>
            <div class="flex items-center gap-2">
              <UIcon name="i-heroicons-list-bullet" class="w-5 h-5 opacity-70" />
              <span class="font-medium">Subdomains</span>
              <UBadge color="gray" variant="subtle">{{ sr.data.subdomains?.length ?? 0 }}</UBadge>
            </div>
          </template>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
            <div
              v-for="s in (sr.data.subdomains ?? [])"
              :key="s"
              class="flex items-center justify-between gap-2 rounded-xl border border-gray-200 dark:border-gray-800 px-3 py-2"
            >
              <span class="font-mono text-sm truncate">{{ s }}</span>
              <UButton size="xs" color="gray" variant="ghost" icon="i-heroicons-clipboard" @click="copyText(s)" />
            </div>
          </div>
        </UCard>

        <!-- ── Domain Graph ── -->
        <UCard>
          <template #header>
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <UIcon name="i-heroicons-share" class="w-5 h-5 opacity-70" />
                <span class="font-medium">Domain graph</span>
              </div>
              <UButton size="xs" color="gray" variant="soft" icon="i-heroicons-arrow-path" @click="renderMermaidForResult(idx)">
                Re-render
              </UButton>
            </div>
          </template>
          <div v-if="!sr.mermaidSvg" class="text-sm opacity-70">Rendering graph…</div>
          <div v-html="sr.mermaidSvg" class="overflow-auto"></div>
        </UCard>

      </template>
    </div>
  </div>
</template>
