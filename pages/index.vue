<script setup lang="ts">
import mermaid from "mermaid";
import { PDFDocument, StandardFonts } from "pdf-lib";

type Severity = "low" | "medium" | "high";

const domain = ref("programuoki.lt");
const loading = ref(false);
const result = ref<any>(null);
const errorMsg = ref<string | null>(null);

const showTeachingMode = ref(true);
const filterSeverity = ref<Severity | "all">("all");
const search = ref("");
const activeTab = ref("findings");

const tabs = [
  { key: "findings", label: "Findings" },
  { key: "email", label: "Email" },
  { key: "hosts", label: "Hosts & Ports" },
  { key: "subdomains", label: "Subdomains" },
  { key: "graph", label: "Graph" },
  { key: "raw", label: "Raw" }
];

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

const findingsFiltered = computed(() => {
  const list = (result.value?.findings ?? []) as any[];
  const q = search.value.trim().toLowerCase();
  return list.filter((f) => {
    const sevOk = filterSeverity.value === "all" || f.severity === filterSeverity.value;
    const text =
      `${f.title ?? ""} ${f.host ?? ""} ${f.details ?? ""} ${f.recommendation ?? ""} ${(f.mitigations ?? []).join(" ")}`.toLowerCase();
    const qOk = !q || text.includes(q);
    return sevOk && qOk;
  });
});

const hostsTableRows = computed(() => {
  const hosts = (result.value?.hosts ?? []) as any[];
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
});

const mxTableRows = computed(() => {
  const mx = result.value?.email?.mx ?? [];
  return mx.map((line: string) => {
    const parts = line.split(" ");
    return { priority: parts[0] ?? "", exchange: parts.slice(1).join(" ") };
  });
});

const summaryCounts = computed(() => {
  const list = (result.value?.findings ?? []) as any[];
  const high = list.filter((f) => f.severity === "high").length;
  const med = list.filter((f) => f.severity === "medium").length;
  const low = list.filter((f) => f.severity === "low").length;
  return { high, med, low, total: list.length };
});

async function runScan() {
  loading.value = true;
  errorMsg.value = null;
  result.value = null;

  try {
    result.value = await $fetch("/api/scan", {
      method: "POST",
      body: { domain: domain.value }
    });

    if (activeTab.value === "graph") {
      await nextTick();
      await renderMermaid();
    }
  } catch (e: any) {
    errorMsg.value = e?.data?.statusMessage || e?.data?.message || e?.message || "Scan failed";
  } finally {
    loading.value = false;
  }
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

async function exportMarkdown() {
  if (!result.value) return;
  const md = buildMarkdownReport(result.value);
  downloadFile(`osint-report-${result.value.domain}.md`, md, "text/markdown");
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

async function exportPDF() {
  if (!result.value) return;
  const md = buildMarkdownReport(result.value);

  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

  const pageSize = { width: 595.28, height: 841.89 }; // A4
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
  a.download = `osint-report-${result.value.domain}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}

const mermaidSvg = ref("");

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

async function renderMermaid() {
  if (!result.value) return;
  mermaid.initialize({ startOnLoad: false, theme: "default", securityLevel: "strict" });
  const code = buildMermaidGraph(result.value);
  const { svg } = await mermaid.render(`graph-${Date.now()}`, code);
  mermaidSvg.value = svg;
}

watch(activeTab, async (t) => {
  if (t === "graph" && result.value) {
    await nextTick();
    await renderMermaid();
  }
});
</script>

<template>
  <div class="max-w-6xl mx-auto p-4 md:p-6 space-y-4">
    <div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
      <div>
        <h1 class="text-2xl md:text-3xl font-semibold tracking-tight">OSINT Exposure Dashboard</h1>
        <p class="text-sm opacity-70 mt-1">
          Amass (passive) + Nmap (-sT) + Email DNS checks · exports + graph + mitigation checklist.
        </p>
      </div>

      <div class="flex items-center gap-2">
        <UButton
            color="gray"
            variant="soft"
            icon="i-heroicons-academic-cap"
            @click="showTeachingMode = !showTeachingMode"
        >
          Teaching mode: {{ showTeachingMode ? "On" : "Off" }}
        </UButton>
        <UButton
            v-if="result"
            color="gray"
            variant="soft"
            icon="i-heroicons-arrow-down-tray"
            @click="exportMarkdown"
        >
          Export MD
        </UButton>
        <UButton
            v-if="result"
            color="gray"
            variant="soft"
            icon="i-heroicons-document-arrow-down"
            @click="exportPDF"
        >
          Export PDF
        </UButton>
      </div>
    </div>

    <UCard>
      <template #header>
        <div class="flex items-center justify-between gap-3">
          <div class="flex items-center gap-2">
            <UIcon name="i-heroicons-globe-alt" class="w-5 h-5 opacity-70" />
            <span class="font-medium">Target</span>
          </div>
          <div v-if="result" class="flex items-center gap-2 text-sm">
            <UBadge :color="summaryCounts.high ? 'red' : 'gray'" variant="subtle">High: {{ summaryCounts.high }}</UBadge>
            <UBadge :color="summaryCounts.med ? 'amber' : 'gray'" variant="subtle">Medium: {{ summaryCounts.med }}</UBadge>
            <UBadge :color="summaryCounts.low ? 'green' : 'gray'" variant="subtle">Low: {{ summaryCounts.low }}</UBadge>
          </div>
        </div>
      </template>

      <div class="grid grid-cols-1 md:grid-cols-12 gap-3">
        <div class="md:col-span-5">
          <UFormField label="Domain (allowlisted)">
            <UInput v-model="domain" placeholder="programuoki.lt" icon="i-heroicons-link" />
          </UFormField>
          <p class="text-xs opacity-60 mt-2">
            Allowlist is in <code class="px-1 rounded bg-gray-100 dark:bg-gray-800">server/utils/allowlist.ts</code>
          </p>
        </div>

        <div class="md:col-span-3">
          <UFormField label="Search (findings / hosts)">
            <UInput v-model="search" placeholder="ssh, dmarc, 443..." icon="i-heroicons-magnifying-glass" />
          </UFormField>
        </div>

        <div class="md:col-span-2">
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

        <div class="md:col-span-2 flex items-end gap-2">
          <UButton :loading="loading" icon="i-heroicons-play" class="w-full" @click="runScan">
            Run scan
          </UButton>
        </div>
      </div>

      <UAlert
          v-if="errorMsg"
          class="mt-4"
          color="red"
          variant="soft"
          icon="i-heroicons-exclamation-triangle"
          :title="errorMsg"
      />

      <div v-if="showTeachingMode" class="mt-4">
        <UAlert
            color="blue"
            variant="soft"
            icon="i-heroicons-light-bulb"
            title="Teaching mode"
            description="Use findings as prompts: what is exposed, why it matters, and which mitigations developers should apply."
        />
      </div>
    </UCard>

    <UCard v-if="result">
      <template #header>
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <UIcon name="i-heroicons-chart-bar" class="w-5 h-5 opacity-70" />
            <span class="font-medium">Results</span>
          </div>
          <UButton
              size="xs"
              color="gray"
              variant="soft"
              icon="i-heroicons-clipboard"
              @click="copyText(JSON.stringify(result, null, 2))"
          >
            Copy JSON
          </UButton>
        </div>
      </template>

      <UTabs v-model="activeTab" :items="tabs" class="w-full">
        <template #item="{ item }">
          <!-- Findings -->
          <div v-if="item.key === 'findings'" class="space-y-3">
            <div v-if="!findingsFiltered.length" class="text-sm opacity-70">
              No findings match your filters/search.
            </div>

            <div v-for="(f, i) in findingsFiltered" :key="i">
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
                    <UAccordion
                        :items="[
                        { label: `Mitigation checklist (${f.mitigations.length})`, content: 'checklist' }
                      ]"
                    >
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
                    Discussion idea: “Do we need this exposure? If yes, which mitigations are mandatory?”
                  </div>
                </div>
              </UCard>
            </div>
          </div>

          <!-- Email -->
          <div v-else-if="item.key === 'email'" class="space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <UCard>
                <template #header>
                  <div class="flex items-center justify-between">
                    <span class="font-medium">SPF</span>
                    <UBadge :color="result.email?.spf?.record ? 'green' : 'red'" variant="subtle">
                      {{ result.email?.spf?.record ? 'Found' : 'Missing' }}
                    </UBadge>
                  </div>
                </template>
                <p class="text-sm opacity-80 break-words">
                  {{ result.email?.spf?.record || "No SPF TXT record found." }}
                </p>
              </UCard>

              <UCard>
                <template #header>
                  <div class="flex items-center justify-between">
                    <span class="font-medium">DMARC</span>
                    <UBadge
                        :color="
                        !result.email?.dmarc?.record ? 'red' :
                        (String(result.email?.dmarc?.policy).toLowerCase() === 'none' ? 'amber' : 'green')
                      "
                        variant="subtle"
                    >
                      {{
                        !result.email?.dmarc?.record ? "Missing" :
                            (result.email?.dmarc?.policy ? `p=${result.email.dmarc.policy}` : "Present")
                      }}
                    </UBadge>
                  </div>
                </template>

                <p class="text-sm opacity-80 break-words">
                  {{ result.email?.dmarc?.record || "No DMARC record found at _dmarc.<domain>." }}
                </p>
                <div class="text-sm opacity-80 mt-2" v-if="result.email?.dmarc?.record">
                  <span class="font-medium">Policy:</span> {{ result.email?.dmarc?.policy || "unknown" }}
                  <span v-if="result.email?.dmarc?.subdomainPolicy">
                    · <span class="font-medium">Subdomains:</span> {{ result.email?.dmarc?.subdomainPolicy }}
                  </span>
                </div>
              </UCard>
            </div>

            <UCard>
              <template #header>
                <div class="flex items-center justify-between">
                  <span class="font-medium">MX Records</span>
                  <UBadge color="gray" variant="subtle">{{ mxTableRows.length }}</UBadge>
                </div>
              </template>

              <UTable
                  :rows="mxTableRows"
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
                  <UBadge :color="(result.email?.dkim?.foundSelectors?.length ?? 0) ? 'green' : 'amber'" variant="subtle">
                    {{ (result.email?.dkim?.foundSelectors?.length ?? 0) ? "Likely enabled" : "Unknown" }}
                  </UBadge>
                </div>
              </template>
              <p class="text-sm opacity-80">{{ result.email?.dkim?.note }}</p>
              <div v-if="result.email?.dkim?.foundSelectors?.length" class="mt-3 flex flex-wrap gap-2">
                <UBadge v-for="s in result.email.dkim.foundSelectors" :key="s" color="blue" variant="subtle">
                  {{ s }}
                </UBadge>
              </div>
            </UCard>
          </div>

          <!-- Hosts -->
          <div v-else-if="item.key === 'hosts'" class="space-y-4">
            <UCard>
              <template #header>
                <div class="flex items-center justify-between">
                  <span class="font-medium">Open ports (searchable)</span>
                  <UBadge color="gray" variant="subtle">{{ hostsTableRows.length }}</UBadge>
                </div>
              </template>

              <UTable
                  :rows="hostsTableRows"
                  :columns="[
                  { key: 'host', label: 'Host' },
                  { key: 'ip', label: 'IP' },
                  { key: 'port', label: 'Port' },
                  { key: 'service', label: 'Service' },
                  { key: 'product', label: 'Product/Version' }
                ]"
              />
            </UCard>
          </div>

          <!-- Subdomains -->
          <div v-else-if="item.key === 'subdomains'" class="space-y-3">
            <UCard>
              <template #header>
                <div class="flex items-center justify-between">
                  <span class="font-medium">Discovered subdomains</span>
                  <UBadge color="gray" variant="subtle">{{ result.subdomains?.length ?? 0 }}</UBadge>
                </div>
              </template>

              <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                <div
                    v-for="s in (result.subdomains ?? [])"
                    :key="s"
                    class="flex items-center justify-between gap-2 rounded-xl border border-gray-200 dark:border-gray-800 px-3 py-2"
                >
                  <span class="font-mono text-sm truncate">{{ s }}</span>
                  <UButton size="xs" color="gray" variant="ghost" icon="i-heroicons-clipboard" @click="copyText(s)" />
                </div>
              </div>
            </UCard>
          </div>

          <!-- Graph -->
          <div v-else-if="item.key === 'graph'" class="space-y-3">
            <UCard>
              <template #header>
                <div class="flex items-center justify-between">
                  <span class="font-medium">Domain graph</span>
                  <UButton size="xs" color="gray" variant="soft" icon="i-heroicons-arrow-path" @click="renderMermaid">
                    Re-render
                  </UButton>
                </div>
              </template>

              <div v-if="!mermaidSvg" class="text-sm opacity-70">Rendering graph...</div>
              <div v-html="mermaidSvg" class="overflow-auto"></div>
            </UCard>
          </div>

          <!-- Raw -->
          <div v-else-if="item.key === 'raw'">
            <UCard>
              <template #header>
                <div class="flex items-center justify-between">
                  <span class="font-medium">Raw JSON</span>
                  <UButton size="xs" color="gray" variant="soft" icon="i-heroicons-clipboard" @click="copyText(JSON.stringify(result, null, 2))">
                    Copy
                  </UButton>
                </div>
              </template>
              <pre class="text-xs overflow-auto whitespace-pre-wrap">{{ JSON.stringify(result, null, 2) }}</pre>
            </UCard>
          </div>
        </template>
      </UTabs>
    </UCard>

    <UCard v-else>
      <div class="text-sm opacity-70">
        Run a scan to see results. Exports + graph become available after a scan.
      </div>
    </UCard>
  </div>
</template>
