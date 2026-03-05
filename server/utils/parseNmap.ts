import { XMLParser } from "fast-xml-parser";

export type NmapPort = {
  port: number;
  protocol: string;
  state: string;
  service?: { name?: string; product?: string; version?: string };
};

export type NmapHost = {
  target: string;
  address?: string;
  ports: NmapPort[];
};

export function parseNmapXml(xml: string): NmapHost[] {
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "" });
  const doc = parser.parse(xml);

  const hostsRaw = doc?.nmaprun?.host;
  if (!hostsRaw) return [];

  const hostsArr = Array.isArray(hostsRaw) ? hostsRaw : [hostsRaw];

  return hostsArr.map((h: any) => {
    const addrObj = Array.isArray(h.address) ? h.address : h.address ? [h.address] : [];
    const ipv4 = addrObj.find((a: any) => a.addrtype === "ipv4")?.addr;
    const target = h?.hostnames?.hostname?.name || ipv4 || "unknown";

    const portsRaw = h?.ports?.port ? (Array.isArray(h.ports.port) ? h.ports.port : [h.ports.port]) : [];

    const ports: NmapPort[] = portsRaw.map((p: any) => ({
      port: Number(p.portid),
      protocol: p.protocol,
      state: p?.state?.state ?? "unknown",
      service: p.service ? { name: p.service.name, product: p.service.product, version: p.service.version } : undefined
    }));

    return { target, address: ipv4, ports };
  });
}
