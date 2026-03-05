const ALLOWED_ROOTS = [
  "programuoki.lt"
  // Add more ONLY when you have explicit permission:
  // "example-company.com"
];

export function normalizeDomain(input: string) {
  const s = (input || "").trim().toLowerCase();
  return s.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
}

export function isAllowedDomain(domain: string) {
  return ALLOWED_ROOTS.some((root) => domain === root || domain.endsWith("." + root));
}
