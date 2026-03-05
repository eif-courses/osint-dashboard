export function normalizeDomain(input: string) {
  const s = (input || "").trim().toLowerCase();
  return s.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
}

export function isAllowedDomain(domain: string) {
  // Accept any valid-looking domain (has at least one dot, valid characters)
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(domain);
}
