import { assertValidDomain } from "../validate.js";

export interface CertTransparencyResult {
  domain: string;
  subdomains: string[];
  certificates: CertEntry[];
  totalCerts: number;
  error: string | null;
}

export interface CertEntry {
  commonName: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
}

export async function queryCertTransparency(domain: string): Promise<CertTransparencyResult> {
  assertValidDomain(domain);

  const result: CertTransparencyResult = {
    domain,
    subdomains: [],
    certificates: [],
    totalCerts: 0,
    error: null,
  };

  try {
    const resp = await fetch(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { signal: AbortSignal.timeout(15000) }
    );

    if (!resp.ok) {
      result.error = `crt.sh returned HTTP ${resp.status}`;
      return result;
    }

    const data = await resp.json() as Array<{
      common_name?: string;
      name_value?: string;
      issuer_name?: string;
      not_before?: string;
      not_after?: string;
    }>;

    result.totalCerts = data.length;

    // Extract unique subdomains
    const subdomainSet = new Set<string>();
    for (const cert of data) {
      if (cert.common_name) {
        const cn = cert.common_name.toLowerCase().replace(/^\*\./, "");
        if (cn.endsWith(domain) || cn === domain) subdomainSet.add(cn);
      }
      if (cert.name_value) {
        const names = cert.name_value.split("\n");
        for (const name of names) {
          const clean = name.trim().toLowerCase().replace(/^\*\./, "");
          if (clean.endsWith(domain) || clean === domain) subdomainSet.add(clean);
        }
      }
    }

    result.subdomains = Array.from(subdomainSet).sort();

    // Keep recent certs (deduplicated by common name)
    const seen = new Set<string>();
    for (const cert of data.slice(0, 50)) {
      const cn = cert.common_name || "";
      if (seen.has(cn)) continue;
      seen.add(cn);
      result.certificates.push({
        commonName: cn,
        issuer: cert.issuer_name || "",
        notBefore: cert.not_before || "",
        notAfter: cert.not_after || "",
      });
    }

    return result;
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "Certificate transparency lookup failed";
    return result;
  }
}
