/**
 * Domain registrar integrations
 * Supports GoDaddy, Namecheap, and Cloudflare APIs
 */

export type RegistrarProvider = "godaddy" | "namecheap" | "cloudflare";

interface GodaddyAvailabilityResponse {
  available: boolean;
  price?: number;
  currency?: string;
}

interface GodaddyPurchaseResponse {
  orderId?: number;
  message?: string;
}

interface CloudflareResponse<T> {
  success: boolean;
  result?: T;
  errors?: { message: string }[];
}

export interface RegistrarConfig {
  provider: RegistrarProvider;
  apiKey: string;
  apiSecret?: string;
  accountId?: string; // For Cloudflare
  username?: string; // For Namecheap
  clientIp?: string; // For Namecheap
}

export interface RegistrationResult {
  success: boolean;
  domain: string;
  provider: RegistrarProvider;
  message: string;
  orderId?: string;
  error?: string;
}

export interface AvailabilityCheckResult {
  domain: string;
  available: boolean;
  price?: number;
  currency?: string;
  provider: RegistrarProvider;
  error?: string;
}

// ─── GoDaddy ──────────────────────────────────────────────

async function godaddyCheckAvailability(
  domain: string,
  config: RegistrarConfig
): Promise<AvailabilityCheckResult> {
  try {
    const resp = await fetch(
      `https://api.godaddy.com/v1/domains/available?domain=${encodeURIComponent(domain)}`,
      {
        headers: {
          Authorization: `sso-key ${config.apiKey}:${config.apiSecret}`,
          "Content-Type": "application/json",
        },
      }
    );
    const data = (await resp.json()) as GodaddyAvailabilityResponse;
    return {
      domain,
      available: data.available === true,
      price: data.price ? data.price / 1000000 : undefined,
      currency: data.currency || "USD",
      provider: "godaddy" as const,
    };
  } catch (err: unknown) {
    return {
      domain,
      available: false,
      provider: "godaddy" as const,
      error: err instanceof Error ? err.message : "Unknown error",
    };
  }
}

async function godaddyRegister(
  domain: string,
  config: RegistrarConfig
): Promise<RegistrationResult> {
  try {
    const body = {
      domain,
      consent: {
        agreedAt: new Date().toISOString(),
        agreedBy: config.clientIp || "127.0.0.1",
        agreementKeys: ["DNRA"],
      },
      period: 1,
      renewAuto: false,
      nameServers: [],
      privacy: false,
    };

    const resp = await fetch("https://api.godaddy.com/v1/domains/purchase", {
      method: "POST",
      headers: {
        Authorization: `sso-key ${config.apiKey}:${config.apiSecret}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    const data = (await resp.json()) as GodaddyPurchaseResponse;
    if (resp.ok) {
      return {
        success: true,
        domain,
        provider: "godaddy" as const,
        message: `Domain ${domain} registered successfully!`,
        orderId: data.orderId?.toString(),
      };
    }
    return {
      success: false,
      domain,
      provider: "godaddy" as const,
      message: "Registration failed",
      error: data.message || JSON.stringify(data),
    };
  } catch (err: unknown) {
    return {
      success: false,
      domain,
      provider: "godaddy" as const,
      message: "Registration failed",
      error: err instanceof Error ? err.message : "Unknown error",
    };
  }
}

// ─── Namecheap ────────────────────────────────────────────

function parseNamecheapDomain(domain: string): { sld: string; tld: string } {
  const parts = domain.split(".");
  const tld = parts.slice(1).join(".");
  const sld = parts[0] || "";
  return { sld, tld };
}

async function namecheapCheckAvailability(
  domain: string,
  config: RegistrarConfig
): Promise<AvailabilityCheckResult> {
  try {
    const url = new URL("https://api.namecheap.com/xml.response");
    url.searchParams.set("ApiUser", config.username || "");
    url.searchParams.set("ApiKey", config.apiKey);
    url.searchParams.set("UserName", config.username || "");
    url.searchParams.set("ClientIp", config.clientIp || "127.0.0.1");
    url.searchParams.set("Command", "namecheap.domains.check");
    url.searchParams.set("DomainList", domain);

    const resp = await fetch(url.toString());
    const text = await resp.text();

    const available = text.includes('Available="true"');
    return {
      domain,
      available,
      provider: "namecheap" as const,
    };
  } catch (err: unknown) {
    return {
      domain,
      available: false,
      provider: "namecheap" as const,
      error: err instanceof Error ? err.message : "Unknown error",
    };
  }
}

async function namecheapRegister(
  domain: string,
  config: RegistrarConfig
): Promise<RegistrationResult> {
  try {
    const { sld, tld } = parseNamecheapDomain(domain);
    const url = new URL("https://api.namecheap.com/xml.response");
    url.searchParams.set("ApiUser", config.username || "");
    url.searchParams.set("ApiKey", config.apiKey);
    url.searchParams.set("UserName", config.username || "");
    url.searchParams.set("ClientIp", config.clientIp || "127.0.0.1");
    url.searchParams.set("Command", "namecheap.domains.create");
    url.searchParams.set("DomainName", domain);
    url.searchParams.set("Years", "1");
    // Registrant info would need to be configured
    url.searchParams.set("AuxBillingFirstName", "Domain");
    url.searchParams.set("AuxBillingLastName", "Sniper");

    const resp = await fetch(url.toString());
    const text = await resp.text();

    if (text.includes('Status="OK"') || text.includes("DomainCreated")) {
      return {
        success: true,
        domain,
        provider: "namecheap" as const,
        message: `Domain ${domain} registered via Namecheap!`,
      };
    }

    return {
      success: false,
      domain,
      provider: "namecheap" as const,
      message: "Registration failed",
      error: text.match(/<Error.*?>(.*?)<\/Error>/)?.[1] || "Unknown error",
    };
  } catch (err: unknown) {
    return {
      success: false,
      domain,
      provider: "namecheap" as const,
      message: "Registration failed",
      error: err instanceof Error ? err.message : "Unknown error",
    };
  }
}

// ─── Cloudflare ───────────────────────────────────────────

async function cloudflareCheckAvailability(
  domain: string,
  config: RegistrarConfig
): Promise<AvailabilityCheckResult> {
  try {
    if (!config.accountId) {
      return {
        domain,
        available: false,
        provider: "cloudflare",
        error: "Account ID required for Cloudflare",
      };
    }

    const resp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${config.accountId}/registrar/domains/${domain}`,
      {
        headers: {
          Authorization: `Bearer ${config.apiKey}`,
          "Content-Type": "application/json",
        },
      }
    );
    const data = (await resp.json()) as CloudflareResponse<{ available?: boolean }>;

    if (!data.success) {
      return {
        domain,
        available: false,
        provider: "cloudflare" as const,
        error: data.errors?.[0]?.message || "API request failed",
      };
    }

    if (data.result?.available) {
      return {
        domain,
        available: true,
        provider: "cloudflare" as const,
      };
    }

    return {
      domain,
      available: false,
      provider: "cloudflare" as const,
    };
  } catch (err: unknown) {
    return {
      domain,
      available: false,
      provider: "cloudflare" as const,
      error: err instanceof Error ? err.message : "Unknown error",
    };
  }
}

async function cloudflareRegister(
  domain: string,
  config: RegistrarConfig
): Promise<RegistrationResult> {
  try {
    if (!config.accountId) {
      return {
        success: false,
        domain,
        provider: "cloudflare" as const,
        message: "Registration failed",
        error: "Account ID required for Cloudflare",
      };
    }

    const resp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${config.accountId}/registrar/domains/${domain}/register`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          auto_renew: false,
        }),
      }
    );
    const data = (await resp.json()) as CloudflareResponse<{ id?: string }>;

    if (data.success) {
      return {
        success: true,
        domain,
        provider: "cloudflare" as const,
        message: `Domain ${domain} registered via Cloudflare!`,
        orderId: data.result?.id,
      };
    }

    return {
      success: false,
      domain,
      provider: "cloudflare" as const,
      message: "Registration failed",
      error: data.errors?.[0]?.message || "Unknown error",
    };
  } catch (err: unknown) {
    return {
      success: false,
      domain,
      provider: "cloudflare" as const,
      message: "Registration failed",
      error: err instanceof Error ? err.message : "Unknown error",
    };
  }
}

// ─── Unified API ──────────────────────────────────────────

export async function checkAvailabilityViaRegistrar(
  domain: string,
  config: RegistrarConfig
): Promise<AvailabilityCheckResult> {
  switch (config.provider) {
    case "godaddy":
      return godaddyCheckAvailability(domain, config);
    case "namecheap":
      return namecheapCheckAvailability(domain, config);
    case "cloudflare":
      return cloudflareCheckAvailability(domain, config);
    default:
      return {
        domain,
        available: false,
        provider: config.provider,
        error: `Unknown provider: ${config.provider}`,
      };
  }
}

export async function registerDomain(
  domain: string,
  config: RegistrarConfig
): Promise<RegistrationResult> {
  switch (config.provider) {
    case "godaddy":
      return godaddyRegister(domain, config);
    case "namecheap":
      return namecheapRegister(domain, config);
    case "cloudflare":
      return cloudflareRegister(domain, config);
    default:
      return {
        success: false,
        domain,
        provider: config.provider,
        message: "Unknown provider",
        error: `Unknown provider: ${config.provider}`,
      };
  }
}

/**
 * Load registrar config from environment variables
 */
export function loadConfigFromEnv(): RegistrarConfig | null {
  const provider = (process.env.REGISTRAR_PROVIDER || "").toLowerCase() as RegistrarProvider;

  if (!provider || !["godaddy", "namecheap", "cloudflare"].includes(provider)) {
    return null;
  }

  const apiKey = process.env.REGISTRAR_API_KEY || "";
  if (!apiKey) return null;

  return {
    provider,
    apiKey,
    apiSecret: process.env.REGISTRAR_API_SECRET || "",
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID || "",
    username: process.env.NAMECHEAP_USERNAME || "",
    clientIp: process.env.CLIENT_IP || "127.0.0.1",
  };
}
