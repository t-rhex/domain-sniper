/**
 * Domain registrar integrations
 * Supports GoDaddy, Namecheap, and Cloudflare APIs
 */

export type RegistrarProvider = "godaddy" | "namecheap" | "cloudflare";

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
    const data: any = await resp.json();
    return {
      domain,
      available: data.available === true,
      price: data.price ? data.price / 1000000 : undefined,
      currency: data.currency || "USD",
      provider: "godaddy",
    };
  } catch (err: any) {
    return {
      domain,
      available: false,
      provider: "godaddy",
      error: err.message,
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

    const data: any = await resp.json();
    if (resp.ok) {
      return {
        success: true,
        domain,
        provider: "godaddy",
        message: `Domain ${domain} registered successfully!`,
        orderId: data.orderId?.toString(),
      };
    }
    return {
      success: false,
      domain,
      provider: "godaddy",
      message: "Registration failed",
      error: data.message || JSON.stringify(data),
    };
  } catch (err: any) {
    return {
      success: false,
      domain,
      provider: "godaddy",
      message: "Registration failed",
      error: err.message,
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
      provider: "namecheap",
    };
  } catch (err: any) {
    return {
      domain,
      available: false,
      provider: "namecheap",
      error: err.message,
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
        provider: "namecheap",
        message: `Domain ${domain} registered via Namecheap!`,
      };
    }

    return {
      success: false,
      domain,
      provider: "namecheap",
      message: "Registration failed",
      error: text.match(/<Error.*?>(.*?)<\/Error>/)?.[1] || "Unknown error",
    };
  } catch (err: any) {
    return {
      success: false,
      domain,
      provider: "namecheap",
      message: "Registration failed",
      error: err.message,
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
    const data: any = await resp.json();

    // If domain is not found in their registrar, check availability
    if (!data.success || data.result?.available) {
      return {
        domain,
        available: true,
        provider: "cloudflare",
      };
    }

    return {
      domain,
      available: false,
      provider: "cloudflare",
    };
  } catch (err: any) {
    return {
      domain,
      available: false,
      provider: "cloudflare",
      error: err.message,
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
        provider: "cloudflare",
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
    const data: any = await resp.json();

    if (data.success) {
      return {
        success: true,
        domain,
        provider: "cloudflare",
        message: `Domain ${domain} registered via Cloudflare!`,
        orderId: data.result?.id,
      };
    }

    return {
      success: false,
      domain,
      provider: "cloudflare",
      message: "Registration failed",
      error: data.errors?.[0]?.message || "Unknown error",
    };
  } catch (err: any) {
    return {
      success: false,
      domain,
      provider: "cloudflare",
      message: "Registration failed",
      error: err.message,
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

  return {
    provider,
    apiKey: process.env.REGISTRAR_API_KEY || "",
    apiSecret: process.env.REGISTRAR_API_SECRET || "",
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID || "",
    username: process.env.NAMECHEAP_USERNAME || "",
    clientIp: process.env.CLIENT_IP || "127.0.0.1",
  };
}
