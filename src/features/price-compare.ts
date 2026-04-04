import {
  checkAvailabilityViaRegistrar,
  type RegistrarConfig,
  type RegistrarProvider,
} from "../registrar.js";

export interface PriceQuote {
  provider: RegistrarProvider;
  available: boolean;
  price?: number;
  currency?: string;
  error?: string;
}

export async function comparePrices(
  domain: string,
  configs: RegistrarConfig[]
): Promise<PriceQuote[]> {
  const results = await Promise.allSettled(
    configs.map((config) => checkAvailabilityViaRegistrar(domain, config))
  );

  return results.map((r, i) => {
    if (r.status === "fulfilled") {
      return {
        provider: r.value.provider,
        available: r.value.available,
        price: r.value.price,
        currency: r.value.currency,
        error: r.value.error,
      };
    }
    return {
      provider: configs[i]!.provider,
      available: false,
      error: r.reason instanceof Error ? r.reason.message : "Failed",
    };
  });
}
