/**
 * Shared type definitions used across all modules
 */

import type { DomainStatus } from "./theme.js";
import type { WhoisResult } from "./whois.js";
import type { RegistrationResult } from "./registrar.js";

export interface DnsDetails {
  a: string[];
  aaaa: string[];
  mx: string[];
  txt: string[];
  cname: string[];
}

export interface HttpProbeResult {
  status: number | null;
  redirectUrl: string | null;
  server: string | null;
  parked: boolean;
  reachable: boolean;
  error: string | null;
}

export interface WaybackResult {
  hasHistory: boolean;
  firstArchived: string | null;
  lastArchived: string | null;
  snapshots: number;
}

export interface DomainEntry {
  domain: string;
  status: DomainStatus;
  whois: WhoisResult | null;
  verification: { available: boolean; confidence: string; checks: string[] } | null;
  registrarCheck: { available: boolean; price?: number; currency?: string } | null;
  registration: RegistrationResult | null;
  error: string | null;
  tagged: boolean;
  dns: DnsDetails | null;
  httpProbe: HttpProbeResult | null;
  wayback: WaybackResult | null;
  domainAge: string | null;
}

/**
 * Create an empty DomainEntry with sensible defaults
 */
export function createEmptyEntry(domain: string): DomainEntry {
  return {
    domain,
    status: "pending",
    whois: null,
    verification: null,
    registrarCheck: null,
    registration: null,
    error: null,
    tagged: false,
    dns: null,
    httpProbe: null,
    wayback: null,
    domainAge: null,
  };
}
