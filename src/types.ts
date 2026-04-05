/**
 * Shared type definitions used across all modules
 */

import type { DomainStatus } from "./theme.js";
import type { WhoisResult } from "./whois.js";
import type { RegistrationResult } from "./registrar.js";
import type { RdapResult } from "./features/rdap.js";
import type { SslResult } from "./features/ssl-check.js";
import type { SubdomainResult } from "./features/subdomain-discovery.js";
import type { MarketplaceListing } from "./features/marketplace.js";
import type { SocialCheckResult } from "./features/social-check.js";
import type { TechStackResult } from "./features/tech-stack.js";
import type { BlacklistResult } from "./features/blacklist-check.js";
import type { BacklinkResult } from "./features/backlinks.js";
import type { PortScanResult } from "./features/port-scanner.js";
import type { ReverseIpResult } from "./features/reverse-ip.js";
import type { AsnResult } from "./features/asn-lookup.js";
import type { EmailSecurityResult } from "./features/email-security.js";
import type { ZoneTransferResult } from "./features/zone-transfer.js";
import type { CertTransparencyResult } from "./features/cert-transparency.js";
import type { TakeoverResult } from "./features/takeover-detect.js";
import type { SecurityHeadersResult } from "./features/security-headers.js";
import type { WafResult } from "./features/waf-detect.js";
import type { PathScanResult } from "./features/path-scanner.js";
import type { CorsResult } from "./features/cors-check.js";

export type { RdapResult } from "./features/rdap.js";
export type { SslResult } from "./features/ssl-check.js";
export type { SubdomainResult } from "./features/subdomain-discovery.js";
export type { MarketplaceListing } from "./features/marketplace.js";
export type { SocialCheckResult } from "./features/social-check.js";
export type { TechStackResult } from "./features/tech-stack.js";
export type { BlacklistResult } from "./features/blacklist-check.js";
export type { BacklinkResult } from "./features/backlinks.js";
export type { PortScanResult } from "./features/port-scanner.js";
export type { ReverseIpResult } from "./features/reverse-ip.js";
export type { AsnResult } from "./features/asn-lookup.js";
export type { EmailSecurityResult } from "./features/email-security.js";
export type { ZoneTransferResult } from "./features/zone-transfer.js";
export type { CertTransparencyResult } from "./features/cert-transparency.js";
export type { TakeoverResult } from "./features/takeover-detect.js";
export type { SecurityHeadersResult } from "./features/security-headers.js";
export type { WafResult } from "./features/waf-detect.js";
export type { PathScanResult } from "./features/path-scanner.js";
export type { CorsResult } from "./features/cors-check.js";

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
  rdap: RdapResult | null;
  ssl: SslResult | null;
  subdomains: SubdomainResult[] | null;
  marketplace: MarketplaceListing[] | null;
  socialMedia: SocialCheckResult[] | null;
  techStack: TechStackResult | null;
  blacklist: BlacklistResult | null;
  backlinks: BacklinkResult | null;
  portScan: PortScanResult | null;
  reverseIp: ReverseIpResult | null;
  asn: AsnResult | null;
  emailSecurity: EmailSecurityResult | null;
  zoneTransfer: ZoneTransferResult | null;
  certTransparency: CertTransparencyResult | null;
  takeover: TakeoverResult | null;
  securityHeaders: SecurityHeadersResult | null;
  waf: WafResult | null;
  pathScan: PathScanResult | null;
  cors: CorsResult | null;
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
    rdap: null,
    ssl: null,
    subdomains: null,
    marketplace: null,
    socialMedia: null,
    techStack: null,
    blacklist: null,
    backlinks: null,
    portScan: null,
    reverseIp: null,
    asn: null,
    emailSecurity: null,
    zoneTransfer: null,
    certTransparency: null,
    takeover: null,
    securityHeaders: null,
    waf: null,
    pathScan: null,
    cors: null,
  };
}
