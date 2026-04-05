import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { execFileSync } from "child_process";

const CA_DIR = join(homedir(), ".domain-sniper", "ca");
const CA_KEY = join(CA_DIR, "ca.key");
const CA_CERT = join(CA_DIR, "ca.crt");
const CERTS_DIR = join(CA_DIR, "certs");

function ensureDirs(): void {
  if (!existsSync(CA_DIR)) mkdirSync(CA_DIR, { recursive: true });
  if (!existsSync(CERTS_DIR)) mkdirSync(CERTS_DIR, { recursive: true });
}

export function hasCA(): boolean {
  return existsSync(CA_KEY) && existsSync(CA_CERT);
}

export function getCACertPath(): string {
  return CA_CERT;
}

export function generateCA(): { keyPath: string; certPath: string } {
  ensureDirs();
  if (hasCA()) return { keyPath: CA_KEY, certPath: CA_CERT };

  // Generate CA private key
  execFileSync("openssl", [
    "genrsa", "-out", CA_KEY, "2048",
  ], { stdio: "pipe" });

  // Generate CA certificate (valid for 10 years)
  execFileSync("openssl", [
    "req", "-new", "-x509", "-key", CA_KEY,
    "-out", CA_CERT, "-days", "3650",
    "-subj", "/CN=Domain Sniper CA/O=Domain Sniper/OU=Proxy",
  ], { stdio: "pipe" });

  return { keyPath: CA_KEY, certPath: CA_CERT };
}

export function generateHostCert(hostname: string): { key: string; cert: string } {
  ensureDirs();
  if (!hasCA()) generateCA();

  // Sanitize hostname for filename
  const safe = hostname.replace(/[^a-z0-9.-]/gi, "_");
  const hostKey = join(CERTS_DIR, `${safe}.key`);
  const hostCert = join(CERTS_DIR, `${safe}.crt`);
  const hostCsr = join(CERTS_DIR, `${safe}.csr`);
  const extFile = join(CERTS_DIR, `${safe}.ext`);

  // Return cached cert if exists and not expired
  if (existsSync(hostKey) && existsSync(hostCert)) {
    return { key: readFileSync(hostKey, "utf-8"), cert: readFileSync(hostCert, "utf-8") };
  }

  // Generate host key
  execFileSync("openssl", ["genrsa", "-out", hostKey, "2048"], { stdio: "pipe" });

  // Generate CSR
  execFileSync("openssl", [
    "req", "-new", "-key", hostKey, "-out", hostCsr,
    "-subj", `/CN=${hostname}`,
  ], { stdio: "pipe" });

  // Create extensions file for SAN
  writeFileSync(extFile, [
    "authorityKeyIdentifier=keyid,issuer",
    "basicConstraints=CA:FALSE",
    "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment",
    `subjectAltName = DNS:${hostname}, DNS:*.${hostname}`,
  ].join("\n"), "utf-8");

  // Sign with CA
  execFileSync("openssl", [
    "x509", "-req", "-in", hostCsr, "-CA", CA_CERT, "-CAkey", CA_KEY,
    "-CAcreateserial", "-out", hostCert, "-days", "365",
    "-extfile", extFile,
  ], { stdio: "pipe" });

  // Clean up CSR and ext
  try { unlinkSync(hostCsr); } catch {}
  try { unlinkSync(extFile); } catch {}

  return { key: readFileSync(hostKey, "utf-8"), cert: readFileSync(hostCert, "utf-8") };
}

export function getInstallInstructions(): string {
  const certPath = getCACertPath();
  return [
    "Install the Domain Sniper CA certificate to intercept HTTPS:",
    "",
    "macOS:",
    `  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${certPath}"`,
    "",
    "Linux (Ubuntu/Debian):",
    `  sudo cp "${certPath}" /usr/local/share/ca-certificates/domain-sniper-ca.crt`,
    "  sudo update-ca-certificates",
    "",
    "Firefox (manual):",
    "  Settings > Privacy & Security > Certificates > View Certificates > Import",
    `  Select: ${certPath}`,
    "",
    `Certificate: ${certPath}`,
  ].join("\n");
}
