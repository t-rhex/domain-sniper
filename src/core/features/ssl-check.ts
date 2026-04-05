import { assertValidDomain } from "../validate.js";
import { connect } from "tls";

export interface SslResult {
  valid: boolean;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysUntilExpiry: number | null;
  sans: string[];
  protocol: string | null;
  error: string | null;
}

export function checkSsl(domain: string): Promise<SslResult> {
  assertValidDomain(domain);

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      socket.destroy();
      resolve({
        valid: false, issuer: null, subject: null, validFrom: null,
        validTo: null, daysUntilExpiry: null, sans: [], protocol: null,
        error: "Connection timeout",
      });
    }, 8000);

    const socket = connect(
      { host: domain, port: 443, servername: domain, rejectUnauthorized: false },
      () => {
        clearTimeout(timeout);
        try {
          const cert = (socket as any).getPeerCertificate?.();
          if (!cert || !cert.subject) {
            socket.destroy();
            resolve({
              valid: false, issuer: null, subject: null, validFrom: null,
              validTo: null, daysUntilExpiry: null, sans: [], protocol: null,
              error: "No certificate",
            });
            return;
          }

          const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
          const daysLeft = validTo ? Math.floor((validTo.getTime() - Date.now()) / 86400000) : null;

          const sans: string[] = [];
          if (cert.subjectaltname) {
            const parts = (cert.subjectaltname as string).split(",").map((s: string) => s.trim());
            for (const part of parts) {
              if (part.startsWith("DNS:")) sans.push(part.slice(4));
            }
          }

          socket.destroy();
          resolve({
            valid: (socket as any).authorized ?? (daysLeft !== null && daysLeft > 0),
            issuer: cert.issuer?.O || cert.issuer?.CN || null,
            subject: cert.subject?.CN || null,
            validFrom: cert.valid_from || null,
            validTo: cert.valid_to || null,
            daysUntilExpiry: daysLeft,
            sans,
            protocol: (socket as any).getProtocol?.() || null,
            error: null,
          });
        } catch (err: unknown) {
          socket.destroy();
          resolve({
            valid: false, issuer: null, subject: null, validFrom: null,
            validTo: null, daysUntilExpiry: null, sans: [], protocol: null,
            error: err instanceof Error ? err.message : "SSL check failed",
          });
        }
      }
    );

    socket.on("error", (err) => {
      clearTimeout(timeout);
      resolve({
        valid: false, issuer: null, subject: null, validFrom: null,
        validTo: null, daysUntilExpiry: null, sans: [], protocol: null,
        error: err.message,
      });
    });
  });
}
