/**
 * S3 export — upload scan reports and portfolio exports to cloud storage.
 * Uses Bun's built-in S3 client. Requires S3 env vars to be set.
 * Works with AWS S3, Cloudflare R2, DigitalOcean Spaces, MinIO.
 */

import { S3Client } from "bun";
import { existsSync } from "fs";

export function isS3Configured(): boolean {
  return !!(
    process.env.S3_BUCKET &&
    (process.env.S3_ACCESS_KEY_ID || process.env.AWS_ACCESS_KEY_ID)
  );
}

function getS3Client(): S3Client {
  return new S3Client({
    accessKeyId: process.env.S3_ACCESS_KEY_ID || process.env.AWS_ACCESS_KEY_ID || "",
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY || process.env.AWS_SECRET_ACCESS_KEY || "",
    bucket: process.env.S3_BUCKET || "",
    endpoint: process.env.S3_ENDPOINT || undefined,
    region: process.env.S3_REGION || process.env.AWS_REGION || "us-east-1",
  });
}

export async function uploadToS3(
  key: string,
  content: string | Buffer,
  contentType: string = "text/plain"
): Promise<{ url: string; key: string }> {
  const s3 = getS3Client();
  await s3.write(key, content, { type: contentType });

  const bucket = process.env.S3_BUCKET || "";
  const endpoint = process.env.S3_ENDPOINT || `https://${bucket}.s3.amazonaws.com`;
  const url = `${endpoint}/${key}`;

  return { url, key };
}

export async function uploadFileToS3(
  localPath: string,
  s3Key: string,
  contentType?: string
): Promise<{ url: string; key: string }> {
  if (!existsSync(localPath)) throw new Error(`File not found: ${localPath}`);
  const fileContent = await Bun.file(localPath).text();
  const ct =
    contentType ||
    (s3Key.endsWith(".json")
      ? "application/json"
      : s3Key.endsWith(".csv")
        ? "text/csv"
        : "application/octet-stream");
  return uploadToS3(s3Key, fileContent, ct);
}

export function generatePresignedUrl(
  key: string,
  expiresInSec: number = 3600
): string {
  const s3 = getS3Client();
  return s3.presign(key, { expiresIn: expiresInSec });
}

export async function uploadScanReport(
  domain: string,
  report: unknown
): Promise<{ url: string; key: string }> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const key = `reports/${domain}/${timestamp}.json`;
  const content = JSON.stringify(report, null, 2);
  return uploadToS3(key, content, "application/json");
}

export async function uploadPortfolioExport(
  csvContent: string
): Promise<{ url: string; key: string }> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const key = `exports/portfolio-${timestamp}.csv`;
  return uploadToS3(key, csvContent, "text/csv");
}

export async function listS3Exports(
  prefix: string = "exports/"
): Promise<Array<{ key: string; size: number; lastModified: Date }>> {
  const s3 = getS3Client();
  try {
    const result = await s3.list({ prefix, maxKeys: 100 });
    return (result.contents || []).map((obj) => ({
      key: obj.key,
      size: obj.size ?? 0,
      lastModified: obj.lastModified ? new Date(obj.lastModified) : new Date(),
    }));
  } catch {
    return [];
  }
}
