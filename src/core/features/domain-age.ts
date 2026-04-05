export function calculateDomainAge(createdDate: string | null): string | null {
  if (!createdDate) return null;
  try {
    const created = new Date(createdDate);
    if (isNaN(created.getTime())) return null;
    const now = new Date();
    const diffMs = now.getTime() - created.getTime();
    if (diffMs < 0) return "Not yet created";
    const days = Math.floor(diffMs / 86400000);
    if (days < 1) return "< 1 day";
    if (days < 30) return `${days}d`;
    if (days < 365) {
      const months = Math.floor(days / 30);
      return `${months}mo`;
    }
    const years = Math.floor(days / 365);
    const remainingMonths = Math.floor((days % 365) / 30);
    return remainingMonths > 0 ? `${years}y ${remainingMonths}mo` : `${years}y`;
  } catch {
    return null;
  }
}

export function daysUntilExpiry(expiryDate: string | null): number | null {
  if (!expiryDate) return null;
  try {
    const expiry = new Date(expiryDate);
    if (isNaN(expiry.getTime())) return null;
    return Math.floor((expiry.getTime() - Date.now()) / 86400000);
  } catch {
    return null;
  }
}
