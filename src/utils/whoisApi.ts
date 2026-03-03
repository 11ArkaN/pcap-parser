import type { IpLookupData } from '../types';

const LOOKUP_TIMEOUT_MS = 12_000;

export function getCachedIpData(_ip: string): IpLookupData | null {
  return null;
}

export async function enrichIpData(ip: string): Promise<IpLookupData> {
  try {
    if (!window.electronAPI?.lookupIp) {
      throw new Error('lookupIp nie jest dostepne');
    }

    const result = await withTimeout(window.electronAPI.lookupIp(ip), LOOKUP_TIMEOUT_MS, `Timeout lookup IP (${ip})`);
    if (!result.success) {
      throw new Error(result.error || 'Blad pobierania danych IP');
    }

    return result.data;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ip,
      asn: null,
      isp: 'Nieznane',
      org: null,
      country: null,
      city: null,
      cidr: null,
      error: message
    };
  }
}

export async function enrichIpDataBulk(
  ips: string[],
  onProgress?: (current: number, total: number) => void
): Promise<Record<string, IpLookupData>> {
  const results: Record<string, IpLookupData> = {};
  const uniqueIps = [...new Set(ips)];

  for (let i = 0; i < uniqueIps.length; i += 1) {
    const ip = uniqueIps[i];
    results[ip] = await enrichIpData(ip);
    if (onProgress) onProgress(i + 1, uniqueIps.length);
  }

  return results;
}

export function clearCache(): void {}

export function getCacheStats(): { total: number; valid: number; expired: number } {
  return { total: 0, valid: 0, expired: 0 };
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, timeoutMessage: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = window.setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
    promise
      .then((value) => resolve(value))
      .catch((error) => reject(error))
      .finally(() => window.clearTimeout(timer));
  });
}
