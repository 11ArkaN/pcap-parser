import type { IpLookupData } from '../types';

const CACHE_KEY = 'pcap-analyzer-cache-v2';
const CACHE_DURATION = 24 * 60 * 60 * 1000;

type CacheEntry = IpLookupData & { timestamp: number };

class WhoisCache {
  cache: Record<string, CacheEntry>;

  constructor() {
    this.cache = this.loadCache();
  }

  private loadCache(): Record<string, CacheEntry> {
    try {
      const stored = localStorage.getItem(CACHE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as Record<string, CacheEntry>;
        const now = Date.now();
        const valid: Record<string, CacheEntry> = {};

        for (const [ip, data] of Object.entries(parsed)) {
          if (data.timestamp && now - data.timestamp < CACHE_DURATION) {
            valid[ip] = data;
          }
        }

        return valid;
      }
    } catch (e) {
      console.warn('Blad ladowania cache:', e);
    }

    return {};
  }

  private saveCache(): void {
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify(this.cache));
    } catch (e) {
      console.warn('Blad zapisywania cache:', e);
    }
  }

  get(ip: string): CacheEntry | null {
    const data = this.cache[ip];
    if (data?.timestamp) {
      const age = Date.now() - data.timestamp;
      if (age < CACHE_DURATION) {
        return data;
      }
    }
    return null;
  }

  set(ip: string, data: IpLookupData): void {
    this.cache[ip] = {
      ...data,
      timestamp: Date.now()
    };
    this.saveCache();
  }
}

const cache = new WhoisCache();

export async function enrichIpData(ip: string): Promise<IpLookupData> {
  const cached = cache.get(ip);
  if (cached) {
    return cached;
  }

  try {
    if (!window.electronAPI?.lookupIp) {
      throw new Error('lookupIp nie jest dostepne');
    }

    const result = await window.electronAPI.lookupIp(ip);
    if (!result.success) {
      throw new Error(result.error || 'Blad pobierania danych IP');
    }

    const data = result.data;
    cache.set(ip, data);
    return data;
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

    if (onProgress) {
      onProgress(i + 1, uniqueIps.length);
    }

    if (i < uniqueIps.length - 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  return results;
}

export function clearCache(): void {
  localStorage.removeItem(CACHE_KEY);
  cache.cache = {};
}

export function getCacheStats(): { total: number; valid: number; expired: number } {
  const entries = Object.keys(cache.cache).length;
  const valid = Object.values(cache.cache).filter((d) => Date.now() - d.timestamp < CACHE_DURATION).length;

  return {
    total: entries,
    valid,
    expired: entries - valid
  };
}
