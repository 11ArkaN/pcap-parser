import type { IpLookupData } from '../types';

const LOOKUP_TIMEOUT_MS = 12_000;
const CACHE_KEY = 'pcap-analyzer-cache-v2';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_CACHE_ENTRIES = 5000;

interface CacheEntry {
  data: IpLookupData;
  cachedAt: number;
}

let memoryCache: Record<string, CacheEntry> | null = null;

function getNow(): number {
  return Date.now();
}

function normalizeIp(ip: string): string {
  return ip.trim().toLowerCase();
}

function hasLocalStorage(): boolean {
  try {
    return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined';
  } catch {
    return false;
  }
}

function loadCache(): Record<string, CacheEntry> {
  if (memoryCache) return memoryCache;
  memoryCache = {};

  if (!hasLocalStorage()) return memoryCache;

  try {
    const raw = window.localStorage.getItem(CACHE_KEY);
    if (!raw) return memoryCache;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return memoryCache;

    const entries = (parsed as { entries?: Record<string, CacheEntry> }).entries;
    if (!entries || typeof entries !== 'object') return memoryCache;

    memoryCache = entries;
  } catch {
    memoryCache = {};
  }

  return memoryCache;
}

function persistCache(cache: Record<string, CacheEntry>): void {
  if (!hasLocalStorage()) return;
  try {
    const payload = {
      version: 2,
      savedAt: getNow(),
      entries: cache
    };
    window.localStorage.setItem(CACHE_KEY, JSON.stringify(payload));
  } catch { }
}

function isExpired(entry: CacheEntry, now = getNow()): boolean {
  return now - entry.cachedAt > CACHE_TTL_MS;
}

function sweepExpiredEntries(cache: Record<string, CacheEntry>): { removed: number; total: number; valid: number } {
  let removed = 0;
  let total = 0;
  let valid = 0;
  const now = getNow();

  for (const [ip, entry] of Object.entries(cache)) {
    total += 1;
    if (!entry || typeof entry.cachedAt !== 'number' || isExpired(entry, now)) {
      delete cache[ip];
      removed += 1;
      continue;
    }
    valid += 1;
  }

  return { removed, total, valid };
}

function trimCacheSize(cache: Record<string, CacheEntry>): boolean {
  const keys = Object.keys(cache);
  if (keys.length <= MAX_CACHE_ENTRIES) return false;

  const byOldestFirst = keys.sort((a, b) => {
    const at = cache[a]?.cachedAt ?? 0;
    const bt = cache[b]?.cachedAt ?? 0;
    return at - bt;
  });

  const toRemove = byOldestFirst.length - MAX_CACHE_ENTRIES;
  for (let i = 0; i < toRemove; i += 1) {
    delete cache[byOldestFirst[i]];
  }

  return toRemove > 0;
}

function setCachedIpData(ip: string, data: IpLookupData): void {
  const key = normalizeIp(ip);
  if (!key) return;

  const cache = loadCache();
  cache[key] = {
    data,
    cachedAt: getNow()
  };

  const trimmed = trimCacheSize(cache);
  if (trimmed) {
    persistCache(cache);
    return;
  }

  persistCache(cache);
}

export function getCachedIpData(ip: string): IpLookupData | null {
  const key = normalizeIp(ip);
  if (!key) return null;

  const cache = loadCache();
  const entry = cache[key];
  if (!entry) return null;

  if (isExpired(entry)) {
    delete cache[key];
    persistCache(cache);
    return null;
  }

  return entry.data;
}

export async function enrichIpData(ip: string): Promise<IpLookupData> {
  const key = normalizeIp(ip);
  const cached = getCachedIpData(key);
  if (cached) {
    return cached;
  }

  try {
    if (!window.electronAPI?.lookupIp) {
      throw new Error('lookupIp nie jest dostepne');
    }

    const result = await withTimeout(window.electronAPI.lookupIp(key), LOOKUP_TIMEOUT_MS, `Timeout lookup IP (${key})`);
    if (!result.success) {
      throw new Error(result.error || 'Blad pobierania danych IP');
    }

    const normalizedData: IpLookupData = {
      ...result.data,
      ip: result.data.ip || key
    };

    setCachedIpData(key, normalizedData);
    return normalizedData;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const fallback: IpLookupData = {
      ip: key,
      asn: null,
      isp: 'Nieznane',
      org: null,
      country: null,
      city: null,
      cidr: null,
      error: message
    };

    setCachedIpData(key, fallback);
    return fallback;
  }
}

export async function enrichIpDataBulk(
  ips: string[],
  onProgress?: (current: number, total: number) => void
): Promise<Record<string, IpLookupData>> {
  const results: Record<string, IpLookupData> = {};
  const uniqueIps = [...new Set(ips.map((value) => normalizeIp(value)).filter(Boolean))];

  for (let i = 0; i < uniqueIps.length; i += 1) {
    const ip = uniqueIps[i];
    results[ip] = await enrichIpData(ip);
    if (onProgress) onProgress(i + 1, uniqueIps.length);
  }

  return results;
}

export function clearCache(): void {
  memoryCache = {};
  if (!hasLocalStorage()) return;
  try {
    window.localStorage.removeItem(CACHE_KEY);
  } catch { }
}

export function getCacheStats(): { total: number; valid: number; expired: number } {
  const cache = loadCache();
  const snapshotTotal = Object.keys(cache).length;
  const { removed, valid } = sweepExpiredEntries(cache);
  if (removed > 0) {
    persistCache(cache);
  }

  return {
    total: snapshotTotal,
    valid,
    expired: removed
  };
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
