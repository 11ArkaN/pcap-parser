// WHOIS API client with caching
// Uses ipwho.is (free, no API key required)

const CACHE_KEY = 'pcap-analyzer-cache';
const CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

class WhoisCache {
  constructor() {
    this.cache = this.loadCache();
  }

  loadCache() {
    try {
      const stored = localStorage.getItem(CACHE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        // Filter out expired entries
        const now = Date.now();
        const valid = {};
        for (const [ip, data] of Object.entries(parsed)) {
          if (data.timestamp && (now - data.timestamp) < CACHE_DURATION) {
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

  saveCache() {
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify(this.cache));
    } catch (e) {
      console.warn('Blad zapisywania cache:', e);
    }
  }

  get(ip) {
    const data = this.cache[ip];
    if (data && data.timestamp) {
      const age = Date.now() - data.timestamp;
      if (age < CACHE_DURATION) {
        return data;
      }
    }
    return null;
  }

  set(ip, data) {
    this.cache[ip] = {
      ...data,
      timestamp: Date.now()
    };
    this.saveCache();
  }
}

const cache = new WhoisCache();

export async function enrichIpData(ip) {
  console.log(`[WHOIS] Pobieranie danych dla IP: ${ip}`);
  
  // Check cache first
  const cached = cache.get(ip);
  if (cached) {
    console.log(`[WHOIS] Cache hit dla ${ip}`);
    return cached;
  }

  try {
    // Check if electronAPI exists
    if (!window.electronAPI) {
      console.error('[WHOIS] electronAPI nie jest dostępne!');
      throw new Error('electronAPI nie jest dostępne');
    }
    
    if (!window.electronAPI.lookupIp) {
      console.error('[WHOIS] lookupIp nie jest dostępne w electronAPI!');
      throw new Error('lookupIp nie jest dostępne');
    }
    
    // Use Electron IPC to call API from main process (bypasses CORS)
    console.log(`[WHOIS] Wywoływanie lookupIp dla ${ip}`);
    const result = await window.electronAPI.lookupIp(ip);
    console.log(`[WHOIS] Odpowiedź dla ${ip}:`, result);
    
    if (!result.success) {
      throw new Error(result.error || 'Blad pobierania danych IP');
    }

    const data = result.data;
    
    // Cache the result
    cache.set(ip, data);
    
    return data;
  } catch (error) {
    console.error(`[WHOIS] Blad pobierania danych dla ${ip}:`, error);
    
    // Return minimal data on error
    const fallback = {
      ip: ip,
      asn: null,
      isp: 'Nieznane',
      org: null,
      country: null,
      city: null,
      cidr: null,
      error: error.message
    };
    
    return fallback;
  }
}

// Bulk enrichment with rate limiting
export async function enrichIpDataBulk(ips, onProgress) {
  const results = {};
  const uniqueIps = [...new Set(ips)];
  
  for (let i = 0; i < uniqueIps.length; i++) {
    const ip = uniqueIps[i];
    results[ip] = await enrichIpData(ip);
    
    if (onProgress) {
      onProgress(i + 1, uniqueIps.length);
    }
    
    // Rate limiting: wait 100ms between requests
    if (i < uniqueIps.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  
  return results;
}

// Clear cache
export function clearCache() {
  localStorage.removeItem(CACHE_KEY);
  cache.cache = {};
}

// Get cache statistics
export function getCacheStats() {
  const entries = Object.keys(cache.cache).length;
  const valid = Object.values(cache.cache).filter(
    d => Date.now() - d.timestamp < CACHE_DURATION
  ).length;
  
  return {
    total: entries,
    valid: valid,
    expired: entries - valid
  };
}
