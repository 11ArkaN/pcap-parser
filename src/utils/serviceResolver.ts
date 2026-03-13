import type {
  ParsedConnection,
  ResolvedServiceCandidate,
  ResolvedServiceResult,
  ServiceCatalogEntry
} from '../types';

const EPHEMERAL_PORT_START = 49_152;

const SERVICE_CATALOG: ServiceCatalogEntry[] = [
  { protocol: 'TCP', port: 20, serviceName: 'ftp-data', displayName: 'FTP Data', rfcRefs: ['RFC 959'], source: 'IANA', aliases: ['ftp'] },
  { protocol: 'TCP', port: 21, serviceName: 'ftp', displayName: 'FTP', rfcRefs: ['RFC 959'], source: 'IANA' },
  { protocol: 'TCP', port: 22, serviceName: 'ssh', displayName: 'SSH', rfcRefs: ['RFC 4253'], source: 'IANA' },
  { protocol: 'TCP', port: 23, serviceName: 'telnet', displayName: 'Telnet', rfcRefs: ['RFC 854'], source: 'IANA' },
  { protocol: 'TCP', port: 25, serviceName: 'smtp', displayName: 'SMTP', rfcRefs: ['RFC 5321'], source: 'IANA' },
  { protocol: 'UDP', port: 53, serviceName: 'domain', displayName: 'DNS', rfcRefs: ['RFC 1035'], source: 'IANA' },
  { protocol: 'TCP', port: 53, serviceName: 'domain', displayName: 'DNS', rfcRefs: ['RFC 1035'], source: 'IANA' },
  { protocol: 'UDP', port: 67, serviceName: 'bootps', displayName: 'DHCP Server', rfcRefs: ['RFC 2131'], source: 'IANA', aliases: ['dhcp'] },
  { protocol: 'UDP', port: 68, serviceName: 'bootpc', displayName: 'DHCP Client', rfcRefs: ['RFC 2131'], source: 'IANA', aliases: ['dhcp'] },
  { protocol: 'TCP', port: 80, serviceName: 'http', displayName: 'HTTP', rfcRefs: ['RFC 9110'], source: 'IANA' },
  { protocol: 'TCP', port: 110, serviceName: 'pop3', displayName: 'POP3', rfcRefs: ['RFC 1939'], source: 'IANA' },
  { protocol: 'UDP', port: 123, serviceName: 'ntp', displayName: 'NTP', rfcRefs: ['RFC 5905'], source: 'IANA' },
  { protocol: 'TCP', port: 143, serviceName: 'imap', displayName: 'IMAP', rfcRefs: ['RFC 9051'], source: 'IANA' },
  { protocol: 'TCP', port: 389, serviceName: 'ldap', displayName: 'LDAP', rfcRefs: ['RFC 4511'], source: 'IANA' },
  { protocol: 'TCP', port: 443, serviceName: 'https', displayName: 'HTTPS', rfcRefs: ['RFC 2818', 'RFC 9110'], source: 'IANA' },
  { protocol: 'TCP', port: 445, serviceName: 'microsoft-ds', displayName: 'SMB', rfcRefs: [], source: 'IANA', aliases: ['smb'] },
  { protocol: 'TCP', port: 465, serviceName: 'submissions', displayName: 'SMTPS', rfcRefs: ['RFC 8314'], source: 'IANA', aliases: ['smtp'] },
  { protocol: 'TCP', port: 587, serviceName: 'submission', displayName: 'SMTP Submission', rfcRefs: ['RFC 6409'], source: 'IANA', aliases: ['smtp'] },
  { protocol: 'TCP', port: 636, serviceName: 'ldaps', displayName: 'LDAPS', rfcRefs: [], source: 'IANA', aliases: ['ldap'] },
  { protocol: 'TCP', port: 993, serviceName: 'imaps', displayName: 'IMAPS', rfcRefs: ['RFC 8314'], source: 'IANA', aliases: ['imap'] },
  { protocol: 'TCP', port: 995, serviceName: 'pop3s', displayName: 'POP3S', rfcRefs: ['RFC 8314'], source: 'IANA', aliases: ['pop3'] },
  { protocol: 'TCP', port: 1433, serviceName: 'ms-sql-s', displayName: 'Microsoft SQL Server', rfcRefs: [], source: 'IANA', aliases: ['sqlserver'] },
  { protocol: 'TCP', port: 3306, serviceName: 'mysql', displayName: 'MySQL', rfcRefs: [], source: 'IANA' },
  { protocol: 'TCP', port: 3389, serviceName: 'ms-wbt-server', displayName: 'RDP', rfcRefs: [], source: 'IANA' },
  { protocol: 'UDP', port: 5353, serviceName: 'mdns', displayName: 'mDNS', rfcRefs: ['RFC 6762'], source: 'IANA', aliases: ['dns'] },
  { protocol: 'TCP', port: 5432, serviceName: 'postgresql', displayName: 'PostgreSQL', rfcRefs: [], source: 'IANA', aliases: ['postgres'] },
  { protocol: 'TCP', port: 5985, serviceName: 'wsman', displayName: 'WinRM HTTP', rfcRefs: [], source: 'IANA', aliases: ['winrm', 'http'] },
  { protocol: 'TCP', port: 5986, serviceName: 'wsmans', displayName: 'WinRM HTTPS', rfcRefs: [], source: 'IANA', aliases: ['winrm', 'https'] },
  { protocol: 'TCP', port: 8000, serviceName: 'http-alt', displayName: 'HTTP Alternate', rfcRefs: ['RFC 9110'], source: 'IANA', aliases: ['http'] },
  { protocol: 'TCP', port: 8080, serviceName: 'http-alt', displayName: 'HTTP Alternate', rfcRefs: ['RFC 9110'], source: 'IANA', aliases: ['http'] },
  { protocol: 'TCP', port: 8443, serviceName: 'https-alt', displayName: 'HTTPS Alternate', rfcRefs: ['RFC 2818', 'RFC 9110'], source: 'IANA', aliases: ['https'] },
  { protocol: 'TCP', port: 8888, serviceName: 'http-alt', displayName: 'HTTP Alternate', rfcRefs: ['RFC 9110'], source: 'IANA', aliases: ['http'] }
];

const CATALOG_BY_KEY = new Map<string, ServiceCatalogEntry>();
const KNOWN_SERVICE_TOKENS = new Set<string>();

for (const entry of SERVICE_CATALOG) {
  CATALOG_BY_KEY.set(buildCatalogKey(entry.protocol, entry.port), entry);
  KNOWN_SERVICE_TOKENS.add(entry.serviceName.toLowerCase());
  KNOWN_SERVICE_TOKENS.add(entry.displayName.toLowerCase());
  for (const alias of entry.aliases ?? []) {
    KNOWN_SERVICE_TOKENS.add(alias.toLowerCase());
  }
}

export function resolveConnectionServices(
  connection: Pick<ParsedConnection, 'protocol' | 'srcPort' | 'dstPort'>
): ResolvedServiceResult {
  const protocol = normalizeTransportProtocol(connection.protocol);
  if (protocol !== 'TCP' && protocol !== 'UDP') {
    return {
      candidates: [],
      primaryCandidate: null,
      confidence: 'low',
      reason: 'unsupported-transport'
    };
  }

  return resolveServiceFromPorts(protocol, connection.srcPort, connection.dstPort);
}

export function resolveServiceFromPorts(
  protocol: 'TCP' | 'UDP',
  srcPort: number | null,
  dstPort: number | null
): ResolvedServiceResult {
  const srcCandidate = lookupServiceCandidate(protocol, srcPort, 'src');
  const dstCandidate = lookupServiceCandidate(protocol, dstPort, 'dst');
  const candidates = uniqueCandidates([srcCandidate, dstCandidate].filter((value): value is ResolvedServiceCandidate => Boolean(value)));

  if (!candidates.length) {
    return {
      candidates: [],
      primaryCandidate: null,
      confidence: 'low',
      reason: 'no-known-service-port'
    };
  }

  if (candidates.length === 1) {
    const only = candidates[0];
    return {
      candidates,
      primaryCandidate: only,
      confidence: 'high',
      reason: 'single-known-service-port'
    };
  }

  const nonEphemeral = candidates.filter((candidate) => !candidate.isEphemeral);
  if (nonEphemeral.length === 1) {
    return {
      candidates,
      primaryCandidate: nonEphemeral[0],
      confidence: 'high',
      reason: 'selected-non-ephemeral-service-port'
    };
  }

  const srcOnly = candidates.filter((candidate) => candidate.matchedOn === 'src');
  const dstOnly = candidates.filter((candidate) => candidate.matchedOn === 'dst');

  if (protocol === 'UDP' && srcOnly.length === 1 && dstOnly.length === 1) {
    const dnsPair = candidates.every((candidate) => candidate.serviceName === 'domain');
    if (dnsPair) {
      const preferred = candidates.find((candidate) => candidate.matchedOn === 'dst') ?? candidates[0];
      return {
        candidates,
        primaryCandidate: preferred,
        confidence: 'medium',
        reason: 'ambiguous-known-service-ports'
      };
    }
  }

  return {
    candidates,
    primaryCandidate: null,
    confidence: 'low',
    reason: 'ambiguous-known-service-ports'
  };
}

export function formatResolvedServiceName(result: ResolvedServiceResult): string {
  if (result.primaryCandidate) {
    return result.primaryCandidate.displayName;
  }
  if (!result.candidates.length) {
    return 'Niezidentyfikowana';
  }
  return result.candidates.map((candidate) => formatCandidateLabel(candidate)).join(', ');
}

export function formatResolvedServiceNameWithFallback(
  result: ResolvedServiceResult,
  srcPort: number | null,
  dstPort: number | null
): string {
  const resolved = formatResolvedServiceName(result);
  if (resolved !== 'Niezidentyfikowana') {
    return resolved;
  }
  return formatFallbackPorts(srcPort, dstPort);
}

export function formatResolvedServicePort(
  result: ResolvedServiceResult,
  srcPort?: number | null,
  dstPort?: number | null
): string {
  if (result.primaryCandidate) {
    return String(result.primaryCandidate.port);
  }
  if (!result.candidates.length) {
    return formatFallbackPorts(srcPort ?? null, dstPort ?? null);
  }
  return result.candidates.map((candidate) => String(candidate.port)).join(', ');
}

export function formatResolvedServiceRfc(result: ResolvedServiceResult): string {
  const values = new Set<string>();
  for (const candidate of result.candidates) {
    for (const ref of candidate.rfcRefs) {
      values.add(ref);
    }
  }
  return values.size ? Array.from(values).join(', ') : 'N/D';
}

export function getResolvedServiceSearchTokens(result: ResolvedServiceResult): string[] {
  const tokens = new Set<string>();
  for (const candidate of result.candidates) {
    tokens.add(candidate.serviceName.toLowerCase());
    tokens.add(candidate.displayName.toLowerCase());
    for (const alias of candidate.aliases ?? []) {
      tokens.add(alias.toLowerCase());
    }
  }
  return Array.from(tokens);
}

export function isKnownServiceToken(token: string): boolean {
  return KNOWN_SERVICE_TOKENS.has(token.trim().toLowerCase());
}

function lookupServiceCandidate(
  protocol: 'TCP' | 'UDP',
  port: number | null,
  matchedOn: 'src' | 'dst'
): ResolvedServiceCandidate | null {
  if (!Number.isInteger(port) || (port as number) <= 0) {
    return null;
  }

  const normalizedPort = port as number;
  const entry = CATALOG_BY_KEY.get(buildCatalogKey(protocol, normalizedPort));
  if (!entry) {
    return null;
  }

  return {
    ...entry,
    matchedOn,
    isEphemeral: normalizedPort >= EPHEMERAL_PORT_START
  };
}

function uniqueCandidates(candidates: ResolvedServiceCandidate[]): ResolvedServiceCandidate[] {
  const byKey = new Map<string, ResolvedServiceCandidate>();
  for (const candidate of candidates) {
    const key = `${candidate.protocol}:${candidate.port}:${candidate.serviceName}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, candidate);
      continue;
    }

    if (existing.matchedOn !== 'dst' && candidate.matchedOn === 'dst') {
      byKey.set(key, candidate);
    }
  }
  return Array.from(byKey.values()).sort((left, right) => left.port - right.port || left.displayName.localeCompare(right.displayName));
}

function normalizeTransportProtocol(protocol: string): string {
  return protocol.trim().toUpperCase();
}

function buildCatalogKey(protocol: 'TCP' | 'UDP', port: number): string {
  return `${protocol}:${port}`;
}

function formatCandidateLabel(candidate: ResolvedServiceCandidate): string {
  return `${candidate.displayName} (${candidate.port}/${candidate.protocol})`;
}

function formatFallbackPorts(srcPort: number | null, dstPort: number | null): string {
  const validPorts = [srcPort, dstPort].filter((value): value is number => Number.isInteger(value) && value > 0);
  if (!validPorts.length) {
    return 'N/D';
  }

  return Array.from(new Set(validPorts)).map(String).join(', ');
}
