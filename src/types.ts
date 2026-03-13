export type TransportProtocol =
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'ICMPv6'
  | 'IGMP'
  | 'GRE'
  | 'IPSEC'
  | string;

export interface ParsedConnection {
  src: string;
  dst: string;
  protocol: TransportProtocol;
  srcPort: number | null;
  dstPort: number | null;
  packetCount: number;
  length?: number;
  vlan?: number | null;
  type?: string;
}

export type ServiceResolutionConfidence = 'high' | 'medium' | 'low';

export interface ServiceCatalogEntry {
  protocol: 'TCP' | 'UDP';
  port: number;
  serviceName: string;
  displayName: string;
  rfcRefs: string[];
  source: 'IANA';
  aliases?: string[];
}

export interface ResolvedServiceCandidate extends ServiceCatalogEntry {
  matchedOn: 'src' | 'dst';
  isEphemeral: boolean;
}

export interface ResolvedServiceResult {
  candidates: ResolvedServiceCandidate[];
  primaryCandidate: ResolvedServiceCandidate | null;
  confidence: ServiceResolutionConfidence;
  reason: string;
}

export interface IpLookupData {
  ip: string;
  asn: string | null;
  isp: string | null;
  org: string | null;
  country: string | null;
  countryName?: string | null;
  city: string | null;
  region?: string | null;
  cidr: string | null;
  latitude?: number | null;
  longitude?: number | null;
  timezone?: string | null;
  asname?: string | null;
  error?: string;
  range?: string | null;
  [key: string]: unknown;
}

export interface HostNetworkAdapterInfo {
  name: string;
  description: string | null;
  macAddress: string | null;
  ipv4: string[];
  ipv6: string[];
  dnsServers: string[];
  defaultGateway: string | null;
  gatewayMacAddress: string | null;
}

export interface HostNetworkInfo {
  collectedAt: string;
  hostName: string;
  osName: string | null;
  osPlatform: string;
  osRelease: string;
  activeAdapter: HostNetworkAdapterInfo | null;
  adapters: HostNetworkAdapterInfo[];
  localIpv4: string[];
  localIpv6: string[];
  dnsServers: string[];
  defaultGateway: string | null;
  gatewayMacAddress: string | null;
  publicIp: string | null;
  natStatus: 'behind_nat' | 'public_ip' | 'unknown';
}

export interface LoadingProgress {
  current: number;
  total: number;
  text: string;
}

export interface FileInputPayload {
  fileName: string;
  filePath?: string;
  fileSize?: number;
  buffer?: Uint8Array;
}

export interface ParsePcapOptions {
  maxConnections?: number;
}

export interface ParsePcapResult {
  connections: ParsedConnection[];
  truncated: boolean;
}

export interface StreamPayloadRef {
  fileOffset: number;
  capturedLength: number;
}

export interface StreamTcpMeta {
  seq: number;
  ack: number;
  flags: string;
  window: number;
  headerLength: number;
  payloadLength: number;
}

export interface StreamPacketMeta {
  streamId: string;
  packetNo: number;
  timestampUs: number | null;
  protocol: string;
  ipVersion: 'IPv4' | 'IPv6' | 'Other';
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  direction: 'A->B' | 'B->A' | '?';
  capturedLength: number;
  originalLength: number;
  vlan: number | null;
  ttl: number | null;
  hopLimit: number | null;
  payloadLength: number;
  tcp: StreamTcpMeta | null;
  payloadRef: StreamPayloadRef;
}

export interface PcapStreamSummary {
  streamId: string;
  streamIndex: number;
  protocol: string;
  endpointA: string;
  endpointB: string;
  clientIp: string;
  clientPort: number | null;
  serverIp: string;
  serverPort: number | null;
  packets: number;
  bytes: number;
  firstSeenUs: number | null;
  lastSeenUs: number | null;
  durationUs: number | null;
}

export interface PcapStreamCatalog {
  totalPackets: number;
  streams: PcapStreamSummary[];
  packetsByStream: Record<string, StreamPacketMeta[]>;
  truncated: boolean;
  droppedPackets: number;
}

export interface StreamPayloadView {
  capturedLength: number;
  returnedLength: number;
  truncated: boolean;
  hex: string;
  ascii: string;
}

export interface StreamsViewState {
  search: string;
  protocolFilter: string;
  selectedStreamId: string | null;
  selectedPacketNo: number | null;
}

export interface ProcmonAttachment {
  filePath: string;
  fileName: string;
  fileSize?: number;
  addedAt: string;
}

export type CorrelationJobState = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type CorrelationJobStage = 'prepare' | 'ingest_pcap' | 'ingest_procmon' | 'align' | 'match' | 'finalize';
export type CorrelationConfidence = 'high' | 'medium' | 'low' | 'unmatched';

export interface CorrelationProgress {
  stage: CorrelationJobStage;
  current: number;
  total: number;
  message: string;
}

export interface CorrelationDebugEntry {
  ts: string;
  level: 'info' | 'warning' | 'error';
  stage?: CorrelationJobStage;
  message: string;
}

export interface CorrelationJobStatus {
  jobId: string;
  analysisId: string;
  state: CorrelationJobState;
  progress: CorrelationProgress;
  startedAt: string;
  lastEventAt: string;
  debugEntries: CorrelationDebugEntry[];
  endedAt?: string;
  error?: string;
}

export interface CorrelationRequest {
  analysisId: string;
  pcapFilePath: string;
  procmonFilePaths: string[];
  options?: {
    timeWindowMs?: number;
    maxCandidatesPerSession?: number;
    minScore?: number;
    disableProcmonCache?: boolean;
  };
}

export interface CorrelationReason {
  code: string;
  score: number;
  detail: string;
}

export interface CorrelatedSession {
  sessionId: string;
  protocol: string;
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  firstSeenUs: number;
  lastSeenUs: number;
  packets: number;
  bytes: number;
}

export interface CorrelationMatch extends CorrelatedSession {
  eventId: string;
  matchedAtUs: number;
  pid: number | null;
  tid: number | null;
  processName: string | null;
  processPath?: string | null;
  commandLine?: string | null;
  userName?: string | null;
  company?: string | null;
  parentPid?: number | null;
  integrityLevel?: string | null;
  signer?: string | null;
  imageHash?: string | null;
  operation: string | null;
  result: string | null;
  eventLocalIp?: string | null;
  eventLocalPort?: number | null;
  eventRemoteIp?: string | null;
  eventRemotePort?: number | null;
  eventDirection?: string | null;
  score: number;
  confidence: CorrelationConfidence;
  offsetUs: number;
  reasons: CorrelationReason[];
}

export interface CorrelationUnmatchedSession extends CorrelatedSession {
  reason: string;
}

export interface CorrelationUnmatchedProcmonEvent {
  eventId: string;
  tsUs: number;
  pid: number | null;
  processName: string | null;
  processPath?: string | null;
  commandLine?: string | null;
  userName?: string | null;
  company?: string | null;
  parentPid?: number | null;
  integrityLevel?: string | null;
  signer?: string | null;
  imageHash?: string | null;
  operation: string | null;
  eventLocalIp?: string | null;
  eventLocalPort?: number | null;
  remoteIp: string | null;
  remotePort: number | null;
  eventDirection?: string | null;
  reason: string;
}

export interface CorrelationDiagnostics {
  timeOffsetUs: number;
  drift: number;
  totalSessions: number;
  totalProcmonEvents: number;
  matchedSessions: number;
  unmatchedSessions: number;
  unmatchedProcmonEvents: number;
  parserMode: 'hybrid' | 'xml_only' | 'parser_only';
  warnings: string[];
}

export interface CorrelationReportV1 {
  schema: 'correlation_report_v1';
  version: 1;
  generatedAt: string;
  analysisId: string;
  pcapFilePath: string;
  procmonFiles: string[];
  diagnostics: CorrelationDiagnostics;
  matches: CorrelationMatch[];
  unmatchedSessions: CorrelationUnmatchedSession[];
  unmatchedProcmonEvents: CorrelationUnmatchedProcmonEvent[];
  warnings: string[];
}
