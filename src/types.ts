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
  operation: string | null;
  result: string | null;
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
  operation: string | null;
  remoteIp: string | null;
  remotePort: number | null;
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
