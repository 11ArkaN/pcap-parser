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
