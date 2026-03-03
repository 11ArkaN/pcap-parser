import type { ParsePcapOptions, ParsePcapResult, ParsedConnection } from '../types';

const ETHERNET_HEADER_LEN = 14;
const IP_PROTOCOL = 0x0800;
const IPV6_PROTOCOL = 0x86dd;
const VLAN_PROTOCOL = 0x8100;
const QINQ_PROTOCOL = 0x88a8;
const MPLS_PROTOCOL = 0x8847;
const ARP_PROTOCOL = 0x0806;
const PPPOE_PROTOCOL = 0x8864;

export async function parsePcap(buffer: Uint8Array | ArrayBuffer, options: ParsePcapOptions = {}): Promise<ParsedConnection[]> {
  const result = await parsePcapDetailed(buffer, options);
  return result.connections;
}

export async function parsePcapDetailed(
  buffer: Uint8Array | ArrayBuffer,
  options: ParsePcapOptions = {}
): Promise<ParsePcapResult> {
  const data = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const maxConnections = options.maxConnections ?? Number.POSITIVE_INFINITY;

  const magic = readUInt32(data, 0);
  if (magic === 0x0a0d0d0a || magic === 0x0d0a0a0d) {
    return parsePcapNg(data, maxConnections);
  }
  if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1) {
    return parsePcapLegacy(data, maxConnections);
  }

  throw new Error('Unknown file format');
}

function parsePcapLegacy(data: Uint8Array, maxConnections: number): ParsePcapResult {
  const connections: ParsedConnection[] = [];
  const littleEndian = data[0] === 0xd4;
  let offset = 24;
  let truncated = false;

  while (offset < data.length) {
    if (offset + 16 > data.length) break;

    const inclLen = readUInt32(data, offset + 8, littleEndian);
    const origLen = readUInt32(data, offset + 12, littleEndian);
    offset += 16;

    if (offset + inclLen > data.length) break;

    const packetData = data.slice(offset, offset + inclLen);
    const conn = parsePacket(packetData);
    if (conn) {
      conn.length = origLen;
      connections.push(conn);
      if (connections.length >= maxConnections) {
        truncated = true;
        break;
      }
    }

    offset += inclLen;
  }

  return { connections, truncated };
}

function parsePcapNg(data: Uint8Array, maxConnections: number): ParsePcapResult {
  const connections: ParsedConnection[] = [];
  let offset = 0;
  let truncated = false;

  const byteOrderMagic = readUInt32(data, 8);
  const littleEndian = byteOrderMagic === 0x1a2b3c4d;

  while (offset < data.length) {
    const blockType = readUInt32(data, offset, littleEndian);
    const blockLen = readUInt32(data, offset + 4, littleEndian);

    if (blockLen === 0 || offset + blockLen > data.length) break;

    if (blockType === 0x00000006 || blockType === 0x00000003) {
      const conn =
        blockType === 0x00000006
          ? parseEnhancedPacketBlock(data, offset, littleEndian)
          : parseSimplePacketBlock(data, offset, littleEndian);

      if (conn) {
        connections.push(conn);
        if (connections.length >= maxConnections) {
          truncated = true;
          break;
        }
      }
    }

    offset += blockLen;
    while (offset % 4 !== 0) offset += 1;
  }

  return { connections, truncated };
}

function parseEnhancedPacketBlock(data: Uint8Array, offset: number, littleEndian: boolean): ParsedConnection | null {
  try {
    const capturedLen = readUInt32(data, offset + 20, littleEndian);
    const packetLen = readUInt32(data, offset + 24, littleEndian);

    if (capturedLen === 0 || capturedLen > 65535) return null;

    const packetData = data.slice(offset + 28, offset + 28 + capturedLen);
    const conn = parsePacket(packetData);

    if (conn) conn.length = packetLen;

    return conn;
  } catch {
    return null;
  }
}

function parseSimplePacketBlock(data: Uint8Array, offset: number, littleEndian: boolean): ParsedConnection | null {
  try {
    const packetLen = readUInt32(data, offset + 8, littleEndian);
    const packetData = data.slice(offset + 12, offset + 12 + packetLen);
    const conn = parsePacket(packetData);
    if (conn) conn.length = packetLen;
    return conn;
  } catch {
    return null;
  }
}

function parsePacket(data: Uint8Array): ParsedConnection | null {
  if (data.length < ETHERNET_HEADER_LEN) {
    return buildConnection('---', '---', 'TRUNCATED', null, null, 'Truncated');
  }

  let etherType = (data[12] << 8) | data[13];
  let offset = ETHERNET_HEADER_LEN;
  let vlanTag: number | null = null;

  if (etherType === VLAN_PROTOCOL || etherType === QINQ_PROTOCOL) {
    if (data.length >= offset + 4) {
      vlanTag = (data[offset] << 8) | data[offset + 1];
      etherType = (data[offset + 2] << 8) | data[offset + 3];
      offset += 4;

      if (etherType === VLAN_PROTOCOL && data.length >= offset + 4) {
        etherType = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
      }
    }
  }

  if (etherType === MPLS_PROTOCOL) {
    let mplsOffset = offset;
    while (mplsOffset < data.length - 4) {
      const byte = data[mplsOffset + 2];
      mplsOffset += 4;
      if (byte & 0x01) break;
    }

    offset = mplsOffset + 4;
    if (offset < data.length) {
      const firstByte = data[offset];
      if ((firstByte >> 4) === 4) {
        const conn = parseIPv4(data.slice(offset));
        if (conn) conn.vlan = vlanTag;
        return conn;
      }
      if ((firstByte >> 4) === 6) {
        const conn = parseIPv6(data.slice(offset));
        if (conn) conn.vlan = vlanTag;
        return conn;
      }
    }
    return buildConnection('---', '---', 'MPLS', null, null, 'MPLS');
  }

  if (etherType === PPPOE_PROTOCOL) {
    return buildConnection('---', '---', 'PPPoE', null, null, 'PPPoE');
  }

  if (etherType === ARP_PROTOCOL) {
    return buildConnection('---', '---', 'ARP', null, null, 'ARP');
  }

  if (etherType === IP_PROTOCOL) {
    const conn = parseIPv4(data.slice(offset));
    if (conn) conn.vlan = vlanTag;
    return conn;
  }

  if (etherType === IPV6_PROTOCOL) {
    const conn = parseIPv6(data.slice(offset));
    if (conn) conn.vlan = vlanTag;
    return conn;
  }

  if (etherType < 1536) {
    if (data.length > offset + 8) {
      const snapType = (data[offset + 6] << 8) | data[offset + 7];
      if (snapType === IP_PROTOCOL) {
        const conn = parseIPv4(data.slice(offset + 8));
        if (conn) conn.vlan = vlanTag;
        return conn;
      }
      if (snapType === IPV6_PROTOCOL) {
        const conn = parseIPv6(data.slice(offset + 8));
        if (conn) conn.vlan = vlanTag;
        return conn;
      }
    }
    return buildConnection('---', '---', `LLC(0x${etherType.toString(16)})`, null, null, 'LLC');
  }

  return buildConnection('---', '---', `0x${etherType.toString(16).toUpperCase().padStart(4, '0')}`, null, null, 'Other');
}

function parseIPv4(data: Uint8Array): ParsedConnection {
  if (data.length < 20) {
    return buildConnection('---', '---', 'IPv4?', null, null, 'IPv4-Short');
  }

  const versionIhl = data[0];
  const version = versionIhl >> 4;
  const ihl = (versionIhl & 0x0f) * 4;

  if (version !== 4 || data.length < ihl) {
    return buildConnection('---', '---', 'IPv4?', null, null, 'IPv4-Bad');
  }

  const protocol = data[9];
  const srcIp = `${data[12]}.${data[13]}.${data[14]}.${data[15]}`;
  const dstIp = `${data[16]}.${data[17]}.${data[18]}.${data[19]}`;

  let srcPort: number | null = null;
  let dstPort: number | null = null;
  let proto = 'OTHER';

  const payload = data.slice(ihl);

  if (protocol === 6) {
    proto = 'TCP';
    if (payload.length >= 4) {
      srcPort = (payload[0] << 8) | payload[1];
      dstPort = (payload[2] << 8) | payload[3];
    }
  } else if (protocol === 17) {
    proto = 'UDP';
    if (payload.length >= 4) {
      srcPort = (payload[0] << 8) | payload[1];
      dstPort = (payload[2] << 8) | payload[3];
    }
  } else if (protocol === 1) {
    proto = 'ICMP';
  } else if (protocol === 2) {
    proto = 'IGMP';
  } else if (protocol === 47) {
    proto = 'GRE';
  } else if (protocol === 50 || protocol === 51) {
    proto = 'IPSEC';
  } else {
    proto = `IP-${protocol}`;
  }

  return buildConnection(srcIp, dstIp, proto, srcPort, dstPort, 'IPv4');
}

function parseIPv6(data: Uint8Array): ParsedConnection {
  if (data.length < 40) {
    return buildConnection('---', '---', 'IPv6?', null, null, 'IPv6-Short');
  }

  const version = data[0] >> 4;
  if (version !== 6) {
    return buildConnection('---', '---', 'IPv6?', null, null, 'IPv6-Bad');
  }

  const nextHeader = data[6];
  const srcIp = formatIPv6(data.slice(8, 24));
  const dstIp = formatIPv6(data.slice(24, 40));

  let srcPort: number | null = null;
  let dstPort: number | null = null;
  let proto = 'OTHER';

  const payload = data.slice(40);

  if (nextHeader === 6) {
    proto = 'TCP';
    if (payload.length >= 4) {
      srcPort = (payload[0] << 8) | payload[1];
      dstPort = (payload[2] << 8) | payload[3];
    }
  } else if (nextHeader === 17) {
    proto = 'UDP';
    if (payload.length >= 4) {
      srcPort = (payload[0] << 8) | payload[1];
      dstPort = (payload[2] << 8) | payload[3];
    }
  } else if (nextHeader === 58) {
    proto = 'ICMPv6';
  } else if (nextHeader === 47) {
    proto = 'GRE';
  } else if (nextHeader === 50 || nextHeader === 51) {
    proto = 'IPSEC';
  } else {
    proto = `IPv6-${nextHeader}`;
  }

  return buildConnection(srcIp, dstIp, proto, srcPort, dstPort, 'IPv6');
}

function buildConnection(
  src: string,
  dst: string,
  protocol: string,
  srcPort: number | null,
  dstPort: number | null,
  type: string
): ParsedConnection {
  return {
    src,
    dst,
    protocol,
    srcPort,
    dstPort,
    packetCount: 1,
    type
  };
}

function formatIPv6(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  }
  return parts.join(':');
}

function readUInt32(data: Uint8Array, offset: number, littleEndian = true): number {
  if (littleEndian) {
    return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
  }

  return (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
}
