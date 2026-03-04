import type { PcapStreamCatalog, PcapStreamSummary, StreamPacketMeta, StreamPayloadRef, StreamPayloadView, StreamTcpMeta } from '../types';

const ETHERNET_HEADER_LEN = 14;
const IP_PROTOCOL = 0x0800;
const IPV6_PROTOCOL = 0x86dd;
const VLAN_PROTOCOL = 0x8100;
const QINQ_PROTOCOL = 0x88a8;

interface ParseStreamOptions {
  maxPackets?: number;
}

interface PcapFlavor {
  container: 'pcap' | 'pcapng';
  littleEndian: boolean;
  tsResolutionPerSecond: bigint;
}

interface ParsedFrame {
  protocol: string;
  ipVersion: 'IPv4' | 'IPv6';
  srcIp: string;
  dstIp: string;
  srcPort: number | null;
  dstPort: number | null;
  vlan: number | null;
  ttl: number | null;
  hopLimit: number | null;
  payloadLength: number;
  tcp: StreamTcpMeta | null;
}

interface PacketEnvelope {
  timestampUs: number | null;
  capturedLength: number;
  originalLength: number;
  fileOffset: number;
  packetBytes: Uint8Array;
}

interface StreamAccumulator {
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
}

export async function parsePcapStreamCatalog(
  buffer: Uint8Array | ArrayBuffer,
  options: ParseStreamOptions = {}
): Promise<PcapStreamCatalog> {
  const data = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const maxPackets = options.maxPackets ?? Number.POSITIVE_INFINITY;

  const flavor = detectPcapFlavor(data);
  if (!flavor) {
    throw new Error('Unknown file format');
  }

  const streamByKey = new Map<string, StreamAccumulator>();
  const packetsByStream = new Map<string, StreamPacketMeta[]>();
  const nextIndexByProto = new Map<string, number>();
  let totalPackets = 0;
  let droppedPackets = 0;
  let truncated = false;

  const onPacket = (envelope: PacketEnvelope) => {
    if (totalPackets >= maxPackets) {
      truncated = true;
      return false;
    }
    totalPackets += 1;

    const frame = parseFrame(envelope.packetBytes);
    if (!frame) {
      droppedPackets += 1;
      return true;
    }

    const endpointSrc = endpointValue(frame.srcIp, frame.srcPort);
    const endpointDst = endpointValue(frame.dstIp, frame.dstPort);
    const [endpointA, endpointB] = endpointSrc <= endpointDst ? [endpointSrc, endpointDst] : [endpointDst, endpointSrc];
    const streamKey = `${frame.protocol}|${endpointA}|${endpointB}`;

    let stream = streamByKey.get(streamKey);
    if (!stream) {
      const current = (nextIndexByProto.get(frame.protocol) ?? 0) + 1;
      nextIndexByProto.set(frame.protocol, current);
      stream = {
        streamId: `${frame.protocol}-${current}`,
        streamIndex: current,
        protocol: frame.protocol,
        endpointA,
        endpointB,
        clientIp: frame.srcIp,
        clientPort: frame.srcPort,
        serverIp: frame.dstIp,
        serverPort: frame.dstPort,
        packets: 0,
        bytes: 0,
        firstSeenUs: null,
        lastSeenUs: null
      };
      streamByKey.set(streamKey, stream);
      packetsByStream.set(stream.streamId, []);
    }

    const direction = frame.srcIp === stream.clientIp && frame.srcPort === stream.clientPort ? 'A->B' : 'B->A';
    const packetMeta: StreamPacketMeta = {
      streamId: stream.streamId,
      packetNo: totalPackets,
      timestampUs: envelope.timestampUs,
      protocol: frame.protocol,
      ipVersion: frame.ipVersion,
      srcIp: frame.srcIp,
      srcPort: frame.srcPort,
      dstIp: frame.dstIp,
      dstPort: frame.dstPort,
      direction,
      capturedLength: envelope.capturedLength,
      originalLength: envelope.originalLength,
      vlan: frame.vlan,
      ttl: frame.ttl,
      hopLimit: frame.hopLimit,
      payloadLength: frame.payloadLength,
      tcp: frame.tcp,
      payloadRef: {
        fileOffset: envelope.fileOffset,
        capturedLength: envelope.capturedLength
      }
    };

    packetsByStream.get(stream.streamId)?.push(packetMeta);
    stream.packets += 1;
    stream.bytes += envelope.originalLength;
    if (typeof envelope.timestampUs === 'number') {
      stream.firstSeenUs = stream.firstSeenUs === null ? envelope.timestampUs : Math.min(stream.firstSeenUs, envelope.timestampUs);
      stream.lastSeenUs = stream.lastSeenUs === null ? envelope.timestampUs : Math.max(stream.lastSeenUs, envelope.timestampUs);
    }

    return true;
  };

  if (flavor.container === 'pcap') {
    parseLegacyPackets(data, flavor, onPacket);
  } else {
    parsePcapNgPackets(data, flavor, onPacket);
  }

  const streams: PcapStreamSummary[] = Array.from(streamByKey.values()).map((item) => ({
    streamId: item.streamId,
    streamIndex: item.streamIndex,
    protocol: item.protocol,
    endpointA: item.endpointA,
    endpointB: item.endpointB,
    clientIp: item.clientIp,
    clientPort: item.clientPort,
    serverIp: item.serverIp,
    serverPort: item.serverPort,
    packets: item.packets,
    bytes: item.bytes,
    firstSeenUs: item.firstSeenUs,
    lastSeenUs: item.lastSeenUs,
    durationUs:
      item.firstSeenUs !== null && item.lastSeenUs !== null
        ? Math.max(0, item.lastSeenUs - item.firstSeenUs)
        : null
  }));

  streams.sort((a, b) => {
    if (a.protocol !== b.protocol) return a.protocol.localeCompare(b.protocol);
    return a.streamIndex - b.streamIndex;
  });

  const packetsByStreamRecord: Record<string, StreamPacketMeta[]> = {};
  for (const [streamId, packets] of packetsByStream.entries()) {
    packetsByStreamRecord[streamId] = packets;
  }

  return {
    totalPackets,
    streams,
    packetsByStream: packetsByStreamRecord,
    truncated,
    droppedPackets
  };
}

export function readStreamPayloadFromBuffer(
  buffer: Uint8Array | ArrayBuffer,
  payloadRef: StreamPayloadRef,
  maxBytes = 64 * 1024
): StreamPayloadView {
  const data = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const start = Math.max(0, Math.floor(payloadRef.fileOffset));
  const capturedLength = Math.max(0, Math.floor(payloadRef.capturedLength));

  if (start >= data.length || capturedLength <= 0) {
    return {
      capturedLength,
      returnedLength: 0,
      truncated: capturedLength > 0,
      hex: '',
      ascii: ''
    };
  }

  const available = Math.max(0, Math.min(capturedLength, data.length - start));
  const returnedLength = Math.max(0, Math.min(available, maxBytes));
  const bytes = data.slice(start, start + returnedLength);

  return {
    capturedLength,
    returnedLength,
    truncated: returnedLength < capturedLength,
    hex: bytesToHexDump(bytes),
    ascii: bytesToAscii(bytes)
  };
}

function parseLegacyPackets(data: Uint8Array, flavor: PcapFlavor, onPacket: (packet: PacketEnvelope) => boolean): void {
  let offset = 24;
  while (offset + 16 <= data.length) {
    const tsSec = readUInt32(data, offset, flavor.littleEndian);
    const tsSub = readUInt32(data, offset + 4, flavor.littleEndian);
    const inclLen = readUInt32(data, offset + 8, flavor.littleEndian);
    const origLen = readUInt32(data, offset + 12, flavor.littleEndian);
    const packetOffset = offset + 16;

    if (inclLen <= 0 || packetOffset + inclLen > data.length) break;
    const packetBytes = data.slice(packetOffset, packetOffset + inclLen);
    const timestampUs = toTimestampUs(tsSec, tsSub, flavor.tsResolutionPerSecond);
    const proceed = onPacket({
      timestampUs,
      capturedLength: inclLen,
      originalLength: origLen,
      fileOffset: packetOffset,
      packetBytes
    });
    if (!proceed) break;
    offset = packetOffset + inclLen;
  }
}

function parsePcapNgPackets(data: Uint8Array, flavor: PcapFlavor, onPacket: (packet: PacketEnvelope) => boolean): void {
  let offset = 0;
  const interfaceResolutionById = new Map<number, bigint>();

  while (offset + 12 <= data.length) {
    const blockType = readUInt32(data, offset, flavor.littleEndian);
    const blockLen = readUInt32(data, offset + 4, flavor.littleEndian);
    if (blockLen < 12 || offset + blockLen > data.length) break;

    if (blockType === 0x00000001) {
      const interfaceId = interfaceResolutionById.size;
      const tsRes = parseIdbTimestampResolution(data, offset, blockLen, flavor.littleEndian);
      interfaceResolutionById.set(interfaceId, tsRes ?? flavor.tsResolutionPerSecond);
    } else if (blockType === 0x00000006) {
      const interfaceId = readUInt32(data, offset + 8, flavor.littleEndian);
      const tsHigh = readUInt32(data, offset + 12, flavor.littleEndian);
      const tsLow = readUInt32(data, offset + 16, flavor.littleEndian);
      const capturedLen = readUInt32(data, offset + 20, flavor.littleEndian);
      const originalLen = readUInt32(data, offset + 24, flavor.littleEndian);
      const packetOffset = offset + 28;
      if (capturedLen > 0 && packetOffset + capturedLen <= offset + blockLen) {
        const resolution = interfaceResolutionById.get(interfaceId) ?? flavor.tsResolutionPerSecond;
        const timestampUs = toTimestampUs64(tsHigh, tsLow, resolution);
        const packetBytes = data.slice(packetOffset, packetOffset + capturedLen);
        const proceed = onPacket({
          timestampUs,
          capturedLength: capturedLen,
          originalLength: originalLen,
          fileOffset: packetOffset,
          packetBytes
        });
        if (!proceed) break;
      }
    } else if (blockType === 0x00000003) {
      const packetLen = readUInt32(data, offset + 8, flavor.littleEndian);
      const packetOffset = offset + 12;
      if (packetLen > 0 && packetOffset + packetLen <= offset + blockLen) {
        const packetBytes = data.slice(packetOffset, packetOffset + packetLen);
        const proceed = onPacket({
          timestampUs: null,
          capturedLength: packetLen,
          originalLength: packetLen,
          fileOffset: packetOffset,
          packetBytes
        });
        if (!proceed) break;
      }
    }

    offset += blockLen;
    while (offset % 4 !== 0) offset += 1;
  }
}

function parseFrame(frame: Uint8Array): ParsedFrame | null {
  if (frame.length < ETHERNET_HEADER_LEN) return null;
  let etherType = (frame[12] << 8) | frame[13];
  let offset = ETHERNET_HEADER_LEN;
  let vlan: number | null = null;

  if (etherType === VLAN_PROTOCOL || etherType === QINQ_PROTOCOL) {
    if (frame.length < offset + 4) return null;
    vlan = ((frame[offset] << 8) | frame[offset + 1]) & 0x0fff;
    etherType = (frame[offset + 2] << 8) | frame[offset + 3];
    offset += 4;
  }

  if (etherType === IP_PROTOCOL) {
    return parseIPv4Frame(frame.slice(offset), vlan);
  }
  if (etherType === IPV6_PROTOCOL) {
    return parseIPv6Frame(frame.slice(offset), vlan);
  }

  return null;
}

function parseIPv4Frame(payload: Uint8Array, vlan: number | null): ParsedFrame | null {
  if (payload.length < 20) return null;
  const version = payload[0] >> 4;
  const ihl = (payload[0] & 0x0f) * 4;
  if (version !== 4 || ihl < 20 || payload.length < ihl) return null;

  const protocolNum = payload[9];
  const srcIp = `${payload[12]}.${payload[13]}.${payload[14]}.${payload[15]}`;
  const dstIp = `${payload[16]}.${payload[17]}.${payload[18]}.${payload[19]}`;
  const ttl = payload[8];

  const transport = payload.slice(ihl);
  const parsedTransport = parseTransport(protocolNum, transport);

  return {
    protocol: parsedTransport.protocol,
    ipVersion: 'IPv4',
    srcIp,
    dstIp,
    srcPort: parsedTransport.srcPort,
    dstPort: parsedTransport.dstPort,
    vlan,
    ttl,
    hopLimit: null,
    payloadLength: parsedTransport.payloadLength,
    tcp: parsedTransport.tcp
  };
}

function parseIPv6Frame(payload: Uint8Array, vlan: number | null): ParsedFrame | null {
  if (payload.length < 40) return null;
  const version = payload[0] >> 4;
  if (version !== 6) return null;
  const nextHeader = payload[6];
  const hopLimit = payload[7];
  const srcIp = formatIPv6(payload.slice(8, 24));
  const dstIp = formatIPv6(payload.slice(24, 40));

  const transport = payload.slice(40);
  const parsedTransport = parseTransport(nextHeader, transport);

  return {
    protocol: parsedTransport.protocol,
    ipVersion: 'IPv6',
    srcIp,
    dstIp,
    srcPort: parsedTransport.srcPort,
    dstPort: parsedTransport.dstPort,
    vlan,
    ttl: null,
    hopLimit,
    payloadLength: parsedTransport.payloadLength,
    tcp: parsedTransport.tcp
  };
}

function parseTransport(protocolNum: number, transport: Uint8Array): {
  protocol: string;
  srcPort: number | null;
  dstPort: number | null;
  payloadLength: number;
  tcp: StreamTcpMeta | null;
} {
  if (protocolNum === 6) {
    if (transport.length < 20) {
      return { protocol: 'TCP', srcPort: null, dstPort: null, payloadLength: 0, tcp: null };
    }
    const srcPort = (transport[0] << 8) | transport[1];
    const dstPort = (transport[2] << 8) | transport[3];
    const seq = readUInt32(transport, 4, false) >>> 0;
    const ack = readUInt32(transport, 8, false) >>> 0;
    const headerLength = ((transport[12] >> 4) & 0x0f) * 4;
    const flags = transport[13];
    const window = ((transport[14] << 8) | transport[15]) >>> 0;
    const payloadLength = Math.max(0, transport.length - Math.max(20, headerLength));
    return {
      protocol: 'TCP',
      srcPort,
      dstPort,
      payloadLength,
      tcp: {
        seq,
        ack,
        flags: parseTcpFlags(flags),
        window,
        headerLength: Math.max(20, headerLength),
        payloadLength
      }
    };
  }

  if (protocolNum === 17) {
    if (transport.length < 8) {
      return { protocol: 'UDP', srcPort: null, dstPort: null, payloadLength: 0, tcp: null };
    }
    const srcPort = (transport[0] << 8) | transport[1];
    const dstPort = (transport[2] << 8) | transport[3];
    const udpLen = ((transport[4] << 8) | transport[5]) >>> 0;
    const payloadLength = Math.max(0, Math.min(transport.length, udpLen || transport.length) - 8);
    return {
      protocol: 'UDP',
      srcPort,
      dstPort,
      payloadLength,
      tcp: null
    };
  }

  if (protocolNum === 1) {
    return { protocol: 'ICMP', srcPort: null, dstPort: null, payloadLength: transport.length, tcp: null };
  }
  if (protocolNum === 58) {
    return { protocol: 'ICMPv6', srcPort: null, dstPort: null, payloadLength: transport.length, tcp: null };
  }
  if (protocolNum === 2) {
    return { protocol: 'IGMP', srcPort: null, dstPort: null, payloadLength: transport.length, tcp: null };
  }
  if (protocolNum === 47) {
    return { protocol: 'GRE', srcPort: null, dstPort: null, payloadLength: transport.length, tcp: null };
  }
  if (protocolNum === 50 || protocolNum === 51) {
    return { protocol: 'IPSEC', srcPort: null, dstPort: null, payloadLength: transport.length, tcp: null };
  }

  return {
    protocol: `IP-${protocolNum}`,
    srcPort: null,
    dstPort: null,
    payloadLength: transport.length,
    tcp: null
  };
}

function detectPcapFlavor(data: Uint8Array): PcapFlavor | null {
  if (data.length < 12) return null;
  const magicBE = readUInt32(data, 0, false) >>> 0;
  if (magicBE === 0xa1b2c3d4) {
    return { container: 'pcap', littleEndian: false, tsResolutionPerSecond: 1_000_000n };
  }
  if (magicBE === 0xd4c3b2a1) {
    return { container: 'pcap', littleEndian: true, tsResolutionPerSecond: 1_000_000n };
  }
  if (magicBE === 0xa1b23c4d) {
    return { container: 'pcap', littleEndian: false, tsResolutionPerSecond: 1_000_000_000n };
  }
  if (magicBE === 0x4d3cb2a1) {
    return { container: 'pcap', littleEndian: true, tsResolutionPerSecond: 1_000_000_000n };
  }

  const pcapNgMagicLE = readUInt32(data, 0, true) >>> 0;
  if (pcapNgMagicLE !== 0x0a0d0d0a && pcapNgMagicLE !== 0x0d0a0a0d) return null;
  if (data.length < 12) return null;
  const bom0 = data[8];
  const bom1 = data[9];
  const bom2 = data[10];
  const bom3 = data[11];
  if (bom0 === 0x1a && bom1 === 0x2b && bom2 === 0x3c && bom3 === 0x4d) {
    return { container: 'pcapng', littleEndian: false, tsResolutionPerSecond: 1_000_000n };
  }
  if (bom0 === 0x4d && bom1 === 0x3c && bom2 === 0x2b && bom3 === 0x1a) {
    return { container: 'pcapng', littleEndian: true, tsResolutionPerSecond: 1_000_000n };
  }
  return { container: 'pcapng', littleEndian: true, tsResolutionPerSecond: 1_000_000n };
}

function parseIdbTimestampResolution(
  data: Uint8Array,
  blockOffset: number,
  blockLen: number,
  littleEndian: boolean
): bigint | null {
  let optionOffset = blockOffset + 16;
  const blockEnd = blockOffset + blockLen - 4;

  while (optionOffset + 4 <= blockEnd) {
    const code = readUInt16(data, optionOffset, littleEndian);
    const length = readUInt16(data, optionOffset + 2, littleEndian);
    optionOffset += 4;
    if (code === 0) break;
    if (optionOffset + length > blockEnd) break;
    if (code === 9 && length >= 1) {
      const raw = data[optionOffset];
      const value = raw & 0x7f;
      if ((raw & 0x80) !== 0) {
        return 1n << BigInt(value);
      }
      return 10n ** BigInt(value);
    }
    optionOffset += length;
    while (optionOffset % 4 !== 0) optionOffset += 1;
  }
  return null;
}

function toTimestampUs(tsSec: number, tsSub: number, tsResolutionPerSecond: bigint): number {
  const base = BigInt(Math.max(0, tsSec)) * 1_000_000n;
  const sub = (BigInt(Math.max(0, tsSub)) * 1_000_000n) / tsResolutionPerSecond;
  return Number(base + sub);
}

function toTimestampUs64(tsHigh: number, tsLow: number, tsResolutionPerSecond: bigint): number {
  const raw = (BigInt(tsHigh >>> 0) << 32n) | BigInt(tsLow >>> 0);
  return Number((raw * 1_000_000n) / tsResolutionPerSecond);
}

function endpointValue(ip: string, port: number | null): string {
  return `${ip}:${port ?? '-'}`;
}

function parseTcpFlags(flags: number): string {
  const tokens: string[] = [];
  if (flags & 0x01) tokens.push('FIN');
  if (flags & 0x02) tokens.push('SYN');
  if (flags & 0x04) tokens.push('RST');
  if (flags & 0x08) tokens.push('PSH');
  if (flags & 0x10) tokens.push('ACK');
  if (flags & 0x20) tokens.push('URG');
  if (flags & 0x40) tokens.push('ECE');
  if (flags & 0x80) tokens.push('CWR');
  return tokens.join(',');
}

function bytesToHexDump(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const line = Array.from(chunk)
      .map((value) => value.toString(16).padStart(2, '0'))
      .join(' ');
    lines.push(line);
  }
  return lines.join('\n');
}

function bytesToAscii(bytes: Uint8Array): string {
  let out = '';
  for (const value of bytes) {
    if (value >= 32 && value <= 126) {
      out += String.fromCharCode(value);
    } else {
      out += '.';
    }
  }
  return out;
}

function formatIPv6(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  }
  return parts.join(':');
}

function readUInt16(data: Uint8Array, offset: number, littleEndian: boolean): number {
  if (offset + 2 > data.length) return 0;
  if (littleEndian) return data[offset] | (data[offset + 1] << 8);
  return (data[offset] << 8) | data[offset + 1];
}

function readUInt32(data: Uint8Array, offset: number, littleEndian: boolean): number {
  if (offset + 4 > data.length) return 0;
  if (littleEndian) {
    return ((data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0);
  }
  return (((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]) >>> 0);
}
