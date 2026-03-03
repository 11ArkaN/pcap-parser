// PCAP/PCAPNG Parser
// Supports both .pcap (libpcap) and .pcapng (pcap-next-generation) formats

const ETHERNET_HEADER_LEN = 14;
const IP_PROTOCOL = 0x0800;
const IPV6_PROTOCOL = 0x86DD;

export async function parsePcap(buffer) {
  const data = new Uint8Array(buffer);
  const connections = [];
  
  // Detect file format
  const magic = readUInt32(data, 0);
  
  if (magic === 0x0a0d0d0a || magic === 0x0d0a0a0d) {
    // PCAPNG format
    return parsePcapNg(data);
  } else if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1) {
    // PCAP format
    return parsePcapLegacy(data);
  } else {
    throw new Error('Unknown file format. Expected PCAP or PCAPNG.');
  }
}

function parsePcapLegacy(data) {
  const connections = [];
  const littleEndian = data[0] === 0xd4;
  
  // Skip global header (24 bytes)
  let offset = 24;
  
  while (offset < data.length) {
    // Packet header (16 bytes)
    if (offset + 16 > data.length) break;
    
    const tsSec = readUInt32(data, offset, littleEndian);
    const tsUsec = readUInt32(data, offset + 4, littleEndian);
    const inclLen = readUInt32(data, offset + 8, littleEndian);
    const origLen = readUInt32(data, offset + 12, littleEndian);
    
    offset += 16;
    
    if (offset + inclLen > data.length) break;
    
    // Parse packet data
    const packetData = data.slice(offset, offset + inclLen);
    const conn = parsePacket(packetData);
    
    if (conn) {
      conn.timestamp = tsSec + tsUsec / 1000000;
      conn.length = origLen;
      connections.push(conn);
    }
    
    offset += inclLen;
  }
  
  return connections;
}

function parsePcapNg(data) {
  const connections = [];
  let offset = 0;
  
  // Byte order magic
  const byteOrderMagic = readUInt32(data, 8);
  const littleEndian = byteOrderMagic === 0x1a2b3c4d;
  
  while (offset < data.length) {
    const blockType = readUInt32(data, offset, littleEndian);
    const blockLen = readUInt32(data, offset + 4, littleEndian);
    
    if (blockLen === 0 || offset + blockLen > data.length) break;
    
    // Enhanced Packet Block (EPB) = 0x00000006
    // Simple Packet Block (SPB) = 0x00000003
    if (blockType === 0x00000006) {
      const conn = parseEnhancedPacketBlock(data, offset, littleEndian);
      if (conn) connections.push(conn);
    } else if (blockType === 0x00000003) {
      const conn = parseSimplePacketBlock(data, offset, littleEndian);
      if (conn) connections.push(conn);
    }
    
    offset += blockLen;
    // Align to 4 bytes
    while (offset % 4 !== 0) offset++;
  }
  
  return connections;
}

function parseEnhancedPacketBlock(data, offset, littleEndian) {
  // EPB structure:
  // Block Type: 4 bytes
  // Block Length: 4 bytes
  // Interface ID: 4 bytes
  // Timestamp (High): 4 bytes
  // Timestamp (Low): 4 bytes
  // Captured Len: 4 bytes
  // Packet Len: 4 bytes
  // Packet Data: variable
  
  const capturedLen = readUInt32(data, offset + 20, littleEndian);
  const packetLen = readUInt32(data, offset + 24, littleEndian);
  
  const packetData = data.slice(offset + 28, offset + 28 + capturedLen);
  const conn = parsePacket(packetData);
  
  if (conn) {
    conn.length = packetLen;
  }
  
  return conn;
}

function parseSimplePacketBlock(data, offset, littleEndian) {
  // SPB structure:
  // Block Type: 4 bytes
  // Block Length: 4 bytes
  // Packet Len: 4 bytes
  // Packet Data: variable
  
  const packetLen = readUInt32(data, offset + 8, littleEndian);
  const packetData = data.slice(offset + 12, offset + 12 + packetLen);
  
  const conn = parsePacket(packetData);
  if (conn) {
    conn.length = packetLen;
  }
  
  return conn;
}

function parsePacket(data) {
  if (data.length < ETHERNET_HEADER_LEN) return null;
  
  // Ethernet header
  const etherType = (data[12] << 8) | data[13];
  
  if (etherType === IP_PROTOCOL) {
    return parseIPv4(data.slice(ETHERNET_HEADER_LEN));
  } else if (etherType === IPV6_PROTOCOL) {
    return parseIPv6(data.slice(ETHERNET_HEADER_LEN));
  }
  
  return null;
}

function parseIPv4(data) {
  if (data.length < 20) return null;
  
  const versionIhl = data[0];
  const ihl = (versionIhl & 0x0f) * 4; // Header length in bytes
  
  if (data.length < ihl) return null;
  
  const protocol = data[9];
  const srcIp = `${data[12]}.${data[13]}.${data[14]}.${data[15]}`;
  const dstIp = `${data[16]}.${data[17]}.${data[18]}.${data[19]}`;
  
  let srcPort = null;
  let dstPort = null;
  let proto = 'OTHER';
  
  const payload = data.slice(ihl);
  
  if (protocol === 6) { // TCP
    proto = 'TCP';
    if (payload.length >= 4) {
      srcPort = (payload[0] << 8) | payload[1];
      dstPort = (payload[2] << 8) | payload[3];
    }
  } else if (protocol === 17) { // UDP
    proto = 'UDP';
    if (payload.length >= 4) {
      srcPort = (payload[0] << 8) | payload[1];
      dstPort = (payload[2] << 8) | payload[3];
    }
  } else if (protocol === 1) { // ICMP
    proto = 'ICMP';
  } else if (protocol === 2) { // IGMP
    proto = 'IGMP';
  }
  
  return {
    src: srcIp,
    dst: dstIp,
    protocol: proto,
    srcPort,
    dstPort,
    packetCount: 1
  };
}

function parseIPv6(data) {
  if (data.length < 40) return null;
  
  const nextHeader = data[6];
  
  // Parse source address (16 bytes)
  const srcIp = formatIPv6(data.slice(8, 24));
  const dstIp = formatIPv6(data.slice(24, 40));
  
  let srcPort = null;
  let dstPort = null;
  let proto = 'OTHER';
  
  const payload = data.slice(40);
  
  if (nextHeader === 6) { // TCP
    proto = 'TCP';
    if (payload.length >= 4) {
      srcPort = (payload[0] << 8) | payload[1];
      dstPort = (payload[2] << 8) | payload[3];
    }
  } else if (nextHeader === 17) { // UDP
    proto = 'UDP';
    if (payload.length >= 4) {
      srcPort = (payload[0] << 8) | payload[1];
      dstPort = (payload[2] << 8) | payload[3];
    }
  } else if (nextHeader === 58) { // ICMPv6
    proto = 'ICMPv6';
  }
  
  return {
    src: srcIp,
    dst: dstIp,
    protocol: proto,
    srcPort,
    dstPort,
    packetCount: 1
  };
}

function formatIPv6(bytes) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  }
  return parts.join(':');
}

function readUInt32(data, offset, littleEndian = true) {
  if (littleEndian) {
    return (data[offset]) | (data[offset + 1] << 8) | 
           (data[offset + 2] << 16) | (data[offset + 3] << 24);
  } else {
    return (data[offset] << 24) | (data[offset + 1] << 16) | 
           (data[offset + 2] << 8) | (data[offset + 3]);
  }
}
