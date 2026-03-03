// PCAP/PCAPNG Parser - wszystkie pakiety
const ETHERNET_HEADER_LEN = 14;
const IP_PROTOCOL = 0x0800;
const IPV6_PROTOCOL = 0x86DD;
const VLAN_PROTOCOL = 0x8100;
const QINQ_PROTOCOL = 0x88A8;
const MPLS_PROTOCOL = 0x8847;
const ARP_PROTOCOL = 0x0806;
const PPPoE_PROTOCOL = 0x8864;

export async function parsePcap(buffer) {
  const data = new Uint8Array(buffer);
  const connections = [];
  
  const magic = readUInt32(data, 0);
  
  if (magic === 0x0a0d0d0a || magic === 0x0d0a0a0d) {
    return parsePcapNg(data);
  } else if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1) {
    return parsePcapLegacy(data);
  } else {
    throw new Error('Unknown file format');
  }
}

function parsePcapLegacy(data) {
  const connections = [];
  const littleEndian = data[0] === 0xd4;
  let offset = 24;
  
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
    }
    
    offset += inclLen;
  }
  
  return connections;
}

function parsePcapNg(data) {
  const connections = [];
  let offset = 0;
  
  const byteOrderMagic = readUInt32(data, 8);
  const littleEndian = byteOrderMagic === 0x1a2b3c4d;
  
  while (offset < data.length) {
    const blockType = readUInt32(data, offset, littleEndian);
    const blockLen = readUInt32(data, offset + 4, littleEndian);
    
    if (blockLen === 0 || offset + blockLen > data.length) break;
    
    if (blockType === 0x00000006 || blockType === 0x00000003) {
      const conn = blockType === 0x00000006 
        ? parseEnhancedPacketBlock(data, offset, littleEndian)
        : parseSimplePacketBlock(data, offset, littleEndian);
      
      if (conn) connections.push(conn);
    }
    
    offset += blockLen;
    while (offset % 4 !== 0) offset++;
  }
  
  return connections;
}

function parseEnhancedPacketBlock(data, offset, littleEndian) {
  try {
    const capturedLen = readUInt32(data, offset + 20, littleEndian);
    const packetLen = readUInt32(data, offset + 24, littleEndian);
    
    if (capturedLen === 0 || capturedLen > 65535) return null;
    
    const packetData = data.slice(offset + 28, offset + 28 + capturedLen);
    const conn = parsePacket(packetData);
    
    if (conn) conn.length = packetLen;
    
    return conn;
  } catch (e) {
    return null;
  }
}

function parseSimplePacketBlock(data, offset, littleEndian) {
  try {
    const packetLen = readUInt32(data, offset + 8, littleEndian);
    const packetData = data.slice(offset + 12, offset + 12 + packetLen);
    const conn = parsePacket(packetData);
    if (conn) conn.length = packetLen;
    return conn;
  } catch (e) {
    return null;
  }
}

function parsePacket(data) {
  if (data.length < ETHERNET_HEADER_LEN) {
    return {
      src: '---',
      dst: '---',
      protocol: 'TRUNCATED',
      srcPort: null,
      dstPort: null,
      packetCount: 1,
      type: 'Truncated'
    };
  }
  
  let etherType = (data[12] << 8) | data[13];
  let offset = ETHERNET_HEADER_LEN;
  let vlanTag = null;
  
  // Obsługa VLAN
  if (etherType === VLAN_PROTOCOL || etherType === QINQ_PROTOCOL) {
    if (data.length >= offset + 4) {
      vlanTag = (data[offset] << 8) | data[offset + 1];
      etherType = (data[offset + 2] << 8) | data[offset + 3];
      offset += 4;
      
      // Double VLAN (QinQ)
      if (etherType === VLAN_PROTOCOL) {
        if (data.length >= offset + 4) {
          etherType = (data[offset + 2] << 8) | data[offset + 3];
          offset += 4;
        }
      }
    }
  }
  
  // Obsługa MPLS
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
      } else if ((firstByte >> 4) === 6) {
        const conn = parseIPv6(data.slice(offset));
        if (conn) conn.vlan = vlanTag;
        return conn;
      }
    }
    return { src: '---', dst: '---', protocol: 'MPLS', srcPort: null, dstPort: null, packetCount: 1, type: 'MPLS' };
  }
  
  // PPPoE
  if (etherType === PPPoE_PROTOCOL) {
    return { src: '---', dst: '---', protocol: 'PPPoE', srcPort: null, dstPort: null, packetCount: 1, type: 'PPPoE' };
  }
  
  // ARP
  if (etherType === ARP_PROTOCOL) {
    return { src: '---', dst: '---', protocol: 'ARP', srcPort: null, dstPort: null, packetCount: 1, type: 'ARP' };
  }
  
  // IPv4
  if (etherType === IP_PROTOCOL) {
    const conn = parseIPv4(data.slice(offset));
    if (conn) conn.vlan = vlanTag;
    return conn;
  }
  
  // IPv6
  if (etherType === IPV6_PROTOCOL) {
    const conn = parseIPv6(data.slice(offset));
    if (conn) conn.vlan = vlanTag;
    return conn;
  }
  
  // LLC/SNAP
  if (etherType < 1536) {
    if (data.length > offset + 8) {
      const snapType = (data[offset + 6] << 8) | data[offset + 7];
      if (snapType === IP_PROTOCOL) {
        const conn = parseIPv4(data.slice(offset + 8));
        if (conn) conn.vlan = vlanTag;
        return conn;
      } else if (snapType === IPV6_PROTOCOL) {
        const conn = parseIPv6(data.slice(offset + 8));
        if (conn) conn.vlan = vlanTag;
        return conn;
      }
    }
    return { src: '---', dst: '---', protocol: `LLC(0x${etherType.toString(16)})`, srcPort: null, dstPort: null, packetCount: 1, type: 'LLC' };
  }
  
  // Inne nieznane
  return { 
    src: '---', 
    dst: '---', 
    protocol: `0x${etherType.toString(16).toUpperCase().padStart(4, '0')}`, 
    srcPort: null, 
    dstPort: null, 
    packetCount: 1,
    type: 'Other'
  };
}

function parseIPv4(data) {
  if (data.length < 20) {
    return { src: '---', dst: '---', protocol: 'IPv4?', srcPort: null, dstPort: null, packetCount: 1, type: 'IPv4-Short' };
  }
  
  const versionIhl = data[0];
  const version = (versionIhl >> 4);
  const ihl = (versionIhl & 0x0f) * 4;
  
  if (version !== 4 || data.length < ihl) {
    return { src: '---', dst: '---', protocol: 'IPv4?', srcPort: null, dstPort: null, packetCount: 1, type: 'IPv4-Bad' };
  }
  
  const protocol = data[9];
  const srcIp = `${data[12]}.${data[13]}.${data[14]}.${data[15]}`;
  const dstIp = `${data[16]}.${data[17]}.${data[18]}.${data[19]}`;
  
  let srcPort = null;
  let dstPort = null;
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
  
  return {
    src: srcIp,
    dst: dstIp,
    protocol: proto,
    srcPort,
    dstPort,
    packetCount: 1,
    type: 'IPv4'
  };
}

function parseIPv6(data) {
  if (data.length < 40) {
    return { src: '---', dst: '---', protocol: 'IPv6?', srcPort: null, dstPort: null, packetCount: 1, type: 'IPv6-Short' };
  }
  
  const version = (data[0] >> 4);
  if (version !== 6) {
    return { src: '---', dst: '---', protocol: 'IPv6?', srcPort: null, dstPort: null, packetCount: 1, type: 'IPv6-Bad' };
  }
  
  const nextHeader = data[6];
  const srcIp = formatIPv6(data.slice(8, 24));
  const dstIp = formatIPv6(data.slice(24, 40));
  
  let srcPort = null;
  let dstPort = null;
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
  
  return {
    src: srcIp,
    dst: dstIp,
    protocol: proto,
    srcPort,
    dstPort,
    packetCount: 1,
    type: 'IPv6'
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
