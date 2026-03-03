// Full test of PCAP parser with actual data extraction
const fs = require('fs');
const path = require('path');

// PCAP Parser implementation for testing
const ETHERNET_HEADER_LEN = 14;
const IP_PROTOCOL = 0x0800;
const IPV6_PROTOCOL = 0x86DD;

function readUInt32(data, offset, littleEndian = true) {
  if (littleEndian) {
    return (data[offset]) | (data[offset + 1] << 8) | 
           (data[offset + 2] << 16) | (data[offset + 3] << 24);
  } else {
    return (data[offset] << 24) | (data[offset + 1] << 16) | 
           (data[offset + 2] << 8) | (data[offset + 3]);
  }
}

function parsePacket(data) {
  if (data.length < ETHERNET_HEADER_LEN) return null;
  
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
  const ihl = (versionIhl & 0x0f) * 4;
  
  if (data.length < ihl) return null;
  
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
  }
  
  return { src: srcIp, dst: dstIp, protocol: proto, srcPort, dstPort };
}

function parseIPv6(data) {
  if (data.length < 40) return null;
  
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
  }
  
  return { src: srcIp, dst: dstIp, protocol: proto, srcPort, dstPort };
}

function formatIPv6(bytes) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  }
  return parts.join(':');
}

function parsePcapNg(data) {
  const connections = [];
  let offset = 0;
  
  const byteOrderMagic = readUInt32(data, 8);
  const littleEndian = byteOrderMagic === 0x1a2b3c4d;
  
  console.log(`Byte order: ${littleEndian ? 'Little Endian' : 'Big Endian'}`);
  
  while (offset < data.length) {
    const blockType = readUInt32(data, offset, littleEndian);
    const blockLen = readUInt32(data, offset + 4, littleEndian);
    
    if (blockLen === 0 || offset + blockLen > data.length) break;
    
    if (blockType === 0x00000006) {
      const capturedLen = readUInt32(data, offset + 20, littleEndian);
      const packetData = data.slice(offset + 28, offset + 28 + capturedLen);
      const conn = parsePacket(packetData);
      if (conn) connections.push(conn);
    } else if (blockType === 0x00000003) {
      const packetLen = readUInt32(data, offset + 8, littleEndian);
      const packetData = data.slice(offset + 12, offset + 12 + packetLen);
      const conn = parsePacket(packetData);
      if (conn) connections.push(conn);
    }
    
    offset += blockLen;
    while (offset % 4 !== 0) offset++;
  }
  
  return connections;
}

function isPublicIp(ip) {
  if (!ip || ip === '0.0.0.0' || ip === '255.255.255.255') return false;
  if (ip.includes(':')) return true; // IPv6 - treat as public for simplicity
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  if (parts[0] === 10) return false;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
  if (parts[0] === 192 && parts[1] === 168) return false;
  if (parts[0] === 127) return false;
  if (parts[0] === 169 && parts[1] === 254) return false;
  if (parts[0] >= 224) return false;
  return true;
}

// Run test
async function runTest() {
  console.log('=== PCAP ANALYZER TEST ===\n');
  
  const filePath = path.join(__dirname, 'captures', 'Wifi.pcapng');
  
  if (!fs.existsSync(filePath)) {
    console.error('ERROR: File not found:', filePath);
    process.exit(1);
  }
  
  console.log('Loading file:', filePath);
  const buffer = fs.readFileSync(filePath);
  const data = new Uint8Array(buffer);
  console.log('File size:', (data.length / 1024 / 1024).toFixed(2), 'MB\n');
  
  console.log('Parsing PCAPNG file...');
  const connections = parsePcapNg(data);
  
  console.log('\n=== RESULTS ===');
  console.log('Total connections found:', connections.length);
  
  // Get unique IPs
  const uniqueIps = [...new Set(connections.flatMap(c => [c.src, c.dst]))];
  const publicIps = uniqueIps.filter(isPublicIp);
  const localIps = uniqueIps.filter(ip => !isPublicIp(ip));
  
  console.log('Unique IPs:', uniqueIps.length);
  console.log('  - Public IPs:', publicIps.length);
  console.log('  - Local IPs:', localIps.length);
  
  // Protocol distribution
  const protocols = {};
  connections.forEach(c => {
    protocols[c.protocol] = (protocols[c.protocol] || 0) + 1;
  });
  console.log('\nProtocol distribution:');
  Object.entries(protocols)
    .sort((a, b) => b[1] - a[1])
    .forEach(([proto, count]) => {
      console.log(`  ${proto}: ${count}`);
    });
  
  // Top destinations
  const dstCounts = {};
  connections.forEach(c => {
    if (isPublicIp(c.dst)) {
      dstCounts[c.dst] = (dstCounts[c.dst] || 0) + 1;
    }
  });
  
  console.log('\nTop 10 public destinations:');
  Object.entries(dstCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .forEach(([ip, count], i) => {
      console.log(`  ${i + 1}. ${ip} - ${count} packets`);
    });
  
  // Port analysis
  const portCounts = {};
  connections.forEach(c => {
    if (c.dstPort) {
      portCounts[c.dstPort] = (portCounts[c.dstPort] || 0) + 1;
    }
  });
  
  console.log('\nTop 10 destination ports:');
  Object.entries(portCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .forEach(([port, count], i) => {
      const service = getServiceName(parseInt(port));
      console.log(`  ${i + 1}. Port ${port} (${service}) - ${count} packets`);
    });
  
  console.log('\n=== TEST COMPLETED SUCCESSFULLY ===');
  console.log('\nSample data ready for WHOIS lookup:');
  console.log('First 3 public IPs:', publicIps.slice(0, 3));
}

function getServiceName(port) {
  const services = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP',
    993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
  };
  return services[port] || 'Unknown';
}

runTest().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
