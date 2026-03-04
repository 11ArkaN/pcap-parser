import { describe, expect, test } from 'bun:test';
import { parsePcapStreamCatalog, readStreamPayloadFromBuffer } from '../src/utils/pcapStreams';

function buildTestPcap(): Uint8Array {
  const packet1 = buildEthernetIPv4TcpFrame('192.168.1.10', '93.184.216.34', 51515, 443, 1, 0, 0x18, 'HELLO-ONE');
  const packet2 = buildEthernetIPv4TcpFrame('93.184.216.34', '192.168.1.10', 443, 51515, 2, 1, 0x18, 'HELLO-TWO');

  const chunks: number[] = [];
  appendPcapGlobalHeader(chunks);
  appendPcapRecord(chunks, 1, 1000, packet1);
  appendPcapRecord(chunks, 2, 2000, packet2);
  return new Uint8Array(chunks);
}

describe('PCAP streams parser', () => {
  test('groups opposite TCP directions into one stream', async () => {
    const input = buildTestPcap();
    const catalog = await parsePcapStreamCatalog(input);

    expect(catalog.totalPackets).toBe(2);
    expect(catalog.droppedPackets).toBe(0);
    expect(catalog.streams.length).toBe(1);

    const stream = catalog.streams[0];
    expect(stream.protocol).toBe('TCP');
    expect(stream.packets).toBe(2);

    const packets = catalog.packetsByStream[stream.streamId] ?? [];
    expect(packets.length).toBe(2);
    expect(packets[0].direction).toBe('A->B');
    expect(packets[1].direction).toBe('B->A');
  });

  test('reads payload bytes from packet reference', async () => {
    const input = buildTestPcap();
    const catalog = await parsePcapStreamCatalog(input);
    const stream = catalog.streams[0];
    const packet = catalog.packetsByStream[stream.streamId][0];

    const partial = readStreamPayloadFromBuffer(input, packet.payloadRef, 16);
    expect(partial.returnedLength).toBe(16);
    expect(partial.truncated).toBe(true);
    expect(partial.hex.length).toBeGreaterThan(0);

    const full = readStreamPayloadFromBuffer(input, packet.payloadRef, packet.payloadRef.capturedLength);
    expect(full.returnedLength).toBe(packet.payloadRef.capturedLength);
    expect(full.truncated).toBe(false);
  });
});

function appendPcapGlobalHeader(chunks: number[]) {
  pushBytes(chunks, [0xd4, 0xc3, 0xb2, 0xa1]); // little-endian magic
  pushUInt16LE(chunks, 2);
  pushUInt16LE(chunks, 4);
  pushUInt32LE(chunks, 0);
  pushUInt32LE(chunks, 0);
  pushUInt32LE(chunks, 65535);
  pushUInt32LE(chunks, 1); // Ethernet
}

function appendPcapRecord(chunks: number[], tsSec: number, tsUsec: number, frame: Uint8Array) {
  pushUInt32LE(chunks, tsSec);
  pushUInt32LE(chunks, tsUsec);
  pushUInt32LE(chunks, frame.length);
  pushUInt32LE(chunks, frame.length);
  pushBytes(chunks, frame);
}

function buildEthernetIPv4TcpFrame(
  srcIp: string,
  dstIp: string,
  srcPort: number,
  dstPort: number,
  seq: number,
  ack: number,
  flags: number,
  payloadText: string
): Uint8Array {
  const payload = new TextEncoder().encode(payloadText);
  const ipHeaderLen = 20;
  const tcpHeaderLen = 20;
  const totalIpLen = ipHeaderLen + tcpHeaderLen + payload.length;

  const ip = new Uint8Array(totalIpLen);
  ip[0] = 0x45;
  ip[1] = 0;
  ip[2] = (totalIpLen >> 8) & 0xff;
  ip[3] = totalIpLen & 0xff;
  ip[4] = 0;
  ip[5] = 1;
  ip[6] = 0;
  ip[7] = 0;
  ip[8] = 64;
  ip[9] = 6;
  ip[10] = 0;
  ip[11] = 0;
  const src = srcIp.split('.').map((part) => Number(part));
  const dst = dstIp.split('.').map((part) => Number(part));
  ip.set(src, 12);
  ip.set(dst, 16);

  const tcpOffset = ipHeaderLen;
  ip[tcpOffset] = (srcPort >> 8) & 0xff;
  ip[tcpOffset + 1] = srcPort & 0xff;
  ip[tcpOffset + 2] = (dstPort >> 8) & 0xff;
  ip[tcpOffset + 3] = dstPort & 0xff;
  writeUInt32BE(ip, tcpOffset + 4, seq);
  writeUInt32BE(ip, tcpOffset + 8, ack);
  ip[tcpOffset + 12] = 0x50;
  ip[tcpOffset + 13] = flags & 0xff;
  ip[tcpOffset + 14] = 0x20;
  ip[tcpOffset + 15] = 0x00;
  ip[tcpOffset + 16] = 0;
  ip[tcpOffset + 17] = 0;
  ip[tcpOffset + 18] = 0;
  ip[tcpOffset + 19] = 0;
  ip.set(payload, tcpOffset + tcpHeaderLen);

  const frame = new Uint8Array(14 + ip.length);
  frame.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 0);
  frame.set([0x10, 0x11, 0x12, 0x13, 0x14, 0x15], 6);
  frame[12] = 0x08;
  frame[13] = 0x00;
  frame.set(ip, 14);
  return frame;
}

function pushBytes(chunks: number[], bytes: ArrayLike<number>) {
  for (let i = 0; i < bytes.length; i += 1) {
    chunks.push(bytes[i] & 0xff);
  }
}

function pushUInt16LE(chunks: number[], value: number) {
  chunks.push(value & 0xff, (value >> 8) & 0xff);
}

function pushUInt32LE(chunks: number[], value: number) {
  chunks.push(value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff);
}

function writeUInt32BE(target: Uint8Array, offset: number, value: number) {
  target[offset] = (value >> 24) & 0xff;
  target[offset + 1] = (value >> 16) & 0xff;
  target[offset + 2] = (value >> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}
