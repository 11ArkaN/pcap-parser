import { describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { spawnSync } from 'child_process';
import { existsSync } from 'fs';
import { parsePcapStreamCatalog } from '../src/utils/pcapStreams';

function resolveTsharkPath(): string | null {
  const candidates = [
    process.env.TSHARK_PATH,
    'tshark',
    'C:\\Program Files\\Wireshark\\tshark.exe',
    'C:\\Program Files (x86)\\Wireshark\\tshark.exe'
  ].filter((value): value is string => Boolean(value && value.trim()));

  for (const candidate of candidates) {
    if (candidate.includes('\\') || candidate.includes('/')) {
      if (existsSync(candidate)) {
        const probe = spawnSync(candidate, ['-v'], { encoding: 'utf-8' });
        if (!probe.error && probe.status === 0) {
          return candidate;
        }
      }
      continue;
    }

    const probe = spawnSync(candidate, ['-v'], { encoding: 'utf-8' });
    if (!probe.error && probe.status === 0) {
      return candidate;
    }
  }

  return null;
}

const tsharkPath = resolveTsharkPath();
const hasTshark = Boolean(tsharkPath);
const wiresharkTest = hasTshark ? test : test.skip;

describe('PCAP streams vs Wireshark', () => {
  wiresharkTest('matches tcp.stream grouping for synthetic capture', async () => {
    const pcap = buildTwoStreamPcap();
    const dir = mkdtempSync(join(tmpdir(), 'pcap-stream-ws-'));
    const filePath = join(dir, 'streams-test.pcap');

    try {
      writeFileSync(filePath, Buffer.from(pcap));

      const ours = await parsePcapStreamCatalog(pcap);
      const ourMap = new Map<number, number>();

      for (const stream of ours.streams.filter((item) => item.protocol === 'TCP')) {
        const streamNo = Number(stream.streamId.split('-')[1]);
        const normalized = Number.isFinite(streamNo) ? streamNo - 1 : -1;
        const packets = ours.packetsByStream[stream.streamId] ?? [];
        for (const packet of packets) {
          ourMap.set(packet.packetNo, normalized);
        }
      }

      const ws = spawnSync(tsharkPath!, ['-r', filePath, '-Y', 'tcp', '-T', 'fields', '-E', 'separator=,', '-e', 'frame.number', '-e', 'tcp.stream'], {
        encoding: 'utf-8'
      });

      expect(ws.status).toBe(0);
      const wsMap = new Map<number, number>();
      const lines = (ws.stdout || '')
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);

      for (const line of lines) {
        const [frameRaw, streamRaw] = line.split(',');
        const frameNo = Number(frameRaw);
        const streamNo = Number(streamRaw);
        if (Number.isFinite(frameNo) && Number.isFinite(streamNo)) {
          wsMap.set(frameNo, streamNo);
        }
      }

      expect(wsMap.size).toBeGreaterThan(0);
      expect(ourMap.size).toBe(wsMap.size);

      for (const [frameNo, wsStream] of wsMap.entries()) {
        expect(ourMap.get(frameNo)).toBe(wsStream);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

function buildTwoStreamPcap(): Uint8Array {
  const frame1 = buildEthernetIPv4TcpFrame('192.168.1.10', '93.184.216.34', 51515, 443, 1, 0, 0x18, 'A1');
  const frame2 = buildEthernetIPv4TcpFrame('93.184.216.34', '192.168.1.10', 443, 51515, 2, 2, 0x18, 'A2');
  const frame3 = buildEthernetIPv4TcpFrame('192.168.1.10', '142.250.186.14', 51516, 443, 1, 0, 0x18, 'B1');
  const frame4 = buildEthernetIPv4TcpFrame('142.250.186.14', '192.168.1.10', 443, 51516, 2, 2, 0x18, 'B2');

  const chunks: number[] = [];
  appendPcapGlobalHeader(chunks);
  appendPcapRecord(chunks, 1, 1000, frame1);
  appendPcapRecord(chunks, 2, 1000, frame2);
  appendPcapRecord(chunks, 3, 1000, frame3);
  appendPcapRecord(chunks, 4, 1000, frame4);
  return new Uint8Array(chunks);
}

function appendPcapGlobalHeader(chunks: number[]) {
  pushBytes(chunks, [0xd4, 0xc3, 0xb2, 0xa1]);
  pushUInt16LE(chunks, 2);
  pushUInt16LE(chunks, 4);
  pushUInt32LE(chunks, 0);
  pushUInt32LE(chunks, 0);
  pushUInt32LE(chunks, 65535);
  pushUInt32LE(chunks, 1);
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
  ip[tcpOffset + 15] = 0;
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
