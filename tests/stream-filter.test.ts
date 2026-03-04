import { describe, expect, test } from 'bun:test';
import type { PcapStreamSummary } from '../src/types';
import { filterStreams } from '../src/utils/streamFilter';

const streams: PcapStreamSummary[] = [
  {
    streamId: 'TCP-1',
    streamIndex: 1,
    protocol: 'TCP',
    endpointA: '10.0.0.5:51123',
    endpointB: '142.250.74.14:443',
    clientIp: '10.0.0.5',
    clientPort: 51123,
    serverIp: '142.250.74.14',
    serverPort: 443,
    packets: 120,
    bytes: 98_000,
    firstSeenUs: 1_000_000,
    lastSeenUs: 2_000_000,
    durationUs: 1_000_000
  },
  {
    streamId: 'UDP-1',
    streamIndex: 1,
    protocol: 'UDP',
    endpointA: '10.0.0.5:59000',
    endpointB: '8.8.8.8:53',
    clientIp: '10.0.0.5',
    clientPort: 59000,
    serverIp: '8.8.8.8',
    serverPort: 53,
    packets: 8,
    bytes: 1200,
    firstSeenUs: 3_000_000,
    lastSeenUs: 3_200_000,
    durationUs: 200_000
  },
  {
    streamId: 'TCP-2',
    streamIndex: 2,
    protocol: 'TCP',
    endpointA: '10.0.0.5:51124',
    endpointB: '23.216.134.114:80',
    clientIp: '10.0.0.5',
    clientPort: 51124,
    serverIp: '23.216.134.114',
    serverPort: 80,
    packets: 45,
    bytes: 12_000,
    firstSeenUs: 4_000_000,
    lastSeenUs: 5_000_000,
    durationUs: 1_000_000
  }
];

describe('stream filter', () => {
  test('filters by key:value tokens', () => {
    const result = filterStreams(streams, 'ip:142.250.74.14 port:443 proto:tcp', 'all');
    expect(result.map((item) => item.streamId)).toEqual(['TCP-1']);
  });

  test('supports numeric rules for packets and bytes', () => {
    const result = filterStreams(streams, 'packets:>10 bytes:>=10kb', 'all');
    expect(result.map((item) => item.streamId)).toEqual(['TCP-1', 'TCP-2']);
  });

  test('supports exclusion with !token', () => {
    const result = filterStreams(streams, '!udp', 'all');
    expect(result.map((item) => item.streamId)).toEqual(['TCP-1', 'TCP-2']);
  });

  test('supports implicit numeric port lookup', () => {
    const result = filterStreams(streams, '53', 'all');
    expect(result.map((item) => item.streamId)).toEqual(['UDP-1']);
  });

  test('supports service:http token', () => {
    const result = filterStreams(streams, 'service:http', 'all');
    expect(result.map((item) => item.streamId)).toEqual(['TCP-2']);
  });

  test('plain text http matches inferred service tags', () => {
    const result = filterStreams(streams, 'http', 'all');
    expect(result.map((item) => item.streamId)).toEqual(['TCP-2']);
  });
});
