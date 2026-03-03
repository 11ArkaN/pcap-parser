import { describe, expect, test } from 'bun:test';
import { existsSync, readFileSync } from 'fs';
import { aggregateConnections, prepareExportData } from '../src/components/DataTable';
import { parsePcap, parsePcapDetailed } from '../src/utils/pcapParser';
import type { IpLookupData } from '../src/types';

async function loadTableRows(filePath: string) {
  const parsed = await parsePcap(new Uint8Array(readFileSync(filePath)));
  const rows = aggregateConnections(parsed);
  return { parsed, rows };
}

const WIFI_CAPTURE = 'captures/Wifi.pcapng';
const TEST1_CAPTURE = 'captures/Test1.pcapng';
const hasWifiCapture = existsSync(WIFI_CAPTURE);
const hasTest1Capture = existsSync(TEST1_CAPTURE);
const captureTest = (enabled: boolean) => (enabled ? test : test.skip);

describe('Capture regression - table data', () => {
  captureTest(hasWifiCapture)('Wifi.pcapng table aggregation remains stable', async () => {
    const { parsed, rows } = await loadTableRows(WIFI_CAPTURE);

    expect(parsed.length).toBe(16367);
    expect(rows.length).toBe(127);
    expect(rows.reduce((sum, row) => sum + row.packetCount, 0)).toBe(16367);
    expect(rows.reduce((sum, row) => sum + row.bytes, 0)).toBe(13840925);

    const topByPackets = [...rows].sort((a, b) => b.packetCount - a.packetCount);
    expect(topByPackets[0]).toMatchObject({
      src: '51.124.78.146',
      dst: '192.168.1.159',
      packetCount: 3483,
      protocol: 'TCP'
    });

    expect(topByPackets[1]).toMatchObject({
      src: '213.216.115.19',
      dst: '192.168.1.159',
      packetCount: 2072,
      protocol: 'TCP'
    });

    const exportRows = prepareExportData(rows, {}, true);
    expect(exportRows[0]).toMatchObject({
      'Adres IP': '192.168.100.1',
      Port: 1900,
      Protokol: 'UDP',
      Pakiety: 101,
      Bajty: 29112
    });
  });

  captureTest(hasTest1Capture)('Test1.pcapng table aggregation remains stable', async () => {
    const { parsed, rows } = await loadTableRows(TEST1_CAPTURE);

    expect(parsed.length).toBe(5166);
    expect(rows.length).toBe(85);
    expect(rows.reduce((sum, row) => sum + row.packetCount, 0)).toBe(5166);
    expect(rows.reduce((sum, row) => sum + row.bytes, 0)).toBe(797099);

    const topByPackets = [...rows].sort((a, b) => b.packetCount - a.packetCount);
    expect(topByPackets[0]).toMatchObject({
      src: '---',
      dst: '---',
      packetCount: 972,
      protocol: '0x88E1'
    });

    expect(topByPackets[1]).toMatchObject({
      src: '35.230.86.105',
      dst: '192.168.1.18',
      packetCount: 360,
      protocol: 'TCP'
    });

    const exportRows = prepareExportData(rows, {}, true);
    expect(exportRows[0]).toMatchObject({
      'Adres IP': '---',
      Protokol: '0x88E1',
      Pakiety: 972,
      Bajty: 54846
    });
  });

  captureTest(hasTest1Capture)('Export row uses IP metadata for table-visible columns', async () => {
    const { rows } = await loadTableRows(TEST1_CAPTURE);
    const googleRow = rows.find((row) => row.src === '192.168.1.18' && row.dst === '35.230.86.105');

    expect(googleRow).toBeDefined();

    const ipData: Record<string, IpLookupData> = {
      '35.230.86.105': {
        ip: '35.230.86.105',
        asn: 'AS396982',
        isp: 'Google',
        org: 'Google LLC',
        country: 'US',
        city: 'Mountain View',
        cidr: '35.208.0.0/12, 35.224.0.0/12, 35.240.0.0/13'
      }
    };

    const exportRow = prepareExportData([googleRow!], ipData, true)[0];
    expect(exportRow).toMatchObject({
      'Adres IP': '35.230.86.105',
      ASN: 'AS396982',
      'ISP/Organizacja': 'Google',
      Kraj: 'US',
      Miasto: 'Mountain View',
      'Blok CIDR': '35.208.0.0/12, 35.224.0.0/12, 35.240.0.0/13'
    });
  });

  captureTest(hasWifiCapture)('Parser reports truncation when maxConnections is reached', async () => {
    const input = new Uint8Array(readFileSync(WIFI_CAPTURE));
    const result = await parsePcapDetailed(input, { maxConnections: 500 });

    expect(result.connections.length).toBe(500);
    expect(result.truncated).toBe(true);
  });
});
