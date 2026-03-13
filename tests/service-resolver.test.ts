import { describe, expect, test } from 'bun:test';
import { aggregateConnections, aggregateConnectionsByIp, prepareExportData } from '../src/components/DataTable';
import type { ParsedConnection } from '../src/types';
import { formatResolvedServiceName, resolveConnectionServices } from '../src/utils/serviceResolver';

function buildConnection(partial: Partial<ParsedConnection>): ParsedConnection {
  return {
    src: '10.0.0.5',
    dst: '93.184.216.34',
    protocol: 'TCP',
    srcPort: null,
    dstPort: null,
    packetCount: 1,
    ...partial
  };
}

describe('service resolver', () => {
  test('recognizes HTTPS on destination port with high confidence', () => {
    const result = resolveConnectionServices(buildConnection({ srcPort: 12345, dstPort: 443, protocol: 'TCP' }));

    expect(result.primaryCandidate?.displayName).toBe('HTTPS');
    expect(result.primaryCandidate?.port).toBe(443);
    expect(result.confidence).toBe('high');
  });

  test('recognizes HTTPS when service is on source port', () => {
    const result = resolveConnectionServices(buildConnection({ srcPort: 443, dstPort: 12345, protocol: 'TCP' }));

    expect(result.primaryCandidate?.displayName).toBe('HTTPS');
    expect(result.primaryCandidate?.port).toBe(443);
    expect(result.confidence).toBe('high');
  });

  test('recognizes DNS in both UDP directions', () => {
    const request = resolveConnectionServices(buildConnection({ protocol: 'UDP', srcPort: 53000, dstPort: 53 }));
    const response = resolveConnectionServices(buildConnection({ protocol: 'UDP', srcPort: 53, dstPort: 53000 }));

    expect(request.primaryCandidate?.displayName).toBe('DNS');
    expect(request.primaryCandidate?.port).toBe(53);
    expect(response.primaryCandidate?.displayName).toBe('DNS');
    expect(response.primaryCandidate?.port).toBe(53);
  });

  test('recognizes HTTP alternate on registered ports', () => {
    const result = resolveConnectionServices(buildConnection({ protocol: 'TCP', srcPort: 52000, dstPort: 8080 }));

    expect(result.primaryCandidate?.displayName).toBe('HTTP Alternate');
    expect(result.primaryCandidate?.port).toBe(8080);
  });

  test('returns ambiguous result for two known non-ephemeral ports', () => {
    const result = resolveConnectionServices(buildConnection({ protocol: 'TCP', srcPort: 443, dstPort: 8443 }));

    expect(result.primaryCandidate).toBeNull();
    expect(result.confidence).toBe('low');
    expect(result.candidates.map((candidate) => candidate.port)).toEqual([443, 8443]);
    expect(formatResolvedServiceName(result)).toContain('HTTPS');
    expect(formatResolvedServiceName(result)).toContain('8443');
  });

  test('does not invent service names for unknown ports', () => {
    const result = resolveConnectionServices(buildConnection({ protocol: 'TCP', srcPort: 40000, dstPort: 40001 }));

    expect(result.primaryCandidate).toBeNull();
    expect(result.candidates).toEqual([]);
    expect(formatResolvedServiceName(result)).toBe('Niezidentyfikowana');
  });

  test('uses all ports as fallback label when service is unknown', () => {
    const rows = aggregateConnections([buildConnection({ protocol: 'TCP', srcPort: 40000, dstPort: 40001 })]);

    expect(rows).toHaveLength(1);
    expect(rows[0].services).toBe('40000, 40001');
    expect(rows[0].servicePorts).toBe('40000, 40001');
  });

  test('aggregate and export reuse the same resolved service metadata', () => {
    const rows = aggregateConnections([
      buildConnection({ protocol: 'TCP', srcPort: 12345, dstPort: 443 }),
      buildConnection({ protocol: 'TCP', srcPort: 12346, dstPort: 443 })
    ]);

    expect(rows).toHaveLength(1);
    expect(rows[0].services).toBe('HTTPS');
    expect(rows[0].servicePorts).toBe('443');
    expect(rows[0].serviceConfidence).toBe('high');

    const exportRow = prepareExportData(rows, {}, true)[0];
    expect(exportRow).toMatchObject({
      Usluga: 'HTTPS',
      'Port uslugi': '443',
      Pewnosc: 'high'
    });
    expect(exportRow.RFC).toContain('RFC 2818');
  });

  test('unique IP aggregation creates separate rows for each observed port', () => {
    const rows = aggregateConnectionsByIp(
      [
        buildConnection({ src: '10.0.0.5', dst: '93.184.216.34', protocol: 'TCP', srcPort: 50000, dstPort: 443 }),
        buildConnection({ src: '10.0.0.5', dst: '93.184.216.34', protocol: 'TCP', srcPort: 50001, dstPort: 443 }),
        buildConnection({ src: '10.0.0.5', dst: '1.1.1.1', protocol: 'UDP', srcPort: 53000, dstPort: 53 })
      ],
      true
    );

    expect(rows).toHaveLength(6);
    const httpsRows = rows.filter((row) => row.ip === '93.184.216.34' && row.servicePorts === '443');
    expect(httpsRows).toHaveLength(2);
    expect(httpsRows.every((row) => row.services === 'HTTPS')).toBe(true);
    expect(httpsRows.every((row) => row.packetCount === 1)).toBe(true);
    expect(rows.find((row) => row.ip === '93.184.216.34' && row.servicePorts === '50000')).toMatchObject({
      services: '50000',
      protocol: 'TCP',
      packetCount: 1
    });
    expect(rows.find((row) => row.ip === '93.184.216.34' && row.servicePorts === '50001')).toMatchObject({
      services: '50001',
      protocol: 'TCP',
      packetCount: 1
    });
    expect(rows.find((row) => row.ip === '1.1.1.1' && row.servicePorts === '53')).toMatchObject({
      peerCount: 1,
      services: 'DNS',
      protocol: 'UDP',
      packetCount: 1
    });
  });

  test('unique IP export follows the selected aggregation mode', () => {
    const rows = aggregateConnectionsByIp(
      [buildConnection({ src: '10.0.0.5', dst: '93.184.216.34', protocol: 'TCP', srcPort: 50000, dstPort: 443 })],
      true
    );

    const exportRow = prepareExportData(rows, {}, true, 'uniqueIps').find((row) => row['Port uslugi'] === '443');
    expect(exportRow).toBeDefined();
    expect(exportRow).toMatchObject({
      'Adres IP': '93.184.216.34',
      Usluga: 'HTTPS',
      'Port uslugi': '443',
      'Komunikuje sie z': '10.0.0.5',
      'Liczba peerow': 1
    });
  });

  test('unique IP aggregation keeps separate rows for the same public IP and port when peers differ', () => {
    const rows = aggregateConnectionsByIp(
      [
        buildConnection({ src: '10.0.0.5', dst: '93.184.216.34', protocol: 'TCP', srcPort: 50000, dstPort: 443 }),
        buildConnection({ src: '10.0.0.6', dst: '93.184.216.34', protocol: 'TCP', srcPort: 50000, dstPort: 443 })
      ],
      true
    ).filter((row) => row.ip === '93.184.216.34' && row.servicePorts === '443');

    expect(rows).toHaveLength(2);
    expect(rows.map((row) => row.peers).sort()).toEqual(['10.0.0.5', '10.0.0.6']);
  });

  test('unique IP aggregation keeps separate rows for the same public IP and port when the peer is the same but the relation ports differ', () => {
    const rows = aggregateConnectionsByIp(
      [
        buildConnection({ src: '10.0.0.5', dst: '34.159.75.126', protocol: 'TCP', srcPort: 7500, dstPort: 53232 }),
        buildConnection({ src: '10.0.0.5', dst: '34.159.75.126', protocol: 'TCP', srcPort: 7500, dstPort: 53182 }),
        buildConnection({ src: '10.0.0.5', dst: '34.159.75.126', protocol: 'TCP', srcPort: 7500, dstPort: 53281 })
      ],
      true
    ).filter((row) => row.ip === '34.159.75.126');

    expect(rows).toHaveLength(6);
    expect(rows.filter((row) => row.servicePorts === '7500')).toHaveLength(3);
    expect(rows.filter((row) => row.servicePorts === '53232')).toHaveLength(1);
    expect(rows.filter((row) => row.servicePorts === '53182')).toHaveLength(1);
    expect(rows.filter((row) => row.servicePorts === '53281')).toHaveLength(1);
  });
});
