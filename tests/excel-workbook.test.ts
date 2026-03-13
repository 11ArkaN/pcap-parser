import { describe, expect, test } from 'bun:test';
import type { HostNetworkInfo } from '../src/types';
import { buildHostNetworkRows } from '../src/utils/excelWorkbook';

describe('excel workbook host sheet', () => {
  test('formats host network info into worksheet rows', () => {
    const info: HostNetworkInfo = {
      collectedAt: '2026-03-13T18:00:00.000Z',
      hostName: 'DESKTOP-TEST',
      osName: 'Windows 10 Pro 21H2',
      osPlatform: 'win32',
      osRelease: '10.0.26100',
      activeAdapter: {
        name: 'Wi-Fi',
        description: 'Intel Wireless',
        macAddress: 'AA:BB:CC:DD:EE:FF',
        ipv4: ['192.168.1.10'],
        ipv6: ['fe80::1'],
        dnsServers: ['1.1.1.1', '8.8.8.8'],
        defaultGateway: '192.168.1.1',
        gatewayMacAddress: '11:22:33:44:55:66'
      },
      adapters: [
        {
          name: 'Wi-Fi',
          description: 'Intel Wireless',
          macAddress: 'AA:BB:CC:DD:EE:FF',
          ipv4: ['192.168.1.10'],
          ipv6: ['fe80::1'],
          dnsServers: ['1.1.1.1', '8.8.8.8'],
          defaultGateway: '192.168.1.1',
          gatewayMacAddress: '11:22:33:44:55:66'
        }
      ],
      localIpv4: ['192.168.1.10'],
      localIpv6: ['fe80::1'],
      dnsServers: ['1.1.1.1', '8.8.8.8'],
      defaultGateway: '192.168.1.1',
      gatewayMacAddress: '11:22:33:44:55:66',
      publicIp: '34.159.75.126',
      natStatus: 'behind_nat'
    };

    const rows = buildHostNetworkRows(info);

    expect(rows[0]).toMatchObject({ Sekcja: 'Stanowisko', Pole: 'Czas zebrania' });
    expect(rows.find((row) => row.Pole === 'System')).toMatchObject({ Wartosc: 'Windows 10 Pro 21H2' });
    expect(rows.find((row) => row.Pole === 'Publiczny IP')).toMatchObject({ Wartosc: '34.159.75.126' });
    expect(rows.find((row) => row.Pole === 'Tryb polaczenia')).toMatchObject({ Wartosc: 'Za NAT' });
    expect(rows.find((row) => row.Pole === 'MAC bramy')).toMatchObject({ Wartosc: '11:22:33:44:55:66' });
  });
});
