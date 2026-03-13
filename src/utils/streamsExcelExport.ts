import * as XLSX from 'xlsx';
import type { PcapStreamSummary, StreamPacketMeta } from '../types';
import { appendHostNetworkSheet, createWorkbookWithMetadata } from './excelWorkbook';

interface StreamsExcelExportPayload {
  fileName: string;
  generatedAt: Date;
  searchQuery: string;
  protocolFilter: string;
  totalPackets: number;
  droppedPackets: number;
  filteredStreams: PcapStreamSummary[];
  packetsByStream: Record<string, StreamPacketMeta[]>;
  selectedStreamId: string | null;
}

const MAX_PACKET_ROWS_IN_EXPORT = 200_000;
const MAX_ALL_PACKET_ROWS_IN_EXPORT = 500_000;

export async function exportStreamsToExcel(payload: StreamsExcelExportPayload): Promise<void> {
  const workbook = createWorkbookWithMetadata();
  await appendHostNetworkSheet(workbook);
  const selectedStream = payload.selectedStreamId
    ? payload.filteredStreams.find((stream) => stream.streamId === payload.selectedStreamId) ?? null
    : null;
  const selectedPackets = selectedStream ? payload.packetsByStream[selectedStream.streamId] ?? [] : [];
  const exportPackets = selectedPackets.slice(0, MAX_PACKET_ROWS_IN_EXPORT);
  const allFilteredPackets = flattenPackets(payload.filteredStreams, payload.packetsByStream);
  const exportAllPackets = allFilteredPackets.slice(0, MAX_ALL_PACKET_ROWS_IN_EXPORT);

  const summaryRows = [
    { Pole: 'Plik', Wartosc: payload.fileName },
    { Pole: 'Data eksportu', Wartosc: payload.generatedAt.toLocaleString('pl-PL', { hour12: false }) },
    { Pole: 'Filtr tekstowy', Wartosc: payload.searchQuery.trim() || '(brak)' },
    { Pole: 'Filtr protokolu', Wartosc: payload.protocolFilter === 'all' ? 'Wszystkie protokoly' : payload.protocolFilter },
    { Pole: 'Liczba streamow', Wartosc: payload.filteredStreams.length.toLocaleString() },
    { Pole: 'Pakiety w pliku', Wartosc: payload.totalPackets.toLocaleString() },
    { Pole: 'Pakiety (wszystkie streamy po filtrach)', Wartosc: allFilteredPackets.length.toLocaleString() },
    { Pole: 'Pominiete pakiety', Wartosc: payload.droppedPackets.toLocaleString() },
    {
      Pole: 'Uwagi (wybrany stream)',
      Wartosc:
        selectedPackets.length > exportPackets.length
          ? `Pakiety wybranego streamu przyciete do ${MAX_PACKET_ROWS_IN_EXPORT.toLocaleString()} wierszy.`
          : '-'
    },
    {
      Pole: 'Uwagi (wszystkie streamy)',
      Wartosc:
        allFilteredPackets.length > exportAllPackets.length
          ? `Pakiety wszystkich streamow przyciete do ${MAX_ALL_PACKET_ROWS_IN_EXPORT.toLocaleString()} wierszy.`
          : '-'
    }
  ];

  appendSheet(workbook, 'Podsumowanie', summaryRows);

  const streamRows = payload.filteredStreams.map((stream) => ({
    'ID Streamu': stream.streamId,
    Protokol: stream.protocol,
    'Endpoint A': endpointValue(stream.clientIp, stream.clientPort),
    'Endpoint B': endpointValue(stream.serverIp, stream.serverPort),
    Pakiety: stream.packets,
    Bajty: stream.bytes,
    'Czas Start': formatTimestampUs(stream.firstSeenUs),
    'Czas Koniec': formatTimestampUs(stream.lastSeenUs),
    'Czas Trwania': formatDurationUs(stream.durationUs)
  }));
  appendSheet(workbook, 'Streamy', streamRows);

  const selectedStreamRows = selectedStream
    ? [
      {
        'ID Streamu': selectedStream.streamId,
        Protokol: selectedStream.protocol,
        'Endpoint A': endpointValue(selectedStream.clientIp, selectedStream.clientPort),
        'Endpoint B': endpointValue(selectedStream.serverIp, selectedStream.serverPort),
        Pakiety: selectedStream.packets,
        Bajty: selectedStream.bytes,
        'Czas Start': formatTimestampUs(selectedStream.firstSeenUs),
        'Czas Koniec': formatTimestampUs(selectedStream.lastSeenUs),
        'Czas Trwania': formatDurationUs(selectedStream.durationUs)
      }
    ]
    : [{ Info: 'Brak wybranego streamu w momencie eksportu.' }];
  appendSheet(workbook, 'Wybrany Stream', selectedStreamRows);

  const packetRows = exportPackets.map((packet) => toPacketRow(packet));
  appendSheet(workbook, 'Pakiety Wybranego', packetRows);

  const allPacketRows = exportAllPackets.map((packet) => toPacketRow(packet));
  appendSheet(workbook, 'Pakiety Wszystkich', allPacketRows);

  const timestamp = payload.generatedAt.toISOString().replace(/[:.]/g, '-');
  XLSX.writeFile(workbook, `streamy-${timestamp}.xlsx`);
}

function appendSheet(workbook: XLSX.WorkBook, sheetName: string, rows: Array<Record<string, string | number>>): void {
  const safeRows = rows.length ? rows : [{ Info: '(brak danych)' }];
  const worksheet = XLSX.utils.json_to_sheet(safeRows);
  worksheet['!cols'] = buildExcelColumnWidths(safeRows);
  worksheet['!autofilter'] = {
    ref: buildAutoFilterRef(safeRows)
  };
  XLSX.utils.book_append_sheet(workbook, worksheet, sheetName);
}

function buildAutoFilterRef(rows: Array<Record<string, string | number>>): string {
  const width = Math.max(1, Object.keys(rows[0] || {}).length);
  const height = Math.max(1, rows.length + 1);
  const lastColName = toExcelColumnName(width);
  return `A1:${lastColName}${height}`;
}

function toExcelColumnName(index: number): string {
  let n = index;
  let out = '';
  while (n > 0) {
    const rem = (n - 1) % 26;
    out = String.fromCharCode(65 + rem) + out;
    n = Math.floor((n - 1) / 26);
  }
  return out || 'A';
}

function buildExcelColumnWidths(rows: Array<Record<string, string | number>>) {
  const minWidth = 10;
  const maxWidth = 70;
  if (!rows.length) return [];

  const headers = Object.keys(rows[0]) as Array<keyof (typeof rows)[number]>;
  return headers.map((header) => {
    let longest = String(header).length;
    for (const row of rows) {
      const width = String(row[header] ?? '').length;
      if (width > longest) longest = width;
    }
    return { wch: Math.max(minWidth, Math.min(maxWidth, longest + 2)) };
  });
}

function endpointValue(ip: string, port: number | null): string {
  return `${ip}:${port ?? '-'}`;
}

function formatDurationUs(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return '-';
  if (value < 1_000) return `${value} us`;
  if (value < 1_000_000) return `${(value / 1_000).toFixed(2)} ms`;
  return `${(value / 1_000_000).toFixed(2)} s`;
}

function formatTimestampUs(value: number | null): string {
  if (value === null || !Number.isFinite(value) || value <= 0) return '-';
  const ms = Math.floor(value / 1000);
  if (ms > 946684800000 && ms < 4102444800000) {
    return new Date(ms).toLocaleString('pl-PL', {
      hour12: false,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  }
  return `${value} us`;
}

function flattenPackets(
  streams: PcapStreamSummary[],
  packetsByStream: Record<string, StreamPacketMeta[]>
): StreamPacketMeta[] {
  const out: StreamPacketMeta[] = [];
  for (const stream of streams) {
    const packets = packetsByStream[stream.streamId] ?? [];
    for (const packet of packets) {
      out.push(packet);
    }
  }
  out.sort((a, b) => {
    const aTs = a.timestampUs ?? Number.MAX_SAFE_INTEGER;
    const bTs = b.timestampUs ?? Number.MAX_SAFE_INTEGER;
    if (aTs !== bTs) return aTs - bTs;
    return a.packetNo - b.packetNo;
  });
  return out;
}

function toPacketRow(packet: StreamPacketMeta): Record<string, string | number> {
  return {
    'ID Streamu': packet.streamId,
    'Nr Pakietu': packet.packetNo,
    Czas: formatTimestampUs(packet.timestampUs),
    Kierunek: packet.direction,
    'IP Zrodlowe': packet.srcIp,
    'Port Zrodlowy': packet.srcPort ?? '-',
    'IP Docelowe': packet.dstIp,
    'Port Docelowy': packet.dstPort ?? '-',
    Protokol: packet.protocol,
    'Rozmiar [B]': packet.originalLength,
    'Payload [B]': packet.payloadLength,
    'TCP Flags': packet.tcp?.flags || '-',
    'TCP Seq': packet.tcp?.seq ?? '-',
    'TCP Ack': packet.tcp?.ack ?? '-',
    VLAN: packet.vlan ?? '-'
  };
}
