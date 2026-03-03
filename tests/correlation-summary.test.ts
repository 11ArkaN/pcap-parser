import { describe, expect, test } from 'bun:test';
import { summarizeCorrelation } from '../src/utils/correlationSummary';
import type { CorrelationReportV1 } from '../src/types';

function buildReport(): CorrelationReportV1 {
  return {
    schema: 'correlation_report_v1',
    version: 1,
    generatedAt: '2026-03-03T10:00:00.000Z',
    analysisId: 'analysis-1',
    pcapFilePath: 'captures/Test1.pcapng',
    procmonFiles: ['captures/mock.pml'],
    diagnostics: {
      timeOffsetUs: 120000,
      drift: 1,
      totalSessions: 4,
      totalProcmonEvents: 4,
      matchedSessions: 3,
      unmatchedSessions: 1,
      unmatchedProcmonEvents: 1,
      parserMode: 'hybrid',
      warnings: []
    },
    matches: [
      {
        sessionId: 's1',
        protocol: 'TCP',
        srcIp: '10.0.0.1',
        srcPort: 51234,
        dstIp: '35.230.86.105',
        dstPort: 443,
        firstSeenUs: 1,
        lastSeenUs: 2,
        packets: 3,
        bytes: 1200,
        eventId: 'e1',
        matchedAtUs: 3,
        pid: 100,
        tid: 200,
        processName: 'chrome.exe',
        operation: 'TCP Connect',
        result: 'SUCCESS',
        score: 94,
        confidence: 'high',
        offsetUs: 12,
        reasons: []
      },
      {
        sessionId: 's2',
        protocol: 'TCP',
        srcIp: '10.0.0.1',
        srcPort: 51235,
        dstIp: '35.230.86.105',
        dstPort: 443,
        firstSeenUs: 1,
        lastSeenUs: 2,
        packets: 3,
        bytes: 1200,
        eventId: 'e2',
        matchedAtUs: 3,
        pid: 101,
        tid: 201,
        processName: 'edge.exe',
        operation: 'TCP Send',
        result: 'SUCCESS',
        score: 78,
        confidence: 'medium',
        offsetUs: 10,
        reasons: []
      },
      {
        sessionId: 's3',
        protocol: 'UDP',
        srcIp: '10.0.0.1',
        srcPort: 53,
        dstIp: '8.8.8.8',
        dstPort: 53,
        firstSeenUs: 1,
        lastSeenUs: 2,
        packets: 1,
        bytes: 80,
        eventId: 'e3',
        matchedAtUs: 3,
        pid: 102,
        tid: 202,
        processName: 'svchost.exe',
        operation: 'UDP Send',
        result: 'SUCCESS',
        score: 54,
        confidence: 'low',
        offsetUs: 8,
        reasons: []
      }
    ],
    unmatchedSessions: [
      {
        sessionId: 's4',
        protocol: 'TCP',
        srcIp: '10.0.0.1',
        srcPort: 51444,
        dstIp: '1.1.1.1',
        dstPort: 443,
        firstSeenUs: 1,
        lastSeenUs: 2,
        packets: 1,
        bytes: 60,
        reason: 'No candidate above threshold.'
      }
    ],
    unmatchedProcmonEvents: [
      {
        eventId: 'e4',
        tsUs: 9,
        pid: 103,
        processName: 'other.exe',
        operation: 'TCP Connect',
        remoteIp: '1.1.1.1',
        remotePort: 443,
        reason: 'No session match.'
      }
    ],
    warnings: []
  };
}

describe('Correlation summary', () => {
  test('aggregates confidence buckets and unmatched counts', () => {
    const report = buildReport();
    const summary = summarizeCorrelation(report);

    expect(summary.totalMatches).toBe(3);
    expect(summary.highConfidence).toBe(1);
    expect(summary.mediumConfidence).toBe(1);
    expect(summary.lowConfidence).toBe(1);
    expect(summary.unmatchedSessions).toBe(1);
    expect(summary.unmatchedEvents).toBe(1);
  });
});
