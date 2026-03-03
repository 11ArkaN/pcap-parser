import type { CorrelationReportV1 } from '../types';

export interface CorrelationSummary {
  totalMatches: number;
  highConfidence: number;
  mediumConfidence: number;
  lowConfidence: number;
  unmatchedSessions: number;
  unmatchedEvents: number;
}

export function summarizeCorrelation(report: CorrelationReportV1): CorrelationSummary {
  const totalMatches = report.matches.length;
  const highConfidence = report.matches.filter((item) => item.confidence === 'high').length;
  const mediumConfidence = report.matches.filter((item) => item.confidence === 'medium').length;
  const lowConfidence = report.matches.filter((item) => item.confidence === 'low').length;

  return {
    totalMatches,
    highConfidence,
    mediumConfidence,
    lowConfidence,
    unmatchedSessions: report.unmatchedSessions.length,
    unmatchedEvents: report.unmatchedProcmonEvents.length
  };
}
