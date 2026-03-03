export function summarizeCorrelation(report) {
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
