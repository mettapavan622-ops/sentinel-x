import { Finding } from '../types';

/**
 * Escapes values according to RFC-4180 CSV specifications.
 */
function escapeCSVField(val: unknown): string {
  if (val === undefined || val === null) {
    return '""';
  }
  const str = String(val);
  // Double quote any internal quotes, wrap in quotes
  return `"${str.replace(/"/g, '""')}"`;
}

/**
 * Generates and triggers browser download of an RFC-4180 compliant CSV report.
 */
export function exportFindingsToCSV(findings: Finding[], repositoryName: string = 'sentinel-x'): void {
  const headers = [
    'Finding ID',
    'Risk Level',
    'Status',
    'Secret Category',
    'Detector Rule',
    'File Path',
    'Line Number',
    'Masked Secret',
    'Entropy (Bits)',
    'Confidence (%)',
    'Classification',
    'Blast Radius',
    'In Current Commit',
    'Removed In HEAD',
    'AI Assessment / Reason',
    'Recommended Action',
    'First Detected',
    'Last Updated',
  ];

  const rows = findings.map((f) => [
    escapeCSVField(f.id),
    escapeCSVField(f.riskLevel),
    escapeCSVField(f.status),
    escapeCSVField(f.secretCategory),
    escapeCSVField(f.detectorType),
    escapeCSVField(f.filePath),
    escapeCSVField(f.lineNumber),
    escapeCSVField(f.redactedValue),
    escapeCSVField(f.entropyScore?.entropy ? f.entropyScore.entropy.toFixed(2) : 'N/A'),
    escapeCSVField(Math.round((f.confidence || 0) * 100)),
    escapeCSVField(f.classification || 'unclassified'),
    escapeCSVField(f.attackPath?.estimatedBlastRadius || 'UNKNOWN'),
    escapeCSVField(f.gitExposure?.isPresentInCurrentCommit ? 'YES' : 'NO'),
    escapeCSVField(f.gitExposure?.isRemovedInHead ? 'YES' : 'NO'),
    escapeCSVField(f.aiAnalysis?.reason || 'Heuristic threat assessment pending'),
    escapeCSVField(f.aiAnalysis?.recommendedAction || 'Review credential lifecycle'),
    escapeCSVField(f.firstSeen || f.createdAt || new Date().toISOString()),
    escapeCSVField(f.lastSeen || f.updatedAt || new Date().toISOString()),
  ]);

  const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const cleanRepoName = repositoryName.replace(/[^a-zA-Z0-9-_]/g, '_');
  const filename = `sentinel-x-findings-${cleanRepoName}-${timestamp}.csv`;

  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
