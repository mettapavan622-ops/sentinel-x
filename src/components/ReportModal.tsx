import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  FileSpreadsheet,
  Printer,
  X,
  AlertTriangle,
  CheckCircle2,
  Calendar,
  FolderGit2,
  ExternalLink,
  Lock,
} from 'lucide-react';
import { Finding, Repository } from '../types';
import { exportFindingsToCSV } from '../utils/exportReport';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  findings: Finding[];
  repository: Repository | null;
  securityScore: number;
}

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  findings,
  repository,
  securityScore,
}) => {
  if (!isOpen) return null;

  const repoName = repository?.name || 'sentinel-x-audit';
  const repoBranch = repository?.defaultBranch || 'main';
  const reportDate = new Date().toLocaleString();

  const criticalCount = findings.filter(
    (f) => f.riskLevel === 'CRITICAL' && f.status === 'OPEN' && f.classification !== 'false_positive'
  ).length;

  const highCount = findings.filter(
    (f) => f.riskLevel === 'HIGH' && f.status === 'OPEN' && f.classification !== 'false_positive'
  ).length;

  const mediumLowCount = findings.filter(
    (f) =>
      (f.riskLevel === 'MEDIUM' || f.riskLevel === 'LOW' || f.riskLevel === 'INFO') &&
      f.status === 'OPEN' &&
      f.classification !== 'false_positive'
  ).length;

  const remediatedCount = findings.filter((f) => f.status === 'REMEDIATED').length;
  const falsePositivesCount = findings.filter((f) => f.classification === 'false_positive').length;

  const handleDownloadCSV = () => {
    exportFindingsToCSV(findings, repoName);
  };

  const handlePrintPDF = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4 sm:p-6">
      <div className="relative w-full max-w-5xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Sticky Action Toolbar (Hidden in Print) */}
        <div className="no-print p-4 sm:px-6 bg-slate-950/90 border-b border-slate-800 flex items-center justify-between gap-4 sticky top-0 z-10">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <span className="font-bold text-sm tracking-wide text-slate-100">
              Security Audit Executive Report
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              id="btn-modal-download-csv"
              onClick={handleDownloadCSV}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
              title="Download findings as RFC-4180 CSV"
            >
              <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
              <span>Download CSV</span>
            </button>

            <button
              id="btn-modal-print-pdf"
              onClick={handlePrintPDF}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow transition-colors cursor-pointer"
              title="Print or Save as PDF"
            >
              <Printer className="w-4 h-4" />
              <span>Export PDF / Print</span>
            </button>

            <button
              id="btn-close-report-modal"
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors cursor-pointer"
              title="Close Report View"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Printable Report Document Body */}
        <div
          id="sentinel-printable-report"
          className="p-6 sm:p-8 space-y-6 overflow-y-auto flex-1 font-sans bg-slate-900 text-slate-100"
        >
          {/* Document Header */}
          <div className="border-b border-slate-800 pb-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-extrabold tracking-wider text-slate-100">
                  SENTINEL<span className="text-cyan-400">-X</span>
                </span>
                <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                  SECURITY REPORT
                </span>
              </div>
              <h1 className="text-lg font-bold text-slate-200 mt-1">
                Automated Secret Leak & Exposure Intelligence Audit
              </h1>
              <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 font-mono mt-2">
                <span className="flex items-center gap-1">
                  <FolderGit2 className="w-3.5 h-3.5 text-cyan-400" />
                  Target: <strong className="text-slate-200">{repoName}</strong> ({repoBranch})
                </span>
                <span className="flex items-center gap-1">
                  <Calendar className="w-3.5 h-3.5 text-slate-400" />
                  Generated: {reportDate}
                </span>
              </div>
            </div>

            {/* Score Highlight Box */}
            <div className="flex items-center gap-3 p-3.5 rounded-xl border border-slate-800 bg-slate-950/60">
              <div className="text-right">
                <p className="text-[10px] uppercase tracking-wider text-slate-400 font-mono">
                  Security Health Score
                </p>
                <p
                  className={`text-2xl font-black font-mono ${
                    securityScore >= 80
                      ? 'text-emerald-400'
                      : securityScore >= 60
                      ? 'text-amber-400'
                      : 'text-rose-400'
                  }`}
                >
                  {securityScore}
                  <span className="text-xs text-slate-400 font-normal"> / 100</span>
                </p>
              </div>
              <div
                className={`p-2 rounded-lg ${
                  securityScore >= 80
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                    : securityScore >= 60
                    ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                    : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                }`}
              >
                {securityScore >= 80 ? (
                  <ShieldCheck className="w-6 h-6" />
                ) : (
                  <ShieldAlert className="w-6 h-6" />
                )}
              </div>
            </div>
          </div>

          {/* KPI Summary Tiles */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
            <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] text-slate-400">Total Findings</span>
              <p className="text-xl font-bold text-slate-100 mt-1">{findings.length}</p>
              <span className="text-[10px] text-slate-500">Scanned codebase matches</span>
            </div>

            <div className="p-3.5 rounded-xl bg-rose-950/20 border border-rose-900/30">
              <span className="text-[11px] text-rose-400">Critical Exposures</span>
              <p className="text-xl font-bold text-rose-400 mt-1">{criticalCount}</p>
              <span className="text-[10px] text-rose-300/60">Immediate revocation</span>
            </div>

            <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-900/30">
              <span className="text-[11px] text-amber-400">High Risk Secrets</span>
              <p className="text-xl font-bold text-amber-400 mt-1">{highCount}</p>
              <span className="text-[10px] text-amber-300/60">Rotation required</span>
            </div>

            <div className="p-3.5 rounded-xl bg-emerald-950/20 border border-emerald-900/30">
              <span className="text-[11px] text-emerald-400">Remediated / Filtered</span>
              <p className="text-xl font-bold text-emerald-400 mt-1">
                {remediatedCount + falsePositivesCount}
              </p>
              <span className="text-[10px] text-emerald-300/60">
                {remediatedCount} fixed • {falsePositivesCount} FPs
              </span>
            </div>
          </div>

          {/* Findings Inventory Table */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-200 tracking-wide uppercase font-mono">
                Detected Secrets & Findings Inventory ({findings.length})
              </h2>
              <span className="text-xs text-slate-400 font-mono">
                Status as of {reportDate}
              </span>
            </div>

            {findings.length === 0 ? (
              <div className="p-8 text-center border border-dashed border-slate-800 rounded-xl">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                <p className="text-sm font-medium text-slate-300">
                  Zero active secret leaks detected in target repository.
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  Codebase adheres to clean environment credential separation.
                </p>
              </div>
            ) : (
              <div className="border border-slate-800 rounded-xl overflow-hidden shadow-sm">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-semibold">
                      <th className="py-2.5 px-3">Severity</th>
                      <th className="py-2.5 px-3">Category</th>
                      <th className="py-2.5 px-3">Location</th>
                      <th className="py-2.5 px-3">Masked Value</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">AI Assessment</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {findings.map((f, index) => {
                      const isRemediated = f.status === 'REMEDIATED';
                      const isFP = f.classification === 'false_positive';

                      return (
                        <tr
                          key={f.id || index}
                          className={
                            isRemediated
                              ? 'bg-emerald-950/10'
                              : isFP
                              ? 'bg-slate-950/40 text-slate-400'
                              : f.riskLevel === 'CRITICAL'
                              ? 'bg-rose-950/15'
                              : ''
                          }
                        >
                          <td className="py-2.5 px-3 whitespace-nowrap">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                f.riskLevel === 'CRITICAL'
                                  ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                                  : f.riskLevel === 'HIGH'
                                  ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                                  : f.riskLevel === 'MEDIUM'
                                  ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                                  : 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                              }`}
                            >
                              {f.riskLevel}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-slate-200">
                            {f.secretCategory}
                            <span className="block text-[10px] text-slate-500">{f.detectorType}</span>
                          </td>
                          <td className="py-2.5 px-3 text-slate-300">
                            <span className="text-slate-100 font-semibold">{f.filePath}</span>
                            <span className="text-cyan-400 block text-[10px]">Line {f.lineNumber}</span>
                          </td>
                          <td className="py-2.5 px-3 text-cyan-300 font-mono text-[11px]">
                            {f.redactedValue}
                          </td>
                          <td className="py-2.5 px-3">
                            <span
                              className={`inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded ${
                                isRemediated
                                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                  : isFP
                                  ? 'bg-slate-800 text-slate-300 border border-slate-700'
                                  : 'bg-rose-950 text-rose-300 border border-rose-800'
                              }`}
                            >
                              {f.status}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-slate-300 text-[11px] max-w-xs truncate">
                            {f.aiAnalysis?.reason || f.attackPath?.summary || 'Pending AI evaluation'}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Executive Security Guidance & Next Steps */}
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 text-xs text-slate-300 space-y-2">
            <h3 className="font-bold text-slate-100 flex items-center gap-1.5 uppercase font-mono tracking-wider">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              Recommended Remediation & Hardening Actions
            </h3>
            <ol className="list-decimal list-inside space-y-1 text-slate-400 font-mono leading-relaxed">
              <li>
                <strong className="text-slate-200">Rotate & Revoke Exposed Keys:</strong> Immediately revoke active production credentials at their respective cloud console (AWS, Stripe, GitHub).
              </li>
              <li>
                <strong className="text-slate-200">Transition to Environment Variables:</strong> Load credentials exclusively via <code className="text-cyan-300 bg-slate-900 px-1 py-0.5 rounded">process.env</code> or a secrets manager (GCP Secret Manager, AWS Secrets Manager, Vault).
              </li>
              <li>
                <strong className="text-slate-200">Cleanse Git Commit History:</strong> Overwriting credentials in HEAD leaves historical commits vulnerable. Use <code className="text-cyan-300 bg-slate-900 px-1 py-0.5 rounded">git-filter-repo</code> to purge leaked tokens permanently.
              </li>
              <li>
                <strong className="text-slate-200">Enable Pre-Commit Guard:</strong> Install the SENTINEL-X pre-commit hook (<code className="text-cyan-300 bg-slate-900 px-1 py-0.5 rounded">.git/hooks/pre-commit</code>) to stop secrets before code leaves developer workstations.
              </li>
            </ol>
          </div>

          {/* Footer Note */}
          <div className="pt-4 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-500 font-mono">
            <span>SENTINEL-X • Autonomous Secret Detection & Zero-Trust Prevention Engine</span>
            <span>Confidential Cybersecurity Audit</span>
          </div>
        </div>
      </div>
    </div>
  );
};
