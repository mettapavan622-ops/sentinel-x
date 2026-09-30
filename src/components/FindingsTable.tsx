import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle2,
  FileCode,
  GitCommit,
  Sparkles,
  ExternalLink,
  ChevronRight,
  Filter,
  FileSpreadsheet,
  FileText,
} from 'lucide-react';
import { Finding, RiskLevel, FindingStatus, FindingClassification } from '../types';
import { exportFindingsToCSV } from '../utils/exportReport';

interface FindingsTableProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  selectedFindingId?: string;
  repositoryName?: string;
  onOpenReportModal?: () => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onSelectFinding,
  selectedFindingId,
  repositoryName,
  onOpenReportModal,
}) => {
  const [filterRisk, setFilterRisk] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredFindings = findings.filter((f) => {
    if (filterRisk !== 'ALL' && f.riskLevel !== filterRisk) return false;
    if (filterStatus === 'FALSE_POSITIVE' && f.classification !== 'false_positive') return false;
    if (filterStatus === 'REMEDIATED' && f.status !== 'REMEDIATED') return false;
    if (filterStatus === 'OPEN' && (f.status !== 'OPEN' || f.classification === 'false_positive')) return false;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        f.filePath.toLowerCase().includes(q) ||
        f.secretCategory.toLowerCase().includes(q) ||
        f.detectorType.toLowerCase().includes(q) ||
        f.redactedValue.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleDownloadCSV = () => {
    // Export currently filtered findings if any filter is active, otherwise all findings
    const targetFindings = filteredFindings.length > 0 ? filteredFindings : findings;
    exportFindingsToCSV(targetFindings, repositoryName || 'sentinel-x');
  };

  const getRiskBadge = (level: RiskLevel) => {
    switch (level) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-yellow-500/10 text-yellow-400 border border-yellow-500/30">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-blue-500/10 text-blue-400 border border-blue-500/30">LOW</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-slate-500/10 text-slate-400 border border-slate-500/30">INFO</span>;
    }
  };

  const getClassificationBadge = (c: FindingClassification) => {
    switch (c) {
      case 'true_positive':
        return <span className="text-[10px] font-mono text-rose-400 bg-rose-950/40 px-1.5 py-0.5 rounded border border-rose-900/40">Verified Leak</span>;
      case 'likely_positive':
        return <span className="text-[10px] font-mono text-amber-400 bg-amber-950/40 px-1.5 py-0.5 rounded border border-amber-900/40">Likely Token</span>;
      case 'false_positive':
        return <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-900/40 flex items-center gap-1"><Sparkles className="w-2.5 h-2.5" /> AI Dismissed FP</span>;
      default:
        return <span className="text-[10px] font-mono text-slate-400">Unclassified</span>;
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      {/* Header & Filter Controls */}
      <div className="p-4 border-b border-slate-800 bg-slate-900/90 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <span>Detected Intelligence Findings</span>
            <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded-full border border-cyan-800">
              {filteredFindings.length}
            </span>
          </h3>
          <p className="text-xs text-slate-400">
            Click any finding to inspect attack path, Git history, Shannon entropy, and execute remediation.
          </p>
        </div>

        {/* Filter Toolbar */}
        <div className="flex items-center gap-2 flex-wrap">
          <input
            id="input-finding-search"
            type="text"
            placeholder="Search path, key..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="px-2.5 py-1 text-xs rounded-md bg-slate-950 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-36 sm:w-44"
          />

          <select
            id="select-risk-filter"
            value={filterRisk}
            onChange={(e) => setFilterRisk(e.target.value)}
            className="px-2.5 py-1 text-xs rounded-md bg-slate-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
          </select>

          <select
            id="select-status-filter"
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="px-2.5 py-1 text-xs rounded-md bg-slate-950 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open Only</option>
            <option value="REMEDIATED">Remediated</option>
            <option value="FALSE_POSITIVE">False Positives</option>
          </select>

          {/* Export Report Actions */}
          <div className="flex items-center gap-1.5 ml-auto sm:ml-2">
            <button
              id="btn-download-csv"
              onClick={handleDownloadCSV}
              className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 hover:border-slate-600 transition-colors cursor-pointer shadow-sm"
              title="Download findings report as CSV"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
              <span>Download CSV</span>
            </button>

            {onOpenReportModal && (
              <button
                id="btn-export-pdf"
                onClick={onOpenReportModal}
                className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded-md bg-cyan-950/70 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 hover:border-cyan-700 transition-colors cursor-pointer shadow-sm"
                title="Open executive report & export as PDF"
              >
                <FileText className="w-3.5 h-3.5 text-cyan-400" />
                <span>Export PDF</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 font-mono">
              <th className="py-3 px-4 font-medium">Severity</th>
              <th className="py-3 px-4 font-medium">Type / Category</th>
              <th className="py-3 px-4 font-medium">Location</th>
              <th className="py-3 px-4 font-medium">Masked Secret</th>
              <th className="py-3 px-4 font-medium">Classification</th>
              <th className="py-3 px-4 font-medium">Status</th>
              <th className="py-3 px-4 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {filteredFindings.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center py-8 text-slate-500">
                  No findings match current filter criteria.
                </td>
              </tr>
            ) : (
              filteredFindings.map((f) => {
                const isSelected = selectedFindingId === f.id;
                const isRemediated = f.status === 'REMEDIATED';

                return (
                  <tr
                    key={f.id}
                    id={`row-finding-${f.id}`}
                    onClick={() => onSelectFinding(f)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-950/40 border-l-2 border-l-cyan-500'
                        : isRemediated
                        ? 'hover:bg-slate-800/40 opacity-70'
                        : 'hover:bg-slate-800/60'
                    }`}
                  >
                    <td className="py-3.5 px-4 whitespace-nowrap">{getRiskBadge(f.riskLevel)}</td>
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-slate-200">{f.secretCategory}</div>
                      <div className="text-[10px] text-slate-500 font-sans">{f.detectorType}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1.5 text-slate-300">
                        <FileCode className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
                        <span className="truncate max-w-[200px]">{f.filePath}:{f.lineNumber}</span>
                      </div>
                      {f.gitExposure?.isRemovedInHead && (
                        <div className="text-[10px] text-purple-400 flex items-center gap-1 mt-0.5">
                          <GitCommit className="w-3 h-3" />
                          <span>Removed in HEAD (Exposed in Git)</span>
                        </div>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800 font-mono text-[11px]">
                        {f.redactedValue}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getClassificationBadge(f.classification)}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {isRemediated ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          <CheckCircle2 className="w-3 h-3" />
                          REMEDIATED
                        </span>
                      ) : f.status === 'FALSE_POSITIVE' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                          DISMISSED FP
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] bg-rose-500/10 text-rose-400 border border-rose-500/30">
                          OPEN
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-sans text-xs"
                      >
                        <span>Triage</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
