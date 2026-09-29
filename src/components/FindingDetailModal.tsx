import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  AlertTriangle,
  Flame,
  Key,
  FileCode,
  GitCommit,
  Sparkles,
  RotateCw,
  CheckCircle2,
  Copy,
  Check,
  Terminal,
  ArrowRight,
  ExternalLink,
} from 'lucide-react';
import { Finding, RiskLevel } from '../types';
import { AttackPathViewer } from './AttackPathViewer';

interface FindingDetailModalProps {
  finding: Finding | null;
  onClose: () => void;
  onRemediate: (findingId: string, actionType: string) => Promise<void>;
  isRemediating: boolean;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onRemediate,
  isRemediating,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'attack-path' | 'remediation'>('overview');
  const [copiedDiff, setCopiedDiff] = useState(false);
  const [copiedScript, setCopiedScript] = useState(false);
  const [remediationLogs, setRemediationLogs] = useState<string[]>([]);

  if (!finding) return null;

  const isRemediated = finding.status === 'REMEDIATED';
  const isFalsePositive = finding.classification === 'false_positive';

  const handleAction = async (actionType: string) => {
    setRemediationLogs((prev) => [...prev, `Executing ${actionType}...`]);
    await onRemediate(finding.id, actionType);
    setRemediationLogs((prev) => [...prev, `✔ ${actionType} completed successfully.`]);
  };

  const codeDiff = `--- a/${finding.filePath}
+++ b/${finding.filePath}
@@ -${Math.max(1, finding.lineNumber - 1)},3 +${Math.max(1, finding.lineNumber - 1)},3 @@
- // Hardcoded secret
-${finding.contextSnippet.split('\n')[0] || ''}
+ // Refactored by SENTINEL-X Auto-Remediation
+ const SECRET_KEY = process.env.${finding.secretCategory === 'AWS_CREDENTIAL' ? 'AWS_SECRET_ACCESS_KEY' : 'API_KEY'};`;

  const cleanupScript = `# Run in repository root to scrub secret from Git history:
pip install git-filter-repo
git filter-repo --replace-text <(echo '${finding.redactedValue}==>REDACTED') --force
git push origin --force --all`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 bg-slate-950/80 flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-lg border ${
                finding.riskLevel === 'CRITICAL'
                  ? 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                  : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
              }`}
            >
              <Key className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base text-slate-100">{finding.secretCategory}</span>
                <span
                  className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                    finding.riskLevel === 'CRITICAL'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                      : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                  }`}
                >
                  {finding.riskLevel}
                </span>
                {isRemediated && (
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" />
                    REMEDIATED
                  </span>
                )}
              </div>
              <p className="text-xs font-mono text-slate-400 mt-0.5">
                {finding.filePath}:{finding.lineNumber} • Redacted: {finding.redactedValue}
              </p>
            </div>
          </div>

          <button
            id="btn-close-modal"
            onClick={onClose}
            className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Navigation Tabs */}
        <div className="flex items-center border-b border-slate-800 bg-slate-950/40 px-5 pt-2 text-xs font-medium space-x-4">
          <button
            onClick={() => setActiveTab('overview')}
            className={`pb-2.5 transition-colors border-b-2 ${
              activeTab === 'overview'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Finding Intelligence
          </button>
          <button
            onClick={() => setActiveTab('attack-path')}
            className={`pb-2.5 transition-colors border-b-2 ${
              activeTab === 'attack-path'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Attack Path & Threat Model
          </button>
          <button
            onClick={() => setActiveTab('remediation')}
            className={`pb-2.5 transition-colors border-b-2 ${
              activeTab === 'remediation'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Remediation Workbench
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {activeTab === 'overview' && (
            <>
              {/* AI Context & False-Positive Analysis Banner */}
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5" />
                    AI False-Positive & Risk Evaluation
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">
                    Confidence: {Math.round(finding.confidence * 100)}%
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {finding.aiAnalysis?.reason ||
                    `Context analysis indicates this token is assigned to an active operational configuration in ${finding.filePath}. Shannon entropy (${finding.entropyScore.entropy} bits/char) confirms cryptographic randomness.`}
                </p>
                {finding.aiAnalysis?.recommendedAction && (
                  <div className="mt-3 text-xs font-mono text-cyan-300 bg-cyan-950/40 p-2 rounded border border-cyan-900/40">
                    Recommended Action: {finding.aiAnalysis.recommendedAction}
                  </div>
                )}
              </div>

              {/* Code Context Snippet */}
              <div>
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
                  <span className="flex items-center gap-1.5">
                    <FileCode className="w-3.5 h-3.5 text-slate-500" />
                    Code Context Snippet:
                  </span>
                  <span>Line {finding.lineNumber}</span>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-300 overflow-x-auto">
                  <pre className="text-slate-200">{finding.contextSnippet}</pre>
                </div>
              </div>

              {/* Technical Metrics: Entropy & Git Exposure */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                <div className="bg-slate-950/50 border border-slate-800 rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase mb-1">Shannon Entropy</div>
                  <div className="text-base font-bold text-slate-200">
                    {finding.entropyScore.entropy} bits/char
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Normalized: {finding.entropyScore.normalizedScore} • Charset: {finding.entropyScore.characterSetSize}
                  </div>
                  <div className="mt-2 text-[10px] text-emerald-400">
                    {finding.entropyScore.isHighEntropy ? '✔ High Randomness Confirmed' : 'Moderate Entropy'}
                  </div>
                </div>

                <div className="bg-slate-950/50 border border-slate-800 rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase mb-1">Git Exposure Status</div>
                  <div className="text-base font-bold text-purple-400">
                    {finding.gitExposure.commitCount} Historical Commits
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Introduced: {finding.gitExposure.firstSeenCommit} ({finding.gitExposure.firstSeenDate})
                  </div>
                  {finding.gitExposure.isRemovedInHead && (
                    <div className="mt-2 text-[10px] text-rose-400 font-semibold">
                      ⚠️ Deleted in HEAD, but STILL PRESENT in Git history!
                    </div>
                  )}
                </div>
              </div>
            </>
          )}

          {activeTab === 'attack-path' && (
            <div className="space-y-4">
              <AttackPathViewer attackPath={finding.attackPath} />
            </div>
          )}

          {activeTab === 'remediation' && (
            <div className="space-y-5">
              {/* Action Buttons */}
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4">
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-3">
                  Auto-Remediation Controls
                </h4>
                <div className="flex flex-wrap items-center gap-3">
                  <button
                    id="btn-simulate-revoke"
                    onClick={() => handleAction('SIMULATE_REVOKE')}
                    disabled={isRemediating || isRemediated}
                    className="px-3 py-1.5 rounded-md text-xs font-mono font-semibold bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800 transition-colors disabled:opacity-50"
                  >
                    1. Simulate Revoke
                  </button>

                  <button
                    id="btn-simulate-rotate"
                    onClick={() => handleAction('SIMULATE_ROTATE')}
                    disabled={isRemediating || isRemediated}
                    className="px-3 py-1.5 rounded-md text-xs font-mono font-semibold bg-amber-950/80 hover:bg-amber-900 text-amber-300 border border-amber-800 transition-colors disabled:opacity-50"
                  >
                    2. Simulate Rotate
                  </button>

                  <button
                    id="btn-execute-full-pipeline"
                    onClick={() => handleAction('FULL_PIPELINE')}
                    disabled={isRemediating || isRemediated}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition-all disabled:opacity-50"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>{isRemediated ? 'Remediated & Clean' : 'Execute Full Remediation Pipeline'}</span>
                  </button>
                </div>
              </div>

              {/* Code Replacement Diff */}
              <div>
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1.5">
                  <span>Source Code Safe Refactor (process.env):</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(codeDiff);
                      setCopiedDiff(true);
                      setTimeout(() => setCopiedDiff(false), 2000);
                    }}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px]"
                  >
                    {copiedDiff ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedDiff ? 'Copied Diff' : 'Copy Diff'}</span>
                  </button>
                </div>
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto">
                  {codeDiff}
                </pre>
              </div>

              {/* Git History Cleanup Script */}
              <div>
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1.5">
                  <span>Git History Purge Command (git-filter-repo):</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(cleanupScript);
                      setCopiedScript(true);
                      setTimeout(() => setCopiedScript(false), 2000);
                    }}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px]"
                  >
                    {copiedScript ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedScript ? 'Copied Script' : 'Copy Script'}</span>
                  </button>
                </div>
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto">
                  {cleanupScript}
                </pre>
              </div>

              {/* Activity Logs */}
              {remediationLogs.length > 0 && (
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs text-emerald-400">
                  <div className="text-[10px] text-slate-500 uppercase mb-1">Execution Log</div>
                  {remediationLogs.map((log, i) => (
                    <div key={i}>{log}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <span className="text-xs font-mono text-slate-500">Finding ID: {finding.id}</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
