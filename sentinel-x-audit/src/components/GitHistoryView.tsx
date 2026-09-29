import React from 'react';
import {
  GitCommit,
  GitBranch,
  Clock,
  AlertOctagon,
  ShieldCheck,
  User,
  Calendar,
  FileCode,
  Terminal,
} from 'lucide-react';
import { Finding } from '../types';

interface GitHistoryViewProps {
  findings: Finding[];
}

export const GitHistoryView: React.FC<GitHistoryViewProps> = ({ findings }) => {
  const exposedInHistory = findings.filter(
    (f) => f.gitExposure && f.gitExposure.commitCount > 0
  );

  return (
    <div className="space-y-6">
      {/* Crucial Cybersecurity Warning Banner */}
      <div className="bg-purple-950/20 border border-purple-800/40 rounded-xl p-5 flex items-start gap-4">
        <div className="p-2 rounded-lg bg-purple-900/30 border border-purple-700/50 text-purple-400 mt-1">
          <AlertOctagon className="w-6 h-6" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-purple-200">
            Crucial Principle: Deleting a Secret in HEAD Does NOT Remediate It
          </h3>
          <p className="text-xs text-purple-300/80 mt-1 leading-relaxed">
            Git is an immutable content-addressed ledger. If a developer commits a secret in commit <code className="bg-purple-900/40 px-1 rounded font-mono text-purple-200">a82f91</code> and later "deletes" it in commit <code className="bg-purple-900/40 px-1 rounded font-mono text-purple-200">c72f21</code>, the credential remains intact in the commit tree. Anyone who clones the repository, checks out previous commits, or runs <code className="bg-purple-900/40 px-1 rounded font-mono text-purple-200">git log -p</code> has full access to the live credential!
          </p>
          <div className="mt-3 flex items-center gap-3 text-xs font-mono text-purple-400">
            <span className="font-semibold">Remediation requires:</span>
            <span>1. Revocation at provider</span>
            <span>→</span>
            <span>2. History purge with git-filter-repo</span>
          </div>
        </div>
      </div>

      {/* Historical Audit Items */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h3 className="text-sm font-bold text-slate-100 mb-4 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <span>Historical Exposure Audit by Credential</span>
          </span>
          <span className="text-xs font-mono text-slate-400">
            {exposedInHistory.length} Secrets Tracked in History
          </span>
        </h3>

        <div className="space-y-6">
          {exposedInHistory.map((finding) => {
            const exp = finding.gitExposure;

            return (
              <div
                key={finding.id}
                className="bg-slate-950/60 border border-slate-800 rounded-lg p-4 space-y-3"
              >
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                        finding.riskLevel === 'CRITICAL'
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                      }`}
                    >
                      {finding.secretCategory}
                    </span>
                    <span className="text-xs font-mono text-slate-300 font-semibold">
                      {finding.filePath}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-xs font-mono">
                    <span className="text-slate-400">Masked:</span>
                    <span className="bg-slate-900 px-2 py-0.5 rounded text-slate-200 border border-slate-800">
                      {finding.redactedValue}
                    </span>
                    {exp.isRemovedInHead ? (
                      <span className="px-2 py-0.5 rounded text-[11px] bg-purple-950 text-purple-300 border border-purple-800">
                        DELETED IN HEAD (HISTORICAL)
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[11px] bg-rose-950 text-rose-300 border border-rose-800">
                        ACTIVE IN HEAD
                      </span>
                    )}
                  </div>
                </div>

                {/* Git Metadata Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono text-slate-300">
                  <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">First Seen Commit</div>
                    <div className="flex items-center gap-1.5 mt-1 text-cyan-400 font-semibold">
                      <GitCommit className="w-3.5 h-3.5" />
                      <span>{exp.firstSeenCommit}</span>
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5 truncate">{exp.firstSeenAuthor}</div>
                  </div>

                  <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Commits in Ledger</div>
                    <div className="flex items-center gap-1.5 mt-1 text-purple-400 font-semibold">
                      <Clock className="w-3.5 h-3.5" />
                      <span>{exp.commitCount} Revisions Affected</span>
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">Spans across branches: main</div>
                  </div>

                  <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Last Seen In Git</div>
                    <div className="flex items-center gap-1.5 mt-1 text-slate-300 font-semibold">
                      <GitCommit className="w-3.5 h-3.5" />
                      <span>{exp.lastSeenCommit}</span>
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">{exp.lastSeenDate}</div>
                  </div>
                </div>

                {/* Historical Commits Timeline */}
                {exp.historicalCommits && exp.historicalCommits.length > 0 && (
                  <div className="pt-2">
                    <div className="text-[11px] font-mono text-slate-400 mb-2 font-medium">
                      Historical Commit Trajectory:
                    </div>
                    <div className="space-y-1.5 font-mono text-xs">
                      {exp.historicalCommits.map((c, idx) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between p-2 rounded bg-slate-900/40 border border-slate-800/60 hover:bg-slate-900/80 transition-colors"
                        >
                          <div className="flex items-center gap-2">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                c.action === 'INTRODUCED'
                                  ? 'bg-rose-950 text-rose-400 border border-rose-800'
                                  : c.action === 'REMOVED'
                                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                  : 'bg-amber-950 text-amber-400 border border-amber-800'
                              }`}
                            >
                              {c.action}
                            </span>
                            <span className="text-cyan-400 font-bold">{c.hash}</span>
                            <span className="text-slate-300 truncate max-w-[280px] sm:max-w-md">
                              {c.message}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-500 hidden sm:block">
                            {c.author} • {c.date}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
