import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Clock,
  Sparkles,
  Lock,
} from 'lucide-react';
import { SecurityScoreRecord } from '../types';

interface SecurityScoreCardProps {
  score: number;
  breakdown?: SecurityScoreRecord['breakdown'];
  criticalCount: number;
  highCount: number;
  openCount: number;
  remediatedCount: number;
  falsePositivesFiltered: number;
}

export const SecurityScoreCard: React.FC<SecurityScoreCardProps> = ({
  score,
  breakdown,
  criticalCount,
  highCount,
  openCount,
  remediatedCount,
  falsePositivesFiltered,
}) => {
  const getStatus = (s: number) => {
    if (s >= 85) return { label: 'HEALTHY / FORTIFIED', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30' };
    if (s >= 60) return { label: 'ELEVATED RISK', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' };
    return { label: 'CRITICAL VULNERABILITY', color: 'text-rose-400', bg: 'bg-rose-500/10 border-rose-500/30' };
  };

  const status = getStatus(score);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
        {/* Main Score Gauge */}
        <div className="flex items-center gap-6">
          <div className="relative flex items-center justify-center w-28 h-28">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="40"
                className="stroke-slate-800"
                strokeWidth="8"
                fill="none"
              />
              <circle
                cx="50"
                cy="50"
                r="40"
                className={score >= 80 ? 'stroke-emerald-500' : score >= 60 ? 'stroke-amber-500' : 'stroke-rose-500'}
                strokeWidth="8"
                strokeDasharray={251.2}
                strokeDashoffset={251.2 - (251.2 * score) / 100}
                strokeLinecap="round"
                fill="none"
                style={{ transition: 'stroke-dashoffset 0.8s ease' }}
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center text-center">
              <span className="text-3xl font-bold font-mono text-slate-100">{score}</span>
              <span className="text-[10px] uppercase tracking-wider text-slate-400 font-mono">out of 100</span>
            </div>
          </div>

          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-semibold border ${status.bg} ${status.color}`}>
                {status.label}
              </span>
              <span className="text-xs text-slate-400 font-mono">Dynamic Risk Engine</span>
            </div>
            <h2 className="text-lg font-bold text-slate-100">Repository Posture Index</h2>
            <p className="text-xs text-slate-400 mt-1 max-w-md">
              Score is calculated dynamically across live and historical Git exposure, confidence weighting, Shannon entropy density, and active remediation.
            </p>
          </div>
        </div>

        {/* Quick Threat Metric Pills */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 w-full lg:w-auto">
          <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
            <div className="flex items-center gap-1.5 text-rose-400 mb-1">
              <Flame className="w-3.5 h-3.5" />
              <span className="text-xs font-mono font-medium uppercase">Criticals</span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100">{criticalCount}</div>
            <div className="text-[10px] text-slate-500">Immediate threat</div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
            <div className="flex items-center gap-1.5 text-amber-400 mb-1">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span className="text-xs font-mono font-medium uppercase">High Risk</span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100">{highCount}</div>
            <div className="text-[10px] text-slate-500">Requires review</div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
            <div className="flex items-center gap-1.5 text-emerald-400 mb-1">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span className="text-xs font-mono font-medium uppercase">Remediated</span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100">{remediatedCount}</div>
            <div className="text-[10px] text-slate-500">Neutralized leaks</div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
            <div className="flex items-center gap-1.5 text-cyan-400 mb-1">
              <Sparkles className="w-3.5 h-3.5" />
              <span className="text-xs font-mono font-medium uppercase">Filtered FP</span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100">{falsePositivesFiltered}</div>
            <div className="text-[10px] text-slate-500">AI False-positives</div>
          </div>
        </div>
      </div>

      {/* Penalty Breakdown Bar */}
      {breakdown && (
        <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between text-xs font-mono gap-3 text-slate-400">
          <div className="flex items-center gap-4 flex-wrap">
            <span className="text-slate-500">Deductions:</span>
            {breakdown.criticalFindingsPenalty !== 0 && (
              <span className="text-rose-400 bg-rose-950/30 px-2 py-0.5 rounded border border-rose-900/50">
                Critical Leaks: {breakdown.criticalFindingsPenalty} pts
              </span>
            )}
            {breakdown.highFindingsPenalty !== 0 && (
              <span className="text-amber-400 bg-amber-950/30 px-2 py-0.5 rounded border border-amber-900/50">
                High Risk: {breakdown.highFindingsPenalty} pts
              </span>
            )}
            {breakdown.historicalExposurePenalty !== 0 && (
              <span className="text-purple-400 bg-purple-950/30 px-2 py-0.5 rounded border border-purple-900/50 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                Git History: {breakdown.historicalExposurePenalty} pts
              </span>
            )}
          </div>
          <div className="flex items-center gap-4 flex-wrap">
            <span className="text-slate-500">Bonuses:</span>
            {breakdown.remediationBonus > 0 && (
              <span className="text-emerald-400 bg-emerald-950/30 px-2 py-0.5 rounded border border-emerald-900/50">
                Active Fixes: +{breakdown.remediationBonus} pts
              </span>
            )}
            {breakdown.preventionBonus > 0 && (
              <span className="text-cyan-400 bg-cyan-950/30 px-2 py-0.5 rounded border border-cyan-900/50 flex items-center gap-1">
                <Lock className="w-3 h-3" />
                Prevention Guard: +{breakdown.preventionBonus} pts
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
