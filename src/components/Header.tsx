import React from 'react';
import {
  ShieldAlert,
  Play,
  GitBranch,
  ShieldCheck,
  Cpu,
  Terminal,
} from 'lucide-react';
import { Repository } from '../types';

interface HeaderProps {
  repository: Repository | null;
  securityScore: number;
  isScanning: boolean;
  onTriggerScan: () => void;
  onOpenPrevention: () => void;
  onOpenAssistant: () => void;
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  repository,
  securityScore,
  isScanning,
  onTriggerScan,
  onOpenPrevention,
  onOpenAssistant,
  activeTab,
  setActiveTab,
}) => {
  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
    if (score >= 60) return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
    return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
  };

  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Product Name */}
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-wider text-slate-100">
                  SENTINEL<span className="text-cyan-400">-X</span>
                </span>
                <span className="px-2 py-0.5 text-xs font-mono font-medium rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800">
                  AGENT v1.0
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono hidden sm:block">
                AI Secret Leak Detection & Active Prevention
              </p>
            </div>
          </div>

          {/* Center Tabs */}
          <nav className="hidden md:flex items-center space-x-1 bg-slate-950/60 p-1 rounded-lg border border-slate-800">
            <button
              id="tab-findings"
              onClick={() => setActiveTab('findings')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                activeTab === 'findings'
                  ? 'bg-slate-800 text-cyan-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Intelligence & Findings
            </button>
            <button
              id="tab-git-history"
              onClick={() => setActiveTab('git-history')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                activeTab === 'git-history'
                  ? 'bg-slate-800 text-cyan-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Git History Audit
            </button>
            <button
              id="tab-prevention"
              onClick={() => setActiveTab('prevention')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                activeTab === 'prevention'
                  ? 'bg-slate-800 text-cyan-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Prevention Center
            </button>
          </nav>

          {/* Right Action Controls */}
          <div className="flex items-center gap-3">
            {/* Live Score Badge */}
            <div
              className={`px-3 py-1 rounded-md border text-xs font-mono font-bold flex items-center gap-1.5 ${getScoreColor(
                securityScore
              )}`}
            >
              <span>SCORE:</span>
              <span className="text-sm">{securityScore}/100</span>
            </div>

            {/* Scan Trigger Button */}
            <button
              id="btn-trigger-scan"
              onClick={onTriggerScan}
              disabled={isScanning}
              className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-md text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Play className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
              <span>{isScanning ? 'Scanning...' : 'Trigger Scan'}</span>
            </button>

            {/* AI Assistant Toggle */}
            <button
              id="btn-open-assistant"
              onClick={onOpenAssistant}
              className="p-1.5 rounded-md border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 transition-colors"
              title="Open AI Security Assistant"
            >
              <Cpu className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
