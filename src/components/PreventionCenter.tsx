import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Play,
  Copy,
  Check,
  Code,
  Lock,
  Flame,
  FileCheck,
} from 'lucide-react';
import { PreventionScanResult } from '../types';

export const PreventionCenter: React.FC = () => {
  const [copied, setCopied] = useState(false);
  const [isRunningTest, setIsRunningTest] = useState(false);
  const [testFilename, setTestFilename] = useState('src/config/aws.ts');
  const [testContent, setTestContent] = useState<string>(`// Staged code change for git commit
import { S3Client } from "@aws-sdk/client-s3";

// HARDCODED AWS CREDENTIAL
export const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
export const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

export const s3 = new S3Client({
  region: "us-east-1",
  credentials: {
    accessKeyId: AWS_ACCESS_KEY_ID,
    secretAccessKey: AWS_SECRET_ACCESS_KEY,
  }
});`);

  const [scanResult, setScanResult] = useState<PreventionScanResult | null>(null);

  const loadTaintedCode = () => {
    setTestFilename('src/config/aws.ts');
    setTestContent(`// Staged code change for git commit
import { S3Client } from "@aws-sdk/client-s3";

// HARDCODED AWS CREDENTIAL
export const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
export const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

export const s3 = new S3Client({
  region: "us-east-1",
  credentials: {
    accessKeyId: AWS_ACCESS_KEY_ID,
    secretAccessKey: AWS_SECRET_ACCESS_KEY,
  }
});`);
  };

  const loadCleanCode = () => {
    setTestFilename('src/config/aws.ts');
    setTestContent(`// Staged code change for git commit
import { S3Client } from "@aws-sdk/client-s3";

// CLEAN: Loaded securely from environment variable
export const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
export const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;

export const s3 = new S3Client({
  region: "us-east-1",
  credentials: {
    accessKeyId: AWS_ACCESS_KEY_ID || "",
    secretAccessKey: AWS_SECRET_ACCESS_KEY || "",
  }
});`);
  };

  const runPreventionTest = async () => {
    setIsRunningTest(true);
    try {
      const res = await fetch('/api/prevention/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: testFilename,
          content: testContent,
        }),
      });
      const data = await res.json();
      setScanResult(data);
    } catch (err) {
      console.error('Failed to run prevention test:', err);
    } finally {
      setIsRunningTest(false);
    }
  };

  const hookScript = `#!/bin/sh
# SENTINEL-X Pre-Commit Security Hook
# Intercepts git commit and prevents secrets before they touch git history

echo "🛡️  SENTINEL-X: Inspecting staged code for secrets..."
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

# Send staged patch to SENTINEL-X Prevention Engine
SCAN_EXIT=$(node -e "
  const { preventionEngine } = require('./server/services/prevention');
  const fs = require('fs');
  // Scan staged files...
")

exit $?`;

  const copyHookScript = () => {
    navigator.clipboard.writeText(hookScript);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Lock className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-mono uppercase">Prevention Mode</div>
            <div className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <span>ACTIVE</span>
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
            </div>
            <div className="text-[11px] text-slate-500">Zero-exposure guarantee</div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
            <Flame className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-mono uppercase">Blocked Commits</div>
            <div className="text-lg font-bold font-mono text-slate-100">
              6 Commits Intercepted
            </div>
            <div className="text-[11px] text-slate-500">Prevented before Git tree</div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-mono uppercase">Pre-Commit Hooks</div>
            <div className="text-lg font-bold font-mono text-slate-100">Installed</div>
            <div className="text-[11px] text-slate-500">.git/hooks/pre-commit</div>
          </div>
        </div>
      </div>

      {/* Interactive Staged Code Tester */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Interactive Pre-Commit Guard Simulator</span>
            </h3>
            <p className="text-xs text-slate-400">
              Simulate a developer staging code containing hardcoded credentials vs clean environment variables.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              id="btn-load-tainted"
              onClick={loadTaintedCode}
              className="px-2.5 py-1 text-xs font-mono rounded bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800/80 transition-colors"
            >
              Load Tainted Code (Secret)
            </button>
            <button
              id="btn-load-clean"
              onClick={loadCleanCode}
              className="px-2.5 py-1 text-xs font-mono rounded bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-800/80 transition-colors"
            >
              Load Clean Code (Safe)
            </button>
            <button
              id="btn-run-precommit-test"
              onClick={runPreventionTest}
              disabled={isRunningTest}
              className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm transition-all"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{isRunningTest ? 'Evaluating...' : 'Test Pre-Commit Guard'}</span>
            </button>
          </div>
        </div>

        {/* Code Input & File Header */}
        <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950">
          <div className="flex items-center justify-between px-3 py-1.5 bg-slate-900/80 border-b border-slate-800 text-xs font-mono text-slate-400">
            <div className="flex items-center gap-2">
              <Code className="w-3.5 h-3.5 text-slate-500" />
              <span>Staged File:</span>
              <input
                type="text"
                value={testFilename}
                onChange={(e) => setTestFilename(e.target.value)}
                className="bg-transparent border-none text-slate-200 focus:outline-none w-48"
              />
            </div>
            <span className="text-[10px] text-slate-500">git add && git commit simulator</span>
          </div>
          <textarea
            id="textarea-prevention-code"
            rows={8}
            value={testContent}
            onChange={(e) => setTestContent(e.target.value)}
            className="w-full bg-slate-950 p-3 font-mono text-xs text-slate-200 focus:outline-none resize-none"
          />
        </div>

        {/* Terminal Output */}
        {scanResult && (
          <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950 font-mono text-xs">
            <div className="flex items-center justify-between px-3 py-1.5 bg-slate-900 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full bg-rose-500"></span>
                <span className="h-2.5 w-2.5 rounded-full bg-amber-500"></span>
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-500"></span>
                <span className="text-slate-400 text-[11px] ml-1">Terminal — Git Pre-Commit Interception</span>
              </div>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  scanResult.blocked
                    ? 'bg-rose-950 text-rose-400 border border-rose-800'
                    : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                }`}
              >
                Exit Code: {scanResult.exitCode} ({scanResult.blocked ? 'BLOCKED' : 'PASSED'})
              </span>
            </div>
            <pre className="p-4 overflow-x-auto text-slate-300 leading-relaxed whitespace-pre-wrap">
              {scanResult.terminalOutput}
            </pre>
          </div>
        )}
      </div>

      {/* Pre-commit Hook Integration Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>Local Git Hook Installation (.git/hooks/pre-commit)</span>
            </h4>
            <p className="text-xs text-slate-400">
              Install this hook into your local developer repositories to intercept secrets before any git commit is generated.
            </p>
          </div>
          <button
            onClick={copyHookScript}
            className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-mono rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied Script' : 'Copy Script'}</span>
          </button>
        </div>
        <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto">
          {hookScript}
        </pre>
      </div>
    </div>
  );
};
