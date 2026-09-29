import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { SecurityScoreCard } from './components/SecurityScoreCard';
import { FindingsTable } from './components/FindingsTable';
import { FindingDetailModal } from './components/FindingDetailModal';
import { GitHistoryView } from './components/GitHistoryView';
import { PreventionCenter } from './components/PreventionCenter';
import { AIAssistantDrawer } from './components/AIAssistantDrawer';
import { Repository, Finding, SecurityScoreRecord } from './types';
import { Upload, ShieldCheck, AlertCircle, Sparkles, CheckCircle2 } from 'lucide-react';

export default function App() {
  const [repository, setRepository] = useState<Repository | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [securityScore, setSecurityScore] = useState<number>(100);
  const [scoreBreakdown, setScoreBreakdown] = useState<SecurityScoreRecord['breakdown'] | undefined>(undefined);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [activeTab, setActiveTab] = useState<string>('findings');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isRemediating, setIsRemediating] = useState<boolean>(false);
  const [isAssistantOpen, setIsAssistantOpen] = useState<boolean>(false);
  const [notification, setNotification] = useState<string | null>(null);
  const repositoryId = repository?.id;

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  const loadData = async () => {
    try {
      // 1. Fetch Repositories
      const repoRes = await fetch('/api/repositories');
      const repos = await repoRes.json();
      if (!repos || repos.length === 0) {
        setFindings([]);
        setSecurityScore(100);
        return;
      }

      const activeRepository = repos[0];
      setRepository(activeRepository);

      // 2. Fetch Findings
      const findingsRes = await fetch(`/api/findings?repositoryId=${encodeURIComponent(activeRepository.id)}`);
      if (!findingsRes.ok) throw new Error('Failed to load findings');
      const findingsData = await findingsRes.json();
      setFindings(findingsData);

      // 3. Fetch Security Score
      const scoreRes = await fetch(`/api/security-score?repositoryId=${encodeURIComponent(activeRepository.id)}`);
      if (!scoreRes.ok) throw new Error('Failed to load security score');
      const scoreData = await scoreRes.json();
      setSecurityScore(scoreData.currentScore);
      setScoreBreakdown(scoreData.breakdown);
    } catch (err) {
      console.error('Error loading initial data:', err);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleTriggerScan = async () => {
    if (!repositoryId) {
      showNotification('No repository configured.');
      return;
    }
    setIsScanning(true);
    showNotification('Starting full repository static analysis & Git history audit...');
    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repositoryId: repositoryId,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'Scan failed');
      await loadData();
      showNotification(`Scan completed: ${data.findingsCount} findings processed. Score: ${data.securityScore}/100`);
    } catch (err) {
      console.error('Scan execution error:', err);
      showNotification(err instanceof Error ? err.message : 'Scan failed');
    } finally {
      setIsScanning(false);
    }
  };

  const handleRemediate = async (findingId: string, actionType: string) => {
    setIsRemediating(true);
    try {
      const res = await fetch(`/api/findings/${findingId}/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ actionType }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'Remediation failed');
      await loadData();

      // Update selected finding if still open in modal
      const updatedFinding = findings.find((f) => f.id === findingId);
      if (updatedFinding) {
        setSelectedFinding(null);
      }

      showNotification(`Remediation executed: Security Score increased to ${data.newSecurityScore}/100!`);
    } catch (err) {
      console.error('Remediation error:', err);
      showNotification(err instanceof Error ? err.message : 'Remediation failed');
    } finally {
      setIsRemediating(false);
    }
  };


  const criticalCount = findings.filter(
    (f) => f.riskLevel === 'CRITICAL' && f.status === 'OPEN' && f.classification !== 'false_positive'
  ).length;

  const highCount = findings.filter(
    (f) => f.riskLevel === 'HIGH' && f.status === 'OPEN' && f.classification !== 'false_positive'
  ).length;

  const openCount = findings.filter(
    (f) => f.status === 'OPEN' && f.classification !== 'false_positive'
  ).length;

  const remediatedCount = findings.filter((f) => f.status === 'REMEDIATED').length;
  const falsePositivesFiltered = findings.filter((f) => f.classification === 'false_positive').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Header */}
      <Header
        repository={repository}
        securityScore={securityScore}
        isScanning={isScanning}
        onTriggerScan={handleTriggerScan}
        onOpenPrevention={() => setActiveTab('prevention')}
        onOpenAssistant={() => setIsAssistantOpen(true)}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Active Tab: Intelligence & Findings */}
        {activeTab === 'findings' && (
          <div className="space-y-6">
            <div className="rounded-2xl border border-cyan-500/20 bg-slate-900/70 p-5 shadow-xl">
              <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
                <div>
                  <h2 className="text-sm font-semibold text-slate-100">Scan a project</h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Upload a ZIP exported from any website, GitHub repository, Node/React app, or other codebase.
                    SENTINEL-X will extract it, inspect the files, and analyze exposed secrets.
                  </p>
                </div>
                <label className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-500 text-slate-950 text-xs font-bold cursor-pointer hover:bg-cyan-400 transition-colors">
                  <Upload className="w-4 h-4" />
                  {isScanning ? 'Scanning...' : 'Upload ZIP & Scan'}
                  <input
                    type="file"
                    accept=".zip,application/zip"
                    className="hidden"
                    disabled={isScanning}
                    onChange={async (event) => {
                      const file = event.target.files?.[0];
                      event.target.value = '';
                      if (!file) return;
                      if (file.size > 50 * 1024 * 1024) {
                        showNotification('ZIP is too large. Maximum upload size is 50 MB.');
                        return;
                      }
                      setIsScanning(true);
                      showNotification(`Uploading ${file.name}...`);
                      try {
                        const uploadRes = await fetch('/api/repositories/upload', {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/zip',
                            'X-Project-Name': file.name.replace(/\.zip$/i, ''),
                          },
                          body: file,
                        });
                        const uploadData = await uploadRes.json();
                        if (!uploadRes.ok) throw new Error(uploadData?.error || 'Upload failed');

                        const scanRes = await fetch('/api/scans', {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({ repositoryId: uploadData.repository.id }),
                        });
                        const scanData = await scanRes.json();
                        if (!scanRes.ok) throw new Error(scanData?.error || 'Scan failed');

                        await loadData();
                        showNotification(
                          `Scan complete: ${scanData.findingsCount} findings found. Security Score: ${scanData.securityScore}/100`
                        );
                      } catch (err) {
                        console.error('Upload/scan error:', err);
                        showNotification(err instanceof Error ? err.message : 'Upload or scan failed');
                      } finally {
                        setIsScanning(false);
                      }
                    }}
                  />
                </label>
              </div>
            </div>

            <SecurityScoreCard
              score={securityScore}
              breakdown={scoreBreakdown}
              criticalCount={criticalCount}
              highCount={highCount}
              openCount={openCount}
              remediatedCount={remediatedCount}
              falsePositivesFiltered={falsePositivesFiltered}
            />

            <FindingsTable
              findings={findings}
              onSelectFinding={(f) => setSelectedFinding(f)}
              selectedFindingId={selectedFinding?.id}
            />
          </div>
        )}

        {/* Active Tab: Git History Audit */}
        {activeTab === 'git-history' && <GitHistoryView findings={findings} />}

        {/* Active Tab: Prevention Center */}
        {activeTab === 'prevention' && <PreventionCenter />}
      </main>

      {/* Finding Detail & Remediation Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onRemediate={handleRemediate}
          isRemediating={isRemediating}
        />
      )}

      {/* AI Security Assistant Chat Drawer */}
      {isAssistantOpen && (
        <AIAssistantDrawer
          isOpen={isAssistantOpen}
          onClose={() => setIsAssistantOpen(false)}
          securityScore={securityScore}
          findings={findings}
        />
      )}

      {/* Floating Toast Notification */}
      {notification && (
        <div className="fixed bottom-6 right-6 z-50 bg-slate-900 border border-cyan-500/40 text-slate-200 text-xs px-4 py-3 rounded-xl shadow-2xl flex items-center gap-2.5 animate-in fade-in slide-in-from-bottom-3 duration-200">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <span>{notification}</span>
        </div>
      )}
    </div>
  );
}
