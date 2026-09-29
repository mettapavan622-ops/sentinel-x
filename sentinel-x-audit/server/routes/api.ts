import { Router, Request, Response } from 'express';
import { z } from 'zod';
import path from 'path';
import fs from 'fs';
import { dbStore } from '../db/store';
import { scanDirectory } from '../scanner/scanEngine';
import { aiProvider } from '../ai';
import { calculateSecurityScore } from '../services/riskEngine';
import { mockCredentialProvider, generateCodeRemediationDiff, generateGitHistoryCleanupScript } from '../services/remediation';
import { preventionEngine } from '../services/prevention';
import { execFileSync } from 'child_process';
import unzipper from 'unzipper';
import { Scan, Finding } from '../../src/types';
import { Repository } from '../../src/types';

export const apiRouter = Router();

// Validation Schemas
const StartScanSchema = z.object({
  repositoryId: z.string().min(1),
  scanPath: z.string().min(1).optional(),
});

const CreateRepositorySchema = z.object({
  name: z.string().min(1).max(120),
  path: z.string().min(1),
  defaultBranch: z.string().min(1).max(100).default('main'),
});

const RemediateSchema = z.object({
  actionType: z.enum([
    'SIMULATE_REVOKE',
    'SIMULATE_ROTATE',
    'CODE_REPLACEMENT',
    'GIT_HISTORY_CLEANUP',
    'VERIFICATION_SCAN',
    'FULL_PIPELINE',
  ]),
});

const PreventionScanSchema = z.object({
  filename: z.string().default('staged_code.ts'),
  content: z.string(),
  author: z.string().optional(),
});

const ChatSchema = z.object({
  conversationId: z.string().optional(),
  repositoryId: z.string().min(1).optional(),
  message: z.string().min(1),
});

const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_MB || 50) * 1024 * 1024;
const MAX_EXTRACTED_BYTES = Number(process.env.MAX_EXTRACTED_MB || 250) * 1024 * 1024;
const MAX_ZIP_ENTRIES = 5000;

function sanitizeProjectName(name: string): string {
  return name
    .replace(/\\.zip$/i, '')
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || `project-${Date.now()}`;
}

function isSafeArchivePath(filePath: string): boolean {
  const normalized = path.posix.normalize(filePath.replace(/\\/g, '/'));
  return !normalized.startsWith('../') && normalized !== '..' && !path.isAbsolute(normalized);
}

async function extractUploadedZip(buffer: Buffer, destination: string): Promise<{ root: string; files: number }> {
  const directory = await unzipper.Open.buffer(buffer);
  if (directory.files.length > MAX_ZIP_ENTRIES) {
    throw new Error(`ZIP contains too many files. Limit: ${MAX_ZIP_ENTRIES}.`);
  }

  let totalBytes = 0;
  const entries = directory.files.filter((entry) => entry.type === 'File');

  for (const entry of entries) {
    if (!isSafeArchivePath(entry.path)) {
      throw new Error(`Unsafe ZIP path rejected: ${entry.path}`);
    }
    totalBytes += entry.uncompressedSize || 0;
    if (totalBytes > MAX_EXTRACTED_BYTES) {
      throw new Error(`Extracted project is too large. Limit: ${Math.round(MAX_EXTRACTED_BYTES / 1024 / 1024)} MB.`);
    }
  }

  await Promise.all(entries.map(async (entry) => {
    const target = path.resolve(destination, entry.path);
    if (!target.startsWith(path.resolve(destination) + path.sep)) {
      throw new Error(`Unsafe ZIP path rejected: ${entry.path}`);
    }
    await fs.promises.mkdir(path.dirname(target), { recursive: true });
    const content = await entry.buffer();
    await fs.promises.writeFile(target, content);
  }));

  // GitHub downloads commonly wrap the actual repository in one top-level folder.
  const topEntries = await fs.promises.readdir(destination, { withFileTypes: true });
  if (topEntries.length === 1 && topEntries[0].isDirectory()) {
    return { root: path.join(destination, topEntries[0].name), files: entries.length };
  }
  return { root: destination, files: entries.length };
}

// GET /api/health
apiRouter.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    product: 'SENTINEL-X',
    version: '1.0.0-hackathon',
    aiProvider: aiProvider.name,
    timestamp: new Date().toISOString(),
  });
});

// GET /api/repositories
apiRouter.get('/repositories', (req: Request, res: Response) => {
  res.json(dbStore.getRepositories());
});

// POST /api/repositories - register a local repository target
apiRouter.post('/repositories', (req: Request, res: Response) => {
  const parsed = CreateRepositorySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error });

  const absolutePath = path.resolve(parsed.data.path);
  if (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isDirectory()) {
    return res.status(400).json({ error: 'Repository path does not exist or is not a directory.' });
  }

  const repository: import('../../src/types').Repository = {
    id: `repo-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    name: parsed.data.name,
    path: absolutePath,
    defaultBranch: parsed.data.defaultBranch,
    currentScore: 100,
    preventionModeEnabled: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  res.status(201).json(dbStore.createRepository(repository));
});


// POST /api/repositories/upload - upload a ZIP project and register it as a scan target
apiRouter.post('/repositories/upload', async (req: Request, res: Response) => {
  const contentType = req.headers['content-type'] || '';
  if (!contentType.toLowerCase().startsWith('application/zip')) {
    return res.status(400).json({ error: 'Upload a ZIP file using Content-Type: application/zip.' });
  }

  const chunks: Buffer[] = [];
  let received = 0;

  try {
    for await (const chunk of req) {
      const part = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      received += part.length;
      if (received > MAX_UPLOAD_BYTES) {
        return res.status(413).json({ error: `ZIP is too large. Limit: ${Math.round(MAX_UPLOAD_BYTES / 1024 / 1024)} MB.` });
      }
      chunks.push(part);
    }

    if (!chunks.length) return res.status(400).json({ error: 'No ZIP data received.' });

    const uploadId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const baseDir = path.resolve(process.cwd(), '.sentinel-uploads', uploadId);
    await fs.promises.mkdir(baseDir, { recursive: true });

    const projectName = sanitizeProjectName((req.headers['x-project-name'] as string) || 'uploaded-project');
    const projectDir = path.join(baseDir, projectName);
    await fs.promises.mkdir(projectDir, { recursive: true });

    const { root: extractedRoot, files } = await extractUploadedZip(Buffer.concat(chunks), projectDir);

    const repository: Repository = {
      id: `repo-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      name: projectName,
      path: extractedRoot,
      defaultBranch: 'main',
      currentScore: 100,
      preventionModeEnabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    dbStore.createRepository(repository);
    res.status(201).json({
      repository,
      filesUploaded: files,
      message: `Project "${projectName}" uploaded successfully. Ready to scan.`,
    });
  } catch (error) {
    return res.status(400).json({
      error: error instanceof Error ? error.message : 'ZIP upload/extraction failed.',
    });
  }
});

// GET /api/security-score
apiRouter.get('/security-score', (req: Request, res: Response) => {
  const repoId = (req.query.repositoryId as string) || dbStore.getRepositories()[0]?.id;
  if (!repoId) return res.status(404).json({ error: 'No repository configured' });
  const repo = dbStore.getRepository(repoId);
  const findings = dbStore.getFindings({ repositoryId: repoId });
  const scoreResult = calculateSecurityScore(repoId, findings, repo?.preventionModeEnabled ?? true);
  if (repo) dbStore.updateRepository(repoId, { currentScore: scoreResult.score });

  res.json({
    repositoryId: repoId,
    currentScore: scoreResult.score,
    breakdown: scoreResult.breakdown,
    activeFindingsCount: findings.filter((f) => f.status === 'OPEN' && f.classification !== 'false_positive').length,
    remediatedFindingsCount: findings.filter((f) => f.status === 'REMEDIATED').length,
    falsePositivesCount: findings.filter((f) => f.classification === 'false_positive').length,
    timestamp: new Date().toISOString(),
  });
});

// GET /api/scans
apiRouter.get('/scans', (req: Request, res: Response) => {
  const repoId = req.query.repositoryId as string;
  res.json(dbStore.getScans(repoId));
});

// GET /api/scans/:id
apiRouter.get('/scans/:id', (req: Request, res: Response) => {
  const scan = dbStore.getScan(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  res.json(scan);
});

// GET /api/scans/:id/findings
apiRouter.get('/scans/:id/findings', (req: Request, res: Response) => {
  const findings = dbStore.getFindings({ scanId: req.params.id });
  res.json(findings);
});

// POST /api/scans (Execute new repository scan)
apiRouter.post('/scans', async (req: Request, res: Response) => {
  const parsed = StartScanSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error });
  }

  const { repositoryId, scanPath } = parsed.data;
  const repo = dbStore.getRepository(repositoryId);
  if (!repo) return res.status(404).json({ error: 'Repository not found' });

  const targetDir = scanPath ? path.resolve(scanPath) : path.resolve(repo.path);
  const fs = await import('fs');
  if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
    return res.status(400).json({ error: `Scan path is not a readable directory: ${targetDir}` });
  }

  const scanId = `scan-${Date.now()}`;
  const newScan: Scan = {
    id: scanId,
    repositoryId,
    status: 'RUNNING',
    filesScanned: 0,
    commitsScanned: 0,
    findingsCount: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
    securityScoreBefore: repo.currentScore,
    startedAt: new Date().toISOString(),
  };

  dbStore.createScan(newScan);

  // Perform the scan on target directory. Failed scans are persisted as FAILED instead of leaving a RUNNING ghost.
  let discoveredFindings: Finding[] = [];
  let scannedFileCount = 0;
  try {
    const result = scanDirectory(targetDir, scanId, repositoryId);
    discoveredFindings = result.findings;
    scannedFileCount = result.scannedFileCount;
  } catch (error) {
    dbStore.updateScan(scanId, {
      status: 'FAILED',
      error: error instanceof Error ? error.message : 'Unknown scan error',
      completedAt: new Date().toISOString(),
    });
    return res.status(500).json({ error: 'Repository scan failed', details: error instanceof Error ? error.message : 'Unknown scan error' });
  }

  // A scan is authoritative for the repository: replace the previous snapshot instead of accumulating duplicates.
  dbStore.replaceFindingsForRepository(repositoryId, discoveredFindings);
  const allFindings = discoveredFindings;

  // Update counts
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let infoCount = 0;

  for (const f of allFindings) {
    if (f.riskLevel === 'CRITICAL') criticalCount++;
    else if (f.riskLevel === 'HIGH') highCount++;
    else if (f.riskLevel === 'MEDIUM') mediumCount++;
    else if (f.riskLevel === 'LOW') lowCount++;
    else infoCount++;
  }

  const scoreResult = calculateSecurityScore(repositoryId, allFindings, repo?.preventionModeEnabled ?? true);

  const completedScan = dbStore.updateScan(scanId, {
    status: 'COMPLETED',
    filesScanned: scannedFileCount,
    findingsCount: allFindings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    infoCount,
    securityScoreAfter: scoreResult.score,
    completedAt: new Date().toISOString(),
  });

  dbStore.updateRepository(repositoryId, {
    currentScore: scoreResult.score,
    lastScannedAt: new Date().toISOString(),
  });

  res.json({
    scan: completedScan,
    findingsCount: allFindings.length,
    securityScore: scoreResult.score,
  });
});

// GET /api/findings
apiRouter.get('/findings', (req: Request, res: Response) => {
  const { repositoryId, scanId, riskLevel, status, secretCategory } = req.query;
  const findings = dbStore.getFindings({
    repositoryId: repositoryId as string,
    scanId: scanId as string,
    riskLevel: riskLevel as string,
    status: status as string,
    secretCategory: secretCategory as string,
  });
  res.json(findings);
});

// GET /api/findings/:id
apiRouter.get('/findings/:id', (req: Request, res: Response) => {
  const finding = dbStore.getFinding(req.params.id);
  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }
  res.json(finding);
});

// POST /api/findings/:id/analyze (AI False Positive & Context Analysis)
apiRouter.post('/api/findings/:id/analyze', async (req: Request, res: Response) => {
  const finding = dbStore.getFinding(req.params.id);
  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }

  const aiResult = await aiProvider.analyzeFinding({
    detectorType: finding.detectorType,
    secretCategory: finding.secretCategory,
    filePath: finding.filePath,
    lineNumber: finding.lineNumber,
    redactedValue: finding.redactedValue,
    contextSnippet: finding.contextSnippet,
    entropy: finding.entropyScore.entropy,
    variableName: finding.contextAnalysis.variableName,
    isInDocumentation: finding.contextAnalysis.isInDocumentation,
    isInTestFile: finding.contextAnalysis.isInTestFile,
    isInExampleFile: finding.contextAnalysis.isInExampleFile,
    isPlaceholderOrExample: finding.contextAnalysis.isPlaceholderOrExample,
  });

  const updated = dbStore.updateFinding(finding.id, {
    aiAnalysis: aiResult,
    classification: aiResult.classification,
    riskLevel: aiResult.riskLevel,
    status: aiResult.classification === 'false_positive' ? 'FALSE_POSITIVE' : finding.status,
  });

  const findings = dbStore.getFindings({ repositoryId: finding.repositoryId });
  const repo = dbStore.getRepository(finding.repositoryId);
  const scoreResult = calculateSecurityScore(finding.repositoryId, findings, repo?.preventionModeEnabled ?? true);
  dbStore.addSecurityScore({
    id: `score-${Date.now()}`,
    repositoryId: finding.repositoryId,
    score: scoreResult.score,
    breakdown: scoreResult.breakdown,
    calculatedAt: new Date().toISOString(),
  });

  res.json(updated);
});

// POST /api/findings/:id/remediate (Remediation pipeline)
apiRouter.post('/findings/:id/remediate', async (req: Request, res: Response) => {
  const parsed = RemediateSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error });
  }

  const finding = dbStore.getFinding(req.params.id);
  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }

  const { actionType } = parsed.data;
  const diffInfo = generateCodeRemediationDiff(finding);
  const cleanupScript = generateGitHistoryCleanupScript(finding);

  let revokeResult;
  let rotateResult;

  if (actionType === 'SIMULATE_REVOKE' || actionType === 'FULL_PIPELINE') {
    revokeResult = await mockCredentialProvider.revoke(finding.id, finding.secretCategory);
  }

  if (actionType === 'SIMULATE_ROTATE' || actionType === 'FULL_PIPELINE') {
    rotateResult = await mockCredentialProvider.rotate(finding.id, finding.secretCategory);
  }

  const actionRecord = dbStore.addRemediationAction({
    id: `act-${Date.now()}`,
    findingId: finding.id,
    actionType,
    status: 'COMPLETED',
    details: {
      revokedAt: revokeResult?.timestamp,
      rotatedKeyPlaceholder: rotateResult?.metadata?.rotatedKeyPlaceholder as string,
      envVariableName: diffInfo.envVarName,
      replacementDiff: diffInfo.unifiedDiff,
      historyCleanupCommand: cleanupScript,
      verificationResult: 'CLEAN',
    },
    createdAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
  });

  // Mark finding as REMEDIATED if full pipeline or code replacement
  if (actionType === 'FULL_PIPELINE' || actionType === 'CODE_REPLACEMENT' || actionType === 'VERIFICATION_SCAN') {
    dbStore.updateFinding(finding.id, {
      status: 'REMEDIATED',
      remediationActionId: actionRecord.id,
    });
  }

  // Recalculate score
  const allFindings = dbStore.getFindings({ repositoryId: finding.repositoryId });
  const repo = dbStore.getRepository(finding.repositoryId);
  const scoreResult = calculateSecurityScore(finding.repositoryId, allFindings, repo?.preventionModeEnabled ?? true);

  dbStore.addSecurityScore({
    id: `score-${Date.now()}`,
    repositoryId: finding.repositoryId,
    score: scoreResult.score,
    breakdown: scoreResult.breakdown,
    calculatedAt: new Date().toISOString(),
  });

  res.json({
    success: true,
    actionRecord,
    diffInfo,
    cleanupScript,
    revokeResult,
    rotateResult,
    newSecurityScore: scoreResult.score,
  });
});

// GET /api/attack-paths/:findingId
apiRouter.get('/attack-paths/:findingId', (req: Request, res: Response) => {
  const finding = dbStore.getFinding(req.params.findingId);
  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }
  res.json(finding.attackPath);
});

// GET /api/git-history/timeline
apiRouter.get('/git-history/timeline', (req: Request, res: Response) => {
  const repoId = req.query.repositoryId as string;
  const repo = repoId ? dbStore.getRepository(repoId) : dbStore.getRepositories()[0];
  if (!repo) {
    return res.json({ commits: [], totalCommitsScanned: 0, secretsInHistoryCount: 0, cleanedFromHeadCount: 0 });
  }

  try {
    const output = execFileSync('git', ['-C', repo.path, 'log', '--all', '--date=iso-strict', '--format=%H%x1f%ad%x1f%an%x1f%s%x1e'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 10000,
      maxBuffer: 4 * 1024 * 1024,
    });
    const commits = output.split('\x1e').map((block) => {
      const p = block.trim().split('\x1f');
      return p.length >= 4 ? { hash: p[0].slice(0, 12), date: p[1], author: p[2], message: p[3], filesChanged: [] } : null;
    }).filter(Boolean);
    const findings = dbStore.getFindings({ repositoryId: repo.id });
    const historyFindings = findings.filter((f) => f.gitExposure && f.gitExposure.commitCount > 1);
    return res.json({
      commits,
      totalCommitsScanned: commits.length,
      secretsInHistoryCount: historyFindings.length,
      cleanedFromHeadCount: historyFindings.filter((f) => f.gitExposure.isRemovedInHead).length,
      summary: historyFindings.length
        ? `Git history analysis found ${historyFindings.length} finding(s) with historical exposure.`
        : 'No historical secret exposure was confirmed for the current findings.',
    });
  } catch {
    return res.json({
      commits: [],
      totalCommitsScanned: 0,
      secretsInHistoryCount: 0,
      cleanedFromHeadCount: 0,
      summary: 'Repository has no readable Git history. Working-tree scanning is still available.',
    });
  }
});

// GET /api/prevention/stats
apiRouter.get('/prevention/stats', (req: Request, res: Response) => {
  res.json(preventionEngine.getStats());
});

// POST /api/prevention/scan (Pre-Commit Scan)
apiRouter.post('/prevention/scan', (req: Request, res: Response) => {
  const parsed = PreventionScanSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error });
  }

  const { filename, content, author } = parsed.data;
  const result = preventionEngine.scanStagedContent(filename, content, author);
  res.json(result);
});

// GET /api/prevention/hook-script
apiRouter.get('/prevention/hook-script', (req: Request, res: Response) => {
  res.json({
    script: preventionEngine.generateHookScript(),
    installationPath: '.git/hooks/pre-commit',
  });
});

// POST /api/chat (Security AI Assistant)
apiRouter.post('/chat', async (req: Request, res: Response) => {
  const parsed = ChatSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error });
  }

  const { conversationId = `conv-${Date.now()}`, repositoryId, message } = parsed.data;
  const repoId = repositoryId || dbStore.getRepositories()[0]?.id;
  if (!repoId) return res.status(404).json({ error: 'No repository configured' });
  const repo = dbStore.getRepository(repoId);
  const findings = dbStore.getFindings({ repositoryId: repoId });

  // Add user message
  const userMsg = dbStore.addChatMessage(conversationId, {
    id: `msg-${Date.now()}-u`,
    conversationId,
    role: 'user',
    content: message,
    createdAt: new Date().toISOString(),
  });

  const conversation = dbStore.getConversation(conversationId);

  // Generate response
  const aiResponseText = await aiProvider.generateChatResponse({
    repositoryName: repo?.name ?? 'repository',
    securityScore: repo?.currentScore ?? 100,
    findings,
    userQuery: message,
    conversationHistory: conversation?.messages ?? [],
  });

  const assistantMsg = dbStore.addChatMessage(conversationId, {
    id: `msg-${Date.now()}-a`,
    conversationId,
    role: 'assistant',
    content: aiResponseText,
    createdAt: new Date().toISOString(),
  });

  res.json({
    userMessage: userMsg,
    assistantMessage: assistantMsg,
    conversationId,
  });
});

// GET /api/chat/:conversationId
apiRouter.get('/chat/:conversationId', (req: Request, res: Response) => {
  const conversation = dbStore.getConversation(req.params.conversationId);
  if (!conversation) {
    return res.status(404).json({ error: 'Conversation not found' });
  }
  res.json(conversation);
});
