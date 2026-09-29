import fs from 'fs';
import path from 'path';
import { Finding, RiskLevel, FindingClassification, FindingStatus } from '../../src/types';
import { detectorRegistry } from './detectorRegistry';
import { evaluateEntropy } from './entropy';
import { analyzeContext } from './context';
import { generateAttackPathForFinding } from '../services/attackPath';
import { analyzeGitHistoryInRepository } from '../git/gitIntelligence';

const IGNORED_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  'vendor',
  '.next',
  '.cache',
  'artifacts',
]);

const IGNORED_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.svg',
  '.ico',
  '.pdf',
  '.zip',
  '.tar',
  '.gz',
  '.lock',
  '.log',
  '.map',
  '.wasm',
]);

const MAX_FILE_SIZE = 1024 * 1024; // 1 MB limit per file to prevent memory exhaustion

export interface ScanProgressCallback {
  (step: string, percent: number, details?: string): void;
}

export function scanDirectory(
  rootDir: string,
  scanId: string,
  repositoryId: string,
  onProgress?: ScanProgressCallback
): { findings: Finding[]; scannedFileCount: number } {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  let scannedFileCount = 0;

  function walk(currentDir: string) {
    if (!fs.existsSync(currentDir)) return;
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relativePath = path.relative(rootDir, fullPath);

      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name)) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (IGNORED_EXTENSIONS.has(ext)) continue;

        try {
          const stats = fs.statSync(fullPath);
          if (stats.size > MAX_FILE_SIZE) continue;

          scannedFileCount++;
          if (onProgress && scannedFileCount % 5 === 0) {
            onProgress(`Scanning ${relativePath}`, Math.min(60, 10 + scannedFileCount * 2));
          }

          const content = fs.readFileSync(fullPath, 'utf-8');
          const matches = detectorRegistry.scanContent(content, relativePath);

          for (const match of matches) {
            const dedupeKey = `${relativePath}:${match.lineNumber}:${match.columnStart}:${match.category}:${match.redactedValue}`;
            if (seen.has(dedupeKey)) continue;
            seen.add(dedupeKey);

            const entropyScore = evaluateEntropy(match.rawMatchedText);
            const contextAnalysis = analyzeContext(relativePath, match.lineNumber, content, match.rawMatchedText);

            // Compute combined confidence score
            const combinedConfidence = Math.round(
              (match.patternConfidence * 0.45 + entropyScore.normalizedScore * 0.25 + contextAnalysis.contextScore * 0.3) * 100
            ) / 100;

            // Classify finding
            let classification: FindingClassification = 'true_positive';
            let riskLevel: RiskLevel = 'HIGH';

            if (contextAnalysis.isPlaceholderOrExample || contextAnalysis.isInDocumentation) {
              classification = 'false_positive';
              riskLevel = 'INFO';
            } else if (contextAnalysis.isInTestFile) {
              classification = 'likely_positive';
              riskLevel = 'LOW';
            } else {
              if (match.category === 'AWS_CREDENTIAL' || match.category === 'STRIPE_SECRET') {
                riskLevel = 'CRITICAL';
              } else if (match.category === 'DATABASE_URI' || match.category === 'PRIVATE_KEY' || match.category === 'GITHUB_TOKEN') {
                riskLevel = 'HIGH';
              } else {
                riskLevel = 'MEDIUM';
              }
            }

            const lines = content.split('\n');
            const startLine = Math.max(0, match.lineNumber - 2);
            const endLine = Math.min(lines.length, match.lineNumber + 2);
            const contextSnippet = lines.slice(startLine, endLine).join('\n');

            const findingId = `find-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

            const attackPath = generateAttackPathForFinding({
              category: match.category,
              filePath: relativePath,
              riskLevel,
              redactedValue: match.redactedValue,
            });

            const finding: Finding = {
              id: findingId,
              scanId,
              repositoryId,
              detectorType: match.detectorId,
              secretCategory: match.category,
              filePath: relativePath,
              lineNumber: match.lineNumber,
              firstSeen: new Date().toISOString(),
              lastSeen: new Date().toISOString(),
              confidence: combinedConfidence,
              entropyScore,
              contextAnalysis,
              riskLevel,
              status: classification === 'false_positive' ? 'FALSE_POSITIVE' : 'OPEN',
              classification,
              redactedValue: match.redactedValue,
              contextSnippet,
              attackPath,
              gitExposure: analyzeGitHistoryInRepository(rootDir, relativePath, match.rawMatchedText),
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            };

            findings.push(finding);
          }
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  walk(rootDir);
  return { findings, scannedFileCount };
}
