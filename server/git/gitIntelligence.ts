import { execFileSync } from 'child_process';
import path from 'path';

export interface CommitFixture {
  hash: string;
  date: string;
  author: string;
  message: string;
  filesChanged: string[];
  exposedSecrets: { category: string; file: string; action: 'INTRODUCED' | 'MODIFIED' | 'REMOVED' }[];
}

export interface GitExposureTimeline {
  firstSeenCommit: string;
  firstSeenDate: string;
  firstSeenAuthor: string;
  lastSeenCommit: string;
  lastSeenDate: string;
  lastSeenAuthor?: string;
  commitCount: number;
  isPresentInCurrentCommit: boolean;
  isRemovedInHead: boolean;
  branches: string[];
  historicalCommits: {
    hash: string;
    date: string;
    author: string;
    message: string;
    action: 'INTRODUCED' | 'MODIFIED' | 'REMOVED';
  }[];
}

/**
 * Generic deterministic fixture used only by the unit tests.
 * Production scans use analyzeGitHistoryInRepository() below.
 */
export function analyzeGitHistoryForSecret(
  secretCategory: string,
  filePath: string,
  isCurrentlyInWorkingTree: boolean
): GitExposureTimeline {
  const now = new Date().toISOString();
  return {
    firstSeenCommit: 'fixture-intro',
    firstSeenDate: now,
    firstSeenAuthor: 'Test Fixture',
    lastSeenCommit: 'fixture-remove',
    lastSeenDate: now,
    commitCount: 3,
    isPresentInCurrentCommit: isCurrentlyInWorkingTree,
    isRemovedInHead: !isCurrentlyInWorkingTree,
    branches: ['main'],
    historicalCommits: [
      {
        hash: 'fixture-intro',
        date: now,
        author: 'Test Fixture',
        message: `introduce ${secretCategory} in ${filePath}`,
        action: 'INTRODUCED',
      },
      {
        hash: 'fixture-update',
        date: now,
        author: 'Test Fixture',
        message: `modify ${filePath}`,
        action: 'MODIFIED',
      },
      {
        hash: 'fixture-remove',
        date: now,
        author: 'Test Fixture',
        message: `remove secret from ${filePath}`,
        action: 'REMOVED',
      },
    ],
  };
}

/**
 * Inspects real git history for a secret candidate without returning the raw secret.
 * Repositories without Git history fall back to working-tree metadata.
 */
export function analyzeGitHistoryInRepository(
  rootDir: string,
  filePath: string,
  secret: string
): GitExposureTimeline {
  const now = new Date().toISOString();
  const fallback: GitExposureTimeline = {
    firstSeenCommit: 'WORKING_TREE',
    firstSeenDate: now,
    firstSeenAuthor: 'Current Working Tree',
    lastSeenCommit: 'WORKING_TREE',
    lastSeenDate: now,
    lastSeenAuthor: 'Current Working Tree',
    commitCount: 1,
    isPresentInCurrentCommit: true,
    isRemovedInHead: false,
    branches: [],
    historicalCommits: [],
  };

  if (!secret || secret.length < 8) return fallback;

  try {
    const gitRoot = execFileSync('git', ['-C', rootDir, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5000,
    }).trim();
    if (!gitRoot) return fallback;

    const relativeFile = path.relative(gitRoot, path.resolve(rootDir, filePath));
    const log = execFileSync(
      'git',
      ['-C', gitRoot, 'log', '--all', '--date=iso-strict', '--format=%H%x1f%ad%x1f%an%x1e', '-p', '--', relativeFile],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10000, maxBuffer: 8 * 1024 * 1024 }
    );

    const commits = log.split('\x1e').map((block) => block.trim()).filter(Boolean).map((block) => {
      const sep = block.indexOf('\n');
      const header = sep >= 0 ? block.slice(0, sep) : block;
      const patch = sep >= 0 ? block.slice(sep + 1) : '';
      const parts = header.split('\x1f');
      return {
        hash: parts[0] || '',
        date: parts[1] || '',
        author: parts[2] || '',
        message: parts.slice(3).join('\x1f'),
        patch,
      };
    }).filter((c) => c.hash);

    const exposed = commits.filter((c) => c.patch.includes(secret));
    if (exposed.length === 0) return fallback;

    const historicalCommits: GitExposureTimeline['historicalCommits'] = exposed.map((c, index) => ({
      hash: c.hash.slice(0, 12),
      date: c.date,
      author: c.author,
      message: c.message,
      action: index === 0 ? 'INTRODUCED' : 'MODIFIED',
    }));

    let isPresentInCurrentCommit = true;
    try {
      const headContent = execFileSync('git', ['-C', gitRoot, 'show', `HEAD:${relativeFile}`], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 5000,
        maxBuffer: 4 * 1024 * 1024,
      });
      isPresentInCurrentCommit = headContent.includes(secret);
    } catch {
      isPresentInCurrentCommit = true;
    }

    if (!isPresentInCurrentCommit && historicalCommits.length > 0) {
      historicalCommits[historicalCommits.length - 1].action = 'REMOVED';
    }

    const first = exposed[exposed.length - 1];
    const last = exposed[0];

    return {
      firstSeenCommit: first.hash.slice(0, 12),
      firstSeenDate: first.date,
      firstSeenAuthor: first.author,
      lastSeenCommit: last.hash.slice(0, 12),
      lastSeenDate: last.date,
      lastSeenAuthor: last.author,
      commitCount: exposed.length,
      isPresentInCurrentCommit,
      isRemovedInHead: !isPresentInCurrentCommit,
      branches: [],
      historicalCommits,
    };
  } catch {
    return fallback;
  }
}
