import fs from 'fs';
import path from 'path';
import {
  Finding,
  Scan,
  Repository,
  RemediationAction,
  SecurityScoreRecord,
  ChatConversation,
  ChatMessage,
} from '../../src/types';

export interface DatabaseState {
  repositories: Repository[];
  scans: Scan[];
  findings: Finding[];
  remediationActions: RemediationAction[];
  securityScores: SecurityScoreRecord[];
  conversations: ChatConversation[];
}

const DATA_FILE = path.join(process.cwd(), '.sentinel-data.json');

class DataStore {
  private state: DatabaseState = {
    repositories: [],
    scans: [],
    findings: [],
    remediationActions: [],
    securityScores: [],
    conversations: [],
  };

  constructor() {
    this.load();
  }

  private load(): void {
    try {
      if (fs.existsSync(DATA_FILE)) {
        const raw = fs.readFileSync(DATA_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
          this.state = {
            repositories: Array.isArray(parsed.repositories) ? parsed.repositories : [],
            scans: Array.isArray(parsed.scans) ? parsed.scans : [],
            findings: Array.isArray(parsed.findings) ? parsed.findings : [],
            remediationActions: Array.isArray(parsed.remediationActions) ? parsed.remediationActions : [],
            securityScores: Array.isArray(parsed.securityScores) ? parsed.securityScores : [],
            conversations: Array.isArray(parsed.conversations) ? parsed.conversations : [],
          };
        }
      }

      if (this.state.repositories.length === 0) {
        this.seedInitialData();
      }
    } catch (err) {
      console.warn('[DataStore] .sentinel-data.json could not be loaded, re-initializing store:', err);
      // fallback to memory and re-seed
      this.seedInitialData();
    }
  }

  private save(): void {
    try {
      const tempFile = `${DATA_FILE}.tmp`;
      fs.writeFileSync(tempFile, JSON.stringify(this.state, null, 2), 'utf-8');
      fs.renameSync(tempFile, DATA_FILE);
    } catch {
      // safe fallback direct write
      try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(this.state, null, 2), 'utf-8');
      } catch {
        // safe ignore in readonly environments
      }
    }
  }

  /**
   * Reset the local datastore to default state with the active workspace repository.
   */
  public seedInitialData(): void {
    const defaultRepo: Repository = {
      id: 'repo-sentinel-x',
      name: 'sentinel-x (workspace)',
      path: process.cwd(),
      defaultBranch: 'main',
      currentScore: 100,
      preventionModeEnabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    this.state = {
      repositories: [defaultRepo],
      scans: [],
      findings: [],
      remediationActions: [],
      securityScores: [],
      conversations: [],
    };
    this.save();
  }

  // Repository Methods
  public getRepositories(): Repository[] {
    return this.state.repositories;
  }

  public getRepository(id: string): Repository | undefined {
    return this.state.repositories.find((repo) => repo.id === id);
  }

  public createRepository(repository: Repository): Repository {
    this.state.repositories.unshift(repository);
    this.save();
    return repository;
  }

  public updateRepository(id: string, updates: Partial<Repository>): Repository | undefined {
    const repository = this.state.repositories.find((repo) => repo.id === id);
    if (!repository) return undefined;
    Object.assign(repository, updates, { updatedAt: new Date().toISOString() });
    this.save();
    return repository;
  }

  // Scan Methods
  public getScans(repositoryId?: string): Scan[] {
    if (repositoryId) {
      return this.state.scans.filter((s) => s.repositoryId === repositoryId);
    }
    return this.state.scans;
  }

  public getScan(id: string): Scan | undefined {
    return this.state.scans.find((s) => s.id === id);
  }

  public createScan(scan: Scan): Scan {
    this.state.scans.unshift(scan);
    this.save();
    return scan;
  }

  public updateScan(id: string, updates: Partial<Scan>): Scan | undefined {
    const scan = this.state.scans.find((s) => s.id === id);
    if (!scan) return undefined;
    Object.assign(scan, updates);
    this.save();
    return scan;
  }

  // Finding Methods
  public getFindings(filter?: {
    repositoryId?: string;
    scanId?: string;
    riskLevel?: string;
    status?: string;
    secretCategory?: string;
  }): Finding[] {
    let list = [...this.state.findings];
    if (filter?.repositoryId) {
      list = list.filter((f) => f.repositoryId === filter.repositoryId);
    }
    if (filter?.scanId) {
      list = list.filter((f) => f.scanId === filter.scanId);
    }
    if (filter?.riskLevel) {
      list = list.filter((f) => f.riskLevel === filter.riskLevel);
    }
    if (filter?.status) {
      list = list.filter((f) => f.status === filter.status);
    }
    if (filter?.secretCategory) {
      list = list.filter((f) => f.secretCategory === filter.secretCategory);
    }
    return list;
  }

  public getFinding(id: string): Finding | undefined {
    return this.state.findings.find((f) => f.id === id);
  }

  public updateFinding(id: string, updates: Partial<Finding>): Finding | undefined {
    const finding = this.state.findings.find((f) => f.id === id);
    if (!finding) return undefined;
    Object.assign(finding, updates, { updatedAt: new Date().toISOString() });
    this.save();
    return finding;
  }

  public replaceFindingsForScan(scanId: string, newFindings: Finding[]): void {
    this.state.findings = this.state.findings.filter((f) => f.scanId !== scanId).concat(newFindings);
    this.save();
  }

  public replaceFindingsForRepository(repositoryId: string, newFindings: Finding[]): void {
    this.state.findings = this.state.findings.filter((f) => f.repositoryId !== repositoryId).concat(newFindings);
    this.save();
  }

  // Remediation Methods
  public getRemediationActions(findingId?: string): RemediationAction[] {
    if (findingId) {
      return this.state.remediationActions.filter((r) => r.findingId === findingId);
    }
    return this.state.remediationActions;
  }

  public addRemediationAction(action: RemediationAction): RemediationAction {
    this.state.remediationActions.push(action);
    this.save();
    return action;
  }

  // Security Score Methods
  public getSecurityScores(repositoryId?: string): SecurityScoreRecord[] {
    if (repositoryId) {
      return this.state.securityScores.filter((s) => s.repositoryId === repositoryId);
    }
    return this.state.securityScores;
  }

  public addSecurityScore(record: SecurityScoreRecord): SecurityScoreRecord {
    this.state.securityScores.push(record);
    const repo = this.state.repositories.find((r) => r.id === record.repositoryId);
    if (repo) {
      repo.currentScore = record.score;
      repo.updatedAt = new Date().toISOString();
    }
    this.save();
    return record;
  }

  // Chat Conversations
  public getConversations(): ChatConversation[] {
    return this.state.conversations;
  }

  public getConversation(id: string): ChatConversation | undefined {
    return this.state.conversations.find((c) => c.id === id);
  }

  public addChatMessage(conversationId: string, message: ChatMessage): ChatMessage {
    let conv = this.state.conversations.find((c) => c.id === conversationId);
    if (!conv) {
      conv = {
        id: conversationId,
        title: 'Security Conversation',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        messages: [],
      };
      this.state.conversations.push(conv);
    }
    conv.messages.push(message);
    conv.updatedAt = new Date().toISOString();
    this.save();
    return message;
  }
}

export const dbStore = new DataStore();
