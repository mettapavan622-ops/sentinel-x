// SENTINEL-X Core Types & Interfaces

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus = 'OPEN' | 'IN_REMEDIATION' | 'REMEDIATED' | 'FALSE_POSITIVE' | 'IGNORED';

export type FindingClassification = 'true_positive' | 'likely_positive' | 'false_positive' | 'uncertain';

export type SecretCategory =
  | 'AWS_CREDENTIAL'
  | 'STRIPE_SECRET'
  | 'GITHUB_TOKEN'
  | 'GOOGLE_API_KEY'
  | 'DATABASE_URI'
  | 'PRIVATE_KEY'
  | 'JWT_TOKEN'
  | 'GENERIC_API_KEY'
  | 'GENERIC_PASSWORD'
  | 'SLACK_WEBHOOK';

export interface DetectionMatch {
  detectorId: string;
  detectorName: string;
  category: SecretCategory;
  rawMatchedText: string;
  redactedValue: string;
  lineNumber: number;
  columnStart: number;
  columnEnd: number;
  patternConfidence: number;
  matchedRule: string;
}

export interface EntropyScore {
  entropy: number; // Raw Shannon entropy e.g. 4.2
  normalizedScore: number; // 0.0 - 1.0
  characterSetSize: number;
  isHighEntropy: boolean;
}

export interface ContextAnalysisResult {
  variableName?: string;
  isAssignment: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  isInExampleFile: boolean;
  isPlaceholderOrExample: boolean;
  isReferencedInCode: boolean;
  commentContext?: string;
  contextScore: number; // 0.0 - 1.0 (higher means more likely real secret in prod code)
  signals: string[];
}

export interface AttackNode {
  id: string;
  type: 'CREDENTIAL' | 'IAM_IDENTITY' | 'CLOUD_SERVICE' | 'DATA_STORE' | 'IMPACT';
  label: string;
  description: string;
  risk: RiskLevel;
  icon?: string;
}

export interface AttackEdge {
  source: string;
  target: string;
  reason: string;
  protocol?: string;
}

export interface AttackPath {
  summary: string;
  estimatedBlastRadius: 'LOCAL' | 'SERVICE' | 'INFRASTRUCTURE' | 'ORGANIZATION';
  nodes: AttackNode[];
  edges: AttackEdge[];
}

export interface GitExposureTimeline {
  firstSeenCommit: string;
  firstSeenDate: string;
  firstSeenAuthor: string;
  lastSeenCommit: string;
  lastSeenDate: string;
  commitCount: number;
  isPresentInCurrentCommit: boolean;
  isRemovedInHead: boolean;
  branches: string[];
  historicalCommits: Array<{
    hash: string;
    date: string;
    author: string;
    message: string;
    action: 'INTRODUCED' | 'MODIFIED' | 'REMOVED';
  }>;
}

export interface AIAnalysisResult {
  classification: FindingClassification;
  confidence: number;
  reason: string;
  riskLevel: RiskLevel;
  recommendedAction: 'rotate_and_remove' | 'verify_permissions' | 'mark_as_test_fixture' | 'dismiss_false_positive';
  detailedRemediationSteps: string[];
  providerUsed: string;
}

export interface Finding {
  id: string;
  scanId: string;
  repositoryId: string;
  detectorType: string;
  secretCategory: SecretCategory;
  filePath: string;
  lineNumber: number;
  commitHash?: string;
  firstSeen: string;
  lastSeen: string;
  confidence: number; // Combined 0.0 - 1.0
  entropyScore: EntropyScore;
  contextAnalysis: ContextAnalysisResult;
  riskLevel: RiskLevel;
  status: FindingStatus;
  classification: FindingClassification;
  redactedValue: string;
  contextSnippet: string;
  attackPath: AttackPath;
  gitExposure: GitExposureTimeline;
  aiAnalysis?: AIAnalysisResult;
  remediationActionId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Scan {
  id: string;
  repositoryId: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  filesScanned: number;
  commitsScanned: number;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  securityScoreBefore: number;
  securityScoreAfter?: number;
  startedAt: string;
  completedAt?: string;
  error?: string;
}

export interface Repository {
  id: string;
  name: string;
  path: string;
  defaultBranch: string;
  lastScannedAt?: string;
  currentScore: number;
  preventionModeEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface RemediationAction {
  id: string;
  findingId: string;
  actionType: 'SIMULATE_REVOKE' | 'SIMULATE_ROTATE' | 'CODE_REPLACEMENT' | 'GIT_HISTORY_CLEANUP' | 'VERIFICATION_SCAN' | 'FULL_PIPELINE';
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
  details: {
    revokedAt?: string;
    rotatedKeyPlaceholder?: string;
    envVariableName?: string;
    replacementDiff?: string;
    historyCleanupCommand?: string;
    verificationResult?: 'CLEAN' | 'STILL_DETECTED';
  };
  createdAt: string;
  completedAt?: string;
}

export interface SecurityScoreRecord {
  id: string;
  repositoryId: string;
  score: number;
  breakdown: {
    criticalFindingsPenalty: number;
    highFindingsPenalty: number;
    mediumFindingsPenalty: number;
    historicalExposurePenalty: number;
    remediationBonus: number;
    preventionBonus: number;
  };
  calculatedAt: string;
}

export interface ChatMessage {
  id: string;
  conversationId: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  createdAt: string;
}

export interface ChatConversation {
  id: string;
  title: string;
  repositoryId?: string;
  createdAt: string;
  updatedAt: string;
  messages: ChatMessage[];
}

export interface PreventionScanResult {
  blocked: boolean;
  exitCode: 0 | 1;
  summary: string;
  blockingFindings: Array<{
    category: SecretCategory;
    file: string;
    line: number;
    redactedValue: string;
    risk: RiskLevel;
    suggestedFix: string;
  }>;
  terminalOutput: string;
  timestamp: string;
}
