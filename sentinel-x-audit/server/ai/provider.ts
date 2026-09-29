import {
  Finding,
  AIAnalysisResult,
  FindingClassification,
  RiskLevel,
  ChatMessage,
} from '../../src/types';

export interface FindingAnalysisInput {
  detectorType: string;
  secretCategory: string;
  filePath: string;
  lineNumber: number;
  redactedValue: string;
  contextSnippet: string;
  entropy: number;
  variableName?: string;
  isInDocumentation: boolean;
  isInTestFile: boolean;
  isInExampleFile: boolean;
  isPlaceholderOrExample: boolean;
}

export interface ChatContextInput {
  repositoryName: string;
  securityScore: number;
  findings: Finding[];
  userQuery: string;
  conversationHistory: ChatMessage[];
}

export interface AIProvider {
  name: string;
  analyzeFinding(input: FindingAnalysisInput): Promise<AIAnalysisResult>;
  generateChatResponse(input: ChatContextInput): Promise<string>;
}
