import { GoogleGenAI, Type } from '@google/genai';
import { AIProvider, FindingAnalysisInput, ChatContextInput } from './provider';
import { AIAnalysisResult } from '../../src/types';
import { LocalFallbackProvider } from './localFallbackProvider';

export class GeminiProvider implements AIProvider {
  private model = process.env.GEMINI_MODEL || 'gemini-3.8-flash';
  public name = `Google Gemini (${this.model})`;
  private fallback: LocalFallbackProvider;
  private client: GoogleGenAI | null = null;

  constructor() {
    this.fallback = new LocalFallbackProvider();
    const apiKey = process.env.GEMINI_API_KEY || process.env.AI_API_KEY;
    if (apiKey && apiKey !== 'MY_GEMINI_API_KEY') {
      try {
        this.client = new GoogleGenAI({
          apiKey,
          httpOptions: {
            headers: {
              'User-Agent': 'aistudio-build',
            },
          },
        });
      } catch {
        this.client = null;
      }
    }
  }

  private withTimeout<T>(promise: Promise<T>, timeoutMs = 8000): Promise<T> {
    return Promise.race([
      promise,
      new Promise<T>((_, reject) =>
        setTimeout(() => reject(new Error(`AI operation timed out after ${timeoutMs}ms`)), timeoutMs)
      ),
    ]);
  }

  public async analyzeFinding(input: FindingAnalysisInput): Promise<AIAnalysisResult> {
    if (!this.client) {
      return this.fallback.analyzeFinding(input);
    }

    try {
      const prompt = `You are SENTINEL-X, a senior cybersecurity static analysis and threat-modeling AI.
Analyze the following detected credential candidate and classify it as true_positive, likely_positive, false_positive, or uncertain.

Finding Context:
- Secret Category: ${input.secretCategory}
- Detector Rule: ${input.detectorType}
- File Path: ${input.filePath}
- Line Number: ${input.lineNumber}
- Variable Name: ${input.variableName || 'N/A'}
- Redacted Value: ${input.redactedValue}
- Shannon Entropy: ${input.entropy}
- In Test File: ${input.isInTestFile}
- In Documentation: ${input.isInDocumentation}
- In Example File: ${input.isInExampleFile}
- Placeholder Patterns: ${input.isPlaceholderOrExample}

Code Snippet:
${input.contextSnippet}

Return structured JSON evaluating whether this is an active credential or documentation/test placeholder. Do NOT claim the credential is verified active on the remote server; speak in terms of probable risk, syntactic validity, and potential exposure.`;

      const response = await this.withTimeout(
        this.client.models.generateContent({
          model: this.model,
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                classification: {
                  type: Type.STRING,
                  description: 'true_positive | likely_positive | false_positive | uncertain',
                },
                confidence: {
                  type: Type.NUMBER,
                  description: 'Confidence between 0.0 and 1.0',
                },
                reason: {
                  type: Type.STRING,
                  description: 'Detailed threat explanation and reasoning',
                },
                riskLevel: {
                  type: Type.STRING,
                  description: 'CRITICAL | HIGH | MEDIUM | LOW | INFO',
                },
                recommendedAction: {
                  type: Type.STRING,
                  description: 'rotate_and_remove | verify_permissions | mark_as_test_fixture | dismiss_false_positive',
                },
                detailedRemediationSteps: {
                  type: Type.ARRAY,
                  items: { type: Type.STRING },
                  description: 'List of actionable remediation steps',
                },
              },
              required: ['classification', 'confidence', 'reason', 'riskLevel', 'recommendedAction', 'detailedRemediationSteps'],
            },
          },
        })
      );

      const parsed = JSON.parse(response.text?.trim() || '{}');
      return {
        classification: parsed.classification || 'true_positive',
        confidence: parsed.confidence || 0.9,
        reason: parsed.reason || 'AI verified potential secret leak.',
        riskLevel: parsed.riskLevel || 'HIGH',
        recommendedAction: parsed.recommendedAction || 'rotate_and_remove',
        detailedRemediationSteps: parsed.detailedRemediationSteps || ['Rotate credential', 'Update environment variables'],
        providerUsed: this.name,
      };
    } catch {
      // Graceful fallback to deterministic local logic
      return this.fallback.analyzeFinding(input);
    }
  }

  public async generateChatResponse(input: ChatContextInput): Promise<string> {
    if (!this.client) {
      return this.fallback.generateChatResponse(input);
    }

    try {
      const prompt = `You are SENTINEL-X, the AI-Powered Secret Leak Detection & Prevention Assistant.
You have analyzed repository '${input.repositoryName}'.
Current Security Score: ${input.securityScore}/100.

Active Findings Summary:
${input.findings.map((f) => `- [${f.riskLevel}] ${f.secretCategory} at ${f.filePath}:${f.lineNumber} (${f.redactedValue}) - Status: ${f.status}`).join('\n')}

User Query:
"${input.userQuery}"

Provide a concise, highly technical, and actionable cybersecurity response using markdown formatting. Explain risk levels, blast radius, potential attack paths, and remediation instructions clearly.`;

      const response = await this.withTimeout(
        this.client.models.generateContent({
          model: this.model,
          contents: prompt,
        }),
        8000
      );

      return response.text?.trim() || (await this.fallback.generateChatResponse(input));
    } catch {
      return this.fallback.generateChatResponse(input);
    }
  }
}
