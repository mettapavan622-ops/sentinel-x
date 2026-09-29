import { DetectionMatch, SecretCategory } from '../../src/types';
import { redactSecret } from './redaction';

export interface SecretDetector {
  id: string;
  name: string;
  category: SecretCategory;
  description: string;
  detect(content: string, filePath: string): DetectionMatch[];
}

export class DetectorRegistry {
  private detectors: Map<string, SecretDetector> = new Map();

  constructor() {
    this.registerDefaults();
  }

  public register(detector: SecretDetector): void {
    this.detectors.set(detector.id, detector);
  }

  public getDetectors(): SecretDetector[] {
    return Array.from(this.detectors.values());
  }

  public scanContent(content: string, filePath: string): DetectionMatch[] {
    const matches: DetectionMatch[] = [];
    for (const detector of this.detectors.values()) {
      const found = detector.detect(content, filePath);
      matches.push(...found);
    }
    return matches;
  }

  private registerDefaults(): void {
    // 1. AWS Access Key Detector
    this.register({
      id: 'aws-access-key',
      name: 'AWS Access Key ID',
      category: 'AWS_CREDENTIAL',
      description: 'Matches 20-character AWS Access Key IDs starting with AKIA or ASIA',
      detect: (content: string) => {
        const matches: DetectionMatch[] = [];
        const regex = /\b(AKIA[0-9A-Z]{16})\b/g;
        const lines = content.split('\n');

        lines.forEach((line, index) => {
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            matches.push({
              detectorId: 'aws-access-key',
              detectorName: 'AWS Access Key ID',
              category: 'AWS_CREDENTIAL',
              rawMatchedText: match[1],
              redactedValue: redactSecret(match[1]),
              lineNumber: index + 1,
              columnStart: match.index,
              columnEnd: match.index + match[1].length,
              patternConfidence: 0.98,
              matchedRule: 'AKIA[0-9A-Z]{16}',
            });
          }
        });
        return matches;
      },
    });

    // 2. Stripe Secret Key Detector
    this.register({
      id: 'stripe-secret-key',
      name: 'Stripe Secret Key',
      category: 'STRIPE_SECRET',
      description: 'Matches Stripe Live or Restricted Secret API Keys (sk_live_, rk_live_)',
      detect: (content: string) => {
        const matches: DetectionMatch[] = [];
        const regex = /\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b/g;
        const lines = content.split('\n');

        lines.forEach((line, index) => {
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            matches.push({
              detectorId: 'stripe-secret-key',
              detectorName: 'Stripe Live Secret Key',
              category: 'STRIPE_SECRET',
              rawMatchedText: match[1],
              redactedValue: redactSecret(match[1]),
              lineNumber: index + 1,
              columnStart: match.index,
              columnEnd: match.index + match[1].length,
              patternConfidence: 0.99,
              matchedRule: '(sk|rk)_live_[0-9a-zA-Z]{24,}',
            });
          }
        });
        return matches;
      },
    });

    // 3. GitHub Personal Access Token Detector
    this.register({
      id: 'github-token',
      name: 'GitHub Access Token',
      category: 'GITHUB_TOKEN',
      description: 'Matches GitHub classic (ghp_) or fine-grained (github_pat_) tokens',
      detect: (content: string) => {
        const matches: DetectionMatch[] = [];
        const regex = /\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b/g;
        const lines = content.split('\n');

        lines.forEach((line, index) => {
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            matches.push({
              detectorId: 'github-token',
              detectorName: 'GitHub Access Token',
              category: 'GITHUB_TOKEN',
              rawMatchedText: match[1],
              redactedValue: redactSecret(match[1]),
              lineNumber: index + 1,
              columnStart: match.index,
              columnEnd: match.index + match[1].length,
              patternConfidence: 0.97,
              matchedRule: 'ghp_[A-Za-z0-9_]{36}',
            });
          }
        });
        return matches;
      },
    });

    // 4. Google API Key Detector
    this.register({
      id: 'google-api-key',
      name: 'Google Cloud / Maps API Key',
      category: 'GOOGLE_API_KEY',
      description: 'Matches Google Cloud 39-character AIza API Keys',
      detect: (content: string) => {
        const matches: DetectionMatch[] = [];
        const regex = /\b(AIza[0-9A-Za-z\-_]{35})\b/g;
        const lines = content.split('\n');

        lines.forEach((line, index) => {
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            matches.push({
              detectorId: 'google-api-key',
              detectorName: 'Google API Key',
              category: 'GOOGLE_API_KEY',
              rawMatchedText: match[1],
              redactedValue: redactSecret(match[1]),
              lineNumber: index + 1,
              columnStart: match.index,
              columnEnd: match.index + match[1].length,
              patternConfidence: 0.95,
              matchedRule: 'AIza[0-9A-Za-z\\-_]{35}',
            });
          }
        });
        return matches;
      },
    });

    // 5. Database Connection String Detector
    this.register({
      id: 'database-uri',
      name: 'Database Connection String',
      category: 'DATABASE_URI',
      description: 'Matches postgresql, mysql, mongodb connection strings containing embedded credentials',
      detect: (content: string) => {
        const matches: DetectionMatch[] = [];
        const regex = /(?:postgres|postgresql|mysql|mongodb|mongodb\+srv):\/\/[^:\s'"]+:([^@\s'"]+)@[^\s'"]+/g;
        const lines = content.split('\n');

        lines.forEach((line, index) => {
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            const raw = match[0];
            matches.push({
              detectorId: 'database-uri',
              detectorName: 'Database URI with Password',
              category: 'DATABASE_URI',
              rawMatchedText: raw,
              redactedValue: redactSecret(raw),
              lineNumber: index + 1,
              columnStart: match.index,
              columnEnd: match.index + raw.length,
              patternConfidence: 0.94,
              matchedRule: '(postgres|mysql|mongodb)://user:pass@host',
            });
          }
        });
        return matches;
      },
    });

    // 6. Private Key Detector (RSA, OPENSSH, EC)
    this.register({
      id: 'private-key',
      name: 'Private Cryptographic Key',
      category: 'PRIVATE_KEY',
      description: 'Matches PEM formatted private key headers',
      detect: (content: string) => {
        const matches: DetectionMatch[] = [];
        const regex = /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g;
        const lines = content.split('\n');

        lines.forEach((line, index) => {
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            matches.push({
              detectorId: 'private-key',
              detectorName: 'Private Key PEM Block',
              category: 'PRIVATE_KEY',
              rawMatchedText: match[0],
              redactedValue: '-----BEGIN PRIVATE KEY••••••••END-----',
              lineNumber: index + 1,
              columnStart: match.index,
              columnEnd: match.index + match[0].length,
              patternConfidence: 0.99,
              matchedRule: 'BEGIN .* PRIVATE KEY',
            });
          }
        });
        return matches;
      },
    });

    // 7. JWT Token Detector
    this.register({
      id: 'jwt-token',
      name: 'JSON Web Token (JWT)',
      category: 'JWT_TOKEN',
      description: 'Matches standard 3-part base64 encoded JWTs starting with eyJ',
      detect: (content: string) => {
        const matches: DetectionMatch[] = [];
        const regex = /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g;
        const lines = content.split('\n');

        lines.forEach((line, index) => {
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            matches.push({
              detectorId: 'jwt-token',
              detectorName: 'JWT Bearer Token',
              category: 'JWT_TOKEN',
              rawMatchedText: match[1],
              redactedValue: redactSecret(match[1]),
              lineNumber: index + 1,
              columnStart: match.index,
              columnEnd: match.index + match[1].length,
              patternConfidence: 0.92,
              matchedRule: 'eyJ...eyJ...signature',
            });
          }
        });
        return matches;
      },
    });

    // 8. Slack Webhook Detector
    this.register({
      id: 'slack-webhook',
      name: 'Slack Webhook URL',
      category: 'SLACK_WEBHOOK',
      description: 'Matches Slack incoming webhook URLs',
      detect: (content: string) => {
        const matches: DetectionMatch[] = [];
        const regex = /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9A-Za-z]{24}/g;
        const lines = content.split('\n');

        lines.forEach((line, index) => {
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            matches.push({
              detectorId: 'slack-webhook',
              detectorName: 'Slack Incoming Webhook',
              category: 'SLACK_WEBHOOK',
              rawMatchedText: match[0],
              redactedValue: redactSecret(match[0]),
              lineNumber: index + 1,
              columnStart: match.index,
              columnEnd: match.index + match[0].length,
              patternConfidence: 0.99,
              matchedRule: 'hooks.slack.com/services/...',
            });
          }
        });
        return matches;
      },
    });

    // 9. Generic API Key & Password Assignment Detector
    this.register({
      id: 'generic-api-key',
      name: 'Generic Hardcoded Credential / API Key',
      category: 'GENERIC_API_KEY',
      description: 'Matches hardcoded strings assigned to credential-like variable names',
      detect: (content: string) => {
        const matches: DetectionMatch[] = [];
        const regex = /(?:api_?key|secret_?key|auth_?token|client_?secret|private_?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']/gi;
        const lines = content.split('\n');

        lines.forEach((line, index) => {
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            const secretValue = match[1];
            // Filter out known placeholders
            if (
              !secretValue.toLowerCase().includes('example') &&
              !secretValue.toLowerCase().includes('dummy') &&
              !secretValue.toLowerCase().includes('your')
            ) {
              matches.push({
                detectorId: 'generic-api-key',
                detectorName: 'Generic Hardcoded Secret',
                category: 'GENERIC_API_KEY',
                rawMatchedText: secretValue,
                redactedValue: redactSecret(secretValue),
                lineNumber: index + 1,
                columnStart: match.index,
                columnEnd: match.index + match[0].length,
                patternConfidence: 0.82,
                matchedRule: 'api_key = "[A-Za-z0-9_-]{20,}"',
              });
            }
          }
        });
        return matches;
      },
    });
  }
}

export const detectorRegistry = new DetectorRegistry();
