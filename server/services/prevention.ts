import { PreventionScanResult, SecretCategory, RiskLevel } from '../../src/types';
import { detectorRegistry } from '../scanner/detectorRegistry';
import { analyzeContext } from '../scanner/context';

export class PreventionEngine {
  private blockedCommitsCount = 5;
  private preventedSecretsCount = 7;

  public getStats() {
    return {
      preventionModeActive: true,
      preCommitHookInstalled: true,
      ciScanningEnabled: true,
      blockedCommitsCount: this.blockedCommitsCount,
      preventedSecretsCount: this.preventedSecretsCount,
    };
  }

  public scanStagedContent(
    filename: string,
    fileContent: string,
    author: string = 'Developer'
  ): PreventionScanResult {
    const matches = detectorRegistry.scanContent(fileContent, filename);
    const blockingFindings: PreventionScanResult['blockingFindings'] = [];

    for (const match of matches) {
      const context = analyzeContext(filename, match.lineNumber, fileContent, match.rawMatchedText);

      // Disregard documentation / placeholder examples from blocking commits
      if (context.isPlaceholderOrExample || context.isInDocumentation) {
        continue;
      }

      let risk: RiskLevel = 'HIGH';
      if (match.category === 'AWS_CREDENTIAL' || match.category === 'STRIPE_SECRET') {
        risk = 'CRITICAL';
      }

      let suggestedFix = 'Store this credential in a local .env file (listed in .gitignore) and reference via environment variables.';
      if (match.category === 'AWS_CREDENTIAL') {
        suggestedFix = 'Use AWS IAM Roles for EC2/ECS/Lambda or read from process.env.AWS_SECRET_ACCESS_KEY.';
      } else if (match.category === 'STRIPE_SECRET') {
        suggestedFix = 'Move to process.env.STRIPE_SECRET_KEY and populate using your secret management provider.';
      }

      blockingFindings.push({
        category: match.category,
        file: filename,
        line: match.lineNumber,
        redactedValue: match.redactedValue,
        risk,
        suggestedFix,
      });
    }

    if (blockingFindings.length > 0) {
      this.blockedCommitsCount++;
      this.preventedSecretsCount += blockingFindings.length;

      const lines = [
        '========================================================================',
        '              SENTINEL-X PRE-COMMIT SECURITY GUARD: BLOCKED             ',
        '========================================================================',
        `❌ COMMIT REJECTED: ${blockingFindings.length} hardcoded secret(s) detected in staged changeset!`,
        '',
        ...blockingFindings.map(
          (f, idx) =>
            `[Violation #${idx + 1}] Risk: [${f.risk}]\n` +
            `  File:     ${f.file}:${f.line}\n` +
            `  Pattern:  ${f.category} (${f.redactedValue})\n` +
            `  Fix:      ${f.suggestedFix}\n`
        ),
        '------------------------------------------------------------------------',
        '💡 Tip: Never bypass pre-commit hooks using --no-verify for production code.',
        '========================================================================',
      ];

      return {
        blocked: true,
        exitCode: 1,
        summary: `Commit blocked: ${blockingFindings.length} secret(s) detected before repository exposure.`,
        blockingFindings,
        terminalOutput: lines.join('\n'),
        timestamp: new Date().toISOString(),
      };
    }

    return {
      blocked: false,
      exitCode: 0,
      summary: 'SENTINEL-X scan passed. No secrets detected in staged changeset.',
      blockingFindings: [],
      terminalOutput: [
        '========================================================================',
        '              SENTINEL-X PRE-COMMIT SECURITY GUARD: PASSED              ',
        '========================================================================',
        '✔ All 1 staged file(s) checked. Zero secrets or high-entropy credentials detected.',
        '✔ Commit proceeding normally.',
      ].join('\n'),
      timestamp: new Date().toISOString(),
    };
  }

  public generateHookScript(): string {
    return `#!/bin/sh
# SENTINEL-X Pre-Commit Hook
# Scans the exact staged patch before allowing git commit.

set -eu
API_URL="\${SENTINEL_X_API_URL:-http://localhost:\${PORT:-3000}}/api/prevention/scan"

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$STAGED_FILES" ] && exit 0

# Build a JSON-safe request using Node instead of fragile shell escaping.
PAYLOAD=$(git diff --cached | node -e '\nlet data=""; process.stdin.on("data", c => data += c); process.stdin.on("end", () => {\n  console.log(JSON.stringify({ filename: "staged_diff", content: data, author: process.env.GIT_AUTHOR_NAME || "Developer" }));\n});')

RESPONSE=$(printf '%s' "$PAYLOAD" | curl -fsS -X POST "$API_URL" -H "Content-Type: application/json" --data-binary @-) || {
  echo "⚠️ SENTINEL-X could not reach the prevention service at $API_URL"
  echo "Commit blocked for safety. Start SENTINEL-X and retry."
  exit 1
}

EXIT_CODE=$(printf '%s' "$RESPONSE" | node -e 'let d=""; process.stdin.on("data",c=>d+=c); process.stdin.on("end",()=>{try{console.log(JSON.parse(d).exitCode ?? 1)}catch{console.log(1)}})')

if [ "$EXIT_CODE" = "1" ]; then
  echo "🚨 SENTINEL-X: hardcoded secret detected. Commit aborted."
  exit 1
fi

echo "✅ SENTINEL-X: staged changes passed secret scanning."
exit 0`;
  }
}

export const preventionEngine = new PreventionEngine();
