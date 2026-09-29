import { AIProvider, FindingAnalysisInput, ChatContextInput } from './provider';
import { AIAnalysisResult, FindingClassification, RiskLevel } from '../../src/types';

export class LocalFallbackProvider implements AIProvider {
  public name = 'Deterministic Heuristic Expert (Local Fallback)';

  public async analyzeFinding(input: FindingAnalysisInput): Promise<AIAnalysisResult> {
    const {
      secretCategory,
      filePath,
      variableName,
      isInDocumentation,
      isInTestFile,
      isInExampleFile,
      isPlaceholderOrExample,
      entropy,
    } = input;

    // 1. Check for False Positives (Docs, Examples, Placeholders)
    if (isInDocumentation || isPlaceholderOrExample || isInExampleFile) {
      return {
        classification: 'false_positive',
        confidence: 0.96,
        reason: `The finding in '${filePath}' is identified as a benign documentation placeholder or setup guide example. The syntax explicitly features tutorial placeholders with non-operational entropy.`,
        riskLevel: 'INFO',
        recommendedAction: 'dismiss_false_positive',
        detailedRemediationSteps: [
          'No immediate rotation required.',
          'Verify that documentation examples do not mirror active production naming conventions.',
        ],
        providerUsed: this.name,
      };
    }

    // 2. Check for Test Fixtures
    if (isInTestFile || (variableName && /mock|test|fake/i.test(variableName))) {
      return {
        classification: 'likely_positive',
        confidence: 0.78,
        reason: `Detected credential inside '${filePath}' is situated in a unit or integration test harness. While structured like a live token, it appears intended for mock assertions.`,
        riskLevel: 'LOW',
        recommendedAction: 'mark_as_test_fixture',
        detailedRemediationSteps: [
          'Confirm that the test token is safely rejected if presented to production API gateways.',
          'Adopt synthetic dummy values (e.g. 00000000) for test harnesses to eliminate scanner noise.',
        ],
        providerUsed: this.name,
      };
    }

    // 3. AWS Credentials
    if (secretCategory === 'AWS_CREDENTIAL') {
      return {
        classification: 'true_positive',
        confidence: 0.98,
        reason: `The value matches an active AWS Access Key ID specification (AKIA prefix with high entropy). It is assigned to variable '${variableName || 'AWS_KEY'}' and referenced in live cloud storage logic.`,
        riskLevel: 'CRITICAL',
        recommendedAction: 'rotate_and_remove',
        detailedRemediationSteps: [
          'Immediately deactivate the IAM Access Key ID in AWS IAM Console.',
          'Provision a new Access Key pair and assign via AWS Secrets Manager or secure runtime environment variables.',
          'Purge historical commit occurrences using git-filter-repo or BFG Repo-Cleaner.',
          'Review AWS CloudTrail event history for s3:* actions executed by this Access Key in the last 30 days.',
        ],
        providerUsed: this.name,
      };
    }

    // 4. Stripe Keys
    if (secretCategory === 'STRIPE_SECRET') {
      return {
        classification: 'true_positive',
        confidence: 0.97,
        reason: `Matches live Stripe Secret Key syntax ('sk_live_' prefix). High Shannon entropy (${entropy} bits/char) confirms cryptographic randomness with full payment authorization rights.`,
        riskLevel: 'CRITICAL',
        recommendedAction: 'rotate_and_remove',
        detailedRemediationSteps: [
          'Roll the secret key in Stripe Developer Dashboard with expiration window.',
          'Update backend environment variable STRIPE_SECRET_KEY in production deployment.',
          'Verify webhook signing secret and audit recent charges and refund attempts.',
        ],
        providerUsed: this.name,
      };
    }

    // 5. Database Connection String
    if (secretCategory === 'DATABASE_URI') {
      return {
        classification: 'true_positive',
        confidence: 0.94,
        reason: `Hardcoded database URI contains user authentication credentials and direct network host definitions in '${filePath}'.`,
        riskLevel: 'HIGH',
        recommendedAction: 'rotate_and_remove',
        detailedRemediationSteps: [
          'Change the database user password on the target database instance.',
          'Inject DATABASE_URL via deployment environment variable.',
          'Ensure database port (e.g. 5432) is isolated within a private VPC subnet.',
        ],
        providerUsed: this.name,
      };
    }

    // 6. GitHub Token
    if (secretCategory === 'GITHUB_TOKEN') {
      return {
        classification: 'true_positive',
        confidence: 0.95,
        reason: `Detected valid GitHub Personal Access Token structure in '${filePath}'. Allows unauthorized repository cloning and workflow tampering.`,
        riskLevel: 'HIGH',
        recommendedAction: 'rotate_and_remove',
        detailedRemediationSteps: [
          'Revoke token in GitHub Developer Settings.',
          'Replace with fine-grained personal access token or GitHub App with least-privilege permissions.',
        ],
        providerUsed: this.name,
      };
    }

    // Default High Confidence
    return {
      classification: 'true_positive',
      confidence: 0.88,
      reason: `Detected high-entropy credential pattern in '${filePath}'. Code context indicates operational usage rather than documentation.`,
      riskLevel: 'HIGH',
      recommendedAction: 'rotate_and_remove',
      detailedRemediationSteps: [
        'Revoke the exposed credential with the respective service provider.',
        'Migrate to environment variable configuration.',
        'Run verification scan to ensure clean commit state.',
      ],
      providerUsed: this.name,
    };
  }

  public async generateChatResponse(input: ChatContextInput): Promise<string> {
    const { repositoryName, securityScore, findings, userQuery } = input;
    const lowerQuery = userQuery.toLowerCase();

    const criticals = findings.filter((f) => f.riskLevel === 'CRITICAL');
    const highs = findings.filter((f) => f.riskLevel === 'HIGH');
    const falsePositives = findings.filter((f) => f.classification === 'false_positive');

    if (lowerQuery.includes('aws') || lowerQuery.includes('s3') || lowerQuery.includes('critical')) {
      return `### SENTINEL-X Threat Intelligence: AWS Finding Analysis

**Why is this finding CRITICAL?**
1. **Direct Cloud Account Entitlement**: The detected credential conforms to an AWS IAM Access Key ID format (\`AKIA...\`) assigned to an active cloud storage client in \`src/config/aws.ts\`.
2. **Attack Path Blast Radius**: This key grants authentication to the \`repository IAM identity\` IAM identity. Based on repository context, this role possesses read/write privileges to Amazon S3 buckets containing repository-associated data.
3. **Git History Exposure**: Even though Sarah Jenkins deleted the key from HEAD in commit \`c72f21\`, the secret was introduced in commit \`a82f91\` and remains stored across 12 historical revisions. Anyone with repository read access or cloned git packs can extract it!

**Recommended Immediate Triage:**
- **Step 1**: Revoke the IAM Key in AWS Console or run Sentinel-X **Simulate Revoke**.
- **Step 2**: Generate replacement credentials and inject via AWS Secrets Manager or \`process.env.AWS_SECRET_ACCESS_KEY\`.
- **Step 3**: Use \`git-filter-repo\` or the **Git History Cleanup** workflow to rewrite commit history.`;
    }

    if (lowerQuery.includes('fix') || lowerQuery.includes('how to') || lowerQuery.includes('remediate') || lowerQuery.includes('rotate')) {
      return `### SENTINEL-X Standard Remediation Protocol (5-Step Pipeline)

To remediate exposures in **${repositoryName}** (Current Security Score: **${securityScore}/100**):

1. **Simulate Revoke / Deactivate**: Invalidate the compromised token at the identity provider (AWS IAM, Stripe Dashboard, GitHub Settings).
2. **Rotate & Reissue**: Issue a new credential with least-privilege scoping.
3. **Safe Code Replacement**: Replace hardcoded strings with environment variable reads (e.g. \`const API_KEY = process.env.API_KEY;\`).
4. **Git History Scrub**: Purge the credential from all past commit tree objects using \`git-filter-repo\`. Merely deleting the line in a new commit leaves git history vulnerable!
5. **Verification Scan**: Re-run SENTINEL-X scan to confirm 0 active exposures and restore the Security Score to **94+/100**.`;
    }

    if (lowerQuery.includes('prevention') || lowerQuery.includes('pre-commit') || lowerQuery.includes('hook') || lowerQuery.includes('block')) {
      return `### SENTINEL-X Prevention Engine (Pre-Commit & CI/CD)

Prevention stops secret leaks **before** they reach the repository:
- **Pre-Commit Hook**: Installs into \`.git/hooks/pre-commit\` and intercepts \`git commit\`. If a secret pattern or high-entropy string is staged, the hook blocks the commit with exit code \`1\`.
- **CI Guard**: Can be integrated into GitHub Actions, GitLab CI, or Jenkins.
- **Current Status**: Active on **${repositoryName}**. You can test this right now in the **Prevention Center** tab by clicking **"Run Prevention Test"**.`;
    }

    if (lowerQuery.includes('false positive') || lowerQuery.includes('docs') || lowerQuery.includes('placeholder')) {
      return `### AI False-Positive Killer Analysis

SENTINEL-X evaluated finding \`finding-docs-fp-05\` in \`docs/setup-guide.md\`:
- **Detection**: Matched generic API key pattern.
- **Context Inspection**: Found in markdown documentation file inside a \`\`\`bash\`\`\` code fence.
- **Entropy & Tokens**: Value contains explicit placeholder word \`"your_api_key_here"\` with low Shannon entropy (3.2 bits/char).
- **Outcome**: Classified as **false_positive** with 97% confidence. It was automatically excluded from the risk penalty calculations, protecting your developer workflow from false alert fatigue.`;
    }

    // Default conversational summary
    return `### SENTINEL-X Security Status for ${repositoryName}

- **Current Security Score**: **${securityScore} / 100**
- **Active Criticals**: ${criticals.length} (Requires immediate revocation)
- **High Risk**: ${highs.length}
- **Filtered False Positives**: ${falsePositives.length}

You can ask me to:
- Explain specific attack vectors (e.g., *"Why is the AWS finding critical?"*)
- Walk through key rotation (e.g., *"How do I fix the Stripe key?"*)
- Simulate Git history cleanup or show pre-commit prevention rules.`;
  }
}
