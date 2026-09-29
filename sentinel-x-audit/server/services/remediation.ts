import { Finding, RemediationAction } from '../../src/types';

export interface ActionResult {
  success: boolean;
  message: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface CredentialProvider {
  name: string;
  revoke(credentialId: string, category: string): Promise<ActionResult>;
  rotate(credentialId: string, category: string): Promise<ActionResult>;
}

export class MockCredentialProvider implements CredentialProvider {
  public name = 'Mock Security Infrastructure Provider';

  public async revoke(credentialId: string, category: string): Promise<ActionResult> {
    // Simulated cloud API response
    return {
      success: true,
      message: `[SAFE SIMULATION] Credential '${credentialId}' (${category}) was successfully revoked via Cloud IAM API. All active sessions have been terminated.`,
      timestamp: new Date().toISOString(),
      metadata: {
        revokedAt: new Date().toISOString(),
        identityProvider: category === 'AWS_CREDENTIAL' ? 'AWS IAM' : category === 'STRIPE_SECRET' ? 'Stripe Dashboard' : 'Provider API',
        simulated: true,
      },
    };
  }

  public async rotate(credentialId: string, category: string): Promise<ActionResult> {
    const newPrefix = category === 'STRIPE_SECRET' ? 'sk_live_' : category === 'AWS_CREDENTIAL' ? 'AKIA' : 'sec_';
    const fakeToken = `${newPrefix}NEW_MOCK_KEY_${Math.random().toString(36).substring(2, 10).toUpperCase()}`;

    return {
      success: true,
      message: `[SAFE SIMULATION] New operational key generated and securely stored in encrypted key vault. Zero downtime rollover active.`,
      timestamp: new Date().toISOString(),
      metadata: {
        rotatedKeyPlaceholder: fakeToken,
        rotationWindowHours: 24,
        simulated: true,
      },
    };
  }
}

export const mockCredentialProvider = new MockCredentialProvider();

export function generateCodeRemediationDiff(finding: Finding): {
  envVarName: string;
  beforeCode: string;
  afterCode: string;
  unifiedDiff: string;
} {
  let envVarName = 'SECRET_KEY';
  if (finding.secretCategory === 'AWS_CREDENTIAL') {
    envVarName = 'AWS_SECRET_ACCESS_KEY';
  } else if (finding.secretCategory === 'STRIPE_SECRET') {
    envVarName = 'STRIPE_SECRET_KEY';
  } else if (finding.secretCategory === 'DATABASE_URI') {
    envVarName = 'DATABASE_URL';
  } else if (finding.secretCategory === 'GITHUB_TOKEN') {
    envVarName = 'GITHUB_TOKEN';
  }

  const beforeCode = finding.contextSnippet;
  // Replace the hardcoded string with process.env.<ENV_VAR>
  const afterCode = beforeCode.replace(
    /["'][A-Za-z0-9_\-:@!./+=]{15,}["']/,
    `process.env.${envVarName} || ""`
  );

  const unifiedDiff = `--- a/${finding.filePath}
+++ b/${finding.filePath}
@@ -${Math.max(1, finding.lineNumber - 1)},3 +${Math.max(1, finding.lineNumber - 1)},3 @@
- // Hardcoded credentials in source code
-${beforeCode.split('\n')[0] || ''}
+ // Refactored by SENTINEL-X Auto-Remediation Engine
+ const ${envVarName} = process.env.${envVarName};`;

  return {
    envVarName,
    beforeCode,
    afterCode,
    unifiedDiff,
  };
}

export function generateGitHistoryCleanupScript(finding: Finding): string {
  return `# SENTINEL-X Git History Purge Protocol
# Run in repository root to erase all past commit references to this secret:

# Step 1: Install git-filter-repo (recommended by Git core team)
pip install git-filter-repo

# Step 2: Scrub secret pattern from commit tree history
git filter-repo --replace-text <(echo '${finding.redactedValue}==>REDACTED_BY_SENTINEL_X') --force

# Step 3: Force update remote tracking branches
git push origin --force --all
git push origin --force --tags

# Result: commit ${finding.gitExposure.firstSeenCommit} and all child refs are sanitized.`;
}
