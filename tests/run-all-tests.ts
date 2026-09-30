import { detectorRegistry } from '../server/scanner/detectorRegistry';
import { calculateShannonEntropy, evaluateEntropy } from '../server/scanner/entropy';
import { analyzeContext } from '../server/scanner/context';
import { redactSecret } from '../server/scanner/redaction';
import { analyzeGitHistoryForSecret } from '../server/git/gitIntelligence';
import { calculateSecurityScore } from '../server/services/riskEngine';
import { generateCodeRemediationDiff, MockCredentialProvider } from '../server/services/remediation';
import { preventionEngine } from '../server/services/prevention';
import { LocalFallbackProvider } from '../server/ai/localFallbackProvider';
import { Finding } from '../src/types';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  ✅ PASS: ${testName}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${testName} ${detail ? `- ${detail}` : ''}`);
    failed++;
  }
}

async function runTests() {
  console.log('\n============================================================');
  console.log('         SENTINEL-X SECURITY AGENT — TEST SUITE            ');
  console.log('============================================================\n');

  // Test Group 1: Secret Detection Patterns
  console.log('🔹 [1/7] Testing Secret Detection Patterns...');
  {
    const awsPrefix = 'AK' + 'IA';
    const awsSample = `const KEY = "${awsPrefix}1234567890ABCDEF";`;
    const awsMatches = detectorRegistry.scanContent(awsSample, 'config/aws.ts');
    assert(awsMatches.length > 0 && awsMatches[0].category === 'AWS_CREDENTIAL', 'AWS Access Key Detection (AKIA...)');

    const stripePrefix = 'sk' + '_live_';
    const stripeSample = `export const stripe = new Stripe("${stripePrefix}51M0000000000000000000000ABCD");`;
    const stripeMatches = detectorRegistry.scanContent(stripeSample, 'payments/stripe.ts');
    assert(stripeMatches.length > 0 && stripeMatches[0].category === 'STRIPE_SECRET', 'Stripe Secret Key Detection (sk_live_...)');

    const githubPrefix = 'gh' + 'p_';
    const githubSample = `const token = "${githubPrefix}1234567890abcdefghijklmnopqrstuvwxyz";`;
    const ghMatches = detectorRegistry.scanContent(githubSample, 'services/bot.ts');
    assert(ghMatches.length > 0 && ghMatches[0].category === 'GITHUB_TOKEN', 'GitHub PAT Detection (ghp_...)');

    const pemSample = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...';
    const pemMatches = detectorRegistry.scanContent(pemSample, 'keys/server.key');
    assert(pemMatches.length > 0 && pemMatches[0].category === 'PRIVATE_KEY', 'Private Key PEM Detection');

    const dbSample = 'const uri = "postgres://admin:secretPass123@prod.internal:5432/app";';
    const dbMatches = detectorRegistry.scanContent(dbSample, 'db.ts');
    assert(dbMatches.length > 0 && dbMatches[0].category === 'DATABASE_URI', 'Database URI Credentials Detection');
  }

  // Test Group 2: Shannon Entropy Analysis
  console.log('\n🔹 [2/7] Testing Shannon Entropy Engine...');
  {
    const lowEntropyStr = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; // All same chars
    const highEntropyStr = 'k9#mP!98qZw#L1&xR4$vN0@yB7%tE3*u'; // Diverse 32 chars

    const lowScore = evaluateEntropy(lowEntropyStr);
    const highScore = evaluateEntropy(highEntropyStr);

    assert(lowScore.entropy < 1.0 && !lowScore.isHighEntropy, 'Low Entropy Detection (< 1.0 bits)');
    assert(highScore.entropy > 4.2 && highScore.isHighEntropy, 'High Entropy Detection (> 4.2 bits)');
  }

  // Test Group 3: Context Analysis (False Positive vs Real Secret)
  console.log('\n🔹 [3/7] Testing Context Analysis & False-Positive Signals...');
  {
    const realAwsValue = 'AK' + 'IA' + '1234567890ABCDEF';
    const realCode = `const AWS_ACCESS_KEY = "${realAwsValue}";`;
    const realCtx = analyzeContext('src/config/aws.ts', 1, realCode, realAwsValue);
    assert(!realCtx.isInDocumentation && !realCtx.isPlaceholderOrExample && realCtx.contextScore > 0.7, 'Real Production Context Scored High');

    const docsAwsValue = 'AK' + 'IA' + 'EXAMPLEPLACEHOLDER01';
    const docsCode = '```bash\nexport AWS_ACCESS_KEY="' + docsAwsValue + '"\n```';
    const docsCtx = analyzeContext('docs/guide.md', 2, docsCode, docsAwsValue);
    assert(docsCtx.isInDocumentation && docsCtx.isPlaceholderOrExample && docsCtx.contextScore < 0.4, 'Documentation Placeholder Detected as False Positive Candidate');

    const testCode = 'const MOCK_KEY = "dummy_mock_secret_key_12345";';
    const testCtx = analyzeContext('tests/mock.test.ts', 1, testCode, 'dummy_mock_secret_key_12345');
    assert(testCtx.isInTestFile && testCtx.isPlaceholderOrExample, 'Test Harness Mock Token Identified');
  }

  // Test Group 4: Git History Intelligence
  console.log('\n🔹 [4/7] Testing Git History Intelligence...');
  {
    const gitAws = analyzeGitHistoryForSecret('AWS_CREDENTIAL', 'src/config/aws.ts', false);
    assert(gitAws.isRemovedInHead === true && gitAws.commitCount > 1, 'Historical Secret Persistence (Removed in HEAD but in commits)');
    assert(gitAws.historicalCommits.length === 3, 'Multi-Commit History Timeline Reconstruction');
  }

  // Test Group 5: Risk Engine & Security Score
  console.log('\n🔹 [5/7] Testing Risk Engine & Dynamic Score Calculation...');
  {
    const dummyFindings: Finding[] = [
      {
        id: 'f1',
        scanId: 's1',
        repositoryId: 'r1',
        detectorType: 'AWS_ACCESS_KEY',
        secretCategory: 'AWS_CREDENTIAL',
        filePath: 'src/aws.ts',
        lineNumber: 10,
        firstSeen: '',
        lastSeen: '',
        confidence: 0.98,
        entropyScore: { entropy: 4.8, normalizedScore: 0.9, characterSetSize: 32, isHighEntropy: true },
        contextAnalysis: { isAssignment: true, isInTestFile: false, isInDocumentation: false, isInExampleFile: false, isPlaceholderOrExample: false, isReferencedInCode: true, contextScore: 0.9, signals: [] },
        riskLevel: 'CRITICAL',
        status: 'OPEN',
        classification: 'true_positive',
        redactedValue: ('AK' + 'IA') + '••••••••7F2A',
        contextSnippet: 'AKIA...',
        attackPath: { summary: '', estimatedBlastRadius: 'INFRASTRUCTURE', nodes: [], edges: [] },
        gitExposure: { firstSeenCommit: 'a82', firstSeenDate: '', firstSeenAuthor: '', lastSeenCommit: 'c72', lastSeenDate: '', commitCount: 5, isPresentInCurrentCommit: false, isRemovedInHead: true, branches: [], historicalCommits: [] },
        createdAt: '',
        updatedAt: '',
      },
      {
        id: 'f2',
        scanId: 's1',
        repositoryId: 'r1',
        detectorType: 'STRIPE_KEY',
        secretCategory: 'STRIPE_SECRET',
        filePath: 'src/stripe.ts',
        lineNumber: 5,
        firstSeen: '',
        lastSeen: '',
        confidence: 0.95,
        entropyScore: { entropy: 4.7, normalizedScore: 0.88, characterSetSize: 32, isHighEntropy: true },
        contextAnalysis: { isAssignment: true, isInTestFile: false, isInDocumentation: false, isInExampleFile: false, isPlaceholderOrExample: false, isReferencedInCode: true, contextScore: 0.9, signals: [] },
        riskLevel: 'CRITICAL',
        status: 'OPEN',
        classification: 'true_positive',
        redactedValue: ('sk' + '_live_') + '••••••••9012cdef',
        contextSnippet: 'sk_live...',
        attackPath: { summary: '', estimatedBlastRadius: 'ORGANIZATION', nodes: [], edges: [] },
        gitExposure: { firstSeenCommit: 'd19', firstSeenDate: '', firstSeenAuthor: '', lastSeenCommit: 'd19', lastSeenDate: '', commitCount: 1, isPresentInCurrentCommit: true, isRemovedInHead: false, branches: [], historicalCommits: [] },
        createdAt: '',
        updatedAt: '',
      },
    ];

    const initialScore = calculateSecurityScore('r1', dummyFindings, true);
    assert(initialScore.score <= 60, `Initial Unresolved Score is Degraded (Score: ${initialScore.score}/100)`);

    // Remediate both findings
    dummyFindings[0].status = 'REMEDIATED';
    dummyFindings[1].status = 'REMEDIATED';
    const remediatedScore = calculateSecurityScore('r1', dummyFindings, true);
    assert(remediatedScore.score >= 90, `Post-Remediation Score Jumps to High Health (Score: ${remediatedScore.score}/100)`);
  }

  // Test Group 6: Secret Redaction & Remediation Diff
  console.log('\n🔹 [6/7] Testing Secret Redaction & Code Remediation...');
  {
    const rawAws = 'AK' + 'IA' + '1234567890ABCDEF';
    const redacted = redactSecret(rawAws);
    assert(redacted.startsWith('AKIA') && redacted.includes('••••••••') && !redacted.includes('1234567890'), 'Secret Redaction Masks Sensitive Chars');

    const mockProvider = new MockCredentialProvider();
    const revokeRes = await mockProvider.revoke('test-cred', 'AWS_CREDENTIAL');
    assert(revokeRes.success && revokeRes.metadata?.simulated === true, 'Mock Safe Credential Revocation');

    const rotateRes = await mockProvider.rotate('test-cred', 'AWS_CREDENTIAL');
    assert(rotateRes.success && Boolean(rotateRes.metadata?.rotatedKeyPlaceholder), 'Mock Safe Credential Rotation');
  }

  // Test Group 7: Prevention Engine (Pre-Commit Scan)
  console.log('\n🔹 [7/7] Testing Prevention Engine (Pre-Commit Block)...');
  {
    const preventionAwsValue = 'AK' + 'IA' + '5DEMOEXAMPLE7F2A';
    const taintedDiff = `
+ const AWS_KEY = "${preventionAwsValue}";
+ const s3 = new S3Client({ key: AWS_KEY });
`;
    const blockedRes = preventionEngine.scanStagedContent('staged/config.ts', taintedDiff);
    assert(blockedRes.blocked === true && blockedRes.exitCode === 1, 'Prevention Mode Blocks Commit With Exposed Secret');
    assert(blockedRes.terminalOutput.includes('COMMIT REJECTED'), 'Terminal Pre-Commit Block Diagnostic Generated');

    const cleanDiff = `
+ const AWS_KEY = process.env.AWS_KEY;
+ const s3 = new S3Client({ key: AWS_KEY });
`;
    const passedRes = preventionEngine.scanStagedContent('staged/config.ts', cleanDiff);
    assert(passedRes.blocked === false && passedRes.exitCode === 0, 'Prevention Mode Passes Clean Environment Variable Commit');
  }

  // Test Group 8: Report Generation & CSV Export
  console.log('\n🔹 [8/8] Testing Report Generation & RFC-4180 CSV Export...');
  {
    const { exportFindingsToCSV } = await import('../src/utils/exportReport');
    let generatedContent = '';
    let generatedFilename = '';

    const origBlob = globalThis.Blob;
    const origURL = globalThis.URL;
    const origDoc = globalThis.document;

    globalThis.Blob = class MockBlob {
      content: string[];
      constructor(content: string[]) {
        this.content = content;
        generatedContent = content.join('');
      }
    } as any;

    globalThis.URL = {
      createObjectURL: () => 'blob:mock-url',
      revokeObjectURL: () => {},
    } as any;

    globalThis.document = {
      createElement: () => ({
        setAttribute: (k: string, v: string) => {
          if (k === 'download') generatedFilename = v;
        },
        click: () => {},
        style: {},
      }),
      body: {
        appendChild: () => {},
        removeChild: () => {},
      },
    } as any;

    const mockFindings: Finding[] = [
      {
        id: 'finding-rep-1',
        scanId: 'scan-1',
        repositoryId: 'repo-1',
        detectorType: 'AWS Access Key ID',
        secretCategory: 'AWS_CREDENTIAL',
        filePath: 'src/aws.ts',
        lineNumber: 10,
        confidence: 0.99,
        entropyScore: { entropy: 4.8, normalizedScore: 0.9, characterSetSize: 36, isHighEntropy: true },
        contextAnalysis: {
          isAssignment: true,
          isInTestFile: false,
          isInDocumentation: false,
          isInExampleFile: false,
          isPlaceholderOrExample: false,
          isReferencedInCode: true,
          contextScore: 0.9,
          signals: [],
        },
        riskLevel: 'CRITICAL',
        status: 'OPEN',
        classification: 'true_positive',
        redactedValue: 'AKIA************7EXA',
        contextSnippet: 'const key = "AKIA...";',
        attackPath: { summary: 'AWS cloud account takeover', estimatedBlastRadius: 'INFRASTRUCTURE', nodes: [], edges: [] },
        gitExposure: {
          firstSeenCommit: 'c1',
          firstSeenDate: '2026-09-29',
          firstSeenAuthor: 'dev',
          lastSeenCommit: 'c1',
          lastSeenDate: '2026-09-29',
          commitCount: 1,
          isPresentInCurrentCommit: true,
          isRemovedInHead: false,
          branches: ['main'],
          historicalCommits: [],
        },
        createdAt: '2026-09-29T00:00:00Z',
        updatedAt: '2026-09-29T00:00:00Z',
        firstSeen: '2026-09-29T00:00:00Z',
        lastSeen: '2026-09-29T00:00:00Z',
      },
    ];

    exportFindingsToCSV(mockFindings, 'demo-repo');

    assert(generatedContent.includes('Finding ID,Risk Level,Status'), 'CSV Contains RFC Header Columns');
    assert(generatedContent.includes('finding-rep-1') && generatedContent.includes('CRITICAL'), 'CSV Formats Finding Rows Correctly');
    assert(generatedFilename.startsWith('sentinel-x-findings-demo-repo-'), 'CSV Generates Valid Audit Filename');

    globalThis.Blob = origBlob;
    globalThis.URL = origURL;
    globalThis.document = origDoc;
  }

  console.log('\n============================================================');
  console.log(`TEST SUMMARY: ${passed} PASSED | ${failed} FAILED`);
  console.log('============================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
