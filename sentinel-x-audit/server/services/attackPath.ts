import { AttackPath, RiskLevel, SecretCategory } from '../../src/types';

interface AttackPathInput {
  category: SecretCategory;
  filePath: string;
  riskLevel: RiskLevel;
  redactedValue: string;
}

export function generateAttackPathForFinding(input: AttackPathInput): AttackPath {
  const { category, filePath } = input;

  switch (category) {
    case 'AWS_CREDENTIAL':
      return {
        summary: 'Compromised AWS IAM Access Key enables adversary to authenticate against AWS API endpoints, query IAM policies, list S3 buckets, and exfiltrate customer databases or backups.',
        estimatedBlastRadius: 'INFRASTRUCTURE',
        nodes: [
          {
            id: 'node-cred',
            type: 'CREDENTIAL',
            label: 'AWS Access Key',
            description: `Exposed in ${filePath}`,
            risk: 'CRITICAL',
          },
          {
            id: 'node-iam',
            type: 'IAM_IDENTITY',
            label: 'IAM User / Role',
            description: 'arn:aws:iam::account-id:role/app-backend',
            risk: 'HIGH',
          },
          {
            id: 'node-service',
            type: 'CLOUD_SERVICE',
            label: 'Amazon S3 & KMS',
            description: 'Cloud storage and encryption envelope service',
            risk: 'HIGH',
          },
          {
            id: 'node-data',
            type: 'DATA_STORE',
            label: 'Customer Data Backups',
            description: 'PII, transaction history, order exports',
            risk: 'CRITICAL',
          },
          {
            id: 'node-impact',
            type: 'IMPACT',
            label: 'Data Breach & Extortion',
            description: 'Public disclosure, GDPR regulatory audit, extortion demand',
            risk: 'CRITICAL',
          },
        ],
        edges: [
          { source: 'node-cred', target: 'node-iam', reason: 'Direct aws:sts:GetCallerIdentity authentication' },
          { source: 'node-iam', target: 'node-service', reason: 'Attached policy permissions s3:* and kms:Decrypt' },
          { source: 'node-service', target: 'node-data', reason: 'Target storage contains potentially sensitive application data' },
          { source: 'node-data', target: 'node-impact', reason: 'Adversary downloads complete bucket archive' },
        ],
      };

    case 'STRIPE_SECRET':
      return {
        summary: 'Live Stripe secret key affords programmatic access to customer payment methods, allows processing arbitrary refund loops, and balance exfiltration via connected accounts.',
        estimatedBlastRadius: 'ORGANIZATION',
        nodes: [
          {
            id: 'node-cred',
            type: 'CREDENTIAL',
            label: 'Stripe Live Secret Key',
            description: `sk_live_ credential in ${filePath}`,
            risk: 'CRITICAL',
          },
          {
            id: 'node-service',
            type: 'CLOUD_SERVICE',
            label: 'Stripe Merchant API',
            description: 'https://api.stripe.com/v1',
            risk: 'HIGH',
          },
          {
            id: 'node-data',
            type: 'DATA_STORE',
            label: 'Payment Vault & Customers',
            description: 'Stored cards, tokenized payment methods, billing logs',
            risk: 'CRITICAL',
          },
          {
            id: 'node-impact',
            type: 'IMPACT',
            label: 'Financial Fraud & Chargebacks',
            description: 'Arbitrary refund trigger, merchant account suspension',
            risk: 'CRITICAL',
          },
        ],
        edges: [
          { source: 'node-cred', target: 'node-service', reason: 'Bearer token authorization to Stripe API' },
          { source: 'node-service', target: 'node-data', reason: 'Read /v1/customers and /v1/payment_intents' },
          { source: 'node-data', target: 'node-impact', reason: 'Execute unauthorized refunds to attacker-controlled instruments' },
        ],
      };

    case 'DATABASE_URI':
      return {
        summary: 'Database connection URI contains plain text administrative credentials. If database port is exposed or accessible via SSRF / internal pivot, entire relational dataset is compromised.',
        estimatedBlastRadius: 'INFRASTRUCTURE',
        nodes: [
          {
            id: 'node-cred',
            type: 'CREDENTIAL',
            label: 'Database Admin URI',
            description: `Connection string in ${filePath}`,
            risk: 'HIGH',
          },
          {
            id: 'node-data',
            type: 'DATA_STORE',
            label: 'Production Database Host',
            description: 'PostgreSQL Server port 5432',
            risk: 'HIGH',
          },
          {
            id: 'node-impact',
            type: 'IMPACT',
            label: 'Data Exfiltration / Ransom',
            description: 'SQL injection, schema drop, ransomware wipe',
            risk: 'CRITICAL',
          },
        ],
        edges: [
          { source: 'node-cred', target: 'node-data', reason: 'Direct network connection over postgres protocol' },
          { source: 'node-data', target: 'node-impact', reason: 'Full DDL/DML access to user, order, and auth tables' },
        ],
      };

    case 'GITHUB_TOKEN':
      return {
        summary: 'GitHub Access Token allows attacker to inspect private code repositories, manipulate CI/CD pipelines, and tamper with release assets.',
        estimatedBlastRadius: 'INFRASTRUCTURE',
        nodes: [
          {
            id: 'node-cred',
            type: 'CREDENTIAL',
            label: 'GitHub PAT',
            description: `Token in ${filePath}`,
            risk: 'HIGH',
          },
          {
            id: 'node-service',
            type: 'CLOUD_SERVICE',
            label: 'GitHub API & Actions',
            description: 'Repository workflows and deployment secrets',
            risk: 'HIGH',
          },
          {
            id: 'node-impact',
            type: 'IMPACT',
            label: 'Supply Chain Injection',
            description: 'Inject backdoor into build artifacts',
            risk: 'CRITICAL',
          },
        ],
        edges: [
          { source: 'node-cred', target: 'node-service', reason: 'OAuth2 bearer token with repo write scope' },
          { source: 'node-service', target: 'node-impact', reason: 'Modify GitHub Actions workflow to steal build secrets' },
        ],
      };

    default:
      return {
        summary: `Generic hardcoded credential in ${filePath}. Requires identity and entitlement validation to determine exact reach.`,
        estimatedBlastRadius: 'LOCAL',
        nodes: [
          {
            id: 'node-cred',
            type: 'CREDENTIAL',
            label: 'Detected Credential',
            description: `Found in ${filePath}`,
            risk: input.riskLevel,
          },
          {
            id: 'node-service',
            type: 'CLOUD_SERVICE',
            label: 'Associated Service Endpoint',
            description: 'Requires verification against identity provider',
            risk: 'MEDIUM',
          },
          {
            id: 'node-impact',
            type: 'IMPACT',
            label: 'Unauthorized API Operations',
            description: 'Potential unauthorized read/write access',
            risk: input.riskLevel,
          },
        ],
        edges: [
          { source: 'node-cred', target: 'node-service', reason: 'API key authentication header' },
          { source: 'node-service', target: 'node-impact', reason: 'Invoking privileged service endpoints' },
        ],
      };
  }
}
