import { Finding, SecurityScoreRecord } from '../../src/types';

export interface ScoreCalculationResult {
  score: number;
  breakdown: SecurityScoreRecord['breakdown'];
}

export function calculateSecurityScore(
  repositoryId: string,
  findings: Finding[],
  preventionModeEnabled: boolean
): ScoreCalculationResult {
  let baseScore = 100;

  // Filter only active, unresolved findings that are NOT false positives
  const openFindings = findings.filter(
    (f) => f.status === 'OPEN' && f.classification !== 'false_positive'
  );

  const remediatedFindings = findings.filter((f) => f.status === 'REMEDIATED');

  // Penalties
  let criticalPenalty = 0;
  let highPenalty = 0;
  let mediumPenalty = 0;
  let historyPenalty = 0;

  for (const finding of openFindings) {
    switch (finding.riskLevel) {
      case 'CRITICAL':
        criticalPenalty -= 25;
        break;
      case 'HIGH':
        highPenalty -= 15;
        break;
      case 'MEDIUM':
        mediumPenalty -= 8;
        break;
      case 'LOW':
        mediumPenalty -= 3;
        break;
      default:
        break;
    }

    // Historical exposure without git cleanup penalty
    if (finding.gitExposure && finding.gitExposure.commitCount > 1 && !finding.gitExposure.isPresentInCurrentCommit) {
      historyPenalty -= 5;
    }
  }

  // Bonus for remediation and prevention
  const remediationBonus = Math.min(25, remediatedFindings.length * 15);
  const preventionBonus = preventionModeEnabled ? 10 : 0;

  let calculated =
    baseScore +
    criticalPenalty +
    highPenalty +
    mediumPenalty +
    historyPenalty +
    remediationBonus +
    preventionBonus;

  // Bound to 0 - 100
  calculated = Math.max(5, Math.min(100, calculated));

  return {
    score: calculated,
    breakdown: {
      criticalFindingsPenalty: criticalPenalty,
      highFindingsPenalty: highPenalty,
      mediumFindingsPenalty: mediumPenalty,
      historicalExposurePenalty: historyPenalty,
      remediationBonus,
      preventionBonus,
    },
  };
}
