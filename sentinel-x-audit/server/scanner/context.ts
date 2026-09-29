import { ContextAnalysisResult } from '../../src/types';

export function analyzeContext(
  filePath: string,
  lineNumber: number,
  fileContent: string,
  matchedValue: string
): ContextAnalysisResult {
  const lines = fileContent.split('\n');
  const targetLine = lines[lineNumber - 1] || '';
  const prevLine = lineNumber > 1 ? lines[lineNumber - 2] : '';
  const nextLine = lineNumber < lines.length ? lines[lineNumber] : '';
  const contextBlock = [prevLine, targetLine, nextLine].join('\n');

  const normalizedPath = filePath.toLowerCase();

  // File location signals
  const isInTestFile =
    normalizedPath.includes('test') ||
    normalizedPath.includes('spec') ||
    normalizedPath.includes('__test__') ||
    normalizedPath.includes('mock') ||
    normalizedPath.includes('fixtures');

  const isInDocumentation =
    normalizedPath.includes('doc') ||
    normalizedPath.endsWith('.md') ||
    normalizedPath.endsWith('.mdx') ||
    normalizedPath.endsWith('.txt');

  const isInExampleFile =
    normalizedPath.includes('example') ||
    normalizedPath.includes('sample') ||
    normalizedPath.includes('.env.example') ||
    normalizedPath.includes('.env.template');

  // Variable assignment check
  const assignmentMatch = targetLine.match(/(?:const|let|var|export\s+const|export\s+let|final)\s+([a-zA-Z0-9_$]+)\s*[:=]/);
  const variableName = assignmentMatch ? assignmentMatch[1] : undefined;
  const isAssignment = Boolean(assignmentMatch);

  // Placeholder detection
  const placeholderPatterns = [
    /your[-_]?api[-_]?key/i,
    /your[-_]?secret/i,
    /dummy/i,
    /mock/i,
    /sample[-_]?value/i,
    /my[-_]?secret/i,
    /replace[-_]?with/i,
    /xxxx+/i,
  ];

  // Specific check for obvious placeholders vs structured keys
  const isObviousPlaceholderToken =
    placeholderPatterns.some((p) => p.test(matchedValue)) ||
    (matchedValue.toLowerCase().includes('placeholder') && !matchedValue.startsWith('sk_live_'));

  const isPlaceholderOrExample =
    isInExampleFile ||
    isInDocumentation ||
    isObviousPlaceholderToken ||
    (variableName && /mock|dummy|fake|sample/i.test(variableName)) ||
    (targetLine.toLowerCase().includes('placeholder') && !targetLine.includes('sk_live_'));

  // Authentication/Secret variable keywords
  const authVariablePattern = /(?:key|secret|token|auth|credential|password|passwd|pwd|private|jwt|bearer|access_key)/i;
  const isAuthVariable = variableName ? authVariablePattern.test(variableName) : false;

  // Comments
  const commentMatch = contextBlock.match(/(?:\/\/|\/\*|#)\s*(.+)/);
  const commentContext = commentMatch ? commentMatch[1].trim() : undefined;

  // Code reference check: count occurrences of variableName in file
  let isReferencedInCode = false;
  if (variableName) {
    const varOccurrences = (fileContent.match(new RegExp(`\\b${variableName}\\b`, 'g')) || []).length;
    isReferencedInCode = varOccurrences > 1;
  }

  // Calculate heuristic context score (0.0 to 1.0)
  // Higher = more likely to be an active, dangerous production credential
  let score = 0.5;
  const signals: string[] = [];

  if (isInDocumentation) {
    score -= 0.35;
    signals.push('Located in documentation file');
  }
  if (isInExampleFile) {
    score -= 0.3;
    signals.push('Located in sample or example template');
  }
  if (isInTestFile) {
    score -= 0.25;
    signals.push('Located in test or fixture file');
  }
  if (isPlaceholderOrExample) {
    score -= 0.4;
    signals.push('Contains explicit dummy/placeholder token patterns');
  }

  if (isAuthVariable) {
    score += 0.25;
    signals.push(`Assigned to authentication variable '${variableName}'`);
  }
  if (isReferencedInCode) {
    score += 0.15;
    signals.push(`Variable '${variableName}' is referenced in active code logic`);
  }
  if (commentContext && /production|live|deploy/i.test(commentContext)) {
    score += 0.15;
    signals.push('Surrounding comments reference production/live deployment');
  }

  const contextScore = Math.max(0.05, Math.min(0.99, Math.round(score * 100) / 100));

  return {
    variableName,
    isAssignment,
    isInTestFile,
    isInDocumentation,
    isInExampleFile,
    isPlaceholderOrExample,
    isReferencedInCode,
    commentContext,
    contextScore,
    signals,
  };
}
