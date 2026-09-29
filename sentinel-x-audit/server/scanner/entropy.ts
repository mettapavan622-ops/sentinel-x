import { EntropyScore } from '../../src/types';

/**
 * Calculates the Shannon Entropy of a string.
 * Measures information density / randomness in bits per character.
 * Typical English text: ~2.5 - 3.5 bits/char
 * High-entropy random crypto keys/tokens: > 4.2 bits/char
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies = new Map<string, number>();
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;

  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Math.round(entropy * 100) / 100;
}

/**
 * Evaluates the entropy score and normalizes it to a 0.0 - 1.0 confidence score
 */
export function evaluateEntropy(str: string): EntropyScore {
  const entropy = calculateShannonEntropy(str);
  const charSet = new Set(str.split('')).size;

  // Max theoretical entropy for base64 (64 symbols) is log2(64) = 6.0
  // Alphanumeric (62 symbols) is ~5.95
  // We normalize against ~5.5 as typical maximum practical random entropy
  const normalized = Math.min(1.0, Math.max(0.0, (entropy - 2.0) / 3.5));

  // High entropy threshold: >= 4.0 and at least 16 chars long with diverse charset
  const isHighEntropy = entropy >= 4.0 && str.length >= 16 && charSet >= 12;

  return {
    entropy,
    normalizedScore: Math.round(normalized * 100) / 100,
    characterSetSize: charSet,
    isHighEntropy,
  };
}
