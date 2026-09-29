import { AIProvider } from './provider';
import { GeminiProvider } from './geminiProvider';
import { LocalFallbackProvider } from './localFallbackProvider';

export function getAIProvider(): AIProvider {
  const providerType = process.env.AI_PROVIDER?.toLowerCase();
  const geminiKey = process.env.GEMINI_API_KEY || process.env.AI_API_KEY;

  if (providerType === 'local' || !geminiKey || geminiKey === 'MY_GEMINI_API_KEY') {
    return new LocalFallbackProvider();
  }

  return new GeminiProvider();
}

export const aiProvider = getAIProvider();
export * from './provider';
export * from './localFallbackProvider';
export * from './geminiProvider';
