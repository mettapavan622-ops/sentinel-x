// Redaction utilities to ensure raw secrets are never exposed in UI or logs

export function redactSecret(secret: string): string {
  if (!secret || secret.length < 6) {
    return '••••••••';
  }

  // AWS Access Key format AKIA...
  if (secret.startsWith('AKIA') || secret.startsWith('ASIA')) {
    const prefix = secret.slice(0, 4);
    const suffix = secret.slice(-4);
    return `${prefix}••••••••${suffix}`;
  }

  // Stripe secret keys
  if (secret.startsWith('sk_live_') || secret.startsWith('rk_live_') || secret.startsWith('pk_live_')) {
    const prefix = secret.slice(0, 8);
    const suffix = secret.slice(-4);
    return `${prefix}••••••••${suffix}`;
  }

  // GitHub tokens
  if (secret.startsWith('ghp_') || secret.startsWith('gho_') || secret.startsWith('ghu_')) {
    const prefix = secret.slice(0, 4);
    const suffix = secret.slice(-4);
    return `${prefix}••••••••${suffix}`;
  }

  // Database URIs
  if (secret.includes('://') && secret.includes('@')) {
    return secret.replace(/:([^:@]+)@/, ':••••••••@');
  }

  // Standard high entropy string
  if (secret.length > 16) {
    const start = secret.slice(0, 4);
    const end = secret.slice(-4);
    return `${start}••••••••${end}`;
  }

  return '••••••••';
}
