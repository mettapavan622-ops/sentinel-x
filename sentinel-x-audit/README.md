# SENTINEL-X — AI-Powered Secret Leak Detection & Prevention Agent

> **DETECT → UNDERSTAND → TRACE → FIX → PREVENT**

SENTINEL-X is a target-agnostic security scanner for source-code projects. Upload a ZIP exported from a website, GitHub repository, React/Node application, backend service, or other codebase and SENTINEL-X extracts it, scans the source tree, detects credential leaks, analyzes context and entropy, inspects Git history when available, models potential attack paths, and presents remediation guidance.

## What it detects

- AWS credentials
- Stripe secrets
- GitHub tokens
- Database connection strings
- Private keys
- JWTs
- Google API keys
- Generic high-entropy secrets

## Scan workflow

1. Click **Upload ZIP & Scan**.
2. Select a project ZIP (maximum 50 MB by default).
3. SENTINEL-X safely extracts the archive with ZIP-slip protection.
4. The scanner walks source files while ignoring dependencies/build artifacts.
5. Each match is evaluated using pattern detection, Shannon entropy, and code context.
6. Findings receive a classification, risk level, confidence score, redacted evidence, attack-path analysis, and remediation guidance.
7. If the uploaded project contains a `.git` directory, Git-history analysis can identify secrets that were committed previously.
8. The dashboard calculates a security score from the current findings.

### GitHub repositories

Download any GitHub repository as a ZIP and upload it. GitHub's downloaded ZIP normally contains one top-level folder; SENTINEL-X automatically detects and scans that project root.

### Website projects

For a website you own or are authorized to audit, export/download its source code as a ZIP and upload it. SENTINEL-X scans the source files; it does not treat the public rendered webpage alone as a substitute for source-code security analysis.

## Quick Start

```bash
npm install
cp .env.example .env
npm run dev
```

Open `http://localhost:3000`.

## Environment

```env
AI_PROVIDER=local
GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.5-flash
PORT=3000
HOST=0.0.0.0
MAX_UPLOAD_MB=50
MAX_EXTRACTED_MB=250
```

## Security notes

- Uploads are stored under `.sentinel-uploads/` and should be excluded from Git.
- ZIP paths are validated against path traversal.
- Upload and extraction size limits help reduce archive-bomb/resource-exhaustion risk.
- Secret values are redacted in findings; raw secret values should never be logged or committed.
- Only scan source code you own or are authorized to assess.

## Architecture

```text
src/
  components/       Dashboard, findings, Git history, prevention UI
  App.tsx           Upload + scan workflow

server/
  routes/api.ts     Upload, repository, scan, finding and AI APIs
  scanner/          Secret detectors, entropy and context analysis
  git/              Best-effort Git history intelligence
  services/         Risk, attack-path, remediation and prevention engines
  ai/               Gemini + deterministic local fallback

tests/
  run-all-tests.ts
```

SENTINEL-X ships without a bundled client/demo repository. Every scan target is supplied by the user through the upload workflow or API.
