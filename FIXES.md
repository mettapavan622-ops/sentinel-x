# SENTINEL-X Fixes & Upgrade Notes

## Resolved
- Fixed hardcoded repository IDs in the frontend and API chat flow.
- Fixed scan duplication: each scan now replaces the repository finding snapshot instead of appending duplicate findings.
- Fixed stale repository security score after scans and AI classification.
- Fixed scan failure handling so failed scans are persisted as `FAILED`.
- Fixed deployment runtime to honor `PORT` and `HOST`.
- Added local repository registration through `POST /api/repositories`.
- Added configurable Gemini model via `GEMINI_MODEL`.
- Removed the hardcoded Gemini model name from runtime calls.
- Added real best-effort Git history inspection for scanned repositories.
- Added finding de-duplication during a scan.
- Fixed FULL_PIPELINE remediation records so the action type is preserved.
- Improved pre-commit hook JSON handling so multiline staged diffs do not break shell quoting.
- Added repository path validation before scanning.
- Updated project/package identity from `react-example` to `sentinel-x`.

## Important limitation
The ZIP did not contain installed dependencies. Dependency installation timed out in the validation environment, so a full `npm run build` and live server integration test could not be completed here. The edited TypeScript/TSX source was syntax/transpile-checked successfully.

## Recommended next changes
1. Wire Prisma/PostgreSQL into `server/db/store.ts` for multi-user production persistence.
2. Add GitHub/GitLab repository connectors instead of relying only on local paths.
3. Add authentication/RBAC before exposing remediation endpoints publicly.
4. Replace simulated revoke/rotate actions with provider-specific integrations behind explicit confirmation.
5. Add background scan jobs and live progress updates for large repositories.
