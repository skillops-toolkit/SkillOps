/**
 * Deterministic Security Scanner Facade (`src/auditor/security.ts`).
 *
 * Re-exports modular security scanners, allowlist loaders, and catalog auditors
 * under `src/auditor/security/*` while keeping 100% backwards-compatible API.
 */

export { hasForbiddenBinaryExtension } from "./security/allowlist.js";
export { auditCatalogSecurity, auditSkillSecurity } from "./security/audit.js";
export {
	FORBIDDEN_BINARY_AND_ARCHIVE_EXTENSIONS,
	MAX_SCANNED_FILE_BYTES,
	MAX_SCANNED_LINE_LENGTH,
	type SecurityAllowlistEntry,
	type SecurityAllowlistFile,
	type SecurityAuditOptions,
	type SkillSecurityAuditReport,
	type SkillSecurityFinding,
	type SkillSecurityRuleId,
} from "./security/constants.js";
export { scanJsOrTsScriptContent } from "./security/js-ts.js";
export { scanMarkdownForPromptInjection } from "./security/markdown.js";
export { scanPythonScriptContent } from "./security/python.js";
export { scanShellScriptContent } from "./security/shell.js";
export { scanTextForTrojanUnicode } from "./security/trojan.js";
