import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ParsedSkillDirectory, ParsedSubagentFile } from "../auditor/parser.js";
import {
	auditSkillSecurity,
	scanMarkdownForPromptInjection,
	scanTextForTrojanUnicode,
	type SkillSecurityFinding,
} from "../auditor/security.js";
import type { RuntimeTarget } from "../models.js";
import type { CatalogIndex } from "./catalog-index.js";

export interface AddOptions {
	readonly catalogIndex?: CatalogIndex;
	readonly targets?: readonly RuntimeTarget[];
	readonly dryRun?: boolean;
	readonly force?: boolean;
}

export interface RemoveOptions {
	readonly catalogIndex?: CatalogIndex;
	readonly targets?: readonly RuntimeTarget[];
	readonly dryRun?: boolean;
	readonly force?: boolean;
}

export interface CleanOptions {
	readonly dryRun?: boolean;
	readonly force?: boolean;
}

export type ArtifactHealthState =
	| "up_to_date"
	| "update_available"
	| "drift_modified"
	| "missing_on_disk"
	| "untracked_on_disk";

export interface StatusOptions {
	readonly catalogIndex?: CatalogIndex;
	readonly targets?: readonly RuntimeTarget[];
}

export interface UpdateOptions {
	readonly catalogIndex?: CatalogIndex;
	readonly targets?: readonly RuntimeTarget[];
	readonly names?: readonly string[];
	readonly dryRun?: boolean;
	readonly force?: boolean;
}

export interface InstalledArtifactStatus {
	readonly target: RuntimeTarget;
	readonly itemName: string;
	readonly kind: "skill" | "subagent";
	readonly relativePath: string;
	readonly state: ArtifactHealthState;
	readonly lockfileSha256: string | null;
	readonly diskSha256: string | null;
	readonly catalogSha256: string | null;
}

export interface ProjectStatusReport {
	readonly repo_path: string;
	readonly catalog_path: string;
	readonly lockfile_path: string;
	readonly lockfile_present: boolean;
	readonly targets: RuntimeTarget[];
	readonly installed_skills: string[];
	readonly installed_subagents: string[];
	readonly artifacts: InstalledArtifactStatus[];
	readonly counts: {
		readonly up_to_date: number;
		readonly update_available: number;
		readonly drift_modified: number;
		readonly missing_on_disk: number;
		readonly untracked_on_disk: number;
	};
	readonly passed: boolean;
}

export interface DiscoveredInstalledArtifact {
	readonly target: RuntimeTarget;
	readonly itemName: string;
	readonly kind: "skill" | "subagent";
	readonly relativePath: string;
	readonly sha256: string;
	readonly fromLockfile: boolean;
}

export interface PlannedFile {
	readonly target: RuntimeTarget;
	readonly itemName: string;
	readonly relativePath: string;
	readonly content: string;
}

export interface SkippedTargetItem {
	readonly target: RuntimeTarget;
	readonly itemName: string;
	readonly relativePath: string;
	readonly sha256: string;
}

/**
 * Check whether a Skill or Subagent already exists on disk in a given target AI CLI / IDE directory.
 * Returns the relative path of the existing artifact if found, or `null` if not yet present.
 */

export const CODEX_MARKER_START = "<!-- SKILLOPS:START -->";
export const CODEX_MARKER_END = "<!-- SKILLOPS:END -->";

export function trimSlashes(val: string): string {
	let start = 0;
	let end = val.length;
	while (start < end && val.charCodeAt(start) === 47) {
		start += 1;
	}
	while (end > start && val.charCodeAt(end - 1) === 47) {
		end -= 1;
	}
	return val.slice(start, end);
}

export function trimTrailingSlashes(val: string): string {
	let end = val.length;
	while (end > 1 && val.charCodeAt(end - 1) === 47) {
		end -= 1;
	}
	return val.slice(0, end);
}

export function resolveBuiltinCatalogDir(): string {
	let current = path.dirname(fileURLToPath(import.meta.url));
	for (let depth = 0; depth < 4; depth++) {
		current = path.resolve(current, "..");
		const candidate = path.join(current, "catalog");
		if (
			fs.existsSync(path.join(current, "package.json")) &&
			fs.existsSync(candidate) &&
			fs.statSync(candidate).isDirectory()
		) {
			return candidate;
		}
	}
	return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "catalog");
}

export const PACKAGE_CATALOG_DIR = resolveBuiltinCatalogDir();

function isErrorSecurityFinding(finding: SkillSecurityFinding): boolean {
	const maybeSeverity = (finding as { readonly severity?: string }).severity;
	return maybeSeverity === undefined || maybeSeverity === "error";
}

function formatFindingsError(
	kind: "skill" | "subagent",
	name: string,
	findings: readonly SkillSecurityFinding[],
): Error {
	const summary = findings
		.slice(0, 3)
		.map((f) => `[${f.rule}] ${f.file}:${f.line} ${f.message}`)
		.join("; ");
	return new Error(
		`Security violation in custom catalog ${kind} '${name}': ${summary}`,
	);
}

export function assertCustomCatalogSkillSafe(
	resolvedCatalog: string,
	skill: ParsedSkillDirectory,
): void {
	if (path.resolve(resolvedCatalog) === path.resolve(PACKAGE_CATALOG_DIR)) {
		return;
	}
	const secReport = auditSkillSecurity(skill.skillDir);
	const errorFindings = secReport.findings.filter(isErrorSecurityFinding);
	if (errorFindings.length > 0) {
		throw formatFindingsError("skill", skill.manifest.name, errorFindings);
	}
}

export function assertCustomCatalogSubagentSafe(
	resolvedCatalog: string,
	subagent: ParsedSubagentFile,
): void {
	if (path.resolve(resolvedCatalog) === path.resolve(PACKAGE_CATALOG_DIR)) {
		return;
	}
	const stat = fs.lstatSync(subagent.filePath);
	if (stat.isSymbolicLink() || !stat.isFile()) {
		throw new Error(
			`Security violation in custom catalog subagent '${subagent.manifest.name}': subagent file must not be a symlink.`,
		);
	}
	const relFile = path
		.relative(path.resolve(resolvedCatalog), subagent.filePath)
		.replace(/\\/g, "/");
	const rawText = fs.readFileSync(subagent.filePath, "utf-8");
	const directFindings: SkillSecurityFinding[] = [
		...scanTextForTrojanUnicode(relFile, rawText, false),
		...scanMarkdownForPromptInjection(relFile, rawText),
	];
	if (
		path.basename(subagent.filePath) === "SUBAGENT.md" &&
		path.dirname(subagent.filePath) !== path.join(path.resolve(resolvedCatalog), "subagents")
	) {
		const dirReport = auditSkillSecurity(path.dirname(subagent.filePath));
		directFindings.push(...dirReport.findings);
	}
	const errorFindings = directFindings.filter(isErrorSecurityFinding);
	if (errorFindings.length > 0) {
		throw formatFindingsError("subagent", subagent.manifest.name, errorFindings);
	}
}

