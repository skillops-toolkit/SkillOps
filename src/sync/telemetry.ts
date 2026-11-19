import fs from "node:fs";
import path from "node:path";
import {
	estimateTokenCount,
	RUNTIME_HARNESS_SPECS,
	type RuntimeTarget,
	type SkillOpsConfig,
} from "../models.js";
import type { CatalogIndex } from "./catalog-index.js";

export const DEFAULT_MAX_ALWAYS_ON_TOKENS = 4000;
export const L1_INDEX_OVERHEAD_TOKENS = 12;
export const ROOT_INSTRUCTION_FILES = [
	"AGENTS.md",
	"CLAUDE.md",
	"GEMINI.md",
] as const;

const MAX_TELEMETRY_READ_BYTES = 256 * 1024;

export type HarnessStartupMode = "progressive" | "always-on";

export interface TargetTokenTelemetry {
	readonly target: RuntimeTarget;
	readonly mode: HarnessStartupMode;
	readonly startup_tokens: number;
}

export interface WorkspaceTokenTelemetry {
	readonly total_l1_tokens: number;
	readonly always_on_tokens: number;
	readonly max_always_on_tokens: number;
	readonly per_target: TargetTokenTelemetry[];
	readonly warnings: string[];
}

export function isProgressiveHarness(target: RuntimeTarget): boolean {
	return RUNTIME_HARNESS_SPECS[target].skillFormat === "progressive-skill-dir";
}

function readBoundedRegularText(filePath: string): string | null {
	try {
		const stat = fs.lstatSync(filePath);
		if (
			stat.isSymbolicLink() ||
			!stat.isFile() ||
			stat.size > MAX_TELEMETRY_READ_BYTES
		) {
			return null;
		}
		return fs.readFileSync(filePath, "utf-8");
	} catch {
		return null;
	}
}

function getSkillL1Tokens(name: string, catalogIndex?: CatalogIndex): number {
	const skill = catalogIndex?.skills.get(name);
	if (!skill) {
		return L1_INDEX_OVERHEAD_TOKENS;
	}
	const descTokens =
		skill.manifest.description_tokens > 0
			? skill.manifest.description_tokens
			: estimateTokenCount(skill.manifest.description);
	return Math.max(1, descTokens) + L1_INDEX_OVERHEAD_TOKENS;
}

function getSubagentL1Tokens(
	name: string,
	catalogIndex?: CatalogIndex,
): number {
	const subagent = catalogIndex?.subagents.get(name);
	if (!subagent) {
		return L1_INDEX_OVERHEAD_TOKENS;
	}
	const descTokens =
		subagent.manifest.description_tokens > 0
			? subagent.manifest.description_tokens
			: estimateTokenCount(subagent.manifest.description);
	return Math.max(1, descTokens) + L1_INDEX_OVERHEAD_TOKENS;
}

function getSkillFullBodyTokens(
	name: string,
	catalogIndex?: CatalogIndex,
): number {
	const skill = catalogIndex?.skills.get(name);
	if (!skill) {
		return 0;
	}
	return Math.max(1, estimateTokenCount(skill.rawText));
}

function getSubagentFullBodyTokens(
	name: string,
	catalogIndex?: CatalogIndex,
): number {
	const subagent = catalogIndex?.subagents.get(name);
	if (!subagent) {
		return 0;
	}
	return Math.max(1, estimateTokenCount(subagent.rawText));
}

/**
 * Compute deterministic L1 startup metadata token count across installed skills and subagents
 * for `.skillops-lock.json` telemetry.
 */
export function computeLockfileL1Tokens(
	selectedSkills: readonly string[],
	selectedSubagents: readonly string[],
	catalogIndex?: CatalogIndex,
): number {
	const uniqueSkills = [...new Set(selectedSkills)];
	const uniqueSubagents = [...new Set(selectedSubagents)];

	let total = 0;
	for (const skillName of uniqueSkills) {
		total += getSkillL1Tokens(skillName, catalogIndex);
	}
	for (const saName of uniqueSubagents) {
		total += getSubagentL1Tokens(saName, catalogIndex);
	}
	return total;
}

/**
 * Compute per-harness startup token telemetry distinguishing progressive L1 index harnesses
 * (`progressive-skill-dir`) from always-on full-body rule harnesses (`markdown-rule`) and
 * root instruction files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`).
 */
export function computeWorkspaceTokenTelemetry(params: {
	readonly repoPath?: string;
	readonly targets: readonly RuntimeTarget[];
	readonly selectedSkills: readonly string[];
	readonly selectedSubagents: readonly string[];
	readonly catalogIndex?: CatalogIndex;
	readonly config?: SkillOpsConfig | null;
}): WorkspaceTokenTelemetry {
	const uniqueSkills = [...new Set(params.selectedSkills)];
	const uniqueSubagents = [...new Set(params.selectedSubagents)];
	const uniqueTargets = [...new Set(params.targets)];

	const totalL1Tokens = computeLockfileL1Tokens(
		uniqueSkills,
		uniqueSubagents,
		params.catalogIndex,
	);

	let fullBodySkillTokens = 0;
	for (const skillName of uniqueSkills) {
		fullBodySkillTokens += getSkillFullBodyTokens(
			skillName,
			params.catalogIndex,
		);
	}
	let fullBodySubagentTokens = 0;
	for (const saName of uniqueSubagents) {
		fullBodySubagentTokens += getSubagentFullBodyTokens(
			saName,
			params.catalogIndex,
		);
	}
	const combinedFullBodyTokens =
		fullBodySkillTokens + fullBodySubagentTokens;

	let rootInstructionTokens = 0;
	if (params.repoPath) {
		const seenRoot = new Set<string>();
		for (const fileName of ROOT_INSTRUCTION_FILES) {
			if (seenRoot.has(fileName)) {
				continue;
			}
			seenRoot.add(fileName);
			const raw = readBoundedRegularText(path.join(params.repoPath, fileName));
			if (raw !== null) {
				rootInstructionTokens += estimateTokenCount(raw);
			}
		}
	}

	const perTarget: TargetTokenTelemetry[] = [];
	let maxAlwaysOnHarnessTokens = 0;
	let hasAlwaysOnTarget = false;

	for (const target of uniqueTargets) {
		const progressive = isProgressiveHarness(target);
		if (progressive) {
			perTarget.push({
				target,
				mode: "progressive",
				startup_tokens: totalL1Tokens,
			});
		} else {
			hasAlwaysOnTarget = true;
			const harnessTokens = combinedFullBodyTokens;
			if (harnessTokens > maxAlwaysOnHarnessTokens) {
				maxAlwaysOnHarnessTokens = harnessTokens;
			}
			perTarget.push({
				target,
				mode: "always-on",
				startup_tokens: harnessTokens,
			});
		}
	}

	const alwaysOnTokens =
		rootInstructionTokens +
		(hasAlwaysOnTarget ? maxAlwaysOnHarnessTokens : 0);

	const maxAlwaysOnBudget =
		params.config?.token_economy.max_always_on_tokens ??
		DEFAULT_MAX_ALWAYS_ON_TOKENS;

	const warnings: string[] = [];
	if (alwaysOnTokens > maxAlwaysOnBudget) {
		warnings.push(
			`Always-on startup context (${alwaysOnTokens} tokens) exceeds max_always_on_tokens (${maxAlwaysOnBudget}). Consider moving instructions into progressive skills or trimming always-on rules.`,
		);
	}

	return {
		total_l1_tokens: totalL1Tokens,
		always_on_tokens: alwaysOnTokens,
		max_always_on_tokens: maxAlwaysOnBudget,
		per_target: perTarget,
		warnings,
	};
}
