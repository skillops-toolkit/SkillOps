import fs from "node:fs";
import path from "node:path";
import type {
	ParsedSkillDirectory,
	ParsedSubagentFile,
} from "../auditor/parser.js";
import {
	CORE_RUNTIME_TARGETS,
	RUNTIME_HARNESS_SPECS,
	type RuntimeTarget,
	SKILLOPS_VERSION,
	type SyncedArtifact,
	type SyncLockEntry,
	type SyncLockfile,
	SyncLockfileSchema,
	type SyncReport,
	SyncReportSchema,
} from "../models.js";
import { loadCatalogIndex } from "./catalog-index.js";
import {
	collectInstalledCodexCatalogItems,
	renderCodexAgentsIndex,
	stripCodexAgentsBlock,
} from "./codex-index.js";
import {
	discoverInstalledArtifactsOnDisk,
	findExistingItemPathInTarget,
} from "./discovery.js";
import {
	computeSha256,
	isGlobalHomePath,
	isRegularFileNoFollow,
	resolveSafeRepoTargetPath,
} from "./fs-safety.js";
import {
	assertAllowedHarnessArtifactPath,
	createNullProtoArtifactsMap,
	getLockArtifact,
	loadExistingLockfile,
	writeLockfileAtomically,
} from "./lockfile.js";
import { renderSkillFilesForRuntime } from "./renderers/skills.js";
import { renderSubagentFilesForRuntime } from "./renderers/subagents.js";
import {
	type AddOptions,
	assertCustomCatalogSkillSafe,
	assertCustomCatalogSubagentSafe,
	type ArtifactHealthState,
	type CleanOptions,
	type InstalledArtifactStatus,
	type PlannedFile,

	type ProjectStatusReport,
	type RemoveOptions,
	type SkippedTargetItem,
	type StatusOptions,
	type UpdateOptions,
} from "./types.js";

function applyPlannedFiles(
	resolvedRepo: string,
	resolvedCatalog: string,
	targets: readonly RuntimeTarget[],
	plannedFiles: readonly PlannedFile[],
	options: {
		dryRun: boolean;
		force: boolean;
		preserveUnlistedLockEntries: boolean;
		skippedTargetItems?: readonly SkippedTargetItem[];
		addedSkillName?: string;
		addedSubagentName?: string;
		codexAgentsIndexContent?: string;
	},
): SyncReport {
	const canonicalRepo = fs.existsSync(resolvedRepo) ? fs.realpathSync(resolvedRepo) : null;
	const lockfilePath = path.join(resolvedRepo, ".skillops-lock.json");
	const existingLock = loadExistingLockfile(lockfilePath, {
		allowMalformedRecovery: options.force,
	});
	const newLockArtifacts: Record<string, SyncLockEntry> =
		createNullProtoArtifactsMap(
			options.preserveUnlistedLockEntries
				? existingLock?.artifacts
				: undefined,
		);

	const artifacts: SyncedArtifact[] = [];
	const skippedExisting: string[] = [];
	const driftConflicts: string[] = [];

	for (const skipped of options.skippedTargetItems ?? []) {
		skippedExisting.push(skipped.relativePath);
		artifacts.push({
			target: skipped.target,
			skill_name: skipped.itemName,
			relative_path: skipped.relativePath,
			sha256: skipped.sha256,
			action: "skipped",
		});
		const previousEntry = getLockArtifact(
			existingLock?.artifacts,
			skipped.relativePath,
		);
		if (previousEntry) {
			newLockArtifacts[skipped.relativePath] = previousEntry;
		}
	}

	for (const pf of plannedFiles) {
		assertAllowedHarnessArtifactPath(pf.target, pf.relativePath, pf.itemName);
		const fullPath = resolveSafeRepoTargetPath(resolvedRepo, pf.relativePath, canonicalRepo);
		const desiredSha = computeSha256(pf.content);
		const fileExists = isRegularFileNoFollow(fullPath);

		if (fileExists) {
			if (!options.force) {
				const currentDiskText = fs.readFileSync(fullPath, "utf-8");
				const currentDiskSha = computeSha256(currentDiskText);
				skippedExisting.push(pf.relativePath);
				artifacts.push({
					target: pf.target,
					skill_name: pf.itemName,
					relative_path: pf.relativePath,
					sha256: currentDiskSha,
					action: "skipped",
				});
				const previousEntry = getLockArtifact(
					existingLock?.artifacts,
					pf.relativePath,
				);
				if (previousEntry) {
					newLockArtifacts[pf.relativePath] = previousEntry;
				}
				continue;
			}

			if (!options.dryRun) {
				fs.mkdirSync(path.dirname(fullPath), { recursive: true });
				fs.writeFileSync(fullPath, pf.content, "utf-8");
			}
			artifacts.push({
				target: pf.target,
				skill_name: pf.itemName,
				relative_path: pf.relativePath,
				sha256: desiredSha,
				action: options.dryRun ? "planned" : "updated",
			});
			newLockArtifacts[pf.relativePath] = {
				target: pf.target,
				skill_name: pf.itemName,
				relative_path: pf.relativePath,
				sha256: desiredSha,
			};
		} else {
			if (!options.dryRun) {
				fs.mkdirSync(path.dirname(fullPath), { recursive: true });
				fs.writeFileSync(fullPath, pf.content, "utf-8");
			}
			artifacts.push({
				target: pf.target,
				skill_name: pf.itemName,
				relative_path: pf.relativePath,
				sha256: desiredSha,
				action: options.dryRun ? "planned" : "created",
			});
			newLockArtifacts[pf.relativePath] = {
				target: pf.target,
				skill_name: pf.itemName,
				relative_path: pf.relativePath,
				sha256: desiredSha,
			};
		}
	}

	if (options.codexAgentsIndexContent !== undefined) {
		assertAllowedHarnessArtifactPath("codex", "AGENTS.md", "codex-agents-index");
		const safeAgentsMd = resolveSafeRepoTargetPath(resolvedRepo, "AGENTS.md", canonicalRepo);
		const hasAgentsFile = isRegularFileNoFollow(safeAgentsMd);
		const diskText = hasAgentsFile ? fs.readFileSync(safeAgentsMd, "utf-8") : "";
		const currentDiskSha = computeSha256(diskText);
		const desiredSha = computeSha256(options.codexAgentsIndexContent);
		const existingAgentsLock = getLockArtifact(existingLock?.artifacts, "AGENTS.md");
		if (
			hasAgentsFile &&
			existingAgentsLock &&
			currentDiskSha !== existingAgentsLock.sha256 &&
			!options.force
		) {
			driftConflicts.push("AGENTS.md");
			artifacts.push({
				target: "codex",
				skill_name: "codex-agents-index",
				relative_path: "AGENTS.md",
				sha256: currentDiskSha,
				action: "conflict",
			});
			newLockArtifacts["AGENTS.md"] = existingAgentsLock;
		} else {
			if (desiredSha !== currentDiskSha) {
				if (!options.dryRun) {
					fs.writeFileSync(safeAgentsMd, options.codexAgentsIndexContent, "utf-8");
				}
				artifacts.push({
					target: "codex",
					skill_name: "codex-agents-index",
					relative_path: "AGENTS.md",
					sha256: desiredSha,
					action: options.dryRun ? "planned" : "updated",
				});
			}
			newLockArtifacts["AGENTS.md"] = {
				target: "codex",
				skill_name: "codex-agents-index",
				relative_path: "AGENTS.md",
				sha256: desiredSha,
			};
		}
	}

	const hasWrittenArtifacts = artifacts.some(
		(a) => a.action === "created" || a.action === "updated",
	);

	// Write updated lockfile if not dry-run, no drift conflicts, and at least one file was created/updated (or lockfile already exists)
	if (
		!options.dryRun &&
		driftConflicts.length === 0 &&
		(hasWrittenArtifacts || existingLock !== null)
	) {
		const activeTargetsForItem = artifacts
			.filter((a) => a.action === "created" || a.action === "updated")
			.map((a) => a.target);
		const mergedTargets = [
			...new Set<RuntimeTarget>([
				...(existingLock?.targets ?? []),
				...activeTargetsForItem,
			]),
		];
		const mergedSkills = [
			...new Set<string>([
				...(existingLock?.selected_skills ?? []),
				...(hasWrittenArtifacts && options.addedSkillName
					? [options.addedSkillName]
					: []),
			]),
		];
		const mergedSubagents = [
			...new Set<string>([
				...(existingLock?.selected_subagents ?? []),
				...(hasWrittenArtifacts && options.addedSubagentName
					? [options.addedSubagentName]
					: []),
			]),
		];

		const lockData: SyncLockfile = SyncLockfileSchema.parse({
			schema_version: "1.0",
			skillops_version: SKILLOPS_VERSION,
			targets: mergedTargets,
			selected_skills: mergedSkills,
			selected_subagents: mergedSubagents,
			total_l1_tokens: existingLock?.total_l1_tokens ?? 0,
			artifacts: newLockArtifacts,
		});
		writeLockfileAtomically(lockfilePath, lockData);
	}

	return SyncReportSchema.parse({
		repo_path: resolvedRepo.replace(/\\/g, "/"),
		catalog_path: resolvedCatalog.replace(/\\/g, "/"),
		targets: [...targets],
		dry_run: options.dryRun,
		force: options.force,
		artifacts,
		skipped_existing: skippedExisting,
		drift_conflicts: driftConflicts,
		lockfile_path: lockfilePath.replace(/\\/g, "/"),
		passed: driftConflicts.length === 0,
	});
}

/**
 * Surgically install a single Skill or Subagent by name across active runtime targets.
 */
export function addSkillOrSubagent(
	repoPath: string,
	catalogDir: string,
	itemName: string,
	options: AddOptions = {},
): SyncReport {
	const resolvedRepo = path.resolve(repoPath);
	const resolvedCatalog = path.resolve(catalogDir);
	const targets = options.targets?.length
		? options.targets
		: CORE_RUNTIME_TARGETS;
	const dryRun = options.dryRun ?? false;
	const force = options.force ?? false;

	const index =
		options.catalogIndex &&
		path.resolve(options.catalogIndex.catalogDir) === resolvedCatalog
			? options.catalogIndex
			: loadCatalogIndex(resolvedCatalog);
	const matchedSkill: ParsedSkillDirectory | null =
		index.skills.get(itemName) ?? null;
	const matchedSubagent: ParsedSubagentFile | null = !matchedSkill
		? (index.subagents.get(itemName) ?? null)
		: null;

	if (!matchedSkill && !matchedSubagent) {
		throw new Error(
			`No Skill or Subagent named '${itemName}' found in catalog '${resolvedCatalog.replace(/\\/g, "/")}'.`,
		);
	}

	if (matchedSkill) {
		assertCustomCatalogSkillSafe(resolvedCatalog, matchedSkill);
	} else if (matchedSubagent) {
		assertCustomCatalogSubagentSafe(resolvedCatalog, matchedSubagent);
	}

	const plannedFiles: PlannedFile[] = [];
	const skippedTargetItems: SkippedTargetItem[] = [];
	const itemKind: "skill" | "subagent" = matchedSkill ? "skill" : "subagent";

	const globalHome = isGlobalHomePath(resolvedRepo);
	for (const target of targets) {
		const targetPlanned = matchedSkill
			? renderSkillFilesForRuntime(matchedSkill, target, { globalHome })
			: renderSubagentFilesForRuntime(matchedSubagent!, target);

		if (!force) {
			const existingRelPath = findExistingItemPathInTarget(
				resolvedRepo,
				itemName,
				itemKind,
				target,
				targetPlanned,
			);
			if (existingRelPath !== null) {
				const existingFull = path.join(resolvedRepo, existingRelPath);
				const diskSha = isRegularFileNoFollow(existingFull)
					? computeSha256(fs.readFileSync(existingFull, "utf-8"))
					: computeSha256("");
				skippedTargetItems.push({
					target,
					itemName,
					relativePath: existingRelPath,
					sha256: diskSha,
				});
				continue;
			}
		}

		plannedFiles.push(...targetPlanned);
	}

	let codexAgentsIndexContent: string | undefined;
	if (
		targets.includes("codex") &&
		fs.existsSync(path.join(resolvedRepo, "AGENTS.md"))
	) {
		const canonicalRepo = fs.existsSync(resolvedRepo) ? fs.realpathSync(resolvedRepo) : null;
		const safeAgentsMd = resolveSafeRepoTargetPath(resolvedRepo, "AGENTS.md", canonicalRepo);
		if (isRegularFileNoFollow(safeAgentsMd)) {
			const existingAgentsMd = fs.readFileSync(safeAgentsMd, "utf-8");
			const codexItems = collectInstalledCodexCatalogItems(
				resolvedRepo,
				resolvedCatalog,
				matchedSkill,
				matchedSubagent,
				index,
			);
			codexAgentsIndexContent = renderCodexAgentsIndex(
				existingAgentsMd,
				codexItems.skills,
				codexItems.subagents,
			);
		}
	}

	return applyPlannedFiles(
		resolvedRepo,
		resolvedCatalog,
		targets,
		plannedFiles,
		{
			dryRun,
			force,
			preserveUnlistedLockEntries: true,
			skippedTargetItems,
			addedSkillName: matchedSkill?.manifest.name,
			addedSubagentName: matchedSubagent?.manifest.name,
			codexAgentsIndexContent,
		},
	);
}

