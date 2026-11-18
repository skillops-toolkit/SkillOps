import fs from "node:fs";
import path from "node:path";
import type {
	ParsedSkillDirectory,
	ParsedSubagentFile,
} from "../auditor/parser.js";
import {
	ALL_RUNTIME_TARGETS,
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
	pruneEmptyParentDirs,
	removeEmptyDirsRecursively,
	resolveSafeRepoTargetPath,
} from "./fs-safety.js";
import {
	createNullProtoArtifactsMap,
	getLockArtifact,
	loadExistingLockfile,
} from "./lockfile.js";
import { renderSkillFilesForRuntime } from "./renderers/skills.js";
import { renderSubagentFilesForRuntime } from "./renderers/subagents.js";
import {
	type AddOptions,
	assertCustomCatalogSkillSafe,
	type ArtifactHealthState,
	type CleanOptions,
	type DiscoveredInstalledArtifact,
	type InstalledArtifactStatus,
	type PlannedFile,
	type ProjectStatusReport,
	type RemoveOptions,
	type SkippedTargetItem,
	type StatusOptions,
	type UpdateOptions,
} from "./types.js";

/**
 * Surgically remove a single synced Skill or Subagent by name across target runtimes.
 * Works both with `.skillops-lock.json` and by scanning AI IDE/CLI folders on disk directly.
 */
export function removeSkillOrSubagent(
	repoPath: string,
	catalogDir: string,
	itemName: string,
	options: RemoveOptions = {},
): SyncReport {
	const resolvedRepo = path.resolve(repoPath);
	const resolvedCatalog = path.resolve(catalogDir);
	const targetFilter = options.targets?.length
		? new Set(options.targets)
		: null;
	const dryRun = options.dryRun ?? false;
	const force = options.force ?? false;

	const canonicalRepo = fs.existsSync(resolvedRepo) ? fs.realpathSync(resolvedRepo) : null;
	const lockfilePath = path.join(resolvedRepo, ".skillops-lock.json");
	const existingLock = loadExistingLockfile(lockfilePath);

	const discovered = discoverInstalledArtifactsOnDisk(
		resolvedRepo,
		resolvedCatalog,
		options.targets,
	);
	const matchingMap = new Map<string, DiscoveredInstalledArtifact>();
	for (const d of discovered) {
		if (d.itemName === itemName) {
			matchingMap.set(d.relativePath, d);
		}
	}

	// Fallback check via findExistingItemPathInTarget for custom/unindexed file names matching itemName
	const candidateTargets: readonly RuntimeTarget[] = options.targets?.length
		? options.targets
		: ALL_RUNTIME_TARGETS;
	for (const target of candidateTargets) {
		for (const kind of ["skill", "subagent"] as const) {
			const foundRel = findExistingItemPathInTarget(
				resolvedRepo,
				itemName,
				kind,
				target,
			);
			if (foundRel) {
				const normalizedRel = foundRel.replace(/\\/g, "/");
				if (!matchingMap.has(normalizedRel)) {
					const fullFound = path.join(resolvedRepo, normalizedRel);
					if (fs.existsSync(fullFound) && fs.statSync(fullFound).isFile()) {
						const sha256 = computeSha256(fs.readFileSync(fullFound, "utf-8"));
						matchingMap.set(normalizedRel, {
							target,
							itemName,
							kind,
							relativePath: normalizedRel,
							sha256,
							fromLockfile: false,
						});
					}
				}
			}
		}
	}

	const matchingEntries = [...matchingMap.values()];

	if (matchingEntries.length === 0) {
		throw new Error(
			`No installed artifacts found for '${itemName}' in '${resolvedRepo.replace(/\\/g, "/")}'.`,
		);
	}

	const newLockArtifacts: Record<string, SyncLockEntry> =
		createNullProtoArtifactsMap(existingLock?.artifacts);
	const artifacts: SyncedArtifact[] = [];
	const driftConflicts: string[] = [];

	for (const entry of matchingEntries) {
		const relPath = entry.relativePath;
		const fullPath = resolveSafeRepoTargetPath(resolvedRepo, relPath, canonicalRepo);
		const fileExists =
			fs.existsSync(fullPath) && fs.statSync(fullPath).isFile();

		if (fileExists) {
			const currentDiskSha = computeSha256(fs.readFileSync(fullPath, "utf-8"));
			if (entry.fromLockfile && currentDiskSha !== entry.sha256 && !force) {
				driftConflicts.push(relPath);
				artifacts.push({
					target: entry.target,
					skill_name: entry.itemName,
					relative_path: relPath,
					sha256: currentDiskSha,
					action: "conflict",
				});
				continue;
			}

			if (!dryRun) {
				fs.unlinkSync(fullPath);
				const spec = RUNTIME_HARNESS_SPECS[entry.target];
				const skillFolderFull = path.join(
					resolvedRepo,
					spec.skillsDir,
					entry.itemName,
				);
				removeEmptyDirsRecursively(skillFolderFull);
				pruneEmptyParentDirs(fullPath, resolvedRepo);
			}
		}

		artifacts.push({
			target: entry.target,
			skill_name: entry.itemName,
			relative_path: relPath,
			sha256: entry.sha256,
			action: dryRun ? "planned" : "removed",
		});
		delete newLockArtifacts[relPath];
	}

	if (existingLock && !dryRun && driftConflicts.length === 0) {
		const remainingForSkill = Object.values(newLockArtifacts).some(
			(e) => e.skill_name === itemName,
		);
		const remainingTargetSet = new Set<RuntimeTarget>(
			Object.values(newLockArtifacts).map((e) => e.target),
		);
		const updatedTargets = existingLock.targets.filter((t) =>
			remainingTargetSet.has(t),
		);
		const updatedSkills = remainingForSkill
			? existingLock.selected_skills
			: existingLock.selected_skills.filter((s) => s !== itemName);
		const updatedSubagents = remainingForSkill
			? existingLock.selected_subagents
			: existingLock.selected_subagents.filter((sa) => sa !== itemName);

		const lockData: SyncLockfile = SyncLockfileSchema.parse({
			...existingLock,
			skillops_version: SKILLOPS_VERSION,
			targets: updatedTargets,
			selected_skills: updatedSkills,
			selected_subagents: updatedSubagents,
			artifacts: newLockArtifacts,
		});
		fs.writeFileSync(
			lockfilePath,
			`${JSON.stringify(lockData, null, 2)}\n`,
			"utf-8",
		);
	}

	const affectedTargets = [
		...new Set<RuntimeTarget>(matchingEntries.map((e) => e.target)),
	];
	const reportTargets = targetFilter
		? [...targetFilter]
		: existingLock
			? [
					...new Set<RuntimeTarget>([
						...existingLock.targets,
						...affectedTargets,
					]),
				]
			: affectedTargets;

	return SyncReportSchema.parse({
		repo_path: resolvedRepo.replace(/\\/g, "/"),
		catalog_path: resolvedCatalog.replace(/\\/g, "/"),
		targets: reportTargets,
		dry_run: dryRun,
		force,
		artifacts,
		drift_conflicts: driftConflicts,
		lockfile_path: lockfilePath.replace(/\\/g, "/"),
		passed: driftConflicts.length === 0,
	});
}

/**
 * Clean all SkillOps-managed runtime artifacts tracked in `.skillops-lock.json` or present on disk.
 */
export function cleanSyncedArtifacts(
	repoPath: string,
	catalogDir: string,
	options: CleanOptions = {},
): SyncReport {
	const resolvedRepo = path.resolve(repoPath);
	const resolvedCatalog = path.resolve(catalogDir);
	const dryRun = options.dryRun ?? false;
	const force = options.force ?? false;

	const canonicalRepo = fs.existsSync(resolvedRepo) ? fs.realpathSync(resolvedRepo) : null;
	const lockfilePath = path.join(resolvedRepo, ".skillops-lock.json");
	const existingLock = loadExistingLockfile(lockfilePath);
	const discovered = discoverInstalledArtifactsOnDisk(
		resolvedRepo,
		resolvedCatalog,
	);

	if (!existingLock && discovered.length === 0) {
		return SyncReportSchema.parse({
			repo_path: resolvedRepo.replace(/\\/g, "/"),
			catalog_path: resolvedCatalog.replace(/\\/g, "/"),
			targets: [...ALL_RUNTIME_TARGETS],
			dry_run: dryRun,
			force,
			artifacts: [],
			drift_conflicts: [],
			lockfile_path: lockfilePath.replace(/\\/g, "/"),
			passed: true,
		});
	}

	const artifacts: SyncedArtifact[] = [];
	const driftConflicts: string[] = [];

	// Handle codex AGENTS.md block if tracked in lockfile
	const codexIndexEntry = getLockArtifact(existingLock?.artifacts, "AGENTS.md");
	if (codexIndexEntry && codexIndexEntry.skill_name === "codex-agents-index") {
		const fullAgentsMd = resolveSafeRepoTargetPath(resolvedRepo, "AGENTS.md");
		if (fs.existsSync(fullAgentsMd) && fs.statSync(fullAgentsMd).isFile()) {
			const diskText = fs.readFileSync(fullAgentsMd, "utf-8");
			const currentDiskSha = computeSha256(diskText);
			if (currentDiskSha !== codexIndexEntry.sha256 && !force) {
				driftConflicts.push("AGENTS.md");
				artifacts.push({
					target: codexIndexEntry.target,
					skill_name: codexIndexEntry.skill_name,
					relative_path: "AGENTS.md",
					sha256: currentDiskSha,
					action: "conflict",
				});
			} else {
				if (!dryRun) {
					const stripped = stripCodexAgentsBlock(diskText);
					if (stripped) {
						fs.writeFileSync(fullAgentsMd, stripped, "utf-8");
					} else {
						fs.unlinkSync(fullAgentsMd);
					}
				}
				artifacts.push({
					target: codexIndexEntry.target,
					skill_name: codexIndexEntry.skill_name,
					relative_path: "AGENTS.md",
					sha256: codexIndexEntry.sha256,
					action: dryRun ? "planned" : "removed",
				});
			}
		}
	}

	for (const entry of discovered) {
		const relPath = entry.relativePath;
		const fullPath = resolveSafeRepoTargetPath(resolvedRepo, relPath, canonicalRepo);
		const fileExists =
			fs.existsSync(fullPath) && fs.statSync(fullPath).isFile();

		if (fileExists) {
			const diskText = fs.readFileSync(fullPath, "utf-8");
			const currentDiskSha = computeSha256(diskText);
			if (entry.fromLockfile && currentDiskSha !== entry.sha256 && !force) {
				driftConflicts.push(relPath);
				artifacts.push({
					target: entry.target,
					skill_name: entry.itemName,
					relative_path: relPath,
					sha256: currentDiskSha,
					action: "conflict",
				});
				continue;
			}

			if (!dryRun) {
				fs.unlinkSync(fullPath);
				const spec = RUNTIME_HARNESS_SPECS[entry.target];
				const skillFolderFull = path.join(
					resolvedRepo,
					spec.skillsDir,
					entry.itemName,
				);
				removeEmptyDirsRecursively(skillFolderFull);
				pruneEmptyParentDirs(fullPath, resolvedRepo);
			}
		}

		artifacts.push({
			target: entry.target,
			skill_name: entry.itemName,
			relative_path: relPath,
			sha256: entry.sha256,
			action: dryRun ? "planned" : "removed",
		});
	}

	if (!dryRun && driftConflicts.length === 0 && fs.existsSync(lockfilePath)) {
		fs.unlinkSync(lockfilePath);
	}

	const affectedTargets = [
		...new Set<RuntimeTarget>(discovered.map((d) => d.target)),
	];
	const reportTargets = existingLock
		? [...new Set<RuntimeTarget>([...existingLock.targets, ...affectedTargets])]
		: affectedTargets.length > 0
			? affectedTargets
			: [...ALL_RUNTIME_TARGETS];

	return SyncReportSchema.parse({
		repo_path: resolvedRepo.replace(/\\/g, "/"),
		catalog_path: resolvedCatalog.replace(/\\/g, "/"),
		targets: reportTargets,
		dry_run: dryRun,
		force,
		artifacts,
		drift_conflicts: driftConflicts,
		lockfile_path: lockfilePath.replace(/\\/g, "/"),
		passed: driftConflicts.length === 0,
	});
}

