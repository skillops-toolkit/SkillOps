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
import {
	collectInstalledAiderConventionPaths,
	renderAiderReadConfig,
} from "./aider-config.js";
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
	pruneEmptyParentDirs,
	removeEmptyDirsRecursively,
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

/**
 * Inspect installed Skills and Subagents in a repository (or global `~` scope),
 * combining `.skillops-lock.json` and on-disk runtime directories to classify
 * each artifact's health and SHA-256 drift state (Issue #200).
 */
export function inspectProjectStatus(
	repoPath: string,
	catalogDir: string,
	options: StatusOptions = {},
): ProjectStatusReport {
	const resolvedRepo = path.resolve(repoPath);
	const resolvedCatalog = path.resolve(catalogDir);
	const canonicalRepo = fs.existsSync(resolvedRepo) ? fs.realpathSync(resolvedRepo) : null;
	const lockfilePath = path.join(resolvedRepo, ".skillops-lock.json");
	const existingLock = loadExistingLockfile(lockfilePath);

	const discovered = discoverInstalledArtifactsOnDisk(
		resolvedRepo,
		resolvedCatalog,
		options.targets,
	);
	const catalogMaps =
		options.catalogIndex && path.resolve(options.catalogIndex.catalogDir) === resolvedCatalog
			? options.catalogIndex
			: loadCatalogIndex(resolvedCatalog);

	const globalHome = isGlobalHomePath(resolvedRepo);
	const plannedShaCache = new Map<string, Map<string, string>>();
	const getCatalogShaForFile = (
		itemName: string,
		kind: "skill" | "subagent",
		target: RuntimeTarget,
		relativePath: string,
	): string | null => {
		const cacheKey = `${kind}:${itemName}:${target}`;
		let fileMap = plannedShaCache.get(cacheKey);
		if (!fileMap) {
			fileMap = new Map<string, string>();
			if (kind === "skill") {
				const parsedSkill = catalogMaps.skills.get(itemName);
				if (parsedSkill) {
					for (const pf of renderSkillFilesForRuntime(parsedSkill, target, {
						globalHome,
					})) {
						fileMap.set(
							pf.relativePath.replace(/\\/g, "/"),
							computeSha256(pf.content),
						);
					}
				}
			} else {
				const parsedSubagent = catalogMaps.subagents.get(itemName);
				if (parsedSubagent) {
					for (const pf of renderSubagentFilesForRuntime(
						parsedSubagent,
						target,
					)) {
						fileMap.set(
							pf.relativePath.replace(/\\/g, "/"),
							computeSha256(pf.content),
						);
					}
				}
			}
			plannedShaCache.set(cacheKey, fileMap);
		}
		return fileMap.get(relativePath.replace(/\\/g, "/")) ?? null;
	};

	const counts = {
		up_to_date: 0,
		update_available: 0,
		drift_modified: 0,
		missing_on_disk: 0,
		untracked_on_disk: 0,
	};
	const installedSkills = new Set<string>();
	const installedSubagents = new Set<string>();
	const activeTargets = new Set<RuntimeTarget>();
	const artifacts: InstalledArtifactStatus[] = [];

	for (const d of discovered) {
		const relPath = d.relativePath.replace(/\\/g, "/");
		assertAllowedHarnessArtifactPath(d.target, relPath, d.itemName);
		const fullPath = resolveSafeRepoTargetPath(resolvedRepo, relPath, canonicalRepo);
		const fileExists = isRegularFileNoFollow(fullPath);
		const diskSha256 = fileExists
			? computeSha256(fs.readFileSync(fullPath, "utf-8"))
			: null;
		const lockfileSha256 = d.fromLockfile ? d.sha256 : null;
		const catalogSha256 = getCatalogShaForFile(
			d.itemName,
			d.kind,
			d.target,
			relPath,
		);

		let state: ArtifactHealthState;
		if (!fileExists) {
			state = "missing_on_disk";
		} else if (!d.fromLockfile) {
			state = "untracked_on_disk";
		} else if (diskSha256 !== lockfileSha256) {
			state = "drift_modified";
		} else if (catalogSha256 !== null && catalogSha256 !== diskSha256) {
			state = "update_available";
		} else {
			state = "up_to_date";
		}

		counts[state] += 1;
		activeTargets.add(d.target);
		if (d.kind === "subagent") {
			installedSubagents.add(d.itemName);
		} else {
			installedSkills.add(d.itemName);
		}

		artifacts.push({
			target: d.target,
			itemName: d.itemName,
			kind: d.kind,
			relativePath: relPath,
			state,
			lockfileSha256,
			diskSha256,
			catalogSha256,
		});
	}

	return {
		repo_path: resolvedRepo.replace(/\\/g, "/"),
		catalog_path: resolvedCatalog.replace(/\\/g, "/"),
		lockfile_path: lockfilePath.replace(/\\/g, "/"),
		lockfile_present: existingLock !== null,
		targets: [...activeTargets],
		installed_skills: [...installedSkills],
		installed_subagents: [...installedSubagents],
		artifacts,
		counts,
		passed: counts.drift_modified === 0 && counts.missing_on_disk === 0,
	};
}

function buildEmptyUpdateReport(
	resolvedRepo: string,
	resolvedCatalog: string,
	lockfilePath: string,
	targets: readonly RuntimeTarget[],
	dryRun: boolean,
	force: boolean,
): SyncReport {
	return SyncReportSchema.parse({
		repo_path: resolvedRepo.replace(/\\/g, "/"),
		catalog_path: resolvedCatalog.replace(/\\/g, "/"),
		targets: [...targets],
		dry_run: dryRun,
		force,
		artifacts: [],
		skipped_existing: [],
		drift_conflicts: [],
		lockfile_path: lockfilePath.replace(/\\/g, "/"),
		passed: true,
	});
}

interface InstalledUpdateTuple {
	readonly itemName: string;
	readonly kind: "skill" | "subagent";
	readonly target: RuntimeTarget;
}

function resolveInstalledUpdateTuples(
	resolvedRepo: string,
	resolvedCatalog: string,
	options: UpdateOptions,
): InstalledUpdateTuple[] {
	const discovered = discoverInstalledArtifactsOnDisk(
		resolvedRepo,
		resolvedCatalog,
		options.targets,
		{ allowMalformedRecovery: options.force },
	);
	const requestedNames = options.names?.length
		? [...new Set(options.names)]
		: null;
	if (requestedNames) {
		for (const reqName of requestedNames) {
			if (!discovered.some((d) => d.itemName === reqName)) {
				throw new Error(
					`No installed artifacts found for '${reqName}' in '${resolvedRepo.replace(/\\/g, "/")}'.`,
				);
			}
		}
	}
	const filtered = requestedNames
		? discovered.filter((d) => requestedNames.includes(d.itemName))
		: discovered;
	const tuples = new Map<string, InstalledUpdateTuple>();
	for (const d of filtered) {
		const key = `${d.kind}:${d.itemName}:${d.target}`;
		if (!tuples.has(key)) {
			tuples.set(key, {
				itemName: d.itemName,
				kind: d.kind,
				target: d.target,
			});
		}
	}
	return [...tuples.values()];
}

/**
 * Deterministically update all (or specified) installed Skills and Subagents in a repository
 * (or global `~` scope) to match the latest catalog versions across their active AI harnesses,
 * while preserving locally edited files via SHA-256 drift detection unless `--force` is passed (Issue #202).
 */
export function updateInstalledSkills(
	repoPath: string,
	catalogDir: string,
	options: UpdateOptions = {},
): SyncReport {
	const resolvedRepo = path.resolve(repoPath);
	const resolvedCatalog = path.resolve(catalogDir);
	const dryRun = options.dryRun ?? false;
	const force = options.force ?? false;
	const canonicalRepo = fs.existsSync(resolvedRepo) ? fs.realpathSync(resolvedRepo) : null;
	const lockfilePath = path.join(resolvedRepo, ".skillops-lock.json");
	const existingLock = loadExistingLockfile(lockfilePath, {
		allowMalformedRecovery: force,
	});
	const installedTuples = resolveInstalledUpdateTuples(
		resolvedRepo,
		resolvedCatalog,
		options,
	);
	if (installedTuples.length === 0) {
		const fallbackTargets = options.targets?.length
			? options.targets
			: existingLock?.targets.length
				? existingLock.targets
				: CORE_RUNTIME_TARGETS;
		return buildEmptyUpdateReport(
			resolvedRepo,
			resolvedCatalog,
			lockfilePath,
			fallbackTargets,
			dryRun,
			force,
		);
	}

	const catalogMaps =
		options.catalogIndex && path.resolve(options.catalogIndex.catalogDir) === resolvedCatalog
			? options.catalogIndex
			: loadCatalogIndex(resolvedCatalog);
	const newLockArtifacts: Record<string, SyncLockEntry> =
		createNullProtoArtifactsMap(existingLock?.artifacts);
	const artifacts: SyncedArtifact[] = [];
	const driftConflicts: string[] = [];
	const activeTargets = new Set<RuntimeTarget>();
	const updatedSkills = new Set<string>(existingLock?.selected_skills ?? []);
	const updatedSubagents = new Set<string>(
		existingLock?.selected_subagents ?? [],
	);

	for (const tuple of installedTuples) {
		activeTargets.add(tuple.target);
		let plannedFiles: PlannedFile[] = [];
		if (tuple.kind === "skill") {
			const parsedSkill = catalogMaps.skills.get(tuple.itemName);
			if (!parsedSkill) {
				continue;
			}
			assertCustomCatalogSkillSafe(resolvedCatalog, parsedSkill);
			updatedSkills.add(tuple.itemName);
			plannedFiles = renderSkillFilesForRuntime(parsedSkill, tuple.target, {
				globalHome: isGlobalHomePath(resolvedRepo),
			});
		} else {
			const parsedSubagent = catalogMaps.subagents.get(tuple.itemName);
			if (!parsedSubagent) {
				continue;
			}
			assertCustomCatalogSubagentSafe(resolvedCatalog, parsedSubagent);
			updatedSubagents.add(tuple.itemName);
			plannedFiles = renderSubagentFilesForRuntime(
				parsedSubagent,
				tuple.target,
			);
		}

		// Prune stale companion files tracked in lockfile that were removed from catalog
		if (existingLock) {
			const plannedRelSet = new Set(
				plannedFiles.map((pf) => pf.relativePath.replace(/\\/g, "/")),
			);
			for (const [oldKey, oldEntry] of Object.entries(existingLock.artifacts)) {
				const normOldRel = oldKey.replace(/\\/g, "/");
				if (
					oldEntry.skill_name !== tuple.itemName ||
					oldEntry.target !== tuple.target ||
					plannedRelSet.has(normOldRel)
				) {
					continue;
				}
				assertAllowedHarnessArtifactPath(
					tuple.target,
					normOldRel,
					tuple.itemName,
				);
				const safeOldPath = resolveSafeRepoTargetPath(resolvedRepo, normOldRel, canonicalRepo);
				const oldExists = isRegularFileNoFollow(safeOldPath);
				if (oldExists) {
					const oldDiskSha = computeSha256(
						fs.readFileSync(safeOldPath, "utf-8"),
					);
					if (oldDiskSha !== oldEntry.sha256 && !force) {
						driftConflicts.push(normOldRel);
						artifacts.push({
							target: tuple.target,
							skill_name: tuple.itemName,
							relative_path: normOldRel,
							sha256: oldDiskSha,
							action: "conflict",
						});
						newLockArtifacts[oldKey] = oldEntry;
						continue;
					}
					if (!dryRun) {
						fs.unlinkSync(safeOldPath);
						removeEmptyDirsRecursively(
							path.join(
								resolvedRepo,
								RUNTIME_HARNESS_SPECS[tuple.target].skillsDir,
								tuple.itemName,
							),
						);
						pruneEmptyParentDirs(safeOldPath, resolvedRepo);
					}
					artifacts.push({
						target: tuple.target,
						skill_name: tuple.itemName,
						relative_path: normOldRel,
						sha256: oldEntry.sha256,
						action: dryRun ? "planned" : "removed",
					});
				}
				delete newLockArtifacts[oldKey];
			}
		}

		for (const pf of plannedFiles) {
			const relPath = pf.relativePath.replace(/\\/g, "/");
			assertAllowedHarnessArtifactPath(pf.target, relPath, pf.itemName);
			const fullPath = resolveSafeRepoTargetPath(resolvedRepo, relPath, canonicalRepo);
			const desiredSha = computeSha256(pf.content);
			const fileExists = isRegularFileNoFollow(fullPath);
			const lockEntry = getLockArtifact(existingLock?.artifacts, relPath);

			if (fileExists) {
				const currentDiskSha = computeSha256(fs.readFileSync(fullPath, "utf-8"));
				if (lockEntry && currentDiskSha !== lockEntry.sha256 && !force) {
					driftConflicts.push(relPath);
					artifacts.push({
						target: pf.target,
						skill_name: pf.itemName,
						relative_path: relPath,
						sha256: currentDiskSha,
						action: "conflict",
					});
					continue;
				}

				if (currentDiskSha === desiredSha && !force) {
					artifacts.push({
						target: pf.target,
						skill_name: pf.itemName,
						relative_path: relPath,
						sha256: desiredSha,
						action: "unchanged",
					});
					newLockArtifacts[relPath] = {
						target: pf.target,
						skill_name: pf.itemName,
						relative_path: relPath,
						sha256: desiredSha,
					};
					continue;
				}

				if (!dryRun) {
					fs.mkdirSync(path.dirname(fullPath), { recursive: true });
					fs.writeFileSync(fullPath, pf.content, "utf-8");
				}
				artifacts.push({
					target: pf.target,
					skill_name: pf.itemName,
					relative_path: relPath,
					sha256: desiredSha,
					action: dryRun ? "planned" : "updated",
				});
				newLockArtifacts[relPath] = {
					target: pf.target,
					skill_name: pf.itemName,
					relative_path: relPath,
					sha256: desiredSha,
				};
			} else {
				if (!dryRun) {
					fs.mkdirSync(path.dirname(fullPath), { recursive: true });
					fs.writeFileSync(fullPath, pf.content, "utf-8");
				}
				artifacts.push({
					target: pf.target,
					skill_name: pf.itemName,
					relative_path: relPath,
					sha256: desiredSha,
					action: dryRun ? "planned" : "created",
				});
				newLockArtifacts[relPath] = {
					target: pf.target,
					skill_name: pf.itemName,
					relative_path: relPath,
					sha256: desiredSha,
				};
			}
		}
	}

	if (activeTargets.has("codex") || options.targets?.includes("codex")) {
		assertAllowedHarnessArtifactPath("codex", "AGENTS.md", "codex-agents-index");
		const safeAgentsMd = resolveSafeRepoTargetPath(resolvedRepo, "AGENTS.md", canonicalRepo);
		if (!fs.existsSync(safeAgentsMd) || isRegularFileNoFollow(safeAgentsMd)) {
			const hasAgentsFile = isRegularFileNoFollow(safeAgentsMd);
			const existingAgentsMd = hasAgentsFile ? fs.readFileSync(safeAgentsMd, "utf-8") : "";
			const diskAgentsSha = computeSha256(existingAgentsMd);
			const existingAgentsLock = getLockArtifact(existingLock?.artifacts, "AGENTS.md");
			activeTargets.add("codex");
			if (
				hasAgentsFile &&
				existingAgentsLock &&
				diskAgentsSha !== existingAgentsLock.sha256 &&
				!force
			) {
				driftConflicts.push("AGENTS.md");
				artifacts.push({
					target: "codex",
					skill_name: "codex-agents-index",
					relative_path: "AGENTS.md",
					sha256: diskAgentsSha,
					action: "conflict",
				});
				newLockArtifacts["AGENTS.md"] = existingAgentsLock;
			} else {
				const codexItems = collectInstalledCodexCatalogItems(
					resolvedRepo,
					resolvedCatalog,
					null,
					null,
					catalogMaps,
				);
				if (hasAgentsFile || codexItems.skills.length > 0 || codexItems.subagents.length > 0) {
					const updatedAgentsMd = renderCodexAgentsIndex(
						existingAgentsMd,
						codexItems.skills,
						codexItems.subagents,
					);
					const desiredAgentsSha = computeSha256(updatedAgentsMd);
					if (desiredAgentsSha !== diskAgentsSha) {
						if (!dryRun) {
							fs.writeFileSync(safeAgentsMd, updatedAgentsMd, "utf-8");
						}
						artifacts.push({
							target: "codex",
							skill_name: "codex-agents-index",
							relative_path: "AGENTS.md",
							sha256: desiredAgentsSha,
							action: dryRun ? "planned" : hasAgentsFile ? "updated" : "created",
						});
					}
					newLockArtifacts["AGENTS.md"] = {
						target: "codex",
						skill_name: "codex-agents-index",
						relative_path: "AGENTS.md",
						sha256: desiredAgentsSha,
					};
				}
			}
		}
	}

	if (activeTargets.has("aider") || options.targets?.includes("aider")) {
		assertAllowedHarnessArtifactPath("aider", ".aider.conf.yml", "aider-read-config");
		const safeAiderConf = resolveSafeRepoTargetPath(resolvedRepo, ".aider.conf.yml", canonicalRepo);
		if (!fs.existsSync(safeAiderConf) || isRegularFileNoFollow(safeAiderConf)) {
			const hasAiderFile = isRegularFileNoFollow(safeAiderConf);
			const existingAiderConf = hasAiderFile ? fs.readFileSync(safeAiderConf, "utf-8") : "";
			const diskAiderSha = computeSha256(existingAiderConf);
			const existingAiderLock = getLockArtifact(existingLock?.artifacts, ".aider.conf.yml");
			activeTargets.add("aider");
			if (
				hasAiderFile &&
				existingAiderLock &&
				diskAiderSha !== existingAiderLock.sha256 &&
				!force
			) {
				driftConflicts.push(".aider.conf.yml");
				artifacts.push({
					target: "aider",
					skill_name: "aider-read-config",
					relative_path: ".aider.conf.yml",
					sha256: diskAiderSha,
					action: "conflict",
				});
				newLockArtifacts[".aider.conf.yml"] = existingAiderLock;
			} else {
				const aiderConventions = collectInstalledAiderConventionPaths(resolvedRepo);
				if (hasAiderFile || aiderConventions.length > 0) {
					const updatedAiderConf = renderAiderReadConfig(
						existingAiderConf,
						aiderConventions,
					);
					const desiredAiderSha = computeSha256(updatedAiderConf);
					if (desiredAiderSha !== diskAiderSha) {
						if (!dryRun) {
							fs.writeFileSync(safeAiderConf, updatedAiderConf, "utf-8");
						}
						artifacts.push({
							target: "aider",
							skill_name: "aider-read-config",
							relative_path: ".aider.conf.yml",
							sha256: desiredAiderSha,
							action: dryRun ? "planned" : hasAiderFile ? "updated" : "created",
						});
					}
					newLockArtifacts[".aider.conf.yml"] = {
						target: "aider",
						skill_name: "aider-read-config",
						relative_path: ".aider.conf.yml",
						sha256: desiredAiderSha,
					};
				}
			}
		}
	}

	if (!dryRun && driftConflicts.length === 0 && artifacts.length > 0) {
		const mergedTargets = [
			...new Set<RuntimeTarget>([
				...(existingLock?.targets ?? []),
				...activeTargets,
			]),
		];
		const lockData: SyncLockfile = SyncLockfileSchema.parse({
			schema_version: "1.0",
			skillops_version: SKILLOPS_VERSION,
			targets: mergedTargets,
			selected_skills: [...updatedSkills],
			selected_subagents: [...updatedSubagents],
			total_l1_tokens: existingLock?.total_l1_tokens ?? 0,
			artifacts: newLockArtifacts,
		});
		writeLockfileAtomically(lockfilePath, lockData);
	}

	const reportTargets =
		activeTargets.size > 0
			? [...activeTargets]
			: options.targets?.length
				? [...options.targets]
				: [...CORE_RUNTIME_TARGETS];

	return SyncReportSchema.parse({
		repo_path: resolvedRepo.replace(/\\/g, "/"),
		catalog_path: resolvedCatalog.replace(/\\/g, "/"),
		targets: reportTargets,
		dry_run: dryRun,
		force,
		artifacts,
		skipped_existing: [],
		drift_conflicts: driftConflicts,
		lockfile_path: lockfilePath.replace(/\\/g, "/"),
		passed: driftConflicts.length === 0,
	});
}
