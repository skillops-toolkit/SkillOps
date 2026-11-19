import fs from "node:fs";
import path from "node:path";
import {
	discoverSkillDirectories,
	discoverSubagentFiles,
	parseSkillDirectory,
	parseSubagentFile,
} from "../auditor/parser.js";
import {
	ALL_RUNTIME_TARGETS,
	RUNTIME_HARNESS_SPECS,
	type RuntimeTarget,
} from "../models.js";
import {
	collectFilesRecursively,
	computeSha256,
	resolveSafeRepoTargetPath,
} from "./fs-safety.js";
import { loadExistingLockfile } from "./lockfile.js";
import {
	type DiscoveredInstalledArtifact,
	PACKAGE_CATALOG_DIR,
	type PlannedFile,
	trimTrailingSlashes,
} from "./types.js";

export function findExistingItemPathInTarget(
	resolvedRepo: string,
	itemName: string,
	kind: "skill" | "subagent",
	target: RuntimeTarget,
	plannedForTarget: readonly PlannedFile[] = [],
): string | null {
	for (const pf of plannedForTarget) {
		const fullPlanned = path.join(resolvedRepo, pf.relativePath);
		if (fs.existsSync(fullPlanned) && fs.statSync(fullPlanned).isFile()) {
			return pf.relativePath;
		}
	}

	const spec = RUNTIME_HARNESS_SPECS[target];
	const candidates: string[] =
		kind === "skill"
			? [
					`${spec.skillsDir}/${itemName}/SKILL.md`,
					`${spec.skillsDir}/${itemName}/RULE.md`,
					`${spec.skillsDir}/skillops-${itemName}.mdc`,
					`${spec.skillsDir}/${itemName}.mdc`,
					`${spec.skillsDir}/skillops-${itemName}.md`,
					`${spec.skillsDir}/${itemName}.md`,
					`${spec.skillsDir}/skillops-${itemName}.instructions.md`,
					`${spec.skillsDir}/${itemName}.instructions.md`,
				]
			: [
					`${spec.subagentsDir}/${itemName}.md`,
					`${spec.subagentsDir}/skillops-agent-${itemName}.md`,
					`${spec.subagentsDir}/${itemName}.agent.md`,
					`${spec.subagentsDir}/skillops-agent-${itemName}.mdc`,
					`${spec.subagentsDir}/${itemName}.mdc`,
					`${spec.subagentsDir}/skillops-agent-${itemName}.prompt`,
					`${spec.subagentsDir}/${itemName}.prompt`,
					`${spec.subagentsDir}/skillops-agent-${itemName}.toml`,
					`${spec.subagentsDir}/${itemName}.toml`,
					`${spec.subagentsDir}/skillops-agent-${itemName}.json`,
					`${spec.subagentsDir}/${itemName}.json`,
				];

	for (const relCandidate of candidates) {
		const fullCandidate = path.join(resolvedRepo, relCandidate);
		if (fs.existsSync(fullCandidate) && fs.statSync(fullCandidate).isFile()) {
			return relCandidate;
		}
	}

	if (kind === "skill") {
		const skillFolderRel = `${spec.skillsDir}/${itemName}`;
		const skillFolderFull = path.join(resolvedRepo, skillFolderRel);
		if (
			fs.existsSync(skillFolderFull) &&
			fs.statSync(skillFolderFull).isDirectory()
		) {
			const entries = fs.readdirSync(skillFolderFull);
			const firstFile = entries.find((entry) =>
				fs.statSync(path.join(skillFolderFull, entry)).isFile(),
			);
			if (firstFile) {
				return `${skillFolderRel}/${firstFile}`;
			}
		}
	}

	return null;
}

/**
 * Check which of the candidate target AI IDEs/CLIs already have a given Skill or Subagent present on disk.
 */
export function detectExistingTargetsForItem(
	repoPath: string,
	itemName: string,
	kind: "skill" | "subagent",
	candidateTargets: readonly RuntimeTarget[],
): RuntimeTarget[] {
	const resolvedRepo = path.resolve(repoPath);
	const existing: RuntimeTarget[] = [];
	for (const target of candidateTargets) {
		if (
			findExistingItemPathInTarget(resolvedRepo, itemName, kind, target) !==
			null
		) {
			existing.push(target);
		}
	}
	return existing;
}


/**
 * Inspect the 28 supported `RUNTIME_HARNESS_SPECS` directories on disk in `repoPath`
 * and merge discovered Skills and Subagents with any entries tracked in `.skillops-lock.json`.
 */
export function discoverInstalledArtifactsOnDisk(
	repoPath: string,
	catalogDir: string,
	targetFilter?: readonly RuntimeTarget[],
): DiscoveredInstalledArtifact[] {
	const resolvedRepo = path.resolve(repoPath);
	const resolvedCatalog = path.resolve(catalogDir);
	const candidateTargets: readonly RuntimeTarget[] =
		targetFilter && targetFilter.length > 0
			? targetFilter
			: ALL_RUNTIME_TARGETS;
	const targetSet = new Set<RuntimeTarget>(candidateTargets);

	const knownSkills = new Set<string>();
	const knownSubagents = new Set<string>();

	if (fs.existsSync(resolvedCatalog)) {
		for (const skillDir of discoverSkillDirectories(resolvedCatalog)) {
			try {
				const parsed = parseSkillDirectory(skillDir, { requireLayout: false });
				knownSkills.add(parsed.manifest.name);
			} catch {
				// Ignore
			}
		}
		for (const saPath of discoverSubagentFiles(resolvedCatalog)) {
			try {
				const parsed = parseSubagentFile(saPath);
				knownSubagents.add(parsed.manifest.name);
			} catch {
				// Ignore
			}
		}
	}

	const lockfilePath = path.join(resolvedRepo, ".skillops-lock.json");
	const existingLock = loadExistingLockfile(lockfilePath);
	for (const s of existingLock?.selected_skills ?? []) {
		knownSkills.add(s);
	}
	for (const sa of existingLock?.selected_subagents ?? []) {
		knownSubagents.add(sa);
	}

	const byRelPath = new Map<string, DiscoveredInstalledArtifact>();

	const inferLockKind = (
		itemName: string,
		relPath: string,
	): "skill" | "subagent" => {
		if (knownSubagents.has(itemName)) {
			return "subagent";
		}
		if (knownSkills.has(itemName)) {
			return "skill";
		}
		if (
			relPath.includes("/agents/") ||
			relPath.includes("/droids/") ||
			relPath.includes("/cli-agents/") ||
			relPath.includes("skillops-agent-") ||
			relPath.endsWith(".agent.md") ||
			relPath.endsWith(".prompt")
		) {
			return "subagent";
		}
		return "skill";
	};

	if (existingLock) {
		for (const [relPath, entry] of Object.entries(existingLock.artifacts)) {
			if (entry.skill_name === "codex-agents-index") {
				continue;
			}
			if (!targetSet.has(entry.target)) {
				continue;
			}
			const normalizedRel = relPath.replace(/\\/g, "/");
			byRelPath.set(normalizedRel, {
				target: entry.target,
				itemName: entry.skill_name,
				kind: inferLockKind(entry.skill_name, normalizedRel),
				relativePath: normalizedRel,
				sha256: entry.sha256,
				fromLockfile: true,
			});
		}
	}

	const addDiskFile = (
		target: RuntimeTarget,
		itemName: string,
		kind: "skill" | "subagent",
		relPath: string,
	): void => {
		const normalizedRel = relPath.replace(/\\/g, "/");
		if (byRelPath.has(normalizedRel)) {
			return;
		}
		const fullPath = path.join(resolvedRepo, normalizedRel);
		if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) {
			return;
		}
		const sha256 = computeSha256(fs.readFileSync(fullPath, "utf-8"));
		byRelPath.set(normalizedRel, {
			target,
			itemName,
			kind,
			relativePath: normalizedRel,
			sha256,
			fromLockfile: false,
		});
	};

	for (const target of candidateTargets) {
		const spec = RUNTIME_HARNESS_SPECS[target];

		// 1. Scan skills directory for this target
		const skillsDirFull = path.join(resolvedRepo, spec.skillsDir);
		if (
			fs.existsSync(skillsDirFull) &&
			fs.statSync(skillsDirFull).isDirectory()
		) {
			const entries = fs.readdirSync(skillsDirFull, { withFileTypes: true });
			for (const entry of entries) {
				const entryFull = path.join(skillsDirFull, entry.name);
				if (entry.isDirectory()) {
					// Ignore subagent subdirectories when skillsDir is a parent of subagentsDir (e.g. .clinerules/workflows)
					const relDir = path
						.relative(resolvedRepo, entryFull)
						.replace(/\\/g, "/");
					if (relDir === spec.subagentsDir) {
						continue;
					}
					const nestedFiles = collectFilesRecursively(entryFull, resolvedRepo);
					for (const nf of nestedFiles) {
						addDiskFile(target, entry.name, "skill", nf);
					}
					continue;
				}
				if (!entry.isFile()) {
					continue;
				}
				const fileName = entry.name;
				const relFile = path
					.relative(resolvedRepo, entryFull)
					.replace(/\\/g, "/");

				if (target === "copilot") {
					const copilotMatch =
						/^skillops-(.+)\.instructions\.md$/.exec(fileName) ??
						/^(.+)\.instructions\.md$/.exec(fileName);
					if (copilotMatch?.[1]) {
						const itemName = copilotMatch[1];
						if (
							fileName.startsWith("skillops-") ||
							knownSkills.has(itemName)
						) {
							addDiskFile(target, itemName, "skill", relFile);
						}
					}
					continue;
				}

				if (target === "cursor") {
					const cursorAgentMatch = /^skillops-agent-(.+)\.mdc$/.exec(fileName);
					if (cursorAgentMatch?.[1]) {
						addDiskFile(target, cursorAgentMatch[1], "subagent", relFile);
						continue;
					}
					const cursorSkillMatch = /^skillops-(.+)\.mdc$/.exec(fileName);
					if (cursorSkillMatch?.[1]) {
						addDiskFile(target, cursorSkillMatch[1], "skill", relFile);
						continue;
					}
					const plainMdc = /^(.+)\.mdc$/.exec(fileName);
					if (plainMdc?.[1]) {
						if (knownSkills.has(plainMdc[1])) {
							addDiskFile(target, plainMdc[1], "skill", relFile);
						} else if (knownSubagents.has(plainMdc[1])) {
							addDiskFile(target, plainMdc[1], "subagent", relFile);
						}
					}
					continue;
				}

				const mdAgentMatch = /^skillops-agent-(.+)\.md$/.exec(fileName);
				if (mdAgentMatch?.[1]) {
					addDiskFile(target, mdAgentMatch[1], "subagent", relFile);
					continue;
				}
				const mdSkillMatch = /^skillops-(.+)\.md$/.exec(fileName);
				if (mdSkillMatch?.[1]) {
					addDiskFile(target, mdSkillMatch[1], "skill", relFile);
					continue;
				}
				const plainMd = /^(.+)\.md$/.exec(fileName);
				if (plainMd?.[1]) {
					if (knownSkills.has(plainMd[1])) {
						addDiskFile(target, plainMd[1], "skill", relFile);
					} else if (
						spec.subagentsDir === spec.skillsDir &&
						knownSubagents.has(plainMd[1])
					) {
						addDiskFile(target, plainMd[1], "subagent", relFile);
					}
				}
			}
		}

		// Copilot also writes .github/prompts/skillops-<name>.prompt.md for skills
		if (target === "copilot") {
			const copilotPromptsDir = path.join(resolvedRepo, ".github", "prompts");
			if (
				fs.existsSync(copilotPromptsDir) &&
				fs.statSync(copilotPromptsDir).isDirectory()
			) {
				for (const entry of fs.readdirSync(copilotPromptsDir, {
					withFileTypes: true,
				})) {
					if (!entry.isFile()) continue;
					const m =
						/^skillops-(.+)\.prompt\.md$/.exec(entry.name) ??
						/^(.+)\.prompt\.md$/.exec(entry.name);
					if (
						m?.[1] &&
						(entry.name.startsWith("skillops-") || knownSkills.has(m[1]))
					) {
						const relFile = `.github/prompts/${entry.name}`;
						addDiskFile(target, m[1], "skill", relFile);
					}
				}
			}
		}

		// 2. Scan subagents directory for this target
		const subagentsDirFull = path.join(resolvedRepo, spec.subagentsDir);
		if (
			fs.existsSync(subagentsDirFull) &&
			fs.statSync(subagentsDirFull).isDirectory()
		) {
			const entries = fs.readdirSync(subagentsDirFull, { withFileTypes: true });
			for (const entry of entries) {
				if (!entry.isFile()) {
					continue;
				}
				const fileName = entry.name;
				const relFile = path
					.relative(resolvedRepo, path.join(subagentsDirFull, fileName))
					.replace(/\\/g, "/");

				const prefixedMatch =
					/^skillops-agent-(.+)\.(md|mdc|prompt|toml|json)$/.exec(fileName);
				if (prefixedMatch?.[1]) {
					addDiskFile(target, prefixedMatch[1], "subagent", relFile);
					continue;
				}

				const copilotAgentMatch = /^(.+)\.agent\.md$/.exec(fileName);
				if (copilotAgentMatch?.[1]) {
					addDiskFile(target, copilotAgentMatch[1], "subagent", relFile);
					continue;
				}

				if (spec.subagentsDir !== spec.skillsDir) {
					const directMatch = /^(.+)\.(md|mdc|prompt|toml|json)$/.exec(
						fileName,
					);
					if (
						directMatch?.[1] &&
						!fileName.startsWith("skillops-") &&
						fileName.toLowerCase() !== "readme.md"
					) {
						addDiskFile(target, directMatch[1], "subagent", relFile);
					}
				}
			}
		}
	}

	return [...byRelPath.values()];
}

