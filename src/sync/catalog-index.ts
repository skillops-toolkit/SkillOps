import fs from "node:fs";
import path from "node:path";
import {
	discoverSkillDirectories,
	discoverSubagentFiles,
	type ParsedSkillDirectory,
	type ParsedSubagentFile,
	parseSkillDirectory,
	parseSubagentFile,
} from "../auditor/parser.js";

export interface CatalogIndex {
	readonly catalogDir: string;
	readonly skills: ReadonlyMap<string, ParsedSkillDirectory>;
	readonly subagents: ReadonlyMap<string, ParsedSubagentFile>;
}

const companionFileCache = new WeakMap<
	ParsedSkillDirectory,
	ReadonlyMap<string, string>
>();

/**
 * Read and cache non-SKILL.md companion files for a parsed skill directory once per parse instance.
 */
export function getCachedCompanionFiles(
	parsed: ParsedSkillDirectory,
): ReadonlyMap<string, string> {
	const existing = companionFileCache.get(parsed);
	if (existing) {
		return existing;
	}
	const files = new Map<string, string>();
	for (const relFile of parsed.allFiles) {
		if (relFile === "SKILL.md") {
			continue;
		}
		const fullFile = path.join(parsed.skillDir, relFile);
		if (!fs.existsSync(fullFile) || !fs.statSync(fullFile).isFile()) {
			continue;
		}
		files.set(relFile, fs.readFileSync(fullFile, "utf-8"));
	}
	companionFileCache.set(parsed, files);
	return files;
}

/**
 * Parse all Skills and Subagents in `catalogDir` once into an immutable lookup index.
 */
export function loadCatalogIndex(catalogDir: string): CatalogIndex {
	const resolvedCatalog = path.resolve(catalogDir);
	const skills = new Map<string, ParsedSkillDirectory>();
	const subagents = new Map<string, ParsedSubagentFile>();
	if (!fs.existsSync(resolvedCatalog)) {
		return { catalogDir: resolvedCatalog, skills, subagents };
	}
	for (const skillDir of discoverSkillDirectories(resolvedCatalog)) {
		try {
			const parsed = parseSkillDirectory(skillDir, { requireLayout: false });
			skills.set(parsed.manifest.name, parsed);
		} catch {
			// Ignore invalid catalog skill during discovery
		}
	}
	for (const saPath of discoverSubagentFiles(resolvedCatalog)) {
		try {
			const parsed = parseSubagentFile(saPath);
			subagents.set(parsed.manifest.name, parsed);
		} catch {
			// Ignore invalid catalog subagent during discovery
		}
	}
	return { catalogDir: resolvedCatalog, skills, subagents };
}
