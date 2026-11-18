/**
 * Directory and file discovery/parsing engine for Hybrid Executable Skills (SKILL.md)
 * and Context-Isolated Subagents (SUBAGENT.md / *.agent.md).
 */

import fs from "node:fs";
import path from "node:path";
import {
	MAX_MANIFEST_FILE_BYTES,
	readBoundedUtf8File,
} from "../io/bounded-fs.js";
import {
	type BenchmarkReport,
	BenchmarkReportSchema,
	type EvalSuite,
	EvalSuiteSchema,
	isSafeCrossPlatformPathSegment,
	parseSkillMdText,
	parseSubagentMdText,
	type SkillManifest,
	type SubagentManifest,
} from "../models.js";
import {
	hasForbiddenBinaryExtension,
	scanTextForTrojanUnicode,
} from "./security.js";

export interface ParsedSkillDirectory {
	readonly skillDir: string;
	readonly skillMdPath: string;
	readonly manifest: SkillManifest;
	readonly rawText: string;
	readonly markdownBody: string;
	readonly totalLines: number;
	readonly declaredScripts: string[];
	readonly missingDeclaredScripts: string[];
	readonly extraScripts: string[];
	readonly referenceFiles: string[];
	readonly allFiles: string[];
	readonly evalsPath: string | null;
	readonly benchmarkPath?: string | null;
	readonly evalSuite?: EvalSuite;
	readonly benchmarkReport?: BenchmarkReport;
}

export type ParsedSkill = ParsedSkillDirectory;

export interface ParsedSubagentFile {
	readonly filePath: string;
	readonly manifest: SubagentManifest;
	readonly systemPromptBody: string;
	readonly rawText: string;
}

export interface ParseSkillOptions {
	readonly requireLayout?: boolean;
	readonly requireBenchmark?: boolean;
}

function isStrictlyWithinCanonicalDir(
	canonicalRoot: string,
	candidateRealPath: string,
): boolean {
	const rel = path.relative(canonicalRoot, candidateRealPath);
	return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

function walkForFilesNamed(
	rootDir: string,
	targetFilename: string,
	canonicalRoot?: string,
): string[] {
	if (!fs.existsSync(rootDir)) {
		return [];
	}

	let resolvedCanonicalRoot = canonicalRoot;
	if (resolvedCanonicalRoot === undefined) {
		let rootLstat: fs.Stats;
		try {
			rootLstat = fs.lstatSync(rootDir);
		} catch {
			return [];
		}
		if (rootLstat.isSymbolicLink() || !rootLstat.isDirectory()) {
			return [];
		}
		try {
			resolvedCanonicalRoot = fs.realpathSync(rootDir);
		} catch {
			return [];
		}
	}

	const results: string[] = [];
	const entries = fs.readdirSync(rootDir, { withFileTypes: true });
	for (const entry of entries) {
		if (entry.isSymbolicLink()) {
			continue;
		}
		const fullPath = path.join(rootDir, entry.name);
		let entryLstat: fs.Stats;
		try {
			entryLstat = fs.lstatSync(fullPath);
		} catch {
			continue;
		}
		if (entryLstat.isSymbolicLink()) {
			continue;
		}
		let realFullPath: string;
		try {
			realFullPath = fs.realpathSync(fullPath);
		} catch {
			continue;
		}
		if (!isStrictlyWithinCanonicalDir(resolvedCanonicalRoot, realFullPath)) {
			continue;
		}

		if (entryLstat.isDirectory()) {
			if (
				entry.name.startsWith(".") ||
				entry.name === "node_modules" ||
				entry.name === "dist"
			) {
				continue;
			}
			results.push(
				...walkForFilesNamed(fullPath, targetFilename, resolvedCanonicalRoot),
			);
		} else if (entryLstat.isFile() && entry.name === targetFilename) {
			results.push(fullPath);
		}
	}
	return results.sort();
}

const IGNORED_SKILL_DIRS = new Set([
	".git",
	"__pycache__",
	"node_modules",
	".pytest_cache",
	".ruff_cache",
	".mypy_cache",
]);

const IGNORED_SKILL_FILES = new Set([".DS_Store", "Thumbs.db", "desktop.ini"]);

function tryLstat(targetPath: string): fs.Stats | null {
	try {
		return fs.lstatSync(targetPath);
	} catch (err) {
		const code = (err as NodeJS.ErrnoException | undefined)?.code;
		if (code === "ENOENT" || code === "ENOTDIR") {
			return null;
		}
		throw err;
	}
}

function walkAllSkillFiles(
	rootSkillDir: string,
	currentDir: string = rootSkillDir,
): string[] {
	const dirLstat = tryLstat(currentDir);
	if (!dirLstat || dirLstat.isSymbolicLink() || !dirLstat.isDirectory()) {
		return [];
	}
	const results: string[] = [];
	const entries = fs.readdirSync(currentDir, { withFileTypes: true });
	for (const entry of entries) {
		const fullPath = path.join(currentDir, entry.name);
		const relPath = path.relative(rootSkillDir, fullPath).replace(/\\/g, "/");
		const entryLstat = fs.lstatSync(fullPath);

		if (entry.isSymbolicLink() || entryLstat.isSymbolicLink()) {
			throw new Error(
				`Security violation: Symbolic link '${relPath}' is forbidden inside Skill directories.`,
			);
		}

		if (entryLstat.isDirectory()) {
			if (IGNORED_SKILL_DIRS.has(entry.name)) {
				continue;
			}
			if (!isSafeCrossPlatformPathSegment(entry.name)) {
				throw new Error(
					`Security violation: Unsafe cross-platform directory name '${relPath}' inside Skill directory.`,
				);
			}
			results.push(...walkAllSkillFiles(rootSkillDir, fullPath));
		} else if (entryLstat.isFile()) {
			if (IGNORED_SKILL_FILES.has(entry.name)) {
				continue;
			}
			if (!isSafeCrossPlatformPathSegment(entry.name)) {
				throw new Error(
					`Security violation: Unsafe cross-platform filename '${relPath}' inside Skill directory.`,
				);
			}
			const forbiddenExt = hasForbiddenBinaryExtension(entry.name);
			if (forbiddenExt) {
				throw new Error(
					`Security violation: Forbidden binary or archive file '${relPath}' (${forbiddenExt}) inside Skill directory.`,
				);
			}
			results.push(relPath);
		}
	}
	return results.sort((a, b) => {
		if (a === "SKILL.md") return -1;
		if (b === "SKILL.md") return 1;
		return a.localeCompare(b);
	});
}

/**
 * Recursively discover all skill directories under catalogDir containing SKILL.md.
 * Symbolic links are never traversed and resolved paths must remain strictly inside catalogDir.
 */
export function discoverSkillDirectories(catalogDir: string): string[] {
	const skillMdFiles = walkForFilesNamed(catalogDir, "SKILL.md");
	return skillMdFiles.map((file) => path.dirname(file)).sort();
}

/**
 * Parse a single skill directory and validate its SKILL.md manifest, Level 3 layout,
 * and evaluation / benchmark artifacts (`evals/evals.json`, `evals/benchmark.json`).
 */
export function parseSkillDirectory(
	skillDir: string,
	options: ParseSkillOptions = {},
): ParsedSkillDirectory {
	const requireLayout = options.requireLayout ?? true;
	const requireBenchmark = options.requireBenchmark ?? false;
	const resolvedSkillDir = path.resolve(skillDir);
	const skillMdPath = path.join(skillDir, "SKILL.md");
	const skillMdLstat = tryLstat(skillMdPath);
	if (!skillMdLstat) {
		throw new Error(`Missing SKILL.md in '${skillDir.replace(/\\/g, "/")}'.`);
	}
	if (skillMdLstat.isSymbolicLink()) {
		throw new Error(
			`Security violation: SKILL.md in '${skillDir.replace(/\\/g, "/")}' cannot be a symbolic link.`,
		);
	}

	const rawText = readBoundedUtf8File(
		skillMdPath,
		MAX_MANIFEST_FILE_BYTES,
		skillMdPath.replace(/\\/g, "/"),
	);
	const trojanFindings = scanTextForTrojanUnicode("SKILL.md", rawText, false);
	if (trojanFindings.length > 0) {
		throw new Error(`Security violation: ${trojanFindings[0]!.message}`);
	}

	const { manifest, markdownBody, totalLines } = parseSkillMdText(
		rawText,
		skillMdPath,
	);

	const declaredScripts: string[] = [];
	const missingDeclaredScripts: string[] = [];
	const declaredRelSet = new Set<string>();

	for (const scriptEntry of manifest.entrypoints.scripts) {
		if (
			scriptEntry.path.includes("\0") ||
			path.isAbsolute(scriptEntry.path)
		) {
			throw new Error(
				`Security violation: Declared script path '${scriptEntry.path}' must be a relative path inside the Skill directory.`,
			);
		}
		const resolvedScriptPath = path.resolve(resolvedSkillDir, scriptEntry.path);
		const relToSkill = path.relative(resolvedSkillDir, resolvedScriptPath);
		if (relToSkill.startsWith("..") || path.isAbsolute(relToSkill)) {
			throw new Error(
				`Security violation: Declared script path '${scriptEntry.path}' escapes Skill directory boundary.`,
			);
		}

		declaredRelSet.add(scriptEntry.path);
		const fullScriptPath = path.join(skillDir, scriptEntry.path);
		const scriptLstat = tryLstat(fullScriptPath);
		if (scriptLstat?.isSymbolicLink()) {
			throw new Error(
				`Security violation: Symbolic link '${scriptEntry.path}' is forbidden inside Skill directories.`,
			);
		}
		if (scriptLstat?.isFile()) {
			declaredScripts.push(fullScriptPath);
		} else {
			missingDeclaredScripts.push(scriptEntry.path);
		}
	}

	if (requireLayout && missingDeclaredScripts.length > 0) {
		throw new Error(
			`Skill '${manifest.name}' declares missing Level 3 script(s): ${missingDeclaredScripts.join(", ")}`,
		);
	}

	const scriptsDir = path.join(skillDir, "scripts");
	const scriptsDirLstat = tryLstat(scriptsDir);
	const extraScripts: string[] = [];
	if (
		scriptsDirLstat &&
		!scriptsDirLstat.isSymbolicLink() &&
		scriptsDirLstat.isDirectory()
	) {
		for (const entry of fs.readdirSync(scriptsDir, { withFileTypes: true })) {
			if (entry.isSymbolicLink()) {
				continue;
			}
			const fullEntry = path.join(scriptsDir, entry.name);
			const entryLstat = tryLstat(fullEntry);
			if (
				entryLstat &&
				!entryLstat.isSymbolicLink() &&
				entryLstat.isFile() &&
				(entry.name.endsWith(".py") ||
					entry.name.endsWith(".mjs") ||
					entry.name.endsWith(".js") ||
					entry.name.endsWith(".ts"))
			) {
				const rel = `scripts/${entry.name}`;
				if (!declaredRelSet.has(rel)) {
					extraScripts.push(fullEntry);
				}
			}
		}
	}

	const referencesDir = path.join(skillDir, "references");
	const referencesDirLstat = tryLstat(referencesDir);
	const referenceFiles: string[] = [];
	if (
		referencesDirLstat &&
		!referencesDirLstat.isSymbolicLink() &&
		referencesDirLstat.isDirectory()
	) {
		for (const entry of fs.readdirSync(referencesDir, {
			withFileTypes: true,
		})) {
			if (entry.isSymbolicLink()) {
				continue;
			}
			const fullRef = path.join(referencesDir, entry.name);
			const refLstat = tryLstat(fullRef);
			if (
				refLstat &&
				!refLstat.isSymbolicLink() &&
				refLstat.isFile() &&
				entry.name.endsWith(".md")
			) {
				referenceFiles.push(fullRef);
			}
		}
	}

	const evalsDir = path.join(skillDir, "evals");
	const evalsDirLstat = tryLstat(evalsDir);
	if (evalsDirLstat?.isSymbolicLink()) {
		throw new Error(
			"Security violation: Symbolic link 'evals' is forbidden inside Skill directories.",
		);
	}

	const candidateEvalsPath = path.join(evalsDir, "evals.json");
	const evalsLstat =
		evalsDirLstat && evalsDirLstat.isDirectory()
			? tryLstat(candidateEvalsPath)
			: null;
	if (evalsLstat?.isSymbolicLink()) {
		throw new Error(
			"Security violation: Symbolic link 'evals/evals.json' is forbidden inside Skill directories.",
		);
	}
	const evalsPath = evalsLstat?.isFile() ? candidateEvalsPath : null;

	if (requireLayout && !evalsPath) {
		throw new Error(
			`Skill '${manifest.name}' is missing required 'evals/evals.json' suite per SKILL_CONTRACT.md.`,
		);
	}

	let evalSuite: EvalSuite | undefined;
	if (evalsPath) {
		const rawEvalsText = readBoundedUtf8File(
			evalsPath,
			MAX_MANIFEST_FILE_BYTES,
			"evals/evals.json",
		);
		const evalTrojan = scanTextForTrojanUnicode(
			"evals/evals.json",
			rawEvalsText,
			false,
		);
		if (evalTrojan.length > 0) {
			throw new Error(`Security violation: ${evalTrojan[0]!.message}`);
		}
		let rawEvalsJson: unknown;
		try {
			rawEvalsJson = JSON.parse(rawEvalsText) as unknown;
		} catch (err) {
			throw new Error(
				`Invalid JSON in 'evals/evals.json' for skill '${manifest.name}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}
		if (
			rawEvalsJson &&
			typeof rawEvalsJson === "object" &&
			!Array.isArray(rawEvalsJson) &&
			Object.hasOwn(rawEvalsJson, "skill_name") &&
			typeof (rawEvalsJson as Record<string, unknown>).skill_name ===
				"string" &&
			(rawEvalsJson as Record<string, unknown>).skill_name !== manifest.name
		) {
			throw new Error(
				`EvalSuite skill_name '${String((rawEvalsJson as Record<string, unknown>).skill_name)}' in 'evals/evals.json' does not match SKILL.md manifest name '${manifest.name}'.`,
			);
		}
		if (requireLayout) {
			evalSuite = EvalSuiteSchema.parse(rawEvalsJson);
			if (evalSuite.skill_name !== manifest.name) {
				throw new Error(
					`EvalSuite skill_name '${evalSuite.skill_name}' in 'evals/evals.json' does not match SKILL.md manifest name '${manifest.name}'.`,
				);
			}
		} else {
			const parsedEval = EvalSuiteSchema.safeParse(rawEvalsJson);
			if (parsedEval.success) {
				if (parsedEval.data.skill_name !== manifest.name) {
					throw new Error(
						`EvalSuite skill_name '${parsedEval.data.skill_name}' in 'evals/evals.json' does not match SKILL.md manifest name '${manifest.name}'.`,
					);
				}
				evalSuite = parsedEval.data;
			}
		}
	}

	const candidateBenchmarkPath = path.join(evalsDir, "benchmark.json");
	const benchmarkLstat =
		evalsDirLstat && evalsDirLstat.isDirectory()
			? tryLstat(candidateBenchmarkPath)
			: null;
	if (benchmarkLstat?.isSymbolicLink()) {
		throw new Error(
			"Security violation: Symbolic link 'evals/benchmark.json' is forbidden inside Skill directories.",
		);
	}
	const benchmarkPath = benchmarkLstat?.isFile()
		? candidateBenchmarkPath
		: null;

	if (requireBenchmark && !benchmarkPath) {
		throw new Error(
			`Skill '${manifest.name}' is missing required 'evals/benchmark.json' report per SKILL_CONTRACT.md.`,
		);
	}

	let benchmarkReport: BenchmarkReport | undefined;
	if (benchmarkPath) {
		const rawBenchmarkText = readBoundedUtf8File(
			benchmarkPath,
			MAX_MANIFEST_FILE_BYTES,
			"evals/benchmark.json",
		);
		const benchTrojan = scanTextForTrojanUnicode(
			"evals/benchmark.json",
			rawBenchmarkText,
			false,
		);
		if (benchTrojan.length > 0) {
			throw new Error(`Security violation: ${benchTrojan[0]!.message}`);
		}
		let rawBenchmarkJson: unknown;
		try {
			rawBenchmarkJson = JSON.parse(rawBenchmarkText) as unknown;
		} catch (err) {
			throw new Error(
				`Invalid JSON in 'evals/benchmark.json' for skill '${manifest.name}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}
		benchmarkReport = BenchmarkReportSchema.parse(rawBenchmarkJson);
		if (benchmarkReport.skill_name !== manifest.name) {
			throw new Error(
				`BenchmarkReport skill_name '${benchmarkReport.skill_name}' in 'evals/benchmark.json' does not match SKILL.md manifest name '${manifest.name}'.`,
			);
		}
	}

	const allFiles = walkAllSkillFiles(skillDir);

	return {
		skillDir,
		skillMdPath,
		manifest,
		rawText,
		markdownBody,
		totalLines,
		declaredScripts: declaredScripts.sort(),
		missingDeclaredScripts: missingDeclaredScripts.sort(),
		extraScripts: extraScripts.sort(),
		referenceFiles: referenceFiles.sort(),
		allFiles,
		evalsPath,
		benchmarkPath,
		...(evalSuite ? { evalSuite } : {}),
		...(benchmarkReport ? { benchmarkReport } : {}),
	};
}

function resolveSafeCandidateSubdir(
	baseDir: string,
	canonicalBase: string,
	segments: readonly string[],
): string | null {
	let current = baseDir;
	for (const seg of segments) {
		current = path.join(current, seg);
		if (!fs.existsSync(current)) {
			return null;
		}
		let lstat: fs.Stats;
		try {
			lstat = fs.lstatSync(current);
		} catch {
			return null;
		}
		if (lstat.isSymbolicLink() || !lstat.isDirectory()) {
			return null;
		}
		let realCurrent: string;
		try {
			realCurrent = fs.realpathSync(current);
		} catch {
			return null;
		}
		if (!isStrictlyWithinCanonicalDir(canonicalBase, realCurrent)) {
			return null;
		}
	}
	return current;
}

/**
 * Discover all Subagent Markdown definitions in catalog/subagents/ and .github/agents/*.agent.md.
 * Symbolic links are never traversed and resolved paths must stay strictly inside repoOrCatalogRoot.
 */
export function discoverSubagentFiles(repoOrCatalogRoot: string): string[] {
	if (!fs.existsSync(repoOrCatalogRoot)) {
		return [];
	}
	let rootLstat: fs.Stats;
	try {
		rootLstat = fs.lstatSync(repoOrCatalogRoot);
	} catch {
		return [];
	}
	if (rootLstat.isSymbolicLink() || !rootLstat.isDirectory()) {
		return [];
	}
	let canonicalRoot: string;
	try {
		canonicalRoot = fs.realpathSync(repoOrCatalogRoot);
	} catch {
		return [];
	}

	const results = new Set<string>();
	const candidateSegments: readonly (readonly string[])[] = [
		["subagents"],
		["catalog", "subagents"],
		[".github", "agents"],
	];

	for (const segments of candidateSegments) {
		const dir = resolveSafeCandidateSubdir(
			repoOrCatalogRoot,
			canonicalRoot,
			segments,
		);
		if (!dir) {
			continue;
		}
		const stack = [dir];
		while (stack.length > 0) {
			const current = stack.pop()!;
			for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
				if (entry.isSymbolicLink()) {
					continue;
				}
				const full = path.join(current, entry.name);
				let entryLstat: fs.Stats;
				try {
					entryLstat = fs.lstatSync(full);
				} catch {
					continue;
				}
				if (entryLstat.isSymbolicLink()) {
					continue;
				}
				let realFull: string;
				try {
					realFull = fs.realpathSync(full);
				} catch {
					continue;
				}
				if (!isStrictlyWithinCanonicalDir(canonicalRoot, realFull)) {
					continue;
				}

				if (entryLstat.isDirectory()) {
					stack.push(full);
				} else if (
					entryLstat.isFile() &&
					(entry.name === "SUBAGENT.md" ||
						entry.name === "AGENT.md" ||
						entry.name.endsWith(".agent.md"))
				) {
					results.add(path.resolve(full));
				}
			}
		}
	}

	return [...results].sort();
}

/**
 * Parse and validate a Subagent definition file using bounded, symlink-safe I/O.
 */
export function parseSubagentFile(filePath: string): ParsedSubagentFile {
	const baseName = path.basename(filePath);
	if (!isSafeCrossPlatformPathSegment(baseName)) {
		throw new Error(
			`Security violation: Unsafe cross-platform filename '${baseName}'.`,
		);
	}
	const fileLstat = tryLstat(filePath);
	if (fileLstat?.isSymbolicLink()) {
		throw new Error(
			`Security violation: Subagent file '${filePath.replace(/\\/g, "/")}' cannot be a symbolic link.`,
		);
	}
	const rawText = readBoundedUtf8File(
		filePath,
		MAX_MANIFEST_FILE_BYTES,
		filePath.replace(/\\/g, "/"),
	);
	const trojanFindings = scanTextForTrojanUnicode(baseName, rawText, false);
	if (trojanFindings.length > 0) {
		throw new Error(`Security violation: ${trojanFindings[0]!.message}`);
	}
	const { manifest, systemPromptBody } = parseSubagentMdText(rawText, filePath);
	return {
		filePath,
		manifest,
		systemPromptBody,
		rawText,
	};
}
