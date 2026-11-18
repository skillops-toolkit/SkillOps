import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { discoverSkillDirectories, discoverSubagentFiles } from "../parser.js";
import {
	hasForbiddenBinaryExtension,
	isFindingCoveredByAllowlist,
	loadBuiltinAllowlistEntries,
	readBoundedRegularFile,
	trimLeadingSlashes,
} from "./allowlist.js";
import {
	EXECUTABLE_SCRIPT_EXTENSIONS,
	FORBIDDEN_COMPANION_SCRIPT_EXTENSIONS,
	IGNORED_SCAN_DIRS,
	IGNORED_SCAN_FILES,
	JS_TS_SCRIPT_EXTENSIONS,
	KNOWN_TEXT_EXTENSIONS,
	MAX_SCANNED_FILE_BYTES,
	NON_TEXT_MEDIA_EXTENSIONS,
	PYTHON_SCRIPT_EXTENSIONS,
	type SecurityAllowlistEntry,
	type SecurityAuditOptions,
	SHELL_SCRIPT_EXTENSIONS,
	type SkillSecurityAuditReport,
	type SkillSecurityFinding,
} from "./constants.js";
import { scanJsOrTsScriptContent } from "./js-ts.js";
import { scanMarkdownForPromptInjection, shouldScanMarkdownPromptInjection } from "./markdown.js";
import { scanPythonScriptContent } from "./python.js";
import { scanShellScriptContent } from "./shell.js";
import { scanTextForTrojanUnicode } from "./trojan.js";

function extractShebangLine(rawContent: string): string | null {
	const normalized = rawContent.startsWith("\uFEFF")
		? rawContent.slice(1)
		: rawContent;
	if (!normalized.startsWith("#!")) {
		return null;
	}
	const nl = normalized.indexOf("\n");
	const firstLine = (nl === -1 ? normalized : normalized.slice(0, nl)).trim();
	return firstLine.slice(0, 256);
}

function scanScriptByExtensionOrShebang(
	relFile: string,
	ext: string,
	shebangLine: string | null,
	rawContent: string,
): SkillSecurityFinding[] {
	if (PYTHON_SCRIPT_EXTENSIONS.has(ext)) {
		return scanPythonScriptContent(relFile, rawContent);
	}
	if (SHELL_SCRIPT_EXTENSIONS.has(ext)) {
		return scanShellScriptContent(relFile, rawContent);
	}
	if (JS_TS_SCRIPT_EXTENSIONS.has(ext)) {
		return scanJsOrTsScriptContent(relFile, rawContent);
	}
	if (FORBIDDEN_COMPANION_SCRIPT_EXTENSIONS.has(ext)) {
		return [
			{
				file: relFile,
				line: 1,
				rule: "forbidden-shell-execution",
				symbol: ext,
				message: `Forbidden Windows/PowerShell companion script extension '${ext}' in '${relFile}'.`,
			},
			...scanShellScriptContent(relFile, rawContent),
		];
	}
	if (shebangLine !== null) {
		const lowerShebang = shebangLine.toLowerCase();
		let payloadFindings: SkillSecurityFinding[];
		if (lowerShebang.includes("python")) {
			payloadFindings = scanPythonScriptContent(relFile, rawContent);
		} else if (
			lowerShebang.includes("node") ||
			lowerShebang.includes("deno") ||
			lowerShebang.includes("bun") ||
			lowerShebang.includes("ts-node") ||
			lowerShebang.includes("tsx")
		) {
			payloadFindings = scanJsOrTsScriptContent(relFile, rawContent);
		} else {
			payloadFindings = scanShellScriptContent(relFile, rawContent);
		}
		return [
			{
				file: relFile,
				line: 1,
				rule: "forbidden-shell-execution",
				symbol: "#!",
				message: `Forbidden '#!' shebang executable header in non-standard companion file '${relFile}'.`,
			},
			...payloadFindings,
		];
	}
	return [];
}

interface WalkedSecurityTree {
	readonly candidateTextFiles: string[];
	readonly structuralFindings: SkillSecurityFinding[];
}

function walkSkillSecurityTree(
	rootDir: string,
	currentDir: string = rootDir,
): WalkedSecurityTree {
	if (!fs.existsSync(currentDir)) {
		return { candidateTextFiles: [], structuralFindings: [] };
	}

	const rootStat = fs.lstatSync(currentDir);
	if (rootStat.isSymbolicLink()) {
		const rel =
			path.relative(rootDir, currentDir).replace(/\\/g, "/") || ".";
		return {
			candidateTextFiles: [],
			structuralFindings: [
				{
					file: rel,
					line: 1,
					rule: "forbidden-symlink",
					symbol: "symlink",
					message: `Forbidden symbolic link '${rel}' inside Skill directory.`,
				},
			],
		};
	}

	if (!rootStat.isDirectory()) {
		return { candidateTextFiles: [], structuralFindings: [] };
	}

	const candidateTextFiles: string[] = [];
	const structuralFindings: SkillSecurityFinding[] = [];
	const entries = fs.readdirSync(currentDir, { withFileTypes: true });

	for (const entry of entries) {
		const fullPath = path.join(currentDir, entry.name);
		const relFile = path.relative(rootDir, fullPath).replace(/\\/g, "/");
		const entryLstat = fs.lstatSync(fullPath);

		if (entry.isSymbolicLink() || entryLstat.isSymbolicLink()) {
			structuralFindings.push({
				file: relFile,
				line: 1,
				rule: "forbidden-symlink",
				symbol: "symlink",
				message: `Forbidden symbolic link '${relFile}' inside Skill directory.`,
			});
			continue;
		}

		if (entryLstat.isDirectory()) {
			if (IGNORED_SCAN_DIRS.has(entry.name)) {
				continue;
			}
			const child = walkSkillSecurityTree(rootDir, fullPath);
			candidateTextFiles.push(...child.candidateTextFiles);
			structuralFindings.push(...child.structuralFindings);
			continue;
		}

		if (!entryLstat.isFile()) {
			structuralFindings.push({
				file: relFile,
				line: 1,
				rule: "forbidden-binary-file",
				symbol: "non-regular-file",
				message: `Forbidden non-regular file '${relFile}' inside Skill directory.`,
			});
			continue;
		}

		if (IGNORED_SCAN_FILES.has(entry.name)) {
			continue;
		}

		const forbiddenExt = hasForbiddenBinaryExtension(entry.name);
		if (forbiddenExt) {
			structuralFindings.push({
				file: relFile,
				line: 1,
				rule: "forbidden-binary-file",
				symbol: forbiddenExt,
				message: `Forbidden binary or archive file '${relFile}' (${forbiddenExt}) inside Skill directory.`,
			});
			continue;
		}

		const ext = path.extname(entry.name).toLowerCase();
		if (NON_TEXT_MEDIA_EXTENSIONS.has(ext)) {
			continue;
		}

		candidateTextFiles.push(fullPath);
	}

	return {
		candidateTextFiles: candidateTextFiles.sort(),
		structuralFindings,
	};
}

function decodeUtf8TextIfApplicable(
	rawBuffer: Buffer,
	ext: string,
): string | null {
	if (KNOWN_TEXT_EXTENSIONS.has(ext) || EXECUTABLE_SCRIPT_EXTENSIONS.has(ext)) {
		return rawBuffer.toString("utf-8");
	}
	try {
		return new TextDecoder("utf-8", { fatal: true }).decode(rawBuffer);
	} catch {
		return null;
	}
}

/**
 * Audit a single Skill directory for forbidden network exfiltration, dynamic code execution,
 * unsafe shell primitives, prompt-injection Markdown directives, Trojan-Source hidden Unicode,
 * symbolic links, and forbidden binary files.
 */
export function auditSkillSecurity(
	skillDir: string,
	options?: SecurityAuditOptions,
): SkillSecurityAuditReport {
	const resolvedSkillDir = path.resolve(skillDir);
	const allowlistEntries = loadBuiltinAllowlistEntries(
		resolvedSkillDir,
		options,
	);
	const { candidateTextFiles, structuralFindings } =
		walkSkillSecurityTree(resolvedSkillDir);
	const scannedFiles: string[] = [];
	const findings: SkillSecurityFinding[] = [...structuralFindings];

	for (const fullPath of candidateTextFiles) {
		const relFile = path
			.relative(resolvedSkillDir, fullPath)
			.replace(/\\/g, "/");
		const ext = path.extname(fullPath).toLowerCase();
		const isKnownExecutableExt = EXECUTABLE_SCRIPT_EXTENSIONS.has(ext);

		const boundedRead = readBoundedRegularFile(
			fullPath,
			relFile,
			"Skill directory",
		);
		if (!boundedRead.ok) {
			if (isKnownExecutableExt) {
				scannedFiles.push(relFile);
			}
			findings.push(boundedRead.finding);
			continue;
		}
		const rawBuffer = boundedRead.buffer;
		const rawContent = decodeUtf8TextIfApplicable(rawBuffer, ext);
		if (rawContent === null) {
			if (isKnownExecutableExt) {
				scannedFiles.push(relFile);
			}
			continue;
		}

		const nonStandardShebang = isKnownExecutableExt
			? null
			: extractShebangLine(rawContent);
		const isExecutableScript =
			isKnownExecutableExt || nonStandardShebang !== null;
		if (isExecutableScript) {
			scannedFiles.push(relFile);
		}

		const fileSha256 =
			allowlistEntries.length > 0
				? crypto.createHash("sha256").update(rawBuffer).digest("hex")
				: "";

		const fileFindings: SkillSecurityFinding[] = [];
		const longLineSeen = new Set<number>();

		for (const tf of scanTextForTrojanUnicode(
			relFile,
			rawContent,
			isExecutableScript,
		)) {
			if (tf.rule === "suspicious-long-line") {
				longLineSeen.add(tf.line);
			}
			fileFindings.push(tf);
		}

		if (shouldScanMarkdownPromptInjection(relFile)) {
			for (const mf of scanMarkdownForPromptInjection(relFile, rawContent)) {
				if (mf.rule === "suspicious-long-line" && longLineSeen.has(mf.line)) {
					continue;
				}
				fileFindings.push(mf);
			}
		}

		if (isExecutableScript) {
			const scriptFindings = scanScriptByExtensionOrShebang(
				relFile,
				ext,
				nonStandardShebang,
				rawContent,
			);
			for (const sf of scriptFindings) {
				if (sf.rule === "suspicious-long-line" && longLineSeen.has(sf.line)) {
					continue;
				}
				fileFindings.push(sf);
			}
		}

		for (const item of fileFindings) {
			if (
				fileSha256 &&
				isFindingCoveredByAllowlist(
					allowlistEntries,
					fullPath,
					item.rule,
					fileSha256,
				)
			) {
				continue;
			}
			findings.push(item);
		}
	}

	return {
		targetDir: resolvedSkillDir.replace(/\\/g, "/"),
		passed: findings.length === 0,
		scannedFiles,
		findings,
	};
}

interface NonSkillCatalogAuditResult {
	readonly findings: SkillSecurityFinding[];
	readonly scannedFiles: string[];
	readonly auditedFilePaths: Set<string>;
}

/**
 * Audit all non-skill directories and sibling files under `catalogRoot` (such as
 * `catalog/subagents/**` and track root folders) for symbolic links, forbidden binary
 * extensions, unexpected executable scripts / `#!` shebangs, Trojan Unicode, and
 * Markdown prompt-injection / image-beacon payloads.
 */
function auditNonSkillCatalogTree(
	catalogRoot: string,
	coveredSkillDirs: ReadonlySet<string>,
	allowlistEntries: readonly SecurityAllowlistEntry[],
	currentDir: string = catalogRoot,
	auditedFilePaths: Set<string> = new Set(),
): NonSkillCatalogAuditResult {
	if (!fs.existsSync(currentDir)) {
		return { findings: [], scannedFiles: [], auditedFilePaths };
	}

	const findings: SkillSecurityFinding[] = [];
	const scannedFiles: string[] = [];
	const rootStat = fs.lstatSync(currentDir);

	if (rootStat.isSymbolicLink()) {
		const rel =
			path.relative(catalogRoot, currentDir).replace(/\\/g, "/") || ".";
		return {
			findings: [
				{
					file: rel,
					line: 1,
					rule: "forbidden-symlink",
					symbol: "symlink",
					message: `Forbidden symbolic link '${rel}' in catalog directory.`,
				},
			],
			scannedFiles,
			auditedFilePaths,
		};
	}

	if (!rootStat.isDirectory()) {
		return { findings, scannedFiles, auditedFilePaths };
	}

	const entries = fs
		.readdirSync(currentDir, { withFileTypes: true })
		.sort((a, b) => a.name.localeCompare(b.name));

	for (const entry of entries) {
		const fullPath = path.join(currentDir, entry.name);
		const resolvedFull = path.resolve(fullPath);
		if (coveredSkillDirs.has(resolvedFull)) {
			continue;
		}
		const rel = path.relative(catalogRoot, fullPath).replace(/\\/g, "/");
		const entryLstat = fs.lstatSync(fullPath);

		if (entry.isSymbolicLink() || entryLstat.isSymbolicLink()) {
			findings.push({
				file: rel,
				line: 1,
				rule: "forbidden-symlink",
				symbol: "symlink",
				message: `Forbidden symbolic link '${rel}' in catalog directory.`,
			});
			continue;
		}

		if (entryLstat.isDirectory()) {
			if (IGNORED_SCAN_DIRS.has(entry.name)) {
				continue;
			}
			const child = auditNonSkillCatalogTree(
				catalogRoot,
				coveredSkillDirs,
				allowlistEntries,
				fullPath,
				auditedFilePaths,
			);
			findings.push(...child.findings);
			scannedFiles.push(...child.scannedFiles);
			continue;
		}

		if (!entryLstat.isFile()) {
			findings.push({
				file: rel,
				line: 1,
				rule: "forbidden-binary-file",
				symbol: "non-regular-file",
				message: `Forbidden non-regular file '${rel}' in catalog directory.`,
			});
			continue;
		}

		if (IGNORED_SCAN_FILES.has(entry.name)) {
			continue;
		}

		auditedFilePaths.add(resolvedFull);

		const forbiddenExt = hasForbiddenBinaryExtension(entry.name);
		if (forbiddenExt) {
			findings.push({
				file: rel,
				line: 1,
				rule: "forbidden-binary-file",
				symbol: forbiddenExt,
				message: `Forbidden binary or archive file '${rel}' (${forbiddenExt}) in catalog directory.`,
			});
			continue;
		}

		const ext = path.extname(entry.name).toLowerCase();
		if (NON_TEXT_MEDIA_EXTENSIONS.has(ext)) {
			continue;
		}

		const isKnownScriptExt = EXECUTABLE_SCRIPT_EXTENSIONS.has(ext);
		const boundedRead = readBoundedRegularFile(
			fullPath,
			rel,
			"catalog directory",
		);
		if (!boundedRead.ok) {
			if (isKnownScriptExt) {
				scannedFiles.push(rel);
				if (!FORBIDDEN_COMPANION_SCRIPT_EXTENSIONS.has(ext)) {
					findings.push({
						file: rel,
						line: 1,
						rule: "forbidden-shell-execution",
						symbol: ext,
						message: `Forbidden unexpected executable script '${rel}' outside a Skill directory.`,
					});
				}
			}
			findings.push(boundedRead.finding);
			continue;
		}
		const rawBuffer = boundedRead.buffer;
		const rawContent = decodeUtf8TextIfApplicable(rawBuffer, ext);
		if (rawContent === null) {
			if (isKnownScriptExt) {
				scannedFiles.push(rel);
				findings.push({
					file: rel,
					line: 1,
					rule: "forbidden-shell-execution",
					symbol: ext,
					message: `Forbidden unexpected executable script '${rel}' outside a Skill directory.`,
				});
			}
			continue;
		}

		const shebangLine = isKnownScriptExt ? null : extractShebangLine(rawContent);
		const isExecutable = isKnownScriptExt || shebangLine !== null;
		if (isExecutable) {
			scannedFiles.push(rel);
		}

		const fileSha256 =
			allowlistEntries.length > 0
				? crypto.createHash("sha256").update(rawBuffer).digest("hex")
				: "";

		const fileFindings: SkillSecurityFinding[] = [];
		const longLineSeen = new Set<number>();

		for (const tf of scanTextForTrojanUnicode(rel, rawContent, isExecutable)) {
			if (tf.rule === "suspicious-long-line") {
				longLineSeen.add(tf.line);
			}
			fileFindings.push(tf);
		}

		if (
			shouldScanMarkdownPromptInjection(rel) ||
			ext === ".md" ||
			ext === ".mdc"
		) {
			for (const mf of scanMarkdownForPromptInjection(rel, rawContent)) {
				if (mf.rule === "suspicious-long-line" && longLineSeen.has(mf.line)) {
					continue;
				}
				fileFindings.push(mf);
			}
		}

		if (isKnownScriptExt) {
			if (!FORBIDDEN_COMPANION_SCRIPT_EXTENSIONS.has(ext)) {
				fileFindings.push({
					file: rel,
					line: 1,
					rule: "forbidden-shell-execution",
					symbol: ext,
					message: `Forbidden unexpected executable script '${rel}' outside a Skill directory.`,
				});
			}
			for (const sf of scanScriptByExtensionOrShebang(
				rel,
				ext,
				null,
				rawContent,
			)) {
				if (sf.rule === "suspicious-long-line" && longLineSeen.has(sf.line)) {
					continue;
				}
				fileFindings.push(sf);
			}
		} else if (shebangLine !== null) {
			for (const sf of scanScriptByExtensionOrShebang(
				rel,
				ext,
				shebangLine,
				rawContent,
			)) {
				if (sf.rule === "suspicious-long-line" && longLineSeen.has(sf.line)) {
					continue;
				}
				fileFindings.push(sf);
			}
		}

		for (const item of fileFindings) {
			if (
				fileSha256 &&
				isFindingCoveredByAllowlist(
					allowlistEntries,
					fullPath,
					item.rule,
					fileSha256,
				)
			) {
				continue;
			}
			findings.push(item);
		}
	}

	return { findings, scannedFiles, auditedFilePaths };
}

/**
 * Audit every Skill directory, Subagent definition, and non-skill folder under `catalogDir`
 * for security violations.
 */
export function auditCatalogSecurity(
	catalogDir: string,
	options?: SecurityAuditOptions,
): SkillSecurityAuditReport {
	const resolvedCatalog = path.resolve(catalogDir);
	const allowlistEntries = loadBuiltinAllowlistEntries(
		resolvedCatalog,
		options,
	);
	const skillDirs = discoverSkillDirectories(resolvedCatalog);
	const coveredSkillDirs = new Set(skillDirs.map((d) => path.resolve(d)));

	const nonSkillResult = auditNonSkillCatalogTree(
		resolvedCatalog,
		coveredSkillDirs,
		allowlistEntries,
	);
	const scannedFiles: string[] = [...nonSkillResult.scannedFiles];
	const findings: SkillSecurityFinding[] = [...nonSkillResult.findings];

	for (const skillDir of skillDirs) {
		const report = auditSkillSecurity(skillDir, options);
		const skillRelPrefix = path
			.relative(resolvedCatalog, skillDir)
			.replace(/\\/g, "/");
		for (const sf of report.scannedFiles) {
			scannedFiles.push(`${skillRelPrefix}/${sf}`);
		}
		for (const f of report.findings) {
			findings.push({
				...f,
				file: `${skillRelPrefix}/${f.file}`,
			});
		}
	}

	// Ensure any discovered SUBAGENT.md not already audited above is still checked
	const subagentFiles = discoverSubagentFiles(resolvedCatalog);
	for (const saFullPath of subagentFiles) {
		const resolvedSa = path.resolve(saFullPath);
		if (nonSkillResult.auditedFilePaths.has(resolvedSa)) {
			continue;
		}
		let insideCoveredSkill = false;
		for (const covered of coveredSkillDirs) {
			const relToSkill = path.relative(covered, resolvedSa);
			if (
				relToSkill !== "" &&
				!relToSkill.startsWith("..") &&
				!path.isAbsolute(relToSkill)
			) {
				insideCoveredSkill = true;
				break;
			}
		}
		if (insideCoveredSkill) {
			continue;
		}

		const relFile = path
			.relative(resolvedCatalog, saFullPath)
			.replace(/\\/g, "/");
		const boundedRead = readBoundedRegularFile(
			saFullPath,
			relFile,
			"Subagent definition",
		);
		if (!boundedRead.ok) {
			findings.push(boundedRead.finding);
			continue;
		}
		const rawBuffer = boundedRead.buffer;
		const rawContent = rawBuffer.toString("utf-8");
		const fileSha256 =
			allowlistEntries.length > 0
				? crypto.createHash("sha256").update(rawBuffer).digest("hex")
				: "";
		const longLineSeen = new Set<number>();
		const saFindings: SkillSecurityFinding[] = [];
		for (const tf of scanTextForTrojanUnicode(relFile, rawContent, false)) {
			if (tf.rule === "suspicious-long-line") {
				longLineSeen.add(tf.line);
			}
			saFindings.push(tf);
		}
		for (const mf of scanMarkdownForPromptInjection(relFile, rawContent)) {
			if (mf.rule === "suspicious-long-line" && longLineSeen.has(mf.line)) {
				continue;
			}
			saFindings.push(mf);
		}
		for (const item of saFindings) {
			if (
				fileSha256 &&
				isFindingCoveredByAllowlist(
					allowlistEntries,
					saFullPath,
					item.rule,
					fileSha256,
				)
			) {
				continue;
			}
			findings.push(item);
		}
	}

	return {
		targetDir: resolvedCatalog.replace(/\\/g, "/"),
		passed: findings.length === 0,
		scannedFiles,
		findings,
	};
}
