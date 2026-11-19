import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import {
	ALL_RUNTIME_TARGETS,
	estimateTokenCount,
	loadSkillOpsConfig,
	RUNTIME_HARNESS_SPECS,
	type RuntimeTarget,
	type SkillOpsConfig,
	SyncLockfileSchema,
} from "../models.js";
import {
	inspectProjectStatus,
	loadCatalogIndex,
	toPortableReportPath,
} from "../sync/adapters.js";
import {
	CHARM_PALETTE,
	fgHex,
	formatBadge,
	padVisible,
	renderHeaderBanner,
	renderNextSteps,
	renderSectionHeader,
	style,
} from "../ui/index.js";

export type DoctorCheckStatus = "pass" | "warn" | "fail";

export interface DoctorCheckResult {
	readonly id: string;
	readonly name: string;
	readonly status: DoctorCheckStatus;
	readonly message: string;
	readonly remediation?: string;
}

export interface DoctorReport {
	readonly repo_path: string;
	readonly catalog_path: string;
	readonly passed: boolean;
	readonly checks: DoctorCheckResult[];
	readonly summary: {
		readonly passed: number;
		readonly warned: number;
		readonly failed: number;
	};
}

const DEFAULT_MAX_ALWAYS_ON_TOKENS = 4000;
const DEFAULT_MAX_L1_TOKENS = 1500;
const MAX_DOCTOR_READ_BYTES = 256 * 1024;
const UNSAFE_FILENAME_PATTERN = /[<>:"|?*\x00-\x1f]/;

function readBoundedRegularFile(filePath: string): string | null {
	try {
		const stat = fs.lstatSync(filePath);
		if (
			stat.isSymbolicLink() ||
			!stat.isFile() ||
			stat.size > MAX_DOCTOR_READ_BYTES
		) {
			return null;
		}
		return fs.readFileSync(filePath, "utf-8");
	} catch {
		return null;
	}
}

function checkSkillOpsConfig(repoPath: string): {
	readonly result: DoctorCheckResult;
	readonly config: SkillOpsConfig | null;
} {
	const cfgRes = loadSkillOpsConfig(repoPath);
	if (cfgRes.error) {
		return {
			config: null,
			result: {
				id: "config-validity",
				name: ".skillops.yml Schema & Path Containment",
				status: "fail",
				message: `Invalid .skillops.yml: ${cfgRes.error}`,
				remediation:
					"Fix .skillops.yml syntax, unknown keys, or unsafe relative catalog_dir paths.",
			},
		};
	}
	if (!cfgRes.exists) {
		return {
			config: null,
			result: {
				id: "config-validity",
				name: ".skillops.yml Schema & Path Containment",
				status: "pass",
				message: "No .skillops.yml override present (using built-in defaults).",
			},
		};
	}
	return {
		config: cfgRes.config,
		result: {
			id: "config-validity",
			name: ".skillops.yml Schema & Path Containment",
			status: "pass",
			message: `Valid .skillops.yml (targets: ${cfgRes.config?.targets.join(", ") ?? "default"}).`,
		},
	};
}

function checkLockfileAndDrift(
	repoPath: string,
	catalogDir: string,
	targets?: readonly RuntimeTarget[],
): DoctorCheckResult {
	const lockPath = path.join(repoPath, ".skillops-lock.json");
	if (fs.existsSync(lockPath)) {
		const rawLock = readBoundedRegularFile(lockPath);
		if (rawLock === null) {
			return {
				id: "lockfile-integrity",
				name: ".skillops-lock.json Integrity & Drift",
				status: "fail",
				message:
					".skillops-lock.json is a symlink, unreadable, or exceeds maximum size.",
				remediation:
					"Remove the invalid .skillops-lock.json and run `npx skillops-cli add` to regenerate it.",
			};
		}
		try {
			const parsed: unknown = JSON.parse(rawLock);
			SyncLockfileSchema.parse(parsed);
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			return {
				id: "lockfile-integrity",
				name: ".skillops-lock.json Integrity & Drift",
				status: "fail",
				message: `Corrupted .skillops-lock.json: ${msg}`,
				remediation:
					"Run `npx skillops-cli add --force` or restore .skillops-lock.json from git.",
			};
		}
	}

	const catalogIndex = loadCatalogIndex(catalogDir);
	const statusReport = inspectProjectStatus(repoPath, catalogDir, {
		targets,
		catalogIndex,
	});

	if (
		statusReport.counts.drift_modified > 0 ||
		statusReport.counts.missing_on_disk > 0
	) {
		return {
			id: "lockfile-integrity",
			name: ".skillops-lock.json Integrity & Drift",
			status: "fail",
			message: `Detected ${statusReport.counts.drift_modified} drift-modified and ${statusReport.counts.missing_on_disk} missing artifact(s).`,
			remediation:
				"Run `npx skillops-cli update --force` to reconcile drift or restore missing runtime files.",
		};
	}

	if (statusReport.counts.untracked_on_disk > 0) {
		return {
			id: "lockfile-integrity",
			name: ".skillops-lock.json Integrity & Drift",
			status: "warn",
			message: `Found ${statusReport.counts.untracked_on_disk} untracked runtime file(s) not recorded in .skillops-lock.json.`,
			remediation:
				"Run `npx skillops-cli status` to inspect untracked files or `npx skillops-cli add` to track them.",
		};
	}

	return {
		id: "lockfile-integrity",
		name: ".skillops-lock.json Integrity & Drift",
		status: "pass",
		message: statusReport.lockfile_present
			? `Lockfile healthy (${statusReport.counts.up_to_date} up-to-date, ${statusReport.counts.update_available} update available).`
			: "No .skillops-lock.json present and no untracked artifacts detected.",
	};
}

function checkSymlinkAndFilenameSafety(repoPath: string): DoctorCheckResult {
	const symlinksFound: string[] = [];
	const unsafeNamesFound: string[] = [];
	const seenDirs = new Set<string>();

	const scanDir = (relDir: string, depth: number): void => {
		if (depth > 4) {
			return;
		}
		const fullDir = path.join(repoPath, relDir);
		if (!fs.existsSync(fullDir)) {
			return;
		}
		let stat: fs.Stats;
		try {
			stat = fs.lstatSync(fullDir);
		} catch {
			return;
		}
		if (stat.isSymbolicLink()) {
			symlinksFound.push(relDir.replace(/\\/g, "/"));
			return;
		}
		if (!stat.isDirectory()) {
			return;
		}
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(fullDir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			const relEntry = path.posix.join(relDir.replace(/\\/g, "/"), entry.name);
			if (UNSAFE_FILENAME_PATTERN.test(entry.name)) {
				unsafeNamesFound.push(relEntry);
			}
			if (entry.isSymbolicLink()) {
				symlinksFound.push(relEntry);
			} else if (entry.isDirectory()) {
				scanDir(relEntry, depth + 1);
			}
		}
	};

	for (const target of ALL_RUNTIME_TARGETS) {
		const spec = RUNTIME_HARNESS_SPECS[target];
		for (const dirCandidate of [spec.skillsDir, spec.subagentsDir]) {
			if (!dirCandidate || seenDirs.has(dirCandidate)) {
				continue;
			}
			seenDirs.add(dirCandidate);
			scanDir(dirCandidate, 0);
		}
	}

	if (symlinksFound.length > 0 || unsafeNamesFound.length > 0) {
		return {
			id: "symlink-filename-safety",
			name: "Symlink & Cross-Platform Filename Safety",
			status: "fail",
			message: `Unsafe runtime paths detected (${symlinksFound.length} symlink(s), ${unsafeNamesFound.length} invalid filename(s)): ${[...symlinksFound, ...unsafeNamesFound].slice(0, 4).join(", ")}.`,
			remediation:
				"Replace symbolic links inside IDE directories with real files and rename cross-platform unsafe filenames.",
		};
	}

	return {
		id: "symlink-filename-safety",
		name: "Symlink & Cross-Platform Filename Safety",
		status: "pass",
		message: "All detected IDE runtime folders contain regular files and portable filenames.",
	};
}

function checkStartupTokenBudget(
	repoPath: string,
	catalogDir: string,
	config: SkillOpsConfig | null,
): DoctorCheckResult {
	const maxAlwaysOn =
		(config?.token_economy as { max_always_on_tokens?: number } | undefined)
			?.max_always_on_tokens ?? DEFAULT_MAX_ALWAYS_ON_TOKENS;
	const maxL1 = config?.token_economy.max_l1_tokens ?? DEFAULT_MAX_L1_TOKENS;

	let rootTokens = 0;
	for (const rootFile of ["AGENTS.md", "CLAUDE.md", "GEMINI.md"]) {
		const text = readBoundedRegularFile(path.join(repoPath, rootFile));
		if (text !== null) {
			rootTokens += estimateTokenCount(text);
		}
	}

	const catalogIndex = loadCatalogIndex(catalogDir);
	let statusReport: ReturnType<typeof inspectProjectStatus> | null = null;
	try {
		statusReport = inspectProjectStatus(repoPath, catalogDir, {
			targets: config?.targets,
			catalogIndex,
		});
	} catch {
		statusReport = null;
	}

	let l1Tokens = 0;
	let alwaysOnSkillTokens = 0;
	for (const skillName of statusReport?.installed_skills ?? []) {
		const skill = catalogIndex.skills.get(skillName);
		if (skill) {
			l1Tokens += Math.max(1, skill.manifest.description_tokens) + 12;
			alwaysOnSkillTokens += estimateTokenCount(skill.rawText);
		}
	}
	for (const saName of statusReport?.installed_subagents ?? []) {
		const sa = catalogIndex.subagents.get(saName);
		if (sa) {
			l1Tokens += Math.max(1, sa.manifest.description_tokens) + 12;
			alwaysOnSkillTokens += estimateTokenCount(sa.rawText);
		}
	}

	const hasAlwaysOnTarget = (statusReport?.targets ?? []).some(
		(t) => RUNTIME_HARNESS_SPECS[t].skillFormat !== "progressive-skill-dir",
	);
	const totalAlwaysOn =
		rootTokens + (hasAlwaysOnTarget ? alwaysOnSkillTokens : 0);

	if (l1Tokens > maxL1 || totalAlwaysOn > maxAlwaysOn) {
		return {
			id: "startup-token-budget",
			name: "Startup Token Tax & L1 Index Budget",
			status: "fail",
			message: `Token budget exceeded (L1: ${l1Tokens}/${maxL1}, Always-On: ${totalAlwaysOn}/${maxAlwaysOn}).`,
			remediation:
				"Trim root instruction files (AGENTS.md/CLAUDE.md/GEMINI.md), remove unused skills, or switch always-on harnesses to progressive targets.",
		};
	}

	return {
		id: "startup-token-budget",
		name: "Startup Token Tax & L1 Index Budget",
		status: "pass",
		message: `Within startup budget (L1: ${l1Tokens}/${maxL1} tokens, Always-On: ${totalAlwaysOn}/${maxAlwaysOn} tokens).`,
	};
}

function checkVendorConfigWiring(
	repoPath: string,
	catalogDir: string,
	config: SkillOpsConfig | null,
): DoctorCheckResult {
	let statusReport: ReturnType<typeof inspectProjectStatus> | null = null;
	try {
		statusReport = inspectProjectStatus(repoPath, catalogDir, {
			targets: config?.targets,
		});
	} catch {
		return {
			id: "vendor-config-wiring",
			name: "Vendor Config Wiring",
			status: "warn",
			message:
				"Skipped vendor config wiring check because .skillops-lock.json could not be parsed.",
			remediation:
				"Repair .skillops-lock.json first, then re-run `npx skillops-cli doctor`.",
		};
	}
	const issues: string[] = [];

	const aiderInstalled = statusReport.artifacts.filter(
		(a) => a.target === "aider" && a.relativePath.startsWith(".aider/"),
	);
	if (aiderInstalled.length > 0) {
		const aiderConfRaw = readBoundedRegularFile(
			path.join(repoPath, ".aider.conf.yml"),
		);
		if (aiderConfRaw === null) {
			issues.push("missing .aider.conf.yml for installed Aider conventions");
		} else {
			try {
				const parsed = YAML.parse(aiderConfRaw, { maxAliasCount: 0 }) as {
					read?: unknown;
				} | null;
				const readList = Array.isArray(parsed?.read)
					? parsed.read.map(String)
					: [];
				for (const item of aiderInstalled) {
					if (!readList.includes(item.relativePath)) {
						issues.push(`.aider.conf.yml read: missing '${item.relativePath}'`);
					}
				}
			} catch {
				issues.push(".aider.conf.yml is not valid YAML");
			}
		}
	}

	const codexInstalled = statusReport.artifacts.filter(
		(a) => a.target === "codex" && a.itemName !== "AGENTS.md",
	);
	if (codexInstalled.length > 0) {
		const agentsRaw = readBoundedRegularFile(path.join(repoPath, "AGENTS.md"));
		if (agentsRaw === null || !agentsRaw.includes("skillops:codex-index:start")) {
			issues.push("AGENTS.md missing SkillOps Codex index block");
		}
	}

	if (issues.length > 0) {
		return {
			id: "vendor-config-wiring",
			name: "Vendor Config Wiring",
			status: "warn",
			message: `Wiring mismatch: ${issues.slice(0, 3).join("; ")}.`,
			remediation:
				"Run `npx skillops-cli update --force` to resynchronize .aider.conf.yml and AGENTS.md index blocks.",
		};
	}

	return {
		id: "vendor-config-wiring",
		name: "Vendor Config Wiring",
		status: "pass",
		message: "Vendor config files (.aider.conf.yml, AGENTS.md) are properly wired.",
	};
}

/**
 * Run a zero-mutation 5-point workspace diagnostic without modifying any repository files.
 */
export function runWorkspaceDoctor(
	repoPath: string,
	catalogDir: string,
): DoctorReport {
	const resolvedRepo = path.resolve(repoPath);
	const resolvedCatalog = path.resolve(catalogDir);

	const cfgCheck = checkSkillOpsConfig(resolvedRepo);
	const checks: DoctorCheckResult[] = [
		cfgCheck.result,
		checkLockfileAndDrift(
			resolvedRepo,
			resolvedCatalog,
			cfgCheck.config?.targets,
		),
		checkSymlinkAndFilenameSafety(resolvedRepo),
		checkStartupTokenBudget(resolvedRepo, resolvedCatalog, cfgCheck.config),
		checkVendorConfigWiring(resolvedRepo, resolvedCatalog, cfgCheck.config),
	];

	const passedCount = checks.filter((c) => c.status === "pass").length;
	const warnedCount = checks.filter((c) => c.status === "warn").length;
	const failedCount = checks.filter((c) => c.status === "fail").length;

	return {
		repo_path: resolvedRepo.replace(/\\/g, "/"),
		catalog_path: resolvedCatalog.replace(/\\/g, "/"),
		passed: failedCount === 0,
		checks,
		summary: {
			passed: passedCount,
			warned: warnedCount,
			failed: failedCount,
		},
	};
}

export function formatDoctorReport(
	report: DoctorReport,
	format: "table" | "json" | "markdown" = "table",
	colorEnabled?: boolean,
): string {
	const portableRepo = toPortableReportPath(report.repo_path, report.repo_path);
	const portableCatalog = toPortableReportPath(
		report.catalog_path,
		report.repo_path,
	);

	if (format === "json") {
		return `${JSON.stringify(
			{
				...report,
				repo_path: portableRepo,
				catalog_path: portableCatalog,
			},
			null,
			2,
		)}\n`;
	}

	if (format === "markdown") {
		return [
			"## SkillOps Workspace Doctor Report",
			"",
			`- **Repository**: \`${portableRepo}\``,
			`- **Status**: **${report.passed ? "PASS" : "FAIL"}** (${report.summary.passed} pass, ${report.summary.warned} warn, ${report.summary.failed} fail)`,
			"",
			"| Check | Status | Details |",
			"| :--- | :---: | :--- |",
			...report.checks.map(
				(c) => `| ${c.name} | \`${c.status.toUpperCase()}\` | ${c.message} |`,
			),
			"",
		].join("\n");
	}

	const c = colorEnabled;
	const bar = style.dim("│", c);
	const banner = renderHeaderBanner("Workspace Doctor Diagnostic", {
		colorEnabled: c,
	});
	const statusBadge = report.passed
		? formatBadge("pass", "HEALTHY", c)
		: formatBadge("fail", "ISSUES FOUND", c);
	const statusLine = `${bar}  ${padVisible(fgHex(CHARM_PALETTE.lavender, style.bold("Status:", c), c), 10, "left")}${statusBadge} ${style.dim("·", c)} ${fgHex(CHARM_PALETTE.white, `${report.summary.passed} pass, ${report.summary.warned} warn, ${report.summary.failed} fail`, c)}`;

	const checkLines: string[] = [renderSectionHeader("5-Point Checks", c)];
	for (const chk of report.checks) {
		const pill =
			chk.status === "pass"
				? formatBadge("pass", "PASS", c)
				: chk.status === "warn"
					? formatBadge("warn", "WARN", c)
					: formatBadge("fail", "FAIL", c);
		checkLines.push(`${bar}  ${pill} ${fgHex(CHARM_PALETTE.white, chk.name, c)}`);
		checkLines.push(`${bar}         ${style.dim(chk.message, c)}`);
		if (chk.remediation) {
			checkLines.push(
				`${bar}         ${fgHex(CHARM_PALETTE.amber, `Fix: ${chk.remediation}`, c)}`,
			);
		}
	}

	const nextSteps = renderNextSteps(
		[
			{
				command: "npx skillops-cli status",
				description: "Inspect detailed per-artifact status",
			},
			{
				command: "npx skillops-cli update --force",
				description: "Repair drift or vendor config wiring",
			},
		],
		c,
	);

	return [banner, statusLine, ...checkLines, nextSteps]
		.filter(Boolean)
		.join("\n");
}
