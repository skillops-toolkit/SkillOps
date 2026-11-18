import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
	ALL_RUNTIME_TARGETS,
	BenchmarkReportSchema,
	createSkillManifest,
	createSubagentManifest,
	discoverSkillDirectories,
	discoverSubagentFiles,
	EvalSuiteSchema,
	isAllowedHarnessArtifactPath,
	isSafeCrossPlatformPathSegment,
	isSafeLockRelativePath,
	loadSkillOpsConfig,
	loadSkillOpsConfigFromDisk,
	MAX_COMPANION_OR_LOCK_BYTES,
	MAX_CONFIG_FILE_BYTES,
	MAX_LOCKFILE_ARTIFACTS,
	MAX_MANIFEST_FILE_BYTES,
	parseSkillDirectory,
	parseSkillOpsConfigText,
	parseSubagentFile,
	RUNTIME_HARNESS_SPECS,
	readBoundedUtf8File,
	SandboxModeSchema,
	ScriptEntrypointSchema,
	SkillOpsConfigSchema,
	splitFrontmatter,
	SyncLockfileSchema,
} from "../src/index.js";
import type { ParsedSkill } from "../src/auditor/parser.js";
import { readBoundedUtf8File as directReadBoundedUtf8File } from "../src/io/bounded-fs.js";
import { renderSubagentFilesForRuntime } from "../src/sync/adapters.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");
const CATALOG_ROOT = path.join(REPO_ROOT, "catalog");
const VALID_SHA256 = "b".repeat(64);

const VALID_DESCRIPTION =
	"Use when validating bounded manifest parsing, cross-platform path segments, YAML alias rejection, target-scoped lockfile schemas, and deterministic evaluation contracts across automated regression suites without network access or shell execution. Rejects oversized files, symbolic links, duplicate keys, prototype pollution segments, and reserved device names across all supported coding agent harnesses.";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	tempDirs.push(dir);
	return dir;
}

function createCrossPlatformSymlink(
	targetFile: string,
	targetDir: string,
	linkPath: string,
): void {
	try {
		fs.symlinkSync(targetFile, linkPath, "file");
	} catch {
		const fallbackType = process.platform === "win32" ? "junction" : "dir";
		fs.symlinkSync(targetDir, linkPath, fallbackType);
	}
}

function writeValidSkillFixture(
	skillDir: string,
	name = "sample-bounded-skill",
): void {
	fs.mkdirSync(path.join(skillDir, "scripts"), { recursive: true });
	fs.mkdirSync(path.join(skillDir, "evals"), { recursive: true });

	const skillMd = [
		"---",
		`name: ${name}`,
		`description: "${VALID_DESCRIPTION}"`,
		"version: 1.0.0",
		"track: arch-quality",
		"tags:",
		"  - security",
		"  - bounds",
		"entrypoints:",
		"  scripts:",
		"    - path: scripts/check.py",
		'      description: "Deterministic offline verification helper."',
		"---",
		"",
		"# Sample Bounded Skill",
		"",
		"Deterministic offline instructions.",
		"",
	].join("\n");

	fs.writeFileSync(path.join(skillDir, "SKILL.md"), skillMd, "utf-8");
	fs.writeFileSync(
		path.join(skillDir, "scripts", "check.py"),
		'import json\nprint(json.dumps({"ok": True}))\n',
		"utf-8",
	);
	fs.writeFileSync(
		path.join(skillDir, "evals", "evals.json"),
		JSON.stringify(
			{
				skill_name: name,
				schema_version: "1.0",
				evals: [
					{
						id: "eval-01",
						name: "Verifies bounded JSON output",
						prompt: "Run deterministic check against fixture",
						fixtures: [],
						assertions: [
							{
								id: "assert-01",
								type: "exit_code_zero",
								target: "scripts/check.py",
								description: "Exits with status 0.",
							},
						],
					},
				],
			},
			null,
			2,
		),
		"utf-8",
	);
	fs.writeFileSync(
		path.join(skillDir, "evals", "benchmark.json"),
		JSON.stringify(
			{
				skill_name: name,
				runner: "vitest-offline-harness",
				timestamp: "2026-11-17T12:00:00Z",
				with_skill: {
					pass_rate_mean: 1,
					pass_rate_stddev: 0,
					tokens_mean: 420,
					latency_ms_mean: 95,
				},
				without_skill: {
					pass_rate_mean: 0.5,
					pass_rate_stddev: 0.1,
					tokens_mean: 780,
					latency_ms_mean: 180,
				},
				delta: {
					pass_rate_gain: 0.5,
					token_reduction_pct: 46.15,
					verdict: "CERTIFIED_IMPROVEMENT",
				},
			},
			null,
			2,
		),
		"utf-8",
	);
}

afterEach(() => {
	while (tempDirs.length > 0) {
		const dir = tempDirs.pop();
		if (dir) {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	}
});

describe("ISS-213 Wave 2: Zod v4 Upgrade, Bounded FS/YAML, Cross-Platform Paths & Subagent/Eval Wiring", () => {
	it("upgrades zod to >= 4.6.6 and isolates node:fs out of src/models.ts into src/io/bounded-fs.ts", () => {
		const pkgJson = JSON.parse(
			fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf-8"),
		) as { dependencies: Record<string, string> };
		expect(pkgJson.dependencies.zod).toBe("^4.6.7");

		const installedZodPkg = JSON.parse(
			fs.readFileSync(
				path.join(REPO_ROOT, "node_modules", "zod", "package.json"),
				"utf-8",
			),
		) as { version: string };
		const [major, minor, patch] = installedZodPkg.version
			.split(".")
			.map((n) => Number.parseInt(n, 10));
		expect(major).toBeGreaterThanOrEqual(4);
		if (major === 4 && minor === 6) {
			expect(patch).toBeGreaterThanOrEqual(6);
		}

		expect(MAX_CONFIG_FILE_BYTES).toBe(64 * 1024);
		expect(MAX_MANIFEST_FILE_BYTES).toBe(256 * 1024);
		expect(MAX_COMPANION_OR_LOCK_BYTES).toBe(2 * 1024 * 1024);
		expect(directReadBoundedUtf8File).toBe(readBoundedUtf8File);
		expect(loadSkillOpsConfig).toBe(loadSkillOpsConfigFromDisk);

		const modelsSource = fs.readFileSync(
			path.join(REPO_ROOT, "src", "models.ts"),
			"utf-8",
		);
		expect(modelsSource).not.toContain("node:fs");
	});

	it("enforces bounded fd-backed UTF-8 reads and rejects symlinks, directories, and oversized files", () => {
		const sandbox = makeTempDir("skillops-bounded-fs-");
		const emptyPath = path.join(sandbox, "empty.txt");
		const exactPath = path.join(sandbox, "exact.txt");
		const overPath = path.join(sandbox, "over.txt");
		const subDir = path.join(sandbox, "subdir");
		const linkPath = path.join(sandbox, "linked-target");

		fs.writeFileSync(emptyPath, "", "utf-8");
		fs.writeFileSync(exactPath, "x".repeat(1024), "utf-8");
		fs.writeFileSync(overPath, "y".repeat(1025), "utf-8");
		fs.mkdirSync(subDir, { recursive: true });
		createCrossPlatformSymlink(exactPath, subDir, linkPath);

		expect(readBoundedUtf8File(emptyPath, 1024)).toBe("");
		expect(readBoundedUtf8File(exactPath, 1024)).toHaveLength(1024);
		expect(() => readBoundedUtf8File(exactPath, 0)).toThrow(RangeError);
		expect(() => readBoundedUtf8File(overPath, 1024, "over.txt")).toThrow(
			/Security violation:.*exceeds maximum allowed limit of 1024 bytes/,
		);
		expect(() => readBoundedUtf8File(subDir, 1024, "subdir")).toThrow(
			/Security violation:.*regular file/,
		);
		expect(() => readBoundedUtf8File(linkPath, 1024, "linked-target")).toThrow(
			/Security violation:.*symbolic link/,
		);

		// Verify .skillops.yml symlink rejection and <= 64 KiB cap
		const emptyRepo = makeTempDir("skillops-cfg-empty-");
		const missingCfg = loadSkillOpsConfigFromDisk(emptyRepo);
		expect(missingCfg.exists).toBe(false);
		expect(missingCfg.config).toBeNull();
		expect(missingCfg.error).toBeNull();

		const symlinkRepo = makeTempDir("skillops-cfg-symlink-");
		createCrossPlatformSymlink(
			exactPath,
			subDir,
			path.join(symlinkRepo, ".skillops.yml"),
		);
		const symlinkCfg = loadSkillOpsConfig(symlinkRepo);
		expect(symlinkCfg.exists).toBe(true);
		expect(symlinkCfg.config).toBeNull();
		expect(symlinkCfg.error).toMatch(/symbolic link/i);

		const hugeRepo = makeTempDir("skillops-cfg-huge-");
		fs.writeFileSync(
			path.join(hugeRepo, ".skillops.yml"),
			`version: "1.0"\n# ${"z".repeat(MAX_CONFIG_FILE_BYTES + 16)}\n`,
			"utf-8",
		);
		const hugeCfg = loadSkillOpsConfig(hugeRepo);
		expect(hugeCfg.exists).toBe(true);
		expect(hugeCfg.config).toBeNull();
		expect(hugeCfg.error).toMatch(/exceeds maximum allowed limit/i);

		// Verify oversized SKILL.md and SUBAGENT.md are rejected before full manifest parse
		const hugeSkillDir = makeTempDir("skillops-huge-skill-");
		writeValidSkillFixture(hugeSkillDir);
		fs.writeFileSync(
			path.join(hugeSkillDir, "SKILL.md"),
			`---\nname: huge\n---\n${"a".repeat(MAX_MANIFEST_FILE_BYTES + 32)}\n`,
			"utf-8",
		);
		expect(() => parseSkillDirectory(hugeSkillDir)).toThrow(
			/Security violation:.*exceeds maximum allowed limit/,
		);

		const hugeSubagentPath = path.join(sandbox, "SUBAGENT.md");
		fs.writeFileSync(
			hugeSubagentPath,
			`---\nname: huge-agent\n---\n${"b".repeat(MAX_MANIFEST_FILE_BYTES + 32)}\n`,
			"utf-8",
		);
		expect(() => parseSubagentFile(hugeSubagentPath)).toThrow(
			/Security violation:.*exceeds maximum allowed limit/,
		);
	});

	it("blocks YAML billion-laughs alias amplification, duplicate keys, unsafe catalog_dir, and unbounded Zod collections", () => {
		const billionLaughsFrontmatter = [
			"---",
			'a: &a ["lol","lol","lol","lol","lol"]',
			"b: &b [*a,*a,*a,*a,*a]",
			"c: &c [*b,*b,*b,*b,*b]",
			"name: alias-bomb",
			"---",
			"Body",
		].join("\n");
		expect(() =>
			splitFrontmatter(billionLaughsFrontmatter, "SKILL.md"),
		).toThrow(/alias/i);

		const duplicateKeyFrontmatter = [
			"---",
			"name: safe-name",
			"name: shadowed-name",
			"---",
			"Body",
		].join("\n");
		expect(() => splitFrontmatter(duplicateKeyFrontmatter, "SKILL.md")).toThrow(
			/unique/i,
		);

		const billionLaughsConfig = [
			'version: &v "1.0"',
			"catalog_dir: *v",
		].join("\n");
		expect(() => parseSkillOpsConfigText(billionLaughsConfig)).toThrow(
			/alias/i,
		);

		const duplicateKeyConfig = [
			'version: "1.0"',
			'catalog_dir: "catalog"',
			'catalog_dir: "other"',
		].join("\n");
		expect(() => parseSkillOpsConfigText(duplicateKeyConfig)).toThrow(
			/unique/i,
		);

		// SkillOpsConfigSchema catalog_dir path hardening
		expect(
			SkillOpsConfigSchema.parse({ catalog_dir: "./custom/catalog/" })
				.catalog_dir,
		).toBe("custom/catalog");

		const unsafeCatalogDirs = [
			"/etc/passwd",
			"\\network\\share",
			"../outside-catalog",
			"./../outside-catalog",
			"catalog/../../outside",
			"D:/escape/catalog",
			"C:relative-drive",
			"catalog\0null",
			"CON",
			"catalog/NUL",
			"catalog/LPT1.dir",
		];
		for (const badDir of unsafeCatalogDirs) {
			expect(() =>
				SkillOpsConfigSchema.parse({ catalog_dir: badDir }),
			).toThrow();
		}

		// Zod collection .max(...) bounds
		expect(() =>
			createSkillManifest({
				name: "excess-tags-skill",
				description: VALID_DESCRIPTION,
				track: "arch-quality",
				tags: Array.from({ length: 33 }, (_, idx) => `tag-${idx}`),
				entrypoints: {
					scripts: [
						{
							path: "scripts/check.py",
							description: "Offline verification helper.",
						},
					],
				},
			}),
		).toThrow();

		expect(() =>
			createSkillManifest({
				name: "excess-scripts-skill",
				description: VALID_DESCRIPTION,
				track: "arch-quality",
				tags: ["security"],
				entrypoints: {
					scripts: Array.from({ length: 33 }, (_, idx) => ({
						path: `scripts/check_${idx}.py`,
						description: "Offline verification helper.",
					})),
				},
			}),
		).toThrow();

		expect(() =>
			createSubagentManifest({
				name: "excess-tools-agent",
				description:
					"Use when auditing subagent collection upper bounds across tool allowlists and denylists.",
				tools: Array.from({ length: 65 }, (_, idx) => `tool_${idx}`),
			}),
		).toThrow();

		expect(() =>
			createSubagentManifest({
				name: "excess-denylist-agent",
				description:
					"Use when auditing subagent collection upper bounds across tool allowlists and denylists.",
				tools: ["read"],
				disallowed_tools: Array.from(
					{ length: 65 },
					(_, idx) => `deny_${idx}`,
				),
			}),
		).toThrow();

		expect(() =>
			SyncLockfileSchema.parse({
				skillops_version: "1.5.2",
				selected_skills: Array.from({ length: 513 }, (_, idx) => `s-${idx}`),
			}),
		).toThrow();

		expect(() =>
			EvalSuiteSchema.parse({
				skill_name: "mcp-architect",
				evals: Array.from({ length: 129 }, (_, idx) => ({
					id: `eval-${idx}`,
					name: "Bounded eval",
					prompt: "Run check",
					assertions: [
						{
							id: "a1",
							type: "exit_code_zero",
							target: "scripts/check.py",
							description: "Exits cleanly.",
						},
					],
				})),
			}),
		).toThrow();

		const overMaxArtifacts: Record<string, unknown> = {};
		for (let i = 0; i <= MAX_LOCKFILE_ARTIFACTS; i += 1) {
			const rel = `.claude/skills/skill-${i}/SKILL.md`;
			overMaxArtifacts[rel] = {
				target: "claude",
				skill_name: `skill-${i}`,
				relative_path: rel,
				sha256: VALID_SHA256,
			};
		}
		expect(() =>
			SyncLockfileSchema.parse({
				skillops_version: "1.5.2",
				artifacts: overMaxArtifacts,
			}),
		).toThrow();
	});

	it("validates cross-platform path segments and rejects Windows device stems, trailing dots/spaces, and control characters", () => {
		const validSegments = [
			".claude",
			".github",
			".skillops-lock.json",
			"mcp-architect",
			"SKILL.md",
			"validate_mcp_server.py",
			"com0",
			"lpt0",
			"console-helper.ts",
			"auxiliary.md",
		];
		for (const seg of validSegments) {
			expect(isSafeCrossPlatformPathSegment(seg)).toBe(true);
		}

		const invalidSegments = [
			"",
			".",
			"..",
			"__proto__",
			"constructor",
			"prototype",
			"trailing-dot.",
			".claude.",
			"trailing-space ",
			"has:colon",
			"has/slash",
			"has\\backslash",
			"has\0nul",
			"has\nnewline",
			"has\x7fdel",
			"has*wildcard",
			"has?question",
			"CON",
			"con",
			"CON.md",
			"PRN.txt",
			"aux",
			"AUX   .md",
			"nul.instructions.md",
			"CONIN$",
			"conout$.log",
			"COM1",
			"com9.json",
			"LPT1",
			"lpt9.py",
			"COM\u00B9",
			"com\u00B2.md",
			"LPT\u00B3.txt",
		];
		for (const badSeg of invalidSegments) {
			expect(isSafeCrossPlatformPathSegment(badSeg)).toBe(false);
			if (!badSeg.includes("/")) {
				expect(
					isSafeLockRelativePath(`.claude/skills/${badSeg}/SKILL.md`),
				).toBe(false);
			}
		}

		expect(() =>
			ScriptEntrypointSchema.parse({
				path: "scripts/CON.py",
				description: "Reserved Windows device script name.",
			}),
		).toThrow();

		expect(() =>
			createSkillManifest({
				name: "nul",
				description: VALID_DESCRIPTION,
				track: "arch-quality",
				tags: ["security"],
				entrypoints: {
					scripts: [
						{
							path: "scripts/check.py",
							description: "Offline verification helper.",
						},
					],
				},
			}),
		).toThrow();

		// walkAllSkillFiles rejects unsafe segments (__proto__ on all platforms, CON.md on POSIX)
		const skillDir = makeTempDir("skillops-walk-seg-");
		writeValidSkillFixture(skillDir);
		const baselineParsed = parseSkillDirectory(skillDir);
		expect(baselineParsed.evalSuite?.skill_name).toBe("sample-bounded-skill");
		expect(baselineParsed.benchmarkReport?.skill_name).toBe(
			"sample-bounded-skill",
		);

		fs.mkdirSync(path.join(skillDir, "__proto__"), { recursive: true });
		fs.writeFileSync(
			path.join(skillDir, "__proto__", "pollute.md"),
			"# Pollute\n",
			"utf-8",
		);
		expect(() => parseSkillDirectory(skillDir)).toThrow(
			/Security violation: Unsafe cross-platform directory name/,
		);
		fs.rmSync(path.join(skillDir, "__proto__"), {
			recursive: true,
			force: true,
		});

		if (process.platform !== "win32") {
			fs.mkdirSync(path.join(skillDir, "references"), { recursive: true });
			fs.writeFileSync(
				path.join(skillDir, "references", "CON.md"),
				"# Device stem\n",
				"utf-8",
			);
			expect(() => parseSkillDirectory(skillDir)).toThrow(
				/Security violation: Unsafe cross-platform filename/,
			);
		}
	});

	it("enforces target-scoped harness directories, matching relative_path, and case-insensitive uniqueness in SyncLockfileSchema", () => {
		for (const target of ALL_RUNTIME_TARGETS) {
			const spec = RUNTIME_HARNESS_SPECS[target];
			expect(
				isAllowedHarnessArtifactPath(
					target,
					`${spec.skillsDir}/mcp-architect/SKILL.md`,
					"mcp-architect",
				),
			).toBe(true);
			expect(
				isAllowedHarnessArtifactPath(
					target,
					`${spec.subagentsDir}/context-scout.md`,
					"context-scout",
				),
			).toBe(true);
		}

		expect(
			isAllowedHarnessArtifactPath(
				"copilot",
				".github/prompts/skillops-mcp-architect.prompt.md",
				"mcp-architect",
			),
		).toBe(true);
		expect(isAllowedHarnessArtifactPath("codex", "AGENTS.md")).toBe(true);
		expect(
			isAllowedHarnessArtifactPath("codex", "AGENTS.md", "codex-agents-index"),
		).toBe(true);

		// Disallowed workspace / cross-target / spoofed paths
		expect(
			isAllowedHarnessArtifactPath("codex", "AGENTS.md", "spoofed-skill"),
		).toBe(false);
		expect(
			isAllowedHarnessArtifactPath("claude", "AGENTS.md", "codex-agents-index"),
		).toBe(false);
		expect(
			isAllowedHarnessArtifactPath("claude", ".gitignore", "mcp-architect"),
		).toBe(false);
		expect(
			isAllowedHarnessArtifactPath("claude", "package.json", "mcp-architect"),
		).toBe(false);
		expect(
			isAllowedHarnessArtifactPath("claude", "src/models.ts", "mcp-architect"),
		).toBe(false);
		expect(
			isAllowedHarnessArtifactPath(
				"copilot",
				".github/workflows/ci.yml",
				"mcp-architect",
			),
		).toBe(false);
		expect(
			isAllowedHarnessArtifactPath(
				"kiro",
				".kiro/steering/product.md",
				"mcp-architect",
			),
		).toBe(false);

		// Null-prototype valid artifacts map succeeds
		const nullProtoArtifacts = Object.create(null) as Record<string, unknown>;
		nullProtoArtifacts[".claude/skills/mcp-architect/SKILL.md"] = {
			target: "claude",
			skill_name: "mcp-architect",
			relative_path: ".claude/skills/mcp-architect/SKILL.md",
			sha256: VALID_SHA256,
		};
		nullProtoArtifacts["AGENTS.md"] = {
			target: "codex",
			skill_name: "codex-agents-index",
			relative_path: "AGENTS.md",
			sha256: VALID_SHA256,
		};
		const parsedValidLock = SyncLockfileSchema.parse({
			skillops_version: "1.5.2",
			targets: ["claude", "codex"],
			artifacts: nullProtoArtifacts,
		});
		expect(Object.keys(parsedValidLock.artifacts)).toHaveLength(2);

		// (a) Rejects key !== entry.relative_path
		expect(() =>
			SyncLockfileSchema.parse({
				skillops_version: "1.5.2",
				artifacts: {
					".claude/skills/mcp-architect/SKILL.md": {
						target: "claude",
						skill_name: "mcp-architect",
						relative_path: ".claude/skills/other-skill/SKILL.md",
						sha256: VALID_SHA256,
					},
				},
			}),
		).toThrow(/must exactly match entry\.relative_path/);

		// (b) Rejects workspace files outside allowed harness directories (.gitignore, package.json, src/...)
		for (const forbiddenPath of [".gitignore", "package.json", "src/index.ts"]) {
			expect(() =>
				SyncLockfileSchema.parse({
					skillops_version: "1.5.2",
					artifacts: {
						[forbiddenPath]: {
							target: "claude",
							skill_name: "mcp-architect",
							relative_path: forbiddenPath,
							sha256: VALID_SHA256,
						},
					},
				}),
			).toThrow(/outside allowed harness directories/);
		}

		// (c) Rejects case-insensitive key collisions
		expect(() =>
			SyncLockfileSchema.parse({
				skillops_version: "1.5.2",
				artifacts: {
					".claude/skills/mcp-architect/SKILL.md": {
						target: "claude",
						skill_name: "mcp-architect",
						relative_path: ".claude/skills/mcp-architect/SKILL.md",
						sha256: VALID_SHA256,
					},
					".claude/skills/MCP-ARCHITECT/skill.md": {
						target: "claude",
						skill_name: "mcp-architect",
						relative_path: ".claude/skills/MCP-ARCHITECT/skill.md",
						sha256: VALID_SHA256,
					},
				},
			}),
		).toThrow(/Case-insensitive lockfile artifact key collision/);
	});

	it("wires disallowed_tools and sandbox_mode in SubagentManifestSchema and validates EvalSuiteSchema / BenchmarkReportSchema in parseSkillDirectory", () => {
		expect(SandboxModeSchema.options).toEqual(["read-only", "workspace-write"]);

		const defaultSubagent = createSubagentManifest({
			name: "default-bounded-scout",
			description:
				"Use when inspecting repository context in read-only mode with explicit least-privilege tool boundaries.",
			tools: ["read", "grep"],
		});
		expect(defaultSubagent.disallowed_tools).toEqual([]);
		expect(defaultSubagent.sandbox_mode).toBe("read-only");

		const camelSubagent = createSubagentManifest({
			name: "camel-bounded-scout",
			description:
				"Use when verifying camelCase frontmatter normalization for subagent tool denylists and sandbox modes.",
			tools: ["read", "edit"],
			disallowedTools: ["bash", "write_file"],
			sandboxMode: "workspace-write",
			userInvocable: false,
			contextIsolation: true,
			maxOutputTokens: 250,
			modelTier: "fast",
		});
		expect(camelSubagent.disallowed_tools).toEqual(["bash", "write_file"]);
		expect(camelSubagent.sandbox_mode).toBe("workspace-write");
		expect(camelSubagent.user_invocable).toBe(false);
		expect(camelSubagent.max_output_tokens).toBe(250);
		expect(camelSubagent.model_tier).toBe("fast");

		const kebabDir = makeTempDir("skillops-subagent-denylist-");
		const subagentFile = path.join(kebabDir, "SUBAGENT.md");
		fs.writeFileSync(
			subagentFile,
			[
				"---",
				"name: kebab-bounded-reviewer",
				'description: "Use when reviewing pull request diffs under strict read-only sandbox and explicit tool denylist constraints."',
				"tools:",
				"  - read",
				"  - grep",
				"disallowed-tools:",
				"  - bash",
				"  - edit",
				"sandbox-mode: read-only",
				"---",
				"",
				"Inspect diffs deterministically without modifying files.",
				"",
			].join("\n"),
			"utf-8",
		);
		const parsedSubagent = parseSubagentFile(subagentFile);
		expect(parsedSubagent.manifest.disallowed_tools).toEqual(["bash", "edit"]);
		expect(parsedSubagent.manifest.sandbox_mode).toBe("read-only");

		const claudePlanned = renderSubagentFilesForRuntime(
			parsedSubagent,
			"claude",
		);
		expect(claudePlanned[0]?.content).toContain("disallowed_tools:");
		const geminiPlanned = renderSubagentFilesForRuntime(
			parsedSubagent,
			"gemini",
		);
		expect(geminiPlanned[0]?.content).toContain(
			"**Disallowed tools**: `bash`, `edit`",
		);

		expect(() =>
			createSubagentManifest({
				name: "bad-sandbox-agent",
				description:
					"Use when testing rejection of unsupported sandbox_mode values in subagent manifests.",
				tools: ["read"],
				sandbox_mode: "unrestricted",
			}),
		).toThrow();

		// Zero false positives across all real catalog skills & subagents
		const realSkillDirs = discoverSkillDirectories(CATALOG_ROOT);
		expect(realSkillDirs.length).toBeGreaterThanOrEqual(4);
		for (const dir of realSkillDirs) {
			const parsed: ParsedSkill = parseSkillDirectory(dir, {
				requireLayout: true,
				requireBenchmark: true,
			});
			expect(parsed.evalSuite?.skill_name).toBe(parsed.manifest.name);
			expect(parsed.evalSuite?.evals.length).toBeGreaterThanOrEqual(1);
			expect(parsed.benchmarkReport?.skill_name).toBe(parsed.manifest.name);
		}

		const realSubagents = discoverSubagentFiles(CATALOG_ROOT);
		expect(realSubagents.length).toBeGreaterThanOrEqual(2);
		for (const saFile of realSubagents) {
			const sa = parseSubagentFile(saFile);
			expect(sa.manifest.sandbox_mode).toBe("read-only");
			expect(Array.isArray(sa.manifest.disallowed_tools)).toBe(true);
		}

		// Reject mismatched skill_name and malformed evals.json / benchmark.json
		const mismatchEvalDir = makeTempDir("skillops-eval-mismatch-");
		writeValidSkillFixture(mismatchEvalDir, "expected-skill");
		fs.writeFileSync(
			path.join(mismatchEvalDir, "evals", "evals.json"),
			JSON.stringify({
				skill_name: "different-skill",
				evals: [
					{
						id: "e1",
						name: "Mismatch test",
						prompt: "Check mismatch",
						assertions: [
							{
								id: "a1",
								type: "exit_code_zero",
								target: "scripts/check.py",
								description: "Zero exit code.",
							},
						],
					},
				],
			}),
			"utf-8",
		);
		expect(() => parseSkillDirectory(mismatchEvalDir)).toThrow(
			/does not match SKILL\.md manifest name/,
		);

		const mismatchBenchDir = makeTempDir("skillops-bench-mismatch-");
		writeValidSkillFixture(mismatchBenchDir, "expected-bench-skill");
		const validBench = BenchmarkReportSchema.parse(
			JSON.parse(
				fs.readFileSync(
					path.join(mismatchBenchDir, "evals", "benchmark.json"),
					"utf-8",
				),
			),
		);
		fs.writeFileSync(
			path.join(mismatchBenchDir, "evals", "benchmark.json"),
			JSON.stringify({ ...validBench, skill_name: "wrong-bench-skill" }),
			"utf-8",
		);
		expect(() => parseSkillDirectory(mismatchBenchDir)).toThrow(
			/does not match SKILL\.md manifest name/,
		);

		const invalidBenchSchemaDir = makeTempDir("skillops-bench-invalid-");
		writeValidSkillFixture(invalidBenchSchemaDir, "invalid-bench-skill");
		fs.writeFileSync(
			path.join(invalidBenchSchemaDir, "evals", "benchmark.json"),
			JSON.stringify({
				skill_name: "invalid-bench-skill",
				runner: "broken",
			}),
			"utf-8",
		);
		expect(() => parseSkillDirectory(invalidBenchSchemaDir)).toThrow();
	});
});
