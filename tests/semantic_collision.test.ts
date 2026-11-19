import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	DEFAULT_SEMANTIC_COLLISION_THRESHOLD,
	detectSemanticCollisions,
	extractPositiveTriggerText,
	parseSkillDirectory,
	parseSubagentFile,
} from "../src/auditor/index.js";
import {
	ExitCode,
	estimateTokenCount,
	parseSkillOpsConfigText,
	SyncLockfileSchema,
} from "../src/models.js";
import {
	addSkillOrSubagent,
	computeLockfileL1Tokens,
	computeWorkspaceTokenTelemetry,
	inspectProjectStatus,
	loadCatalogIndex,
	removeSkillOrSubagent,
} from "../src/sync/index.js";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	while (tempDirs.length > 0) {
		const dir = tempDirs.pop();
		if (dir && fs.existsSync(dir)) {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	}
});

function createValidSkill(
	catalogRoot: string,
	track: string,
	name: string,
	description: string,
	keywords: readonly string[] = [],
): string {
	const skillDir = path.join(catalogRoot, track, name);
	const scriptsDir = path.join(skillDir, "scripts");
	const evalsDir = path.join(skillDir, "evals");
	fs.mkdirSync(scriptsDir, { recursive: true });
	fs.mkdirSync(evalsDir, { recursive: true });

	const scriptRel = `scripts/check_${name.replace(/-/g, "_")}.py`;
	const skillMd = [
		"---",
		`name: ${name}`,
		`description: "${description.replace(/"/g, '\\"')}"`,
		`track: ${track}`,
		"version: 1.0.0",
		"tags:",
		"  - security",
		"  - audit",
		"entrypoints:",
		"  scripts:",
		`    - path: ${scriptRel}`,
		'      description: "Deterministic verification script for SQL migration collision tests."',
		"routing_signals:",
		"  languages:",
		...keywords.map((k) => `    - ${k}`),
		"---",
		"",
		`# ${name}`,
		"",
		"Run the bundled Python check:",
		"",
		"```bash",
		`python scripts/check_${name.replace(/-/g, "_")}.py --json`,
		"```",
		"",
	].join("\n");

	fs.writeFileSync(path.join(skillDir, "SKILL.md"), skillMd, "utf-8");
	fs.writeFileSync(
		path.join(scriptsDir, `check_${name.replace(/-/g, "_")}.py`),
		'import json\nprint(json.dumps({"status": "pass", "findings": [], "summary": "ok"}))\n',
		"utf-8",
	);
	fs.writeFileSync(
		path.join(evalsDir, "evals.json"),
		JSON.stringify(
			{
				skill_name: name,
				schema_version: "1.0",
				evals: [
					{
						id: "case-01",
						name: "Basic verification",
						prompt: "Verify SQL migration.",
						fixtures: [],
						assertions: [
							{
								id: "assert-01",
								type: "exit_code_zero",
								target: "script",
								description: "Script exits 0.",
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
		path.join(evalsDir, "benchmark.json"),
		JSON.stringify(
			{
				skill_name: name,
				runner: "skillops-eval-harness/1.0",
				timestamp: "2026-11-19T12:00:00Z",
				with_skill: {
					pass_rate_mean: 1.0,
					pass_rate_stddev: 0.0,
					tokens_mean: 800,
					latency_ms_mean: 1000,
				},
				without_skill: {
					pass_rate_mean: 0.5,
					pass_rate_stddev: 0.2,
					tokens_mean: 1600,
					latency_ms_mean: 2000,
				},
				delta: {
					pass_rate_gain: 0.5,
					token_reduction_pct: 50,
					verdict: "CERTIFIED_IMPROVEMENT",
				},
			},
			null,
			2,
		),
		"utf-8",
	);
	return skillDir;
}

describe("Issue #221 Semantic Collision Auditor, Token Telemetry & Progressive AGENTS.md", () => {
	it("passes INV-SKILL-04 pairwise collision check across built-in catalog", () => {
		const repoRoot = path.resolve(".");
		const catalogIndex = loadCatalogIndex(path.join(repoRoot, "catalog"));
		const report = detectSemanticCollisions(
			[...catalogIndex.skills.values()],
			[...catalogIndex.subagents.values()],
			{ threshold: DEFAULT_SEMANTIC_COLLISION_THRESHOLD },
		);
		expect(report.pairs_checked).toBeGreaterThan(100);
		expect(report.collisions).toEqual([]);
		expect(report.passed).toBe(true);
	});

	it("strips negative trigger clauses and flags colliding descriptions with ExitCode.COLLISION_ERROR (2)", () => {
		const tmpCatalog = makeTempDir("skillops-collision-cat-");
		const basePositive =
			"Use when auditing PostgreSQL SQL migrations, checking destructive DDL table locks, verifying foreign key indexes, validating online index creation, reviewing schema rollbacks, and enforcing safe zero downtime database deployments across production Postgres clusters.";
		const skillADir = createValidSkill(
			tmpCatalog,
			"arch-quality",
			"sql-lint-alpha",
			`${basePositive} Do not trigger for frontend React components or CSS styling.`,
			["sql", "postgres"],
		);
		const skillBDir = createValidSkill(
			tmpCatalog,
			"arch-quality",
			"sql-lint-beta",
			`${basePositive} Do NOT use for Python async FastAPI routers or Pydantic schemas.`,
			["sql", "postgres"],
		);

		const positive = extractPositiveTriggerText(
			"Audits SQL migrations. Do not trigger for React.",
		);
		expect(positive).toBe("audits sql migrations");

		const parsedA = parseSkillDirectory(skillADir);
		const parsedB = parseSkillDirectory(skillBDir);
		const report = detectSemanticCollisions([parsedA, parsedB], [], {
			threshold: DEFAULT_SEMANTIC_COLLISION_THRESHOLD,
		});
		expect(report.passed).toBe(false);
		expect(report.collisions).toHaveLength(1);
		expect(report.collisions[0]?.similarity).toBeGreaterThanOrEqual(0.65);

		const cliRes = spawnSync(
			process.execPath,
			[
				path.resolve("dist/cli.js"),
				"audit",
				"--strict",
				"--catalog",
				tmpCatalog,
				"--json",
			],
			{ encoding: "utf-8" },
		);
		expect(cliRes.status).toBe(ExitCode.COLLISION_ERROR);
		const parsedOut = JSON.parse(cliRes.stdout) as {
			passed: boolean;
			collision_pairs: Array<{ item_a: string; item_b: string }>;
		};
		expect(parsedOut.passed).toBe(false);
		expect(parsedOut.collision_pairs.length).toBe(1);
	});

	it("records deterministic non-zero total_l1_tokens in .skillops-lock.json and distinguishes progressive vs always-on telemetry", () => {
		const tmpRepo = makeTempDir("skillops-telemetry-repo-");
		const catalogDir = path.resolve("catalog");
		const catalogIndex = loadCatalogIndex(catalogDir);

		const addRes = addSkillOrSubagent(tmpRepo, catalogDir, "mcp-architect", {
			targets: ["claude", "cline"],
			catalogIndex,
		});
		expect(addRes.passed).toBe(true);

		const lockPath = path.join(tmpRepo, ".skillops-lock.json");
		const lock = SyncLockfileSchema.parse(
			JSON.parse(fs.readFileSync(lockPath, "utf-8")),
		);
		const expectedL1 = computeLockfileL1Tokens(
			["mcp-architect"],
			[],
			catalogIndex,
		);
		expect(expectedL1).toBeGreaterThan(20);
		expect(lock.total_l1_tokens).toBe(expectedL1);

		const cfg = parseSkillOpsConfigText(
			[
				"version: '1.0'",
				"token_economy:",
				"  max_always_on_tokens: 150",
			].join("\n"),
		);
		const status = inspectProjectStatus(tmpRepo, catalogDir, {
			targets: ["claude", "cline"],
			catalogIndex,
			config: cfg,
		});
		expect(status.token_telemetry).toBeDefined();
		expect(status.token_telemetry?.total_l1_tokens).toBe(expectedL1);
		expect(status.token_telemetry?.always_on_tokens).toBeGreaterThan(
			expectedL1,
		);
		expect(status.token_telemetry?.warnings.length).toBeGreaterThan(0);

		const telemetry = computeWorkspaceTokenTelemetry({
			repoPath: tmpRepo,
			targets: ["claude", "cline"],
			selectedSkills: ["mcp-architect"],
			selectedSubagents: [],
			catalogIndex,
			config: cfg,
		});
		const claudeEntry = telemetry.per_target.find(
			(t) => t.target === "claude",
		);
		const clineEntry = telemetry.per_target.find((t) => t.target === "cline");
		expect(claudeEntry?.mode).toBe("progressive");
		expect(clineEntry?.mode).toBe("always-on");
		expect((clineEntry?.startup_tokens ?? 0)).toBeGreaterThan(
			claudeEntry?.startup_tokens ?? 0,
		);

		removeSkillOrSubagent(tmpRepo, catalogDir, "mcp-architect", {
			targets: ["claude", "cline"],
			catalogIndex,
		});
		const lockAfterRemove = SyncLockfileSchema.parse(
			JSON.parse(fs.readFileSync(lockPath, "utf-8")),
		);
		expect(lockAfterRemove.total_l1_tokens).toBe(0);
	});

	it("keeps AGENTS.md under 120 lines and 900 tokens with zero nonexistent paths", () => {
		const repoRoot = path.resolve(".");
		const agentsContent = fs.readFileSync(
			path.join(repoRoot, "AGENTS.md"),
			"utf-8",
		);
		const lines = agentsContent.split(/\r?\n/);
		expect(lines.length).toBeLessThan(120);
		expect(estimateTokenCount(agentsContent)).toBeLessThan(900);
		expect(agentsContent).not.toContain(".github/agents");

		const linkMatches = [...agentsContent.matchAll(/\]\(([^)]+)\)/g)];
		expect(linkMatches.length).toBeGreaterThan(0);
		for (const match of linkMatches) {
			const relTarget = match[1] ?? "";
			expect(fs.existsSync(path.join(repoRoot, relTarget))).toBe(true);
		}
	});
});
