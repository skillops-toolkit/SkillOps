import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	auditCatalogSecurity,
	discoverSkillDirectories,
	loadCatalogIndex,
	parseSkillDirectory,
	ScriptOutputSchema,
} from "../src/index.js";

const REPO_ROOT = path.resolve(import.meta.dirname, "..");
const CATALOG_ROOT = path.join(REPO_ROOT, "catalog");

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

function resolvePythonBin(): string {
	for (const candidate of ["python", "python3"]) {
		const probe = spawnSync(candidate, ["--version"], {
			encoding: "utf-8",
			timeout: 5_000,
		});
		if (!probe.error && probe.status === 0) {
			return candidate;
		}
	}
	throw new Error("Python 3 interpreter not found on PATH.");
}

const PYTHON_BIN = resolvePythonBin();

function runScript(scriptRelPath: string, args: readonly string[]) {
	const fullScript = path.join(CATALOG_ROOT, scriptRelPath);
	const proc = spawnSync(PYTHON_BIN, [fullScript, ...args, "--json"], {
		encoding: "utf-8",
		timeout: 15_000,
	});
	expect(proc.error).toBeUndefined();
	const parsed = ScriptOutputSchema.parse(JSON.parse(proc.stdout));
	return { exitCode: proc.status ?? -1, parsed };
}

describe("Issue #235 Built-in Catalog Expansion (12 Hybrid Executable Skills)", () => {
	it("expands built-in catalog to 12 balanced skills (3 per track) with zero security findings", () => {
		const skillDirs = discoverSkillDirectories(CATALOG_ROOT);
		expect(skillDirs.length).toBe(12);

		const trackCounts = new Map<string, number>();
		for (const dir of skillDirs) {
			const parsed = parseSkillDirectory(dir, {
				requireLayout: true,
				requireBenchmark: true,
			});
			const track = parsed.manifest.track;
			trackCounts.set(track, (trackCounts.get(track) ?? 0) + 1);
		}
		expect(Object.fromEntries(trackCounts)).toEqual({
			"ai-engineering": 3,
			"arch-quality": 3,
			"python-backend": 3,
			"token-economy": 3,
		});

		const index = loadCatalogIndex(CATALOG_ROOT);
		expect(index.skills.size).toBe(12);

		const secReport = auditCatalogSecurity(CATALOG_ROOT);
		expect(secReport.findings).toEqual([]);
	});

	it("executes all 8 new companion Python scripts across finding, clean, and invalid-path scenarios", () => {
		const cases: Array<{
			script: string;
			expectedRule: string;
			badFiles: Record<string, string>;
			cleanFiles: Record<string, string>;
		}> = [
			{
				script: "ai-engineering/prompt-injection-guard/scripts/audit_prompt_boundaries.py",
				expectedRule: "untrusted-input-in-system-prompt",
				badFiles: {
					"agent.py": 'def ask(user_input: str):\n    return call(system=f"Follow instructions: {user_input}")\n',
				},
				cleanFiles: {
					"agent.py": 'def ask(user_input: str):\n    return call(system="Strict policy", messages=[{"role": "user", "content": user_input}])\n',
				},
			},
			{
				script: "ai-engineering/structured-output-schema-guard/scripts/audit_tool_schemas.py",
				expectedRule: "missing-additional-properties-false",
				badFiles: {
					"tool.schema.json": JSON.stringify({
						type: "object",
						properties: { query: { type: "string", maxLength: 100 } },
						required: ["query"],
					}),
				},
				cleanFiles: {
					"tool.schema.json": JSON.stringify({
						type: "object",
						additionalProperties: false,
						properties: { query: { type: "string", maxLength: 100 } },
						required: ["query"],
					}),
				},
			},
			{
				script: "python-backend/pytest-fixture-auditor/scripts/audit_pytest_fixtures.py",
				expectedRule: "fixture-scope-mismatch",
				badFiles: {
					"conftest.py": 'import pytest\n\n@pytest.fixture(scope="session")\ndef bad_env(monkeypatch):\n    monkeypatch.setenv("X", "1")\n',
				},
				cleanFiles: {
					"conftest.py": 'import pytest\n\n@pytest.fixture(scope="function")\ndef clean_env(monkeypatch):\n    try:\n        monkeypatch.setenv("X", "1")\n        yield\n    finally:\n        monkeypatch.delenv("X", raising=False)\n',
				},
			},
			{
				script: "python-backend/pydantic-v2-boundary-guard/scripts/audit_pydantic_models.py",
				expectedRule: "pydantic-v1-inner-config",
				badFiles: {
					"models.py": 'from pydantic import BaseModel\n\nclass UserIn(BaseModel):\n    name: str\n    class Config:\n        extra = "forbid"\n',
				},
				cleanFiles: {
					"models.py": 'from pydantic import BaseModel, ConfigDict\n\nclass UserIn(BaseModel):\n    model_config = ConfigDict(extra="forbid")\n    name: str\n',
				},
			},
			{
				script: "arch-quality/sql-migration-safety-guard/scripts/audit_sql_migrations.py",
				expectedRule: "not-null-column-without-default",
				badFiles: {
					"001.sql": "ALTER TABLE users ADD COLUMN role TEXT NOT NULL;\n",
				},
				cleanFiles: {
					"001.sql": "CREATE INDEX CONCURRENTLY idx_users_role ON users (role);\n",
				},
			},
			{
				script: "arch-quality/nextjs-security-headers-auditor/scripts/audit_nextjs_security.py",
				expectedRule: "exposed-next-public-secret",
				badFiles: {
					"env.ts": "export const k = process.env.NEXT_PUBLIC_JWT_SECRET;\n",
				},
				cleanFiles: {
					"next.config.ts": 'export default { async headers() { return [{ headers: [{ key: "X-Content-Type-Options", value: "nosniff" }, { key: "X-Frame-Options", value: "DENY" }] }]; } };\n',
				},
			},
			{
				script: "token-economy/skill-token-budget-lint/scripts/lint_skill_budgets.py",
				expectedRule: "skill-over-250-lines",
				badFiles: {
					"demo/SKILL.md": [
						"---",
						"name: too-long",
						`description: "Use when ${"testing ".repeat(45)}budget limits across skill manifests in repos."`,
						"---",
						...Array.from({ length: 260 }, (_, idx) => `Line ${idx}`),
					].join("\n"),
				},
				cleanFiles: {
					"demo/SKILL.md": [
						"---",
						"name: compact-demo",
						`description: "Use when ${"validating ".repeat(45)}progressive disclosure bounds in markdown agent skills cleanly."`,
						"---",
						"",
						"# Compact Demo",
					].join("\n"),
				},
			},
			{
				script: "token-economy/json-schema-compactor/scripts/audit_schema_footprint.py",
				expectedRule: "verbose-schema-description",
				badFiles: {
					"tool.schema.json": JSON.stringify({
						type: "object",
						properties: {
							query: {
								type: "string",
								description: Array.from({ length: 50 }, () => "verbose").join(" "),
							},
						},
					}),
				},
				cleanFiles: {
					"tool.schema.json": JSON.stringify({
						type: "object",
						properties: {
							query: { type: "string", description: "Search query text." },
						},
					}),
				},
			},
		];

		for (const item of cases) {
			const badDir = makeTempDir("skillops-exp-bad-");
			for (const [rel, content] of Object.entries(item.badFiles)) {
				const full = path.join(badDir, rel);
				fs.mkdirSync(path.dirname(full), { recursive: true });
				fs.writeFileSync(full, content, "utf-8");
			}
			const badRun = runScript(item.script, ["--path", badDir]);
			expect(badRun.exitCode, item.script).toBe(1);
			expect(badRun.parsed.status).toBe("findings_detected");
			expect(
				badRun.parsed.findings.some((f) => f.rule_id === item.expectedRule),
			).toBe(true);

			const cleanDir = makeTempDir("skillops-exp-clean-");
			for (const [rel, content] of Object.entries(item.cleanFiles)) {
				const full = path.join(cleanDir, rel);
				fs.mkdirSync(path.dirname(full), { recursive: true });
				fs.writeFileSync(full, content, "utf-8");
			}
			const cleanRun = runScript(item.script, ["--path", cleanDir]);
			expect(cleanRun.exitCode, item.script).toBe(0);
			expect(cleanRun.parsed.status).toBe("ok");

			const invalidRun = runScript(item.script, [
				"--path",
				path.join(cleanDir, "nonexistent-dir"),
			]);
			expect(invalidRun.exitCode, item.script).toBe(2);
			expect(invalidRun.parsed.status).toBe("error");
		}
	});
});
