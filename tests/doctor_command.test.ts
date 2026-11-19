import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runCli } from "../src/cli.js";
import { ALL_RUNTIME_TARGETS, ExitCode } from "../src/models.js";
import { addSkillOrSubagent, loadCatalogIndex } from "../src/sync/index.js";

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

function captureCliRun(argv: string[]): {
	code: number;
	stdout: string;
	stderr: string;
} {
	let stdout = "";
	let stderr = "";
	const outSpy = vi
		.spyOn(process.stdout, "write")
		.mockImplementation((chunk: string | Uint8Array) => {
			stdout +=
				typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf-8");
			return true;
		});
	const errSpy = vi
		.spyOn(process.stderr, "write")
		.mockImplementation((chunk: string | Uint8Array) => {
			stderr +=
				typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf-8");
			return true;
		});
	try {
		const code = runCli(argv);
		return { code, stdout, stderr };
	} finally {
		outSpy.mockRestore();
		errSpy.mockRestore();
	}
}

describe("Issue #223 skillops doctor & skillops completions", () => {
	it("passes cleanly on a healthy workspace in both table and --json modes", () => {
		const tmpRepo = makeTempDir("skillops-doctor-healthy-");
		const catalogDir = path.resolve("catalog");
		const catalogIndex = loadCatalogIndex(catalogDir);

		const addRes = addSkillOrSubagent(tmpRepo, catalogDir, "mcp-architect", {
			targets: ["claude", "cursor"],
			catalogIndex,
		});
		expect(addRes.passed).toBe(true);

		const tableRes = captureCliRun([
			"node",
			"skillops",
			"doctor",
			"--repo",
			tmpRepo,
			"--catalog",
			catalogDir,
		]);
		expect(tableRes.code).toBe(ExitCode.SUCCESS);
		expect(tableRes.stdout).toContain("Workspace Doctor Diagnostic");

		const jsonRes = captureCliRun([
			"node",
			"skillops",
			"doctor",
			"--repo",
			tmpRepo,
			"--catalog",
			catalogDir,
			"--json",
		]);
		expect(jsonRes.code).toBe(ExitCode.SUCCESS);
		const parsed = JSON.parse(jsonRes.stdout) as {
			passed: boolean;
			checks: Array<{ id: string; status: string }>;
			summary: { passed: number; warned: number; failed: number };
		};
		expect(parsed.passed).toBe(true);
		expect(parsed.checks).toHaveLength(5);
		expect(parsed.summary.failed).toBe(0);
	});

	it("fails with actionable remediation hints on drift, broken lockfile, invalid config, and token budget overrun", () => {
		const catalogDir = path.resolve("catalog");
		const catalogIndex = loadCatalogIndex(catalogDir);

		// 1. Drift detection
		const driftRepo = makeTempDir("skillops-doctor-drift-");
		addSkillOrSubagent(driftRepo, catalogDir, "mcp-architect", {
			targets: ["claude"],
			catalogIndex,
		});
		const skillFile = path.join(
			driftRepo,
			".claude/skills/mcp-architect/SKILL.md",
		);
		fs.appendFileSync(skillFile, "\n<!-- local drift -->\n", "utf-8");
		const driftRes = captureCliRun([
			"node",
			"skillops",
			"doctor",
			"--repo",
			driftRepo,
			"--catalog",
			catalogDir,
			"--json",
		]);
		expect(driftRes.code).toBe(ExitCode.ERROR);
		const driftJson = JSON.parse(driftRes.stdout) as {
			passed: boolean;
			checks: Array<{ id: string; status: string; remediation?: string }>;
		};
		expect(driftJson.passed).toBe(false);
		const lockCheck = driftJson.checks.find(
			(c) => c.id === "lockfile-integrity",
		);
		expect(lockCheck?.status).toBe("fail");
		expect(lockCheck?.remediation).toContain("update --force");

		// 2. Corrupted lockfile
		const brokenLockRepo = makeTempDir("skillops-doctor-brokenlock-");
		fs.writeFileSync(
			path.join(brokenLockRepo, ".skillops-lock.json"),
			"{ not valid json",
			"utf-8",
		);
		const brokenRes = captureCliRun([
			"node",
			"skillops",
			"doctor",
			"--repo",
			brokenLockRepo,
			"--catalog",
			catalogDir,
			"--json",
		]);
		expect(brokenRes.code).toBe(ExitCode.ERROR);
		const brokenJson = JSON.parse(brokenRes.stdout) as {
			passed: boolean;
			checks: Array<{ id: string; status: string; message: string }>;
		};
		expect(brokenJson.passed).toBe(false);
		expect(
			brokenJson.checks.find((c) => c.id === "lockfile-integrity")?.message,
		).toContain("Corrupted .skillops-lock.json");

		// 3. Invalid .skillops.yml
		const badCfgRepo = makeTempDir("skillops-doctor-badcfg-");
		fs.writeFileSync(
			path.join(badCfgRepo, ".skillops.yml"),
			"catalog_dir: ../outside\n",
			"utf-8",
		);
		const badCfgRes = captureCliRun([
			"node",
			"skillops",
			"doctor",
			"--repo",
			badCfgRepo,
			"--catalog",
			catalogDir,
			"--json",
		]);
		expect(badCfgRes.code).toBe(ExitCode.BUDGET_OR_CONTRACT_ERROR);

		// 4. Token budget overrun via bloated AGENTS.md
		const bloatRepo = makeTempDir("skillops-doctor-bloat-");
		fs.writeFileSync(
			path.join(bloatRepo, "AGENTS.md"),
			`${"token ".repeat(5000)}\n`,
			"utf-8",
		);
		const bloatRes = captureCliRun([
			"node",
			"skillops",
			"doctor",
			"--repo",
			bloatRepo,
			"--catalog",
			catalogDir,
			"--json",
		]);
		expect(bloatRes.code).toBe(ExitCode.BUDGET_OR_CONTRACT_ERROR);
		const bloatJson = JSON.parse(bloatRes.stdout) as {
			checks: Array<{ id: string; status: string; remediation?: string }>;
		};
		expect(
			bloatJson.checks.find((c) => c.id === "startup-token-budget")?.status,
		).toBe("fail");
	});

	it("emits deterministic shell completion scripts for bash, zsh, fish, and pwsh", () => {
		for (const shell of ["bash", "zsh", "fish", "pwsh"] as const) {
			const res = captureCliRun(["node", "skillops", "completions", shell]);
			expect(res.code).toBe(ExitCode.SUCCESS);
			expect(res.stdout).toContain("doctor");
			expect(res.stdout).toContain("completions");
			expect(res.stdout).toContain("audit");
			for (const target of ALL_RUNTIME_TARGETS) {
				expect(res.stdout).toContain(target);
			}
		}

		const badShellRes = captureCliRun([
			"node",
			"skillops",
			"completions",
			"tcsh",
		]);
		expect(badShellRes.code).toBe(ExitCode.ERROR);
		expect(badShellRes.stderr).toContain("bash|zsh|fish|pwsh");
	});
});
