import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { auditCatalogSecurity, ScriptOutputSchema } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

const SCRIPTS = {
	mcp: path.join(
		REPO_ROOT,
		"catalog",
		"ai-engineering",
		"mcp-architect",
		"scripts",
		"validate_mcp_server.py",
	),
	secrets: path.join(
		REPO_ROOT,
		"catalog",
		"arch-quality",
		"env-secrets-guard",
		"scripts",
		"scan_secrets.py",
	),
	fastapi: path.join(
		REPO_ROOT,
		"catalog",
		"python-backend",
		"fastapi-async-guard",
		"scripts",
		"audit_fastapi_async.py",
	),
	context: path.join(
		REPO_ROOT,
		"catalog",
		"token-economy",
		"context-budget-profiler",
		"scripts",
		"profile_context_budget.py",
	),
} as const;

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
	throw new Error("Python 3.10+ interpreter not found on PATH.");
}

const PYTHON_BIN = resolvePythonBin();
const DIR_LINK_TYPE: fs.symlink.Type =
	process.platform === "win32" ? "junction" : "dir";
const TWO_MIB_BYTES = 2 * 1024 * 1024;

interface ScriptRunResult {
	readonly exitCode: number;
	readonly stdout: string;
	readonly stderr: string;
	readonly parsed: ReturnType<typeof ScriptOutputSchema.parse>;
}

function runPythonScriptJson(
	scriptPath: string,
	args: readonly string[],
): ScriptRunResult {
	const proc = spawnSync(PYTHON_BIN, [scriptPath, ...args, "--json"], {
		encoding: "utf-8",
		timeout: 15_000,
	});
	expect(proc.error).toBeUndefined();
	expect(proc.status).not.toBeNull();

	const rawJson: unknown = JSON.parse(proc.stdout);
	const parsed = ScriptOutputSchema.parse(rawJson);

	return {
		exitCode: proc.status ?? -1,
		stdout: proc.stdout,
		stderr: proc.stderr,
		parsed,
	};
}

function tryCreateFileSymlink(targetFile: string, linkPath: string): boolean {
	try {
		fs.symlinkSync(targetFile, linkPath, "file");
		return true;
	} catch {
		return false;
	}
}

describe("Catalog Companion Python Scripts Hardening (#214)", () => {
	it("emits strict ScriptOutputSchema JSON across clean, findings, and invalid-path runs for all 4 scripts", () => {
		const sandbox = fs.mkdtempSync(
			path.join(os.tmpdir(), "skillops-iss214-schema-"),
		);
		try {
			// 1. Invalid-path runs (all 4 scripts must exit 2 with ScriptOutputSchema status='error')
			const missingPath = path.join(sandbox, "does-not-exist");
			for (const [key, scriptPath] of Object.entries(SCRIPTS)) {
				const flag = key === "context" ? "--repo" : "--path";
				const invalidRes = runPythonScriptJson(scriptPath, [flag, missingPath]);
				expect(invalidRes.exitCode).toBe(2);
				expect(invalidRes.parsed.status).toBe("error");
				expect(invalidRes.parsed.target.length).toBeGreaterThan(0);
			}

			// 2. Clean workspace runs (all 4 scripts must exit 0 with status='ok')
			const cleanDir = path.join(sandbox, "clean-workspace");
			fs.mkdirSync(cleanDir, { recursive: true });
			fs.writeFileSync(
				path.join(cleanDir, "mcp_server.py"),
				[
					"class FakeMcp:",
					"    def tool(self, fn):",
					"        return fn",
					"",
					"mcp = FakeMcp()",
					"",
					"@mcp.tool",
					"def ping(host: str) -> str:",
					'    """Return health response for host."""',
					"    return host",
					"",
				].join("\n"),
				"utf-8",
			);
			fs.writeFileSync(
				path.join(cleanDir, "AGENTS.md"),
				"# Repository Guide\n\nKeep instructions concise and deterministic.\n",
				"utf-8",
			);

			const mcpClean = runPythonScriptJson(SCRIPTS.mcp, ["--path", cleanDir]);
			expect(mcpClean.exitCode).toBe(0);
			expect(mcpClean.parsed.status).toBe("ok");
			expect(mcpClean.parsed.skill).toBe("mcp-architect");

			const secretsClean = runPythonScriptJson(SCRIPTS.secrets, [
				"--path",
				cleanDir,
			]);
			expect(secretsClean.exitCode).toBe(0);
			expect(secretsClean.parsed.status).toBe("ok");
			expect(secretsClean.parsed.skill).toBe("env-secrets-guard");

			const fastapiClean = runPythonScriptJson(SCRIPTS.fastapi, [
				"--path",
				cleanDir,
			]);
			expect(fastapiClean.exitCode).toBe(0);
			expect(fastapiClean.parsed.status).toBe("ok");
			expect(fastapiClean.parsed.skill).toBe("fastapi-async-guard");

			const contextClean = runPythonScriptJson(SCRIPTS.context, [
				"--repo",
				cleanDir,
			]);
			expect(contextClean.exitCode).toBe(0);
			expect(contextClean.parsed.status).toBe("ok");
			expect(contextClean.parsed.skill).toBe("context-budget-profiler");
			// Ensure top-level strictness: 'repo' and 'split_suggestions' live inside 'data'
			const rawContextObj = JSON.parse(contextClean.stdout) as Record<
				string,
				unknown
			>;
			expect(Object.hasOwn(rawContextObj, "repo")).toBe(false);
			expect(Object.hasOwn(rawContextObj, "split_suggestions")).toBe(false);
			expect(contextClean.parsed.data).toBeDefined();
			expect(
				Array.isArray(contextClean.parsed.data?.split_suggestions),
			).toBe(true);

			// 3. Findings runs (all 4 scripts must validate against ScriptOutputSchema)
			const dirtyDir = path.join(sandbox, "dirty-workspace");
			fs.mkdirSync(dirtyDir, { recursive: true });
			fs.writeFileSync(
				path.join(dirtyDir, "bad_app.py"),
				[
					"import time",
					"from pydantic import BaseModel",
					"",
					"class BadSchema(BaseModel):",
					"    tags: list[str] = []",
					"",
					"async def handler():",
					'    print("stdout leak")',
					"    time.sleep(1)",
					"",
				].join("\n"),
				"utf-8",
			);
			const assembledSecret = ["live", "secret", "9876543210"].join("_");
			fs.writeFileSync(
				path.join(dirtyDir, "config.json"),
				JSON.stringify({ api_secret: assembledSecret }),
				"utf-8",
			);
			const bloatedLines = Array.from(
				{ length: 520 },
				(_, idx) => `## Section ${idx}\nDetailed guidance line ${idx}.`,
			).join("\n");
			fs.writeFileSync(path.join(dirtyDir, "CLAUDE.md"), bloatedLines, "utf-8");

			const mcpFindings = runPythonScriptJson(SCRIPTS.mcp, [
				"--path",
				dirtyDir,
			]);
			expect(mcpFindings.exitCode).toBe(1);
			expect(mcpFindings.parsed.findings.length).toBeGreaterThan(0);

			const secretsFindings = runPythonScriptJson(SCRIPTS.secrets, [
				"--path",
				dirtyDir,
			]);
			expect(secretsFindings.exitCode).toBe(1);
			expect(secretsFindings.parsed.findings.length).toBeGreaterThan(0);

			const fastapiFindings = runPythonScriptJson(SCRIPTS.fastapi, [
				"--path",
				dirtyDir,
			]);
			expect(fastapiFindings.exitCode).toBe(1);
			expect(fastapiFindings.parsed.findings.length).toBeGreaterThan(0);

			const contextFindings = runPythonScriptJson(SCRIPTS.context, [
				"--repo",
				dirtyDir,
			]);
			expect(contextFindings.exitCode).toBe(1);
			expect(contextFindings.parsed.status).toBe("error");
			expect(
				(contextFindings.parsed.data?.split_suggestions as unknown[]).length,
			).toBeGreaterThan(0);
		} finally {
			fs.rmSync(sandbox, { recursive: true, force: true });
		}
	});

	it("enforces the 2 MiB file-size guard before reading and emits skipped-oversized-file across all 4 scripts", () => {
		const sandbox = fs.mkdtempSync(
			path.join(os.tmpdir(), "skillops-iss214-oversize-"),
		);
		try {
			const bigBuffer = Buffer.alloc(TWO_MIB_BYTES + 128, 0x23); // '#' bytes > 2 MiB
			fs.writeFileSync(path.join(sandbox, "oversized.py"), bigBuffer);
			fs.writeFileSync(path.join(sandbox, "CLAUDE.md"), bigBuffer);

			for (const [key, scriptPath] of Object.entries(SCRIPTS)) {
				const flag = key === "context" ? "--repo" : "--path";
				const res = runPythonScriptJson(scriptPath, [flag, sandbox]);
				const rules = res.parsed.findings.map((f) => f.rule);
				expect(rules).toContain("skipped-oversized-file");
			}
		} finally {
			fs.rmSync(sandbox, { recursive: true, force: true });
		}
	});

	it("skips .venv/ in validate_mcp_server.py and converts SyntaxError and NUL bytes into parse-error warnings", () => {
		const sandbox = fs.mkdtempSync(
			path.join(os.tmpdir(), "skillops-iss214-mcp-"),
		);
		try {
			const venvDir = path.join(sandbox, ".venv", "lib");
			const nodeModulesDir = path.join(sandbox, "node_modules", "pkg");
			fs.mkdirSync(venvDir, { recursive: true });
			fs.mkdirSync(nodeModulesDir, { recursive: true });

			// Should be completely ignored because .venv and node_modules are in SKIP_DIRS
			fs.writeFileSync(
				path.join(venvDir, "polluted_venv.py"),
				'print("venv stdout should be ignored")\n',
				"utf-8",
			);
			fs.writeFileSync(
				path.join(nodeModulesDir, "polluted_nm.py"),
				'print("node_modules stdout should be ignored")\n',
				"utf-8",
			);

			// Malformed syntax file
			fs.writeFileSync(
				path.join(sandbox, "broken_syntax.py"),
				"def broken(:\n    pass\n",
				"utf-8",
			);
			// Embedded NUL byte file
			fs.writeFileSync(
				path.join(sandbox, "embedded_null.py"),
				Buffer.from("x = 1\x00\ny = 2\n", "utf-8"),
			);
			// Invalid UTF-8 bytes
			fs.writeFileSync(
				path.join(sandbox, "bad_utf8.py"),
				Buffer.from([0xff, 0xfe, 0xfa, 0x0a]),
			);

			const res = runPythonScriptJson(SCRIPTS.mcp, ["--path", sandbox]);
			expect(res.exitCode).toBe(1);
			expect(res.parsed.status).toBe("findings_detected");

			const filesFlagged = res.parsed.findings.map((f) => f.file);
			expect(filesFlagged).not.toContain(".venv/lib/polluted_venv.py");
			expect(filesFlagged).not.toContain("node_modules/pkg/polluted_nm.py");
			expect(filesFlagged).toEqual(
				expect.arrayContaining([
					"bad_utf8.py",
					"broken_syntax.py",
					"embedded_null.py",
				]),
			);
			for (const finding of res.parsed.findings) {
				expect(finding.rule).toBe("parse-error");
				expect(finding.severity).toBe("warning");
			}
		} finally {
			fs.rmSync(sandbox, { recursive: true, force: true });
		}
	});

	it("catches masked same-line secrets, warns on >4096-char lines, and blocks external gitdir traversal in scan_secrets.py", () => {
		const sandbox = fs.mkdtempSync(
			path.join(os.tmpdir(), "skillops-iss214-secrets-"),
		);
		try {
			const outsideGitDir = path.join(sandbox, "outside-fake-git");
			const repoDir = path.join(sandbox, "repo");
			fs.mkdirSync(path.join(outsideGitDir, "info"), { recursive: true });
			fs.mkdirSync(repoDir, { recursive: true });

			// External fake gitdir tries to mask '.env' via info/exclude outside repo
			fs.writeFileSync(
				path.join(outsideGitDir, "info", "exclude"),
				".env\n",
				"utf-8",
			);
			fs.writeFileSync(
				path.join(repoDir, ".git"),
				"gitdir: ../outside-fake-git\n",
				"utf-8",
			);
			fs.writeFileSync(
				path.join(repoDir, ".env"),
				"LOCAL_ONLY=1\n",
				"utf-8",
			);

			// 1. Second secret on the same JSON line after a benign key-value pair
			const realApiSecret = ["prod", "credential", "9988776655"].join("_");
			const sameLineJson = `{"benign": "value1234", "api_secret": "${realApiSecret}"}\n`;

			// 2. Real provider token on the same line after an earlier placeholder provider token
			const placeholderGh = `ghp_${"x".repeat(36)}`;
			const realShapedGh = [
				"ghp",
				"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
			].join("_");
			const dualTokenLine = `tokens = ["${placeholderGh}", "${realShapedGh}"]\n`;

			// 3. Minified line exceeding 4096 characters
			const oversizedLine = `const bundle = "${"a".repeat(4200)}";\n`;

			fs.writeFileSync(
				path.join(repoDir, "app_bundle.js"),
				`${sameLineJson}${dualTokenLine}${oversizedLine}`,
				"utf-8",
			);

			const res = runPythonScriptJson(SCRIPTS.secrets, ["--path", repoDir]);
			expect(res.exitCode).toBe(1);
			expect(res.parsed.status).toBe("findings_detected");

			const symbols = res.parsed.findings.map((f) => f.symbol);
			// External gitdir '../outside-fake-git' was rejected so .env is still caught as unignored
			expect(symbols).toContain("env-file-not-ignored");
			// Second assignment after benign key on the same line was caught
			expect(symbols).toContain("hardcoded-secret-assignment");
			// Second provider token after placeholder token on the same line was caught
			expect(symbols).toContain("github-token");
			// >4096-char line emitted explicit warning instead of silent skip
			expect(symbols).toContain("skipped-long-line");

			// Ensure redacted output never leaks full secret material
			expect(res.stdout).not.toContain(realApiSecret);
			expect(res.stdout).not.toContain(realShapedGh);
		} finally {
			fs.rmSync(sandbox, { recursive: true, force: true });
		}
	});

	it("bounds _is_mutable_expr recursion depth and catches SyntaxError / NUL bytes in audit_fastapi_async.py", () => {
		const sandbox = fs.mkdtempSync(
			path.join(os.tmpdir(), "skillops-iss214-fastapi-"),
		);
		try {
			// Deeply nested Field(default=Field(default=...)) > 32 levels
			let nestedExpr = "[]";
			for (let i = 0; i < 45; i++) {
				nestedExpr = `Field(default=${nestedExpr})`;
			}
			// Shallow nested Field(default=[]) <= 32 levels (must still be caught)
			const shallowExpr = "Field(default=Field(default=[]))";

			fs.writeFileSync(
				path.join(sandbox, "models.py"),
				[
					"from pydantic import BaseModel, Field",
					"",
					"class DeepModel(BaseModel):",
					`    deep_items: list[str] = ${nestedExpr}`,
					`    shallow_items: list[str] = ${shallowExpr}`,
					"",
				].join("\n"),
				"utf-8",
			);
			fs.writeFileSync(
				path.join(sandbox, "null_bytes.py"),
				Buffer.from("async def bad():\x00\n    pass\n", "utf-8"),
			);
			fs.writeFileSync(
				path.join(sandbox, "syntax_err.py"),
				"async def broken(:\n    pass\n",
				"utf-8",
			);

			const res = runPythonScriptJson(SCRIPTS.fastapi, ["--path", sandbox]);
			expect(res.exitCode).toBe(1);

			const mutableFindings = res.parsed.findings.filter(
				(f) => f.rule === "pydantic-mutable-default",
			);
			expect(mutableFindings.map((f) => f.symbol)).toEqual([
				"DeepModel.shallow_items",
			]);

			const parseFindings = res.parsed.findings.filter(
				(f) => f.rule === "parse-error",
			);
			expect(parseFindings.map((f) => f.file)).toEqual(
				expect.arrayContaining(["null_bytes.py", "syntax_err.py"]),
			);
		} finally {
			fs.rmSync(sandbox, { recursive: true, force: true });
		}
	});

	it("rejects symlinked roots and skips symlinked directories and parent chains across all 4 scripts", () => {
		const sandbox = fs.mkdtempSync(
			path.join(os.tmpdir(), "skillops-iss214-symlinks-"),
		);
		try {
			const outsideDir = path.join(sandbox, "outside-secret-zone");
			const workspaceDir = path.join(sandbox, "workspace");
			fs.mkdirSync(path.join(outsideDir, "rules"), { recursive: true });
			fs.mkdirSync(path.join(outsideDir, "skills", "escaped-skill"), {
				recursive: true,
			});
			fs.mkdirSync(workspaceDir, { recursive: true });

			// Populate outsideDir with traps that every script would flag if traversed
			const fakeKey = ["live", "outside", "secret9999"].join("_");
			fs.writeFileSync(
				path.join(outsideDir, "trap.py"),
				[
					"import time",
					`API_SECRET = "${fakeKey}"`,
					"async def leak():",
					'    print("outside leak")',
					"    time.sleep(2)",
					"",
				].join("\n"),
				"utf-8",
			);
			const bloatedOutsideMd = Array.from(
				{ length: 550 },
				(_, i) => `Outside bloated line ${i}`,
			).join("\n");
			fs.writeFileSync(
				path.join(outsideDir, "rules", "escaped.mdc"),
				bloatedOutsideMd,
				"utf-8",
			);
			fs.writeFileSync(
				path.join(outsideDir, "skills", "escaped-skill", "SKILL.md"),
				bloatedOutsideMd,
				"utf-8",
			);

			// 1. Symlinked root directory must be rejected (exit 2, status='error') by all 4 scripts
			const symlinkedRoot = path.join(sandbox, "linked-root");
			fs.symlinkSync(outsideDir, symlinkedRoot, DIR_LINK_TYPE);

			for (const [key, scriptPath] of Object.entries(SCRIPTS)) {
				const flag = key === "context" ? "--repo" : "--path";
				const rootRes = runPythonScriptJson(scriptPath, [flag, symlinkedRoot]);
				expect(rootRes.exitCode).toBe(2);
				expect(rootRes.parsed.status).toBe("error");
			}

			// Symlinked intermediate parent directory on a file target must also be rejected
			for (const scriptPath of [SCRIPTS.mcp, SCRIPTS.fastapi]) {
				const nestedViaLink = runPythonScriptJson(scriptPath, [
					"--path",
					path.join(symlinkedRoot, "trap.py"),
				]);
				expect(nestedViaLink.exitCode).toBe(2);
				expect(nestedViaLink.parsed.status).toBe("error");
			}

			// 2. Inside workspaceDir, link subdirectories and intermediate context parent dirs (.cursor, .claude/skills, .github/instructions)
			fs.symlinkSync(
				outsideDir,
				path.join(workspaceDir, "linked-subdir"),
				DIR_LINK_TYPE,
			);
			fs.symlinkSync(
				outsideDir,
				path.join(workspaceDir, ".cursor"),
				DIR_LINK_TYPE,
			);
			fs.mkdirSync(path.join(workspaceDir, ".claude"), { recursive: true });
			fs.symlinkSync(
				path.join(outsideDir, "skills"),
				path.join(workspaceDir, ".claude", "skills"),
				DIR_LINK_TYPE,
			);
			fs.mkdirSync(path.join(workspaceDir, ".github"), { recursive: true });
			fs.symlinkSync(
				path.join(outsideDir, "rules"),
				path.join(workspaceDir, ".github", "instructions"),
				DIR_LINK_TYPE,
			);

			// Optional file symlink & broken file symlink when OS allows unprivileged file symlinks
			tryCreateFileSymlink(
				path.join(outsideDir, "trap.py"),
				path.join(workspaceDir, "linked_trap.py"),
			);
			tryCreateFileSymlink(
				path.join(outsideDir, "nonexistent_target.py"),
				path.join(workspaceDir, "broken_link.py"),
			);

			// Legitimate safe file inside workspaceDir
			fs.writeFileSync(
				path.join(workspaceDir, "AGENTS.md"),
				"# Clean Workspace\n\nShort instructions.\n",
				"utf-8",
			);

			for (const [key, scriptPath] of Object.entries(SCRIPTS)) {
				const flag = key === "context" ? "--repo" : "--path";
				const wsRes = runPythonScriptJson(scriptPath, [flag, workspaceDir]);
				expect(wsRes.exitCode).toBe(0);
				expect(wsRes.parsed.status).toBe("ok");
				expect(wsRes.parsed.findings).toEqual([]);
			}

			// Built-in catalog security audit must pass with 0 findings on all hardened scripts
			const catalogReport = auditCatalogSecurity(
				path.join(REPO_ROOT, "catalog"),
			);
			expect(catalogReport.findings).toEqual([]);
			expect(catalogReport.passed).toBe(true);
		} finally {
			fs.rmSync(sandbox, { recursive: true, force: true });
		}
	});
});
