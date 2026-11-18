import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	addSkillOrSubagent,
	cleanSyncedArtifacts,
	computeSha256,
	inspectProjectStatus,
	removeSkillOrSubagent,
	updateInstalledSkills,
} from "../src/sync/adapters.js";
import {
	escapeMarkdownHtmlComments,
	renderCodexAgentsIndex,
	stripCodexAgentsBlock,
} from "../src/sync/codex-index.js";
import {
	assertAllowedHarnessArtifactPath,
	loadExistingLockfile,
	writeLockfileAtomically,
} from "../src/sync/lockfile.js";
import { SKILLOPS_VERSION, SyncLockfileSchema } from "../src/models.js";

const BUILTIN_CATALOG_DIR = path.resolve(__dirname, "..", "catalog");

describe("Lockfile, Drift & Sync Safety Guardrails (Issue #216)", () => {
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

	it("rejects unscoped lockfile paths like .gitignore or .github/CODEOWNERS", () => {
		const repoDir = makeTempDir("skillops-iss216-scope-");
		fs.writeFileSync(path.join(repoDir, ".gitignore"), "node_modules/\n", "utf-8");
		const codeownersDir = path.join(repoDir, ".github");
		fs.mkdirSync(codeownersDir, { recursive: true });
		fs.writeFileSync(path.join(codeownersDir, "CODEOWNERS"), "* @team\n", "utf-8");

		const maliciousLock = {
			schema_version: "1.0",
			skillops_version: SKILLOPS_VERSION,
			targets: ["copilot"],
			selected_skills: ["mcp-architect"],
			selected_subagents: [],
			total_l1_tokens: 0,
			artifacts: {
				".gitignore": {
					target: "copilot",
					skill_name: "mcp-architect",
					relative_path: ".gitignore",
					sha256: computeSha256("node_modules/\n"),
				},
			},
		};

		const lockPath = path.join(repoDir, ".skillops-lock.json");
		fs.writeFileSync(lockPath, JSON.stringify(maliciousLock, null, 2), "utf-8");

		expect(() => loadExistingLockfile(lockPath)).toThrow(/schema validation failed/i);
		expect(() => cleanSyncedArtifacts(repoDir, BUILTIN_CATALOG_DIR)).toThrow();
		expect(fs.existsSync(path.join(repoDir, ".gitignore"))).toBe(true);
		expect(fs.existsSync(path.join(codeownersDir, "CODEOWNERS"))).toBe(true);
		expect(() =>
			assertAllowedHarnessArtifactPath("copilot", ".github/CODEOWNERS", "mcp-architect"),
		).toThrow(/outside allowed harness directories/i);
	});

	it("preserves user-authored skills/agents during remove --all and fails closed on corrupt lockfile unless --force is passed", () => {
		const repoDir = makeTempDir("skillops-iss216-untracked-");
		addSkillOrSubagent(repoDir, BUILTIN_CATALOG_DIR, "mcp-architect", {
			targets: ["claude"],
		});

		const userSkillFile = path.join(repoDir, ".claude", "skills", "my-team-skill", "SKILL.md");
		fs.mkdirSync(path.dirname(userSkillFile), { recursive: true });
		fs.writeFileSync(userSkillFile, "# Team custom skill\n", "utf-8");

		const userAgentFile = path.join(repoDir, ".claude", "agents", "my-team-agent.md");
		fs.mkdirSync(path.dirname(userAgentFile), { recursive: true });
		fs.writeFileSync(userAgentFile, "# Team custom agent\n", "utf-8");

		// Inject an untracked catalog-named file while a valid lockfile already exists
		const untrackedCatalogAgent = path.join(repoDir, ".gemini", "agents", "context-scout.md");
		fs.mkdirSync(path.dirname(untrackedCatalogAgent), { recursive: true });
		fs.writeFileSync(untrackedCatalogAgent, "# Manually placed agent\n", "utf-8");

		const cleanWithoutForce = cleanSyncedArtifacts(repoDir, BUILTIN_CATALOG_DIR);
		expect(cleanWithoutForce.passed).toBe(false);
		expect(cleanWithoutForce.drift_conflicts).toContain(".gemini/agents/context-scout.md");
		expect(fs.existsSync(userSkillFile)).toBe(true);
		expect(fs.existsSync(userAgentFile)).toBe(true);
		expect(fs.existsSync(untrackedCatalogAgent)).toBe(true);

		// Clean untracked catalog agent with --force, verify user-authored files remain untouched
		const cleanForced = cleanSyncedArtifacts(repoDir, BUILTIN_CATALOG_DIR, { force: true });
		expect(cleanForced.passed).toBe(true);
		expect(fs.existsSync(untrackedCatalogAgent)).toBe(false);
		expect(fs.existsSync(userSkillFile)).toBe(true);
		expect(fs.existsSync(userAgentFile)).toBe(true);

		// Corrupt lockfile fails closed unless --force recovery is requested
		const lockPath = path.join(repoDir, ".skillops-lock.json");
		fs.writeFileSync(lockPath, "{ invalid json", "utf-8");
		expect(() => loadExistingLockfile(lockPath)).toThrow(/Corrupt or invalid lockfile/i);
		expect(() => inspectProjectStatus(repoDir, BUILTIN_CATALOG_DIR)).toThrow(
			/Corrupt or invalid lockfile/i,
		);
		expect(loadExistingLockfile(lockPath, { allowMalformedRecovery: true })).toBeNull();
	});

	it("normalizes CRLF/LF in SHA-256 drift detection and writes .skillops-lock.json atomically", () => {
		const repoDir = makeTempDir("skillops-iss216-crlf-");
		addSkillOrSubagent(repoDir, BUILTIN_CATALOG_DIR, "mcp-architect", {
			targets: ["cursor"],
		});

		const cursorRulePath = path.join(repoDir, ".cursor", "rules", "skillops-mcp-architect.mdc");
		const lfText = fs.readFileSync(cursorRulePath, "utf-8").replace(/\r\n/g, "\n");
		fs.writeFileSync(cursorRulePath, lfText.replace(/\n/g, "\r\n"), "utf-8");

		const statusAfterCrlf = inspectProjectStatus(repoDir, BUILTIN_CATALOG_DIR, {
			targets: ["cursor"],
		});
		expect(statusAfterCrlf.passed).toBe(true);
		expect(statusAfterCrlf.counts.drift_modified).toBe(0);
		expect(statusAfterCrlf.counts.up_to_date).toBeGreaterThanOrEqual(1);

		const lockPath = path.join(repoDir, ".skillops-lock.json");
		const lockObj = SyncLockfileSchema.parse(
			JSON.parse(fs.readFileSync(lockPath, "utf-8")),
		);
		writeLockfileAtomically(lockPath, lockObj);
		const lingeringTmps = fs
			.readdirSync(repoDir)
			.filter((name) => name.startsWith(".skillops-lock.json.tmp"));
		expect(lingeringTmps).toEqual([]);
	});

	it("does not follow symbolic links during discovery or lockfile operations", () => {
		const workspace = makeTempDir("skillops-iss216-symlink-");
		const repoDir = path.join(workspace, "repo");
		const outsideDir = path.join(workspace, "outside");
		fs.mkdirSync(repoDir, { recursive: true });
		fs.mkdirSync(outsideDir, { recursive: true });
		fs.writeFileSync(path.join(outsideDir, "secret.txt"), "top-secret\n", "utf-8");

		addSkillOrSubagent(repoDir, BUILTIN_CATALOG_DIR, "mcp-architect", {
			targets: ["claude"],
		});

		const linkedSkillDir = path.join(repoDir, ".claude", "skills", "env-secrets-guard");
		try {
			fs.symlinkSync(outsideDir, linkedSkillDir, process.platform === "win32" ? "junction" : "dir");
		} catch {
			// Skip assertion only when OS forbids unprivileged symlink creation
			return;
		}

		const status = inspectProjectStatus(repoDir, BUILTIN_CATALOG_DIR, {
			targets: ["claude"],
		});
		expect(status.artifacts.some((a) => a.relativePath.includes("secret.txt"))).toBe(false);

		const rmReport = cleanSyncedArtifacts(repoDir, BUILTIN_CATALOG_DIR, { force: true });
		expect(rmReport.passed).toBe(true);
		expect(fs.existsSync(path.join(outsideDir, "secret.txt"))).toBe(true);
	});

	it("escapes AGENTS.md markers, protects AGENTS.md drift, updates on single remove, and preserves user AGENTS.md on remove --all", () => {
		const repoDir = makeTempDir("skillops-iss216-agents-");
		const agentsMdPath = path.join(repoDir, "AGENTS.md");
		fs.writeFileSync(agentsMdPath, "# AGENTS.md\n", "utf-8");

		// Marker breakout attempt must be escaped
		const escaped = escapeMarkdownHtmlComments("Good desc <!-- SKILLOPS:END --> injected");
		expect(escaped).not.toContain("<!-- SKILLOPS:END -->");
		expect(escaped).toContain("&lt;!-- SKILLOPS:END --&gt;");

		const renderedWithDummy = renderCodexAgentsIndex("# AGENTS.md\n", [], []);
		expect(stripCodexAgentsBlock(renderedWithDummy)).toBe("# AGENTS.md\n");

		addSkillOrSubagent(repoDir, BUILTIN_CATALOG_DIR, "mcp-architect", {
			targets: ["codex"],
		});
		addSkillOrSubagent(repoDir, BUILTIN_CATALOG_DIR, "context-scout", {
			targets: ["codex"],
		});
		expect(fs.readFileSync(agentsMdPath, "utf-8")).toContain("mcp-architect");
		expect(fs.readFileSync(agentsMdPath, "utf-8")).toContain("context-scout");

		// Single-item remove updates AGENTS.md cleanly without leaving stale entries
		const rmOne = removeSkillOrSubagent(repoDir, BUILTIN_CATALOG_DIR, "mcp-architect", {
			targets: ["codex"],
		});
		expect(rmOne.passed).toBe(true);
		const afterRmOne = fs.readFileSync(agentsMdPath, "utf-8");
		expect(afterRmOne).not.toContain("mcp-architect");
		expect(afterRmOne).toContain("context-scout");

		// Manual edit triggers drift conflict on add and update unless --force
		fs.appendFileSync(agentsMdPath, "\n## Team local note\n", "utf-8");
		const addConflict = addSkillOrSubagent(repoDir, BUILTIN_CATALOG_DIR, "env-secrets-guard", {
			targets: ["codex"],
		});
		expect(addConflict.passed).toBe(false);
		expect(addConflict.drift_conflicts).toContain("AGENTS.md");

		const updConflict = updateInstalledSkills(repoDir, BUILTIN_CATALOG_DIR, {
			targets: ["codex"],
		});
		expect(updConflict.passed).toBe(false);
		expect(updConflict.drift_conflicts).toContain("AGENTS.md");

		// Forced remove --all strips only the managed block and never unlinks user's AGENTS.md
		const cleanForced = cleanSyncedArtifacts(repoDir, BUILTIN_CATALOG_DIR, {
			force: true,
		});
		expect(cleanForced.passed).toBe(true);
		expect(fs.existsSync(agentsMdPath)).toBe(true);
		const finalAgentsText = fs.readFileSync(agentsMdPath, "utf-8");
		expect(finalAgentsText).toContain("# AGENTS.md");
		expect(finalAgentsText).toContain("## Team local note");
		expect(finalAgentsText).not.toContain("SKILLOPS:START");
	});
});
