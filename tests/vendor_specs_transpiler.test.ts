import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import YAML from "yaml";
import { parseSubagentFile } from "../src/auditor/parser.js";
import {
	ALL_RUNTIME_TARGETS,
	RUNTIME_HARNESS_SPECS,
	type RuntimeTarget,
} from "../src/models.js";
import {
	addSkillOrSubagent,
	cleanSyncedArtifacts,
	encodeTomlBasicString,
	inspectProjectStatus,
	mapCanonicalToolsToRuntime,
	removeSkillOrSubagent,
	renderSubagentFilesForRuntime,
	updateInstalledSkills,
} from "../src/sync/adapters.js";

const REPO_ROOT = path.resolve(import.meta.dirname, "..");
const BUILTIN_CATALOG_DIR = path.join(REPO_ROOT, "catalog");

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

function writeSampleSubagent(dir: string, name: string): string {
	const filePath = path.join(dir, `${name}.md`);
	fs.writeFileSync(
		filePath,
		[
			"---",
			`name: ${name}`,
			"description: Use when auditing API endpoints and code paths under strict read-only sandbox rules.",
			"tools:",
			"  - read",
			"  - search",
			"  - glob",
			"disallowed_tools:",
			"  - bash",
			"  - edit",
			"  - write",
			"model_tier: reasoning",
			"max_output_tokens: 350",
			"context_isolation: true",
			"---",
			"",
			"Analyze the requested module and summarize verified findings with line ranges.",
			"",
		].join("\n"),
		"utf-8",
	);
	return filePath;
}

describe("Issue #220 Vendor-Spec Transpilers across harnesses", () => {
	it("maps canonical tools and emits native Claude Code, Copilot, and Codex subagent specs", () => {
		const tmpDir = makeTempDir("skillops-vendor-subagent-");
		const subagent = parseSubagentFile(
			writeSampleSubagent(tmpDir, "spec-auditor"),
		);

		expect(
			mapCanonicalToolsToRuntime(["read", "search", "edit"], "claude"),
		).toEqual(["Read", "Grep", "Glob", "Edit"]);

		// Claude Code: PascalCase tools, disallowedTools (camelCase), omit model_tier/max_output_tokens, constrained body
		const claudeFiles = renderSubagentFilesForRuntime(subagent, "claude");
		expect(claudeFiles).toHaveLength(1);
		expect(claudeFiles[0]?.relativePath).toBe(".claude/agents/spec-auditor.md");
		const claudeContent = claudeFiles[0]?.content ?? "";
		expect(claudeContent).toContain("tools:\n  - Read\n  - Grep\n  - Glob");
		expect(claudeContent).toContain("disallowedTools:\n  - Bash\n  - Edit\n  - Write");
		expect(claudeContent).not.toContain("model_tier:");
		expect(claudeContent).not.toContain("max_output_tokens:");
		expect(claudeContent).toContain("## Tool & Sandbox Constraints");

		// Copilot: .agent.md with native Copilot mapped tools, omitting model/model_tier/max_output_tokens, constrained body
		const copilotFiles = renderSubagentFilesForRuntime(subagent, "copilot");
		expect(copilotFiles).toHaveLength(1);
		expect(copilotFiles[0]?.relativePath).toBe(
			".github/agents/spec-auditor.agent.md",
		);
		const copilotContent = copilotFiles[0]?.content ?? "";
		expect(copilotContent).toContain("tools:\n  - search\n  - usages");
		expect(copilotContent).not.toContain("model:");
		expect(copilotContent).not.toContain("model_tier:");
		expect(copilotContent).not.toContain("max_output_tokens:");
		expect(copilotContent).toContain("## Tool & Sandbox Constraints");

		// Codex: .codex/agents/<name>.toml with sandbox_mode, model_reasoning_effort, developer_instructions
		const codexFiles = renderSubagentFilesForRuntime(subagent, "codex");
		expect(codexFiles).toHaveLength(1);
		expect(codexFiles[0]?.relativePath).toBe(".codex/agents/spec-auditor.toml");
		const codexContent = codexFiles[0]?.content ?? "";
		expect(codexContent).toContain('name = "spec-auditor"');
		expect(codexContent).toContain('model_reasoning_effort = "high"');
		expect(codexContent).toContain('sandbox_mode = "read-only"');
		expect(codexContent).toContain("developer_instructions = ");
		expect(codexContent).toContain("## Tool & Sandbox Constraints");
	});

	it("renders ## Tool & Sandbox Constraints across all 28 harnesses", () => {
		const tmpDir = makeTempDir("skillops-all-28-subagent-");
		const subagent = parseSubagentFile(
			writeSampleSubagent(tmpDir, "every-harness-auditor"),
		);

		for (const target of ALL_RUNTIME_TARGETS) {
			const rendered = renderSubagentFilesForRuntime(subagent, target);
			expect(rendered.length).toBeGreaterThanOrEqual(1);
			for (const file of rendered) {
				expect(
					file.content,
					`Expected ${target} (${file.relativePath}) to include constraints section`,
				).toContain("## Tool & Sandbox Constraints");
			}
		}
	});

	it("encodes TOML basic strings safely for control chars, DEL, and non-BMP astral characters", () => {
		const encoded = encodeTomlBasicString('line1\n"q"\t\u007F🚀');
		expect(encoded).toBe('"line1\\n\\"q\\"\\t\\u007F\\U0001F680"');
		expect(encoded).not.toMatch(/\\uD83D/i);

		const tmpDir = makeTempDir("skillops-toml-astral-");
		const subagentPath = path.join(tmpDir, "astral-reviewer.md");
		fs.writeFileSync(
			subagentPath,
			[
				"---",
				"name: astral-reviewer",
				'description: "Use when checking TOML encoding with emoji 🚀 telemetry and control boundaries."',
				"tools:",
				"  - read",
				"---",
				"",
				"Verify TOML string escaping 🚀 end to end.",
				"",
			].join("\n"),
			"utf-8",
		);
		const parsed = parseSubagentFile(subagentPath);
		for (const target of ["codex", "vibe"] as RuntimeTarget[]) {
			const files = renderSubagentFilesForRuntime(parsed, target);
			expect(files[0]?.content).toContain("\\U0001F680");
			expect(files[0]?.content).not.toMatch(/\\u[Dd][89ABab][0-9A-Fa-f]{2}/);
		}
	});

	it("synchronizes Aider .aider.conf.yml read: entries safely, detects drift, and cleans up user keys intact", () => {
		const repo = makeTempDir("skillops-aider-conf-");
		fs.writeFileSync(
			path.join(repo, ".aider.conf.yml"),
			[
				"model: claude-sonnet-4",
				"auto-commits: false",
				"read:",
				"  - docs/ARCHITECTURE.md",
				"",
			].join("\n"),
			"utf-8",
		);

		const addRes = addSkillOrSubagent(
			repo,
			BUILTIN_CATALOG_DIR,
			"mcp-architect",
			{ targets: ["aider"] },
		);
		expect(addRes.passed).toBe(true);

		const afterAdd = YAML.parse(
			fs.readFileSync(path.join(repo, ".aider.conf.yml"), "utf-8"),
		) as Record<string, unknown>;
		expect(afterAdd.model).toBe("claude-sonnet-4");
		expect(afterAdd["auto-commits"]).toBe(false);
		expect(afterAdd.read).toEqual([
			"docs/ARCHITECTURE.md",
			".aider/conventions/skillops-mcp-architect.md",
		]);

		expect(inspectProjectStatus(repo, BUILTIN_CATALOG_DIR).passed).toBe(true);

		// Local manual edit triggers drift conflict on update without --force
		fs.appendFileSync(path.join(repo, ".aider.conf.yml"), "# user comment\n");
		const driftedUpdate = updateInstalledSkills(repo, BUILTIN_CATALOG_DIR, {
			targets: ["aider"],
		});
		expect(driftedUpdate.passed).toBe(false);
		expect(driftedUpdate.drift_conflicts).toContain(".aider.conf.yml");

		// Clean with --force strips only managed entries and preserves user settings
		const cleaned = cleanSyncedArtifacts(repo, BUILTIN_CATALOG_DIR, {
			force: true,
		});
		expect(cleaned.passed).toBe(true);
		expect(fs.existsSync(path.join(repo, ".aider.conf.yml"))).toBe(true);
		const afterClean = YAML.parse(
			fs.readFileSync(path.join(repo, ".aider.conf.yml"), "utf-8"),
		) as Record<string, unknown>;
		expect(afterClean.model).toBe("claude-sonnet-4");
		expect(afterClean.read).toEqual(["docs/ARCHITECTURE.md"]);

		// Single-item remove after re-add
		addSkillOrSubagent(repo, BUILTIN_CATALOG_DIR, "mcp-architect", {
			targets: ["aider"],
		});
		const removed = removeSkillOrSubagent(
			repo,
			BUILTIN_CATALOG_DIR,
			"mcp-architect",
			{ targets: ["aider"] },
		);
		expect(removed.passed).toBe(true);
		const afterRemove = YAML.parse(
			fs.readFileSync(path.join(repo, ".aider.conf.yml"), "utf-8"),
		) as Record<string, unknown>;
		expect(afterRemove.read).toEqual(["docs/ARCHITECTURE.md"]);
	});

	it("aligns Zed to .agents/skills progressive directories without duplicate-file skipped warnings across --targets all", () => {
		expect(RUNTIME_HARNESS_SPECS.codex.skillsDir).toBe(".agents/skills");
		expect(RUNTIME_HARNESS_SPECS.zed.skillsDir).toBe(".agents/skills");
		expect(RUNTIME_HARNESS_SPECS.zed.skillFormat).toBe("progressive-skill-dir");
		expect(RUNTIME_HARNESS_SPECS.zed.detectionPaths).toEqual([
			".zed",
			".rules",
			".agents/skills",
		]);
		expect(RUNTIME_HARNESS_SPECS.zed.alwaysOnFiles).toEqual([".rules"]);

		const repo = makeTempDir("skillops-all-shared-agents-skills-");
		const report = addSkillOrSubagent(
			repo,
			BUILTIN_CATALOG_DIR,
			"mcp-architect",
			{ targets: [...ALL_RUNTIME_TARGETS] },
		);
		expect(report.passed).toBe(true);
		expect(report.skipped_existing).toEqual([]);
		expect(
			fs.existsSync(
				path.join(repo, ".agents/skills/mcp-architect/SKILL.md"),
			),
		).toBe(true);
	});
});
