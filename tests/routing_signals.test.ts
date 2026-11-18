import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import YAML from "yaml";
import { parseSkillDirectory } from "../src/auditor/index.js";
import { splitFrontmatter } from "../src/models.js";
import { renderSkillFilesForRuntime } from "../src/sync/adapters.js";

const BUILTIN_CATALOG_DIR = path.resolve(process.cwd(), "catalog");
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

describe("Issue #219 semantic skill routing and active_file_globs decoupling", () => {
	it("never maps routing_signals.files_any onto IDE active-editor globs for built-in catalog skills", () => {
		const mcpParsed = parseSkillDirectory(
			path.join(BUILTIN_CATALOG_DIR, "ai-engineering", "mcp-architect"),
			{ requireLayout: true },
		);
		expect(mcpParsed.manifest.routing_signals.files_any).toContain(
			"pyproject.toml",
		);
		expect(mcpParsed.manifest.routing_signals.active_file_globs).toEqual([]);

		// Cursor: omits globs so rule activates via Agent Requested semantic description
		const cursorRule = renderSkillFilesForRuntime(mcpParsed, "cursor").find((f) =>
			f.relativePath.endsWith(".mdc"),
		)!;
		const [cursorFm] = splitFrontmatter(cursorRule.content, cursorRule.relativePath);
		expect(cursorFm.alwaysApply).toBe(false);
		expect(cursorFm.globs).toBeUndefined();

		// Copilot: defaults to "**" rather than config-only files_any
		const copilotInstr = renderSkillFilesForRuntime(mcpParsed, "copilot").find(
			(f) => f.relativePath.endsWith(".instructions.md"),
		)!;
		const [copilotFm] = splitFrontmatter(
			copilotInstr.content,
			copilotInstr.relativePath,
		);
		expect(copilotFm.applyTo).toBe("**");

		// Windsurf: trigger: model_decision without conflicting globs
		const windsurfRule = renderSkillFilesForRuntime(mcpParsed, "windsurf").find(
			(f) => f.relativePath.endsWith(".md"),
		)!;
		const [wsFm] = splitFrontmatter(
			windsurfRule.content,
			windsurfRule.relativePath,
		);
		expect(wsFm.trigger).toBe("model_decision");
		expect(wsFm.globs).toBeUndefined();

		// Kiro: inclusion: auto without dropping fileMatchPattern
		const kiroRule = renderSkillFilesForRuntime(mcpParsed, "kiro").find((f) =>
			f.relativePath.endsWith(".md"),
		)!;
		const [kiroFm] = splitFrontmatter(kiroRule.content, kiroRule.relativePath);
		expect(kiroFm.inclusion).toBe("auto");
		expect(kiroFm.fileMatchPattern).toBeUndefined();

		// Generic rule harness (cline): no files_any globs
		const clineRule = renderSkillFilesForRuntime(mcpParsed, "cline").find((f) =>
			f.relativePath.endsWith(".md"),
		)!;
		const [clineFm] = splitFrontmatter(
			clineRule.content,
			clineRule.relativePath,
		);
		expect(clineFm.globs).toBeUndefined();
	});

	it("maps explicit routing_signals.active_file_globs to Cursor, Copilot, Windsurf, and Kiro without dropping multi-glob patterns", () => {
		const tmpCatalog = makeTempDir("skillops-219-globs-");
		const skillDir = path.join(tmpCatalog, "python-backend", "globbed-skill");
		fs.mkdirSync(path.join(skillDir, "scripts"), { recursive: true });
		fs.mkdirSync(path.join(skillDir, "evals"), { recursive: true });
		fs.writeFileSync(
			path.join(skillDir, "scripts", "check.py"),
			'import json\nprint(json.dumps({"status":"ok"}))\n',
			"utf-8",
		);
		fs.writeFileSync(
			path.join(skillDir, "evals", "evals.json"),
			JSON.stringify({
				skill_name: "globbed-skill",
				schema_version: "1.0",
				evals: [
					{
						id: "e1",
						name: "Test",
						prompt: "Run check",
						fixtures: [],
						assertions: [
							{
								id: "a1",
								type: "tool_call_contains",
								target: "check.py",
								description: "Runs check",
							},
						],
					},
				],
			}),
			"utf-8",
		);
		fs.writeFileSync(
			path.join(skillDir, "SKILL.md"),
			[
				"---",
				'name: "globbed-skill"',
				'description: "Use when auditing Python backend routers, validating active editor files matching Python globs, enforcing deterministic static analysis rules across application modules, inspecting FastAPI dependency injection graphs, checking project configuration files, and ensuring repository-wide Python code hygiene before commits across target workspaces cleanly."',
				'version: "1.0.0"',
				'track: "python-backend"',
				'tags: ["python"]',
				"routing_signals:",
				'  languages: ["python"]',
				'  files_any: ["pyproject.toml"]',
				'  active_file_globs: ["*.py", "app/**/*.py"]',
				"entrypoints:",
				"  scripts:",
				'    - path: "scripts/check.py"',
				'      description: "Run deterministic check cleanly."',
				"---",
				"",
				"# Globbed Skill",
				"",
				"Run check.",
				"",
			].join("\n"),
			"utf-8",
		);

		const parsed = parseSkillDirectory(skillDir, { requireLayout: true });
		expect(parsed.manifest.routing_signals.active_file_globs).toEqual([
			"*.py",
			"app/**/*.py",
		]);

		const cursorRule = renderSkillFilesForRuntime(parsed, "cursor").find((f) =>
			f.relativePath.endsWith(".mdc"),
		)!;
		const [cursorFm] = splitFrontmatter(cursorRule.content, cursorRule.relativePath);
		expect(cursorFm.globs).toEqual(["*.py", "app/**/*.py"]);

		const copilotInstr = renderSkillFilesForRuntime(parsed, "copilot").find(
			(f) => f.relativePath.endsWith(".instructions.md"),
		)!;
		const [copilotFm] = splitFrontmatter(
			copilotInstr.content,
			copilotInstr.relativePath,
		);
		expect(copilotFm.applyTo).toBe("*.py,app/**/*.py");

		const windsurfRule = renderSkillFilesForRuntime(parsed, "windsurf").find(
			(f) => f.relativePath.endsWith(".md"),
		)!;
		const wsRawYaml = YAML.parse(
			windsurfRule.content.split("---")[1] ?? "",
		) as Record<string, unknown>;
		expect(wsRawYaml.trigger).toBe("glob");
		expect(wsRawYaml.globs).toEqual(["*.py", "app/**/*.py"]);

		const kiroRule = renderSkillFilesForRuntime(parsed, "kiro").find((f) =>
			f.relativePath.endsWith(".md"),
		)!;
		const [kiroFm] = splitFrontmatter(kiroRule.content, kiroRule.relativePath);
		expect(kiroFm.inclusion).toBe("fileMatch");
		expect(kiroFm.fileMatchPattern).toBe("*.py,app/**/*.py");
	});
});
