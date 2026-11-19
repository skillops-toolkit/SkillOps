import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseSkillDirectory } from "../src/auditor/index.js";
import { ALL_RUNTIME_TARGETS } from "../src/models.js";
import {
	addSkillOrSubagent,
	inspectProjectStatus,
	renderSkillFilesForRuntime,
	updateInstalledSkills,
} from "../src/sync/adapters.js";
import { rewriteProgressiveSkillRawText } from "../src/sync/renderers/companion-paths.js";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	tempDirs.push(dir);
	return dir;
}

function buildBundlingCatalogSkill(
	catalogDir: string,
	name: string,
	lineEnding: "\n" | "\r\n" | "mixed" = "\n",
): { skillDir: string } {
	const skillDir = path.join(catalogDir, "ai-engineering", name);
	fs.mkdirSync(path.join(skillDir, "scripts"), { recursive: true });
	fs.mkdirSync(path.join(skillDir, "references"), { recursive: true });
	fs.mkdirSync(path.join(skillDir, "assets"), { recursive: true });
	fs.mkdirSync(path.join(skillDir, "evals"), { recursive: true });

	fs.writeFileSync(
		path.join(skillDir, "scripts", "audit_bundle.py"),
		"import json\nprint(json.dumps({'status': 'ok'}))\n",
		"utf-8",
	);
	fs.writeFileSync(
		path.join(skillDir, "references", "checklist.md"),
		"# Checklist\n",
		"utf-8",
	);
	fs.writeFileSync(
		path.join(skillDir, "assets", "template.json"),
		'{"schema": true}\n',
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
						id: "eval-01-bundle",
						name: "Audit bundle fixture cleanly",
						prompt: "Run audit check on test repo.",
						fixtures: [],
						assertions: [
							{
								id: "assert-01",
								type: "tool_call_contains",
								target: "audit_bundle.py",
								description: "Agent executed audit_bundle.py cleanly.",
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
				runner: "deterministic-ast",
				timestamp: "2026-11-18T12:00:00Z",
				with_skill: {
					pass_rate_mean: 0.95,
					pass_rate_stddev: 0.03,
					tokens_mean: 2000,
					latency_ms_mean: 2100,
				},
				without_skill: {
					pass_rate_mean: 0.4,
					pass_rate_stddev: 0.1,
					tokens_mean: 4000,
					latency_ms_mean: 5000,
				},
				delta: {
					pass_rate_gain: 0.55,
					token_reduction_pct: -50,
					verdict: "CERTIFIED_IMPROVEMENT",
				},
			},
			null,
			2,
		),
		"utf-8",
	);

	const fmLines = [
		"---",
		`name: "${name}"`,
		'description: "Use when validating companion file bundling across AI coding harnesses, stripping evals fixtures from end-user repositories, checking mixed line-ending YAML frontmatter preservation, distinguishing real bundled assets from illustrative user repository script paths, and running --global home-relative path rewrites accurately without corrupting examples."',
		'version: "1.0.0"',
		'track: "ai-engineering"',
		'tags: ["bundling", "security"]',
		"routing_signals:",
		'  languages: ["typescript"]',
		'  files_any: ["package.json"]',
		"entrypoints:",
		"  scripts:",
		'    - path: "scripts/audit_bundle.py"',
		'      description: "Bundle audit entrypoint."',
		"---",
	];
	const bodyLines = [
		"",
		`# ${name}`,
		"",
		"- Real script: `python3 scripts/audit_bundle.py --json`",
		"- Real legacy ref: `python3 catalog/ai-engineering/" +
			name +
			"/scripts/audit_bundle.py --json`",
		"- Real reference: [checklist](references/checklist.md)",
		'- Real asset: "assets/template.json"',
		"- Illustrative user script (NOT bundled): `python3 scripts/user_custom_script.py`",
		"- Illustrative user ref (NOT bundled): [custom](references/user_notes.md)",
		"- Illustrative user asset (NOT bundled): `assets/user_diagram.png`",
		"- Illustrative eval path (NEVER bundled): `evals/evals.json`",
		"",
	];

	let rawText: string;
	if (lineEnding === "mixed") {
		rawText = `${fmLines.join("\r\n")}\n${bodyLines.join("\n")}`;
	} else {
		rawText = `${fmLines.join(lineEnding)}${lineEnding}${bodyLines.join(lineEnding)}`;
	}
	fs.writeFileSync(path.join(skillDir, "SKILL.md"), rawText, "utf-8");
	return { skillDir };
}

afterEach(() => {
	while (tempDirs.length > 0) {
		const dir = tempDirs.pop();
		if (dir && fs.existsSync(dir)) {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	}
	delete process.env.SKILLOPS_GLOBAL_HOME;
});

describe("Issue #218 evals/ exclusion, bundleableFiles rewriting & --global prefix", () => {
	it("separates allFiles (including evals/) from bundleableFiles and excludes evals/ across all 28 harnesses", () => {
		const catalog = makeTempDir("skillops-218-cat-");
		const { skillDir } = buildBundlingCatalogSkill(catalog, "bundle-demo");
		const parsed = parseSkillDirectory(skillDir, { requireLayout: true });

		expect(parsed.allFiles).toContain("evals/evals.json");
		expect(parsed.allFiles).toContain("evals/benchmark.json");
		expect(parsed.bundleableFiles).toEqual([
			"assets/template.json",
			"references/checklist.md",
			"scripts/audit_bundle.py",
		]);

		for (const target of ALL_RUNTIME_TARGETS) {
			const planned = renderSkillFilesForRuntime(parsed, target);
			expect(
				planned.some((p) => p.relativePath.includes("/evals/") || p.relativePath.endsWith("/evals.json")),
			).toBe(false);
			expect(
				planned.some((p) => p.relativePath.endsWith("/scripts/audit_bundle.py")),
			).toBe(true);
		}
	});

	it("rewrites only paths present in bundleableFiles and preserves illustrative user-repo examples", () => {
		const catalog = makeTempDir("skillops-218-illus-");
		const { skillDir } = buildBundlingCatalogSkill(catalog, "illustrative-demo");
		const parsed = parseSkillDirectory(skillDir, { requireLayout: true });

		const claudePlanned = renderSkillFilesForRuntime(parsed, "claude");
		const skillMd = claudePlanned.find((f) =>
			f.relativePath.endsWith("/SKILL.md"),
		)!;

		// Real bundleable files ARE rewritten to .claude/skills/...
		expect(skillMd.content).toContain(
			"`.claude/skills/illustrative-demo/scripts/audit_bundle.py --json`".replace(
				"`",
				"`python3 ",
			),
		);
		expect(skillMd.content).toContain(
			"(.claude/skills/illustrative-demo/references/checklist.md)",
		);
		expect(skillMd.content).toContain(
			'".claude/skills/illustrative-demo/assets/template.json"',
		);

		// Illustrative nonexistent companion paths & evals/ remain untouched
		expect(skillMd.content).toContain(
			"`python3 scripts/user_custom_script.py`",
		);
		expect(skillMd.content).toContain("(references/user_notes.md)");
		expect(skillMd.content).toContain("`assets/user_diagram.png`");
		expect(skillMd.content).toContain("`evals/evals.json`");
	});

	it("prefixes rewritten companion paths with ~/ in --global mode and keeps status/update SHA-256 aligned", () => {
		const catalog = makeTempDir("skillops-218-global-cat-");
		const fakeHome = makeTempDir("skillops-218-home-");
		process.env.SKILLOPS_GLOBAL_HOME = fakeHome;
		buildBundlingCatalogSkill(catalog, "global-path-demo");

		const addRes = addSkillOrSubagent(fakeHome, catalog, "global-path-demo", {
			targets: ["claude", "cursor"],
		});
		expect(addRes.passed).toBe(true);

		const claudeSkillContent = fs.readFileSync(
			path.join(fakeHome, ".claude", "skills", "global-path-demo", "SKILL.md"),
			"utf-8",
		);
		expect(claudeSkillContent).toContain(
			"~/.claude/skills/global-path-demo/scripts/audit_bundle.py",
		);
		expect(claudeSkillContent).toContain(
			"(~/.claude/skills/global-path-demo/references/checklist.md)",
		);
		// Frontmatter entrypoint stays unchanged
		expect(claudeSkillContent).toContain('path: "scripts/audit_bundle.py"');

		const cursorMdcContent = fs.readFileSync(
			path.join(fakeHome, ".cursor", "rules", "skillops-global-path-demo.mdc"),
			"utf-8",
		);
		expect(cursorMdcContent).toContain(
			"~/.cursor/rules/global-path-demo/scripts/audit_bundle.py",
		);
		expect(
			fs.existsSync(
				path.join(
					fakeHome,
					".claude",
					"skills",
					"global-path-demo",
					"evals",
					"evals.json",
				),
			),
		).toBe(false);

		const status = inspectProjectStatus(fakeHome, catalog, {
			targets: ["claude", "cursor"],
		});
		expect(status.passed).toBe(true);
		expect(status.counts.drift_modified).toBe(0);

		const upd = updateInstalledSkills(fakeHome, catalog, {
			targets: ["claude", "cursor"],
		});
		expect(upd.passed).toBe(true);
		expect(upd.drift_conflicts).toEqual([]);
	});

	it("never mutates YAML frontmatter under CRLF or mixed CRLF/LF delimiters", () => {
		const catalog = makeTempDir("skillops-218-crlf-cat-");
		const { skillDir } = buildBundlingCatalogSkill(
			catalog,
			"mixed-eol-demo",
			"mixed",
		);
		const parsed = parseSkillDirectory(skillDir, { requireLayout: true });

		const rewritten = rewriteProgressiveSkillRawText(
			parsed.rawText,
			parsed,
			".claude/skills/mixed-eol-demo",
		);
		const splitIdx = rewritten.indexOf("\n# mixed-eol-demo");
		expect(splitIdx).toBeGreaterThan(0);
		const fmSection = rewritten.slice(0, splitIdx);
		const bodySection = rewritten.slice(splitIdx);

		expect(fmSection).toContain('path: "scripts/audit_bundle.py"');
		expect(fmSection).not.toContain(".claude/skills/mixed-eol-demo");
		expect(bodySection).toContain(
			".claude/skills/mixed-eol-demo/scripts/audit_bundle.py",
		);
	});
});
