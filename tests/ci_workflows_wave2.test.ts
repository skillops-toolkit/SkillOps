import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

const SHA_PIN_RE = /^[A-Za-z0-9._/-]+@[0-9a-f]{40}$/;

interface WorkflowStep {
	readonly name?: string;
	readonly if?: string;
	readonly uses?: string;
	readonly shell?: string;
	readonly env?: Record<string, string>;
	readonly with?: Record<string, unknown>;
	readonly run?: string;
}

interface WorkflowJob {
	readonly name?: string;
	readonly "runs-on"?: string;
	readonly strategy?: {
		readonly "fail-fast"?: boolean;
		readonly matrix?: Record<string, unknown>;
	};
	readonly steps?: readonly WorkflowStep[];
}

interface WorkflowDocument {
	readonly name?: string;
	readonly jobs?: Record<string, WorkflowJob>;
}

interface CompositeActionDocument {
	readonly name?: string;
	readonly inputs?: Record<string, unknown>;
	readonly runs?: {
		readonly using?: string;
		readonly steps?: readonly WorkflowStep[];
	};
}

interface DependabotUpdateEntry {
	readonly "package-ecosystem"?: string;
	readonly directory?: string;
	readonly schedule?: { readonly interval?: string };
	readonly labels?: readonly string[];
	readonly groups?: Record<string, unknown>;
}

interface DependabotDocument {
	readonly version?: number;
	readonly updates?: readonly DependabotUpdateEntry[];
}

function loadYamlFile<T>(relativePath: string): { raw: string; doc: T } {
	const fullPath = path.join(REPO_ROOT, relativePath);
	const raw = fs.readFileSync(fullPath, "utf-8");
	const doc = parseYaml(raw, {
		maxAliasCount: 0,
		uniqueKeys: true,
	}) as T;
	return { raw, doc };
}

function collectYamlFiles(dirPath: string): string[] {
	const results: string[] = [];
	if (!fs.existsSync(dirPath)) {
		return results;
	}
	for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
		const childPath = path.join(dirPath, entry.name);
		if (entry.isDirectory()) {
			results.push(...collectYamlFiles(childPath));
		} else if (
			entry.isFile() &&
			(entry.name.endsWith(".yml") || entry.name.endsWith(".yaml"))
		) {
			results.push(childPath);
		}
	}
	return results.sort();
}

describe("Wave 1 CI/CD Workflow & Composite Action Hardening (#212)", () => {
	it("isolates composite audit action binary resolution to github.action_path, pins npx fallback, and runs strict audit + dry-run", () => {
		const pkgJson = JSON.parse(
			fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf-8"),
		) as { version: string };

		const { doc } = loadYamlFile<CompositeActionDocument>(
			".github/actions/skillops-audit/action.yml",
		);
		expect(doc.runs?.using).toBe("composite");

		const steps = doc.runs?.steps ?? [];
		expect(steps.length).toBeGreaterThanOrEqual(2);

		const runSteps = steps.filter((step) => typeof step.run === "string");
		expect(runSteps.length).toBeGreaterThanOrEqual(1);

		const combinedRun = runSteps.map((step) => step.run ?? "").join("\n");

		// Never execute ./dist/cli.js from caller $GITHUB_WORKSPACE (CWE-426)
		expect(combinedRun).not.toContain("./dist/cli.js");

		// Verify ACTION_PATH binding via env: and action-relative dist check
		const auditStep = runSteps[0]!;
		expect(auditStep.env?.ACTION_PATH).toBe("${{ github.action_path }}");
		expect(auditStep.env?.INPUT_CATALOG_PATH).toBe("${{ inputs.catalog-path }}");
		expect(auditStep.env?.INPUT_TARGETS).toBe("${{ inputs.targets }}");
		expect(combinedRun).toContain('"${ACTION_PATH}/dist/cli.js"');

		// Every npx skillops-cli fallback must be version-pinned (never unpinned skillops-cli)
		const tokens = combinedRun.split(/[\s()[\]"']+/).filter(Boolean);
		const skillopsCliTokens = tokens.filter((tok) =>
			tok.startsWith("skillops-cli"),
		);
		expect(skillopsCliTokens.length).toBeGreaterThanOrEqual(1);
		for (const tok of skillopsCliTokens) {
			expect(tok).toBe(`skillops-cli@${pkgJson.version}`);
		}

		// Both strict security/layout audit and multi-runtime dry-run transpilation must execute
		expect(combinedRun).toContain(
			'audit --catalog "$INPUT_CATALOG_PATH" --strict',
		);
		expect(combinedRun).toContain(
			'add --all --catalog "$INPUT_CATALOG_PATH" --targets "$INPUT_TARGETS" --dry-run',
		);
	});

	it("hardens npm-publish.yml with --ignore-scripts, npm audit, tag-version guard, strict layout check, and shell-bound token validation", () => {
		const { doc } = loadYamlFile<WorkflowDocument>(
			".github/workflows/npm-publish.yml",
		);
		const job = doc.jobs?.["publish-npm"];
		expect(job).toBeDefined();

		const steps = job?.steps ?? [];
		const allRuns = steps
			.map((step) => step.run ?? "")
			.filter(Boolean)
			.join("\n");

		// 1. Lockfile install disables lifecycle scripts + production vulnerability audit runs
		expect(allRuns).toContain("npm ci --ignore-scripts");
		for (const line of allRuns.split(/\r?\n/)) {
			if (line.trim().startsWith("npm ci")) {
				expect(line.trim()).toBe("npm ci --ignore-scripts");
			}
		}
		expect(allRuns).toContain("npm audit --omit=dev --audit-level=high");

		// 2. Deterministic release tag vs package.json#version guard via env: binding
		const tagStep = steps.find(
			(step) => step.env?.RELEASE_TAG !== undefined,
		);
		expect(tagStep).toBeDefined();
		expect(tagStep?.if).toContain("github.event_name == 'release'");
		expect(tagStep?.env?.RELEASE_TAG).toBe(
			"${{ github.event.release.tag_name }}",
		);
		expect(tagStep?.run).not.toContain("${{");
		expect(tagStep?.run).toContain(
			'v$(node -p "require(\'./package.json\').version")',
		);
		expect(tagStep?.run).toContain("$RELEASE_TAG");

		// 3. Pre-publish catalog gate runs CLI audit --strict AND requireLayout: true + auditCatalogSecurity
		expect(allRuns).toContain("audit --strict");
		expect(allRuns).toContain("parseSkillDirectory");
		expect(allRuns).toContain("requireLayout: true");
		expect(allRuns).not.toContain("requireLayout:false");
		expect(allRuns).not.toContain("requireLayout: false");
		expect(allRuns).toContain("auditCatalogSecurity");

		// 4. Publish step checks secret inside shell rather than broken step-level if: env.NODE_AUTH_TOKEN != ''
		const publishStep = steps.find((step) =>
			(step.run ?? "").includes("npm publish --provenance --access public"),
		);
		expect(publishStep).toBeDefined();
		expect(publishStep?.if).toBeUndefined();
		expect(publishStep?.env?.NPM_TOKEN).toBe("${{ secrets.NPM_TOKEN }}");
		expect(publishStep?.env?.NPM_TOKEN_CHECK).toBe("${{ secrets.NPM_TOKEN }}");
		expect(publishStep?.env?.NODE_AUTH_TOKEN).toBe("${{ secrets.NPM_TOKEN }}");
		expect(publishStep?.run).toContain("${NPM_TOKEN_CHECK:-}");
	});

	it("expands ai-ci.yml across multi-OS runners, runs strict CLI audit, and enforces 3-tuple allowlist matching", () => {
		const { doc } = loadYamlFile<WorkflowDocument>(
			".github/workflows/ai-ci.yml",
		);

		const contractJob = doc.jobs?.["agent-and-skill-contract-gate"];
		expect(contractJob).toBeDefined();
		const contractRuns = (contractJob?.steps ?? [])
			.map((step) => step.run ?? "")
			.join("\n");

		// Verify 3-tuple (rel_posix, rule_id, digest) allowlist signature & rule field lookup
		expect(contractRuns).toContain(
			"def is_allowlisted(rel_posix: str, rule_id: str, digest: str) -> bool:",
		);
		expect(contractRuns).not.toContain(
			"def is_allowlisted(rel_posix: str, digest: str)",
		);
		expect(contractRuns).toContain('entry.get("rule") or entry.get("rule_id")');
		expect(contractRuns).not.toContain("if is_allowlisted(item.as_posix(), digest):");
		expect(contractRuns).not.toContain(
			"if is_allowlisted(py_file.as_posix(), digest):",
		);

		// Verify multi-OS matrix and CLI parity on npx-engine-qa
		const qaJob = doc.jobs?.["npx-engine-qa"];
		expect(qaJob).toBeDefined();
		expect(qaJob?.["runs-on"]).toBe("${{ matrix.os }}");
		expect(qaJob?.strategy?.["fail-fast"]).toBe(false);

		const matrixOs = qaJob?.strategy?.matrix?.os;
		expect(Array.isArray(matrixOs)).toBe(true);
		expect(matrixOs).toEqual(
			expect.arrayContaining([
				"ubuntu-latest",
				"windows-latest",
				"macos-latest",
			]),
		);

		const qaRuns = (qaJob?.steps ?? [])
			.map((step) => step.run ?? "")
			.filter(Boolean)
			.join("\n");
		expect(qaRuns).toContain("npm ci --ignore-scripts");
		for (const line of qaRuns.split(/\r?\n/)) {
			if (line.trim().startsWith("npm ci")) {
				expect(line.trim()).toBe("npm ci --ignore-scripts");
			}
		}
		expect(qaRuns).toContain("npm audit --omit=dev --audit-level=high");

		const buildIdx = qaRuns.indexOf("npm run build");
		const strictAuditIdx = qaRuns.indexOf("node ./dist/cli.js audit --strict");
		expect(buildIdx).toBeGreaterThanOrEqual(0);
		expect(strictAuditIdx).toBeGreaterThan(buildIdx);
	});

	it("configures dependabot.yml for both github-actions and npm with repository labels and update groups", () => {
		const { doc } = loadYamlFile<DependabotDocument>(".github/dependabot.yml");
		expect(doc.version).toBe(2);

		const updates = doc.updates ?? [];
		const gha = updates.find(
			(u) => u["package-ecosystem"] === "github-actions",
		);
		const npmEco = updates.find((u) => u["package-ecosystem"] === "npm");

		expect(gha).toBeDefined();
		expect(gha?.directory).toBe("/");
		expect(gha?.labels).toEqual(
			expect.arrayContaining(["dependencies", "github_actions"]),
		);
		expect(Object.keys(gha?.groups ?? {}).length).toBeGreaterThanOrEqual(1);

		expect(npmEco).toBeDefined();
		expect(npmEco?.directory).toBe("/");
		expect(npmEco?.labels).toContain("dependencies");
		expect(Object.keys(npmEco?.groups ?? {}).length).toBeGreaterThanOrEqual(1);
	});

	it("pins every third-party uses: across .github/ to a 40-char SHA and forbids untrusted expression interpolation in run: blocks", () => {
		const yamlFiles = [
			...collectYamlFiles(path.join(REPO_ROOT, ".github", "workflows")),
			...collectYamlFiles(path.join(REPO_ROOT, ".github", "actions")),
		];
		expect(yamlFiles.length).toBeGreaterThanOrEqual(8);

		for (const filePath of yamlFiles) {
			const relPath = path.relative(REPO_ROOT, filePath).replace(/\\/g, "/");
			const raw = fs.readFileSync(filePath, "utf-8");
			const parsed = parseYaml(raw, {
				maxAliasCount: 0,
				uniqueKeys: true,
			}) as WorkflowDocument & CompositeActionDocument;

			const allSteps: WorkflowStep[] = [];
			if (Array.isArray(parsed.runs?.steps)) {
				allSteps.push(...parsed.runs.steps);
			}
			if (parsed.jobs && typeof parsed.jobs === "object") {
				for (const job of Object.values(parsed.jobs)) {
					if (Array.isArray(job?.steps)) {
						allSteps.push(...job.steps);
					}
				}
			}

			for (const step of allSteps) {
				if (typeof step.uses === "string" && !step.uses.startsWith("./")) {
					expect(
						SHA_PIN_RE.test(step.uses),
						`Expected 40-char SHA pin in ${relPath}, got '${step.uses}'`,
					).toBe(true);
				}
				if (typeof step.run === "string") {
					expect(
						step.run,
						`Untrusted inputs.* interpolation in ${relPath}`,
					).not.toContain("${{ inputs.");
					expect(
						step.run,
						`Untrusted github.event.* interpolation in ${relPath}`,
					).not.toContain("${{ github.event.");
					expect(
						step.run,
						`Untrusted github.head_ref interpolation in ${relPath}`,
					).not.toContain("${{ github.head_ref");
					expect(
						step.run,
						`Untrusted github.ref_name interpolation in ${relPath}`,
					).not.toContain("${{ github.ref_name");
				}
			}
		}
	});
});
