import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	ALL_RUNTIME_TARGETS,
	auditCatalogSecurity,
	discoverSubagentFiles,
	loadCatalogIndex,
	parseSubagentFile,
} from "../src/index.js";
import { renderSubagentFilesForRuntime } from "../src/sync/adapters.js";

const REPO_ROOT = path.resolve(import.meta.dirname, "..");
const CATALOG_ROOT = path.join(REPO_ROOT, "catalog");

describe("Issue #236 Built-in Subagents Expansion (6 Context-Isolated Subagents)", () => {
	it("includes all 6 canonical read-only subagents matching INV-SKILL-04 and zero security findings", () => {
		const subagentFiles = discoverSubagentFiles(CATALOG_ROOT);
		expect(subagentFiles.length).toBe(6);

		const index = loadCatalogIndex(CATALOG_ROOT);
		expect([...index.subagents.keys()].sort()).toEqual([
			"api-contract-verifier",
			"context-scout",
			"dead-code-and-bloat-scout",
			"dependency-supply-chain-auditor",
			"security-diff-reviewer",
			"test-failure-triager",
		]);

		for (const file of subagentFiles) {
			const parsed = parseSubagentFile(file);
			expect(parsed.manifest.context_isolation).toBe(true);
			expect(parsed.manifest.max_output_tokens).toBeLessThanOrEqual(400);
			expect(parsed.manifest.system_prompt_lines).toBeLessThanOrEqual(180);
			expect(parsed.manifest.tools).toEqual(["read", "search"]);

			for (const target of ALL_RUNTIME_TARGETS) {
				const rendered = renderSubagentFilesForRuntime(parsed, target);
				expect(rendered.length).toBeGreaterThanOrEqual(1);
				expect(rendered[0]?.content).toContain("## Tool & Sandbox Constraints");
			}
		}

		const secReport = auditCatalogSecurity(CATALOG_ROOT);
		expect(secReport.findings).toEqual([]);
	});
});
