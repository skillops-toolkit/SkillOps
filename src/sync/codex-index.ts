import path from "node:path";
import type { ParsedSkillDirectory, ParsedSubagentFile } from "../auditor/parser.js";
import { type CatalogIndex, loadCatalogIndex } from "./catalog-index.js";
import { discoverInstalledArtifactsOnDisk } from "./discovery.js";
import { CODEX_MARKER_END, CODEX_MARKER_START, PACKAGE_CATALOG_DIR } from "./types.js";

/** Neutralize HTML comment sequences and line breaks inside markdown list item fields. */
export function escapeMarkdownHtmlComments(text: string): string {
	return text
		.replace(/<!--/g, "&lt;!--")
		.replace(/-->/g, "--&gt;")
		.replace(/\r?\n+/g, " ")
		.trim();
}

export function renderCodexAgentsIndex(
	existingContent: string | null,
	skills: readonly ParsedSkillDirectory[],
	subagents: readonly ParsedSubagentFile[],
): string {
	const blockLines: string[] = [
		CODEX_MARKER_START,
		"## SkillOps Routed Skills & Context-Isolated Subagents",
		"",
		"### Active Progressive Disclosure Skills",
		...skills.map(
			(s) =>
				`- **\`${escapeMarkdownHtmlComments(s.manifest.name)}\`** (\`.agents/skills/${escapeMarkdownHtmlComments(s.manifest.name)}/SKILL.md\`): ${escapeMarkdownHtmlComments(s.manifest.description)}`,
		),
		"",
		"### Active Context-Isolated Subagents",
		...subagents.map(
			(sa) =>
				`- **\`${escapeMarkdownHtmlComments(sa.manifest.name)}\`** (\`.codex/agents/${escapeMarkdownHtmlComments(sa.manifest.name)}.toml\`, max output \`${sa.manifest.max_output_tokens}\` tokens): ${escapeMarkdownHtmlComments(sa.manifest.description)}`,
		),
		CODEX_MARKER_END,
	];
	const managedBlock = blockLines.join("\n");

	if (!existingContent || !existingContent.trim()) {
		return `# AGENTS.md\n\n${managedBlock}\n`;
	}

	const startIdx = existingContent.indexOf(CODEX_MARKER_START);
	const endIdx =
		startIdx !== -1
			? existingContent.indexOf(
					CODEX_MARKER_END,
					startIdx + CODEX_MARKER_START.length,
				)
			: -1;
	if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
		const before = existingContent.slice(0, startIdx).trimEnd();
		const after = existingContent
			.slice(endIdx + CODEX_MARKER_END.length)
			.trimStart();
		return [before, managedBlock, after].filter(Boolean).join("\n\n") + "\n";
	}

	return `${existingContent.trimEnd()}\n\n${managedBlock}\n`;
}


export function collectInstalledCodexCatalogItems(
	resolvedRepo: string,
	resolvedCatalog: string,
	extraSkill?: ParsedSkillDirectory | null,
	extraSubagent?: ParsedSubagentFile | null,
	catalogIndex?: CatalogIndex,
	excludeItemName?: string,
): {
	skills: ParsedSkillDirectory[];
	subagents: ParsedSubagentFile[];
} {
	const catalogMaps = catalogIndex ?? loadCatalogIndex(resolvedCatalog);
	const builtinMaps =
		path.resolve(resolvedCatalog) !== path.resolve(PACKAGE_CATALOG_DIR)
			? loadCatalogIndex(PACKAGE_CATALOG_DIR)
			: null;
	const discoveredCodex = discoverInstalledArtifactsOnDisk(
		resolvedRepo,
		resolvedCatalog,
		["codex"],
	);
	const skillByName = new Map<string, ParsedSkillDirectory>();
	const subagentByName = new Map<string, ParsedSubagentFile>();
	for (const entry of discoveredCodex) {
		if (excludeItemName && entry.itemName === excludeItemName) {
			continue;
		}
		if (entry.kind === "skill") {
			const parsed =
				catalogMaps.skills.get(entry.itemName) ??
				builtinMaps?.skills.get(entry.itemName);
			if (parsed) {
				skillByName.set(parsed.manifest.name, parsed);
			}
		} else {
			const parsed =
				catalogMaps.subagents.get(entry.itemName) ??
				builtinMaps?.subagents.get(entry.itemName);
			if (parsed) {
				subagentByName.set(parsed.manifest.name, parsed);
			}
		}
	}
	if (extraSkill) {
		skillByName.set(extraSkill.manifest.name, extraSkill);
	}
	if (extraSubagent) {
		subagentByName.set(extraSubagent.manifest.name, extraSubagent);
	}
	const skills = [...skillByName.keys()]
		.sort()
		.map((k) => skillByName.get(k)!);
	const subagents = [...subagentByName.keys()]
		.sort()
		.map((k) => subagentByName.get(k)!);
	return { skills, subagents };
}

export function stripCodexAgentsBlock(existingContent: string): string {
	const startIdx = existingContent.indexOf(CODEX_MARKER_START);
	const endIdx =
		startIdx !== -1
			? existingContent.indexOf(
					CODEX_MARKER_END,
					startIdx + CODEX_MARKER_START.length,
				)
			: -1;
	if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx) {
		return existingContent;
	}
	const before = existingContent.slice(0, startIdx).trimEnd();
	const after = existingContent
		.slice(endIdx + CODEX_MARKER_END.length)
		.trimStart();
	const combined = [before, after].filter(Boolean).join("\n\n").trim();
	if (!combined) {
		return "";
	}
	return `${combined}\n`;
}
