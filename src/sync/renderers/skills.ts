import YAML from "yaml";
import type { ParsedSkillDirectory } from "../../auditor/parser.js";
import { RUNTIME_HARNESS_SPECS, type RuntimeTarget } from "../../models.js";
import { type PlannedFile, trimTrailingSlashes } from "../types.js";
import {
	appendCompanionSkillFiles,
	rewriteBundledSkillPaths,
	rewriteProgressiveSkillRawText,
} from "./companion-paths.js";

export interface RenderSkillOptions {
	readonly globalHome?: boolean;
}

export function renderSkillFilesForRuntime(
	parsed: ParsedSkillDirectory,
	target: RuntimeTarget,
	options: RenderSkillOptions = {},
): PlannedFile[] {
	const name = parsed.manifest.name;
	const spec = RUNTIME_HARNESS_SPECS[target];
	const baseDir = `${spec.skillsDir}/${name}`;
	const companionRootDir = options.globalHome ? `~/${baseDir}` : baseDir;
	const files: PlannedFile[] = [];
	const activeGlobs = parsed.manifest.routing_signals.active_file_globs ?? [];
	const body = rewriteBundledSkillPaths(
		parsed.markdownBody.trim(),
		parsed,
		companionRootDir,
	);

	if (spec.skillFormat === "progressive-skill-dir") {
		files.push({
			target,
			itemName: name,
			relativePath: `${baseDir}/SKILL.md`,
			content: rewriteProgressiveSkillRawText(
				parsed.rawText,
				parsed,
				companionRootDir,
			),
		});
		appendCompanionSkillFiles(files, parsed, target, baseDir);
		return files;
	}

	if (target === "cursor") {
		const mdcFrontmatter = YAML.stringify(
			activeGlobs.length > 0
				? {
						description: parsed.manifest.description,
						globs: activeGlobs,
						alwaysApply: false,
					}
				: {
						description: parsed.manifest.description,
						alwaysApply: false,
					},
		).trim();
		files.push({
			target,
			itemName: name,
			relativePath: `.cursor/rules/skillops-${name}.mdc`,
			content: `---\n${mdcFrontmatter}\n---\n\n${body}\n`,
		});
		appendCompanionSkillFiles(files, parsed, target, baseDir);
		return files;
	}

	if (target === "copilot") {
		const applyTo = activeGlobs.length > 0 ? activeGlobs.join(",") : "**";
		const instrFrontmatter = YAML.stringify({
			applyTo,
			description: parsed.manifest.description,
		}).trim();
		files.push({
			target,
			itemName: name,
			relativePath: `.github/instructions/skillops-${name}.instructions.md`,
			content: `---\n${instrFrontmatter}\n---\n\n${body}\n`,
		});

		const promptFrontmatter = YAML.stringify({
			mode: "agent",
			description: parsed.manifest.description,
		}).trim();
		files.push({
			target,
			itemName: name,
			relativePath: `.github/prompts/skillops-${name}.prompt.md`,
			content: `---\n${promptFrontmatter}\n---\n\n${body}\n`,
		});
		appendCompanionSkillFiles(files, parsed, target, baseDir);
		return files;
	}

	if (target === "windsurf") {
		const wsFrontmatter = YAML.stringify(
			activeGlobs.length > 0
				? {
						trigger: "glob",
						description: parsed.manifest.description,
						globs: activeGlobs,
					}
				: {
						trigger: "model_decision",
						description: parsed.manifest.description,
					},
		).trim();
		files.push({
			target,
			itemName: name,
			relativePath: `.windsurf/rules/skillops-${name}.md`,
			content: `---\n${wsFrontmatter}\n---\n\n${body}\n`,
		});
		appendCompanionSkillFiles(files, parsed, target, baseDir);
		return files;
	}

	if (target === "openhands") {
		const ohFrontmatter = YAML.stringify({
			name,
			type: "knowledge",
			version: parsed.manifest.version,
			agent: "CodeActAgent",
			triggers: parsed.manifest.tags,
		}).trim();
		files.push({
			target,
			itemName: name,
			relativePath: `.openhands/microagents/skillops-${name}.md`,
			content: `---\n${ohFrontmatter}\n---\n\n${body}\n`,
		});
		appendCompanionSkillFiles(files, parsed, target, baseDir);
		return files;
	}

	if (target === "kiro") {
		const kiroFrontmatter = YAML.stringify(
			activeGlobs.length > 0
				? {
						inclusion: "fileMatch",
						fileMatchPattern: activeGlobs.join(","),
						description: parsed.manifest.description,
					}
				: {
						inclusion: "auto",
						description: parsed.manifest.description,
					},
		).trim();
		files.push({
			target,
			itemName: name,
			relativePath: `.kiro/steering/skillops-${name}.md`,
			content: `---\n${kiroFrontmatter}\n---\n\n${body}\n`,
		});
		appendCompanionSkillFiles(files, parsed, target, baseDir);
		return files;
	}

	if (target === "augment") {
		const augFrontmatter = YAML.stringify({
			type: "agent_requested",
			description: parsed.manifest.description,
		}).trim();
		files.push({
			target,
			itemName: name,
			relativePath: `.augment/rules/skillops-${name}.md`,
			content: `---\n${augFrontmatter}\n---\n\n${body}\n`,
		});
		appendCompanionSkillFiles(files, parsed, target, baseDir);
		return files;
	}

	// Remaining markdown-rule harnesses: cline, roocode, kilocode, zed, continue, aider, trae, amazonq, junie, idx
	const ruleFrontmatter = YAML.stringify({
		name,
		description: parsed.manifest.description,
		track: parsed.manifest.track,
		tags: parsed.manifest.tags,
		...(activeGlobs.length > 0 ? { globs: activeGlobs } : {}),
		alwaysApply: false,
	}).trim();
	files.push({
		target,
		itemName: name,
		relativePath: `${spec.skillsDir}/skillops-${name}.md`,
		content: `---\n${ruleFrontmatter}\n---\n\n${body}\n`,
	});
	appendCompanionSkillFiles(files, parsed, target, baseDir);

	return files;
}

