import YAML from "yaml";
import type { ParsedSubagentFile } from "../../auditor/parser.js";
import { RUNTIME_HARNESS_SPECS, type RuntimeTarget } from "../../models.js";
import { type PlannedFile, trimTrailingSlashes } from "../types.js";

const MUTATING_OR_SHELL_TOOL_NAMES = new Set([
	"write",
	"edit",
	"multiedit",
	"patch",
	"create",
	"delete",
	"rm",
	"bash",
	"sh",
	"shell",
	"exec",
	"terminal",
	"command",
	"run_command",
	"execute",
	"write_file",
	"edit_file",
]);

function isMutatingOrShellTool(toolName: string): boolean {
	const lower = toolName.trim().toLowerCase();
	return (
		MUTATING_OR_SHELL_TOOL_NAMES.has(lower) ||
		lower.includes("write") ||
		lower.includes("edit") ||
		lower.includes("bash") ||
		lower.includes("shell") ||
		lower.includes("exec")
	);
}

function buildSubagentToolConstraintsBlock(
	manifest: ParsedSubagentFile["manifest"],
): string {
	const extManifest = manifest as unknown as {
		readonly tools?: readonly string[];
		readonly disallowed_tools?: readonly string[];
		readonly disallowedTools?: readonly string[];
	};
	const allowedTools = extManifest.tools ?? [];
	const disallowedTools =
		extManifest.disallowed_tools ?? extManifest.disallowedTools ?? [];
	if (allowedTools.length === 0 && disallowedTools.length === 0) {
		return "";
	}

	const lines: string[] = ["## Tool & Sandbox Constraints", ""];
	if (allowedTools.length > 0) {
		lines.push(
			`- **Allowed tools**: ${allowedTools.map((t) => `\`${t}\``).join(", ")}`,
		);
	}
	if (disallowedTools.length > 0) {
		lines.push(
			`- **Disallowed tools**: ${disallowedTools.map((t) => `\`${t}\``).join(", ")}`,
		);
	}
	const hasWriteOrBash = allowedTools.some(isMutatingOrShellTool);
	if (allowedTools.length > 0 && !hasWriteOrBash) {
		lines.push(
			"- **Read-only rule**: File write/edit and shell/bash execution tools are excluded; operate strictly read-only.",
		);
	}
	return lines.join("\n");
}

function appendSubagentToolConstraints(
	promptBody: string,
	manifest: ParsedSubagentFile["manifest"],
): string {
	if (promptBody.includes("## Tool & Sandbox Constraints")) {
		return promptBody;
	}
	const block = buildSubagentToolConstraintsBlock(manifest);
	return block ? `${promptBody}\n\n${block}` : promptBody;
}

export function renderSubagentFilesForRuntime(
	subagent: ParsedSubagentFile,
	target: RuntimeTarget,
): PlannedFile[] {
	const name = subagent.manifest.name;
	const spec = RUNTIME_HARNESS_SPECS[target];
	const promptBody = subagent.systemPromptBody.trim();
	const constrainedBody = appendSubagentToolConstraints(
		promptBody,
		subagent.manifest,
	);
	const extManifest = subagent.manifest as unknown as {
		readonly disallowed_tools?: readonly string[];
		readonly disallowedTools?: readonly string[];
	};
	const disallowedTools =
		extManifest.disallowed_tools ?? extManifest.disallowedTools;
	const fmObj: Record<string, unknown> = {
		name: subagent.manifest.name,
		description: subagent.manifest.description,
		model: "inherit",
		model_tier: subagent.manifest.model_tier,
		tools: subagent.manifest.tools,
		...(disallowedTools && disallowedTools.length > 0
			? { disallowed_tools: disallowedTools }
			: {}),
		max_output_tokens: subagent.manifest.max_output_tokens,
	};
	const fm = YAML.stringify(fmObj).trim();
	const normalizedDoc = `---\n${fm}\n---\n\n${promptBody}\n`;
	const constrainedNormalizedDoc = `---\n${fm}\n---\n\n${constrainedBody}\n`;

	switch (target) {
		case "claude":
		case "antigravity":
		case "codex":
		case "opencode":
			return [
				{
					target,
					itemName: name,
					relativePath: `${spec.subagentsDir}/${name}.md`,
					content: normalizedDoc,
				},
			];

		case "gemini":
		case "amp":
		case "goose":
		case "qwen":
		case "warp":
		case "crush":
			return [
				{
					target,
					itemName: name,
					relativePath: `${spec.subagentsDir}/${name}.md`,
					content: constrainedNormalizedDoc,
				},
			];

		case "factory": {
			const droidFm = YAML.stringify({
				name,
				description: subagent.manifest.description,
				model: "inherit",
				tools: subagent.manifest.tools,
			}).trim();
			return [
				{
					target,
					itemName: name,
					relativePath: `.factory/droids/skillops-agent-${name}.md`,
					content: `---\n${droidFm}\n---\n\n${constrainedBody}\n`,
				},
			];
		}

		case "vibe": {
			const escapedDesc = JSON.stringify(subagent.manifest.description);
			const escapedPrompt = JSON.stringify(constrainedBody);
			const tomlDoc = [
				`name = "${name}"`,
				`description = ${escapedDesc}`,
				`system_prompt = ${escapedPrompt}`,
				"",
			].join("\n");
			return [
				{
					target,
					itemName: name,
					relativePath: `.vibe/agents/skillops-agent-${name}.toml`,
					content: tomlDoc,
				},
			];
		}

		case "copilot":
			return [
				{
					target,
					itemName: name,
					relativePath: `.github/agents/${name}.agent.md`,
					content: normalizedDoc,
				},
			];

		case "cursor": {
			const mdcFm = YAML.stringify({
				description: `[Subagent: ${name}] ${subagent.manifest.description}`,
				alwaysApply: false,
			}).trim();
			return [
				{
					target,
					itemName: name,
					relativePath: `.cursor/rules/skillops-agent-${name}.mdc`,
					content: `---\n${mdcFm}\n---\n\n${constrainedBody}\n`,
				},
			];
		}

		case "continue": {
			const contFm = YAML.stringify({
				name,
				description: subagent.manifest.description,
				invokable: true,
			}).trim();
			return [
				{
					target,
					itemName: name,
					relativePath: `.continue/prompts/skillops-agent-${name}.prompt`,
					content: `---\n${contFm}\n---\n\n${constrainedBody}\n`,
				},
			];
		}

		case "openhands": {
			const ohFm = YAML.stringify({
				name: `agent-${name}`,
				type: "knowledge",
				version: "1.0.0",
				agent: "CodeActAgent",
				triggers: [name, ...subagent.manifest.tags],
			}).trim();
			return [
				{
					target,
					itemName: name,
					relativePath: `.openhands/microagents/skillops-agent-${name}.md`,
					content: `---\n${ohFm}\n---\n\n${constrainedBody}\n`,
				},
			];
		}

		case "amazonq": {
			const qPayload = {
				name,
				description: subagent.manifest.description,
				prompt: constrainedBody,
				tools: subagent.manifest.tools,
				...(disallowedTools && disallowedTools.length > 0
					? { disallowed_tools: disallowedTools }
					: {}),
				max_output_tokens: subagent.manifest.max_output_tokens,
			};
			return [
				{
					target,
					itemName: name,
					relativePath: `.amazonq/cli-agents/skillops-agent-${name}.json`,
					content: `${JSON.stringify(qPayload, null, 2)}\n`,
				},
			];
		}

		case "windsurf":
		case "kiro":
		case "cline":
		case "roocode":
		case "kilocode":
		case "zed":
		case "aider":
		case "trae":
		case "junie":
		case "augment":
		case "idx":
			// Preserve frontmatter tools/disallowedTools and Tool & Sandbox Constraints in Markdown body
			return [
				{
					target,
					itemName: name,
					relativePath: `${spec.subagentsDir}/skillops-agent-${name}.md`,
					content: constrainedNormalizedDoc,
				},
			];
	}
}

