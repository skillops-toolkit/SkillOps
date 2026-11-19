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

const CLAUDE_TOOL_MAP: Readonly<Record<string, readonly string[]>> = {
	read: ["Read"],
	search: ["Grep", "Glob"],
	grep: ["Grep"],
	glob: ["Glob"],
	edit: ["Edit"],
	write: ["Write"],
	bash: ["Bash"],
	shell: ["Bash"],
	webfetch: ["WebFetch"],
	websearch: ["WebSearch"],
};

const COPILOT_TOOL_MAP: Readonly<Record<string, readonly string[]>> = {
	read: ["search"],
	search: ["search", "usages"],
	grep: ["search"],
	glob: ["search"],
	edit: ["edit"],
	write: ["edit"],
	bash: ["runCommands"],
	shell: ["runCommands"],
};

/**
 * Translate canonical SkillOps tool vocabulary (`read`, `search`, `edit`, `write`, `bash`)
 * into vendor-native tool identifiers for Claude Code, GitHub Copilot, and peer harnesses.
 */
export function mapCanonicalToolsToRuntime(
	tools: readonly string[],
	target: RuntimeTarget,
): string[] {
	const mapped: string[] = [];
	const seen = new Set<string>();
	const pushUnique = (val: string): void => {
		if (val && !seen.has(val)) {
			seen.add(val);
			mapped.push(val);
		}
	};

	for (const rawTool of tools) {
		const trimmed = rawTool.trim();
		if (!trimmed) continue;
		const key = trimmed.toLowerCase();
		if (target === "claude") {
			const nativeTools = CLAUDE_TOOL_MAP[key];
			if (nativeTools) {
				for (const t of nativeTools) pushUnique(t);
			} else {
				pushUnique(trimmed);
			}
		} else if (target === "copilot") {
			const nativeTools = COPILOT_TOOL_MAP[key];
			if (nativeTools) {
				for (const t of nativeTools) pushUnique(t);
			} else {
				pushUnique(trimmed);
			}
		} else {
			pushUnique(trimmed);
		}
	}
	return mapped;
}

/**
 * Encode a JavaScript UTF-16 string as a strict TOML v1.0 basic string, escaping `U+007F`
 * and emitting UTF-32 `\UXXXXXXXX` sequences for astral plane characters instead of UTF-16 surrogates.
 */
export function encodeTomlBasicString(value: string): string {
	let out = '"';
	for (const ch of value) {
		const cp = ch.codePointAt(0) ?? 0;
		switch (cp) {
			case 0x08:
				out += "\\b";
				break;
			case 0x09:
				out += "\\t";
				break;
			case 0x0a:
				out += "\\n";
				break;
			case 0x0c:
				out += "\\f";
				break;
			case 0x0d:
				out += "\\r";
				break;
			case 0x22:
				out += '\\"';
				break;
			case 0x5c:
				out += "\\\\";
				break;
			default:
				if (cp < 0x20 || cp === 0x7f) {
					out += `\\u${cp.toString(16).toUpperCase().padStart(4, "0")}`;
				} else if (cp > 0xffff) {
					out += `\\U${cp.toString(16).toUpperCase().padStart(8, "0")}`;
				} else {
					out += ch;
				}
				break;
		}
	}
	out += '"';
	return out;
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
		tools: mapCanonicalToolsToRuntime(subagent.manifest.tools, target),
		...(disallowedTools && disallowedTools.length > 0
			? {
					disallowed_tools: mapCanonicalToolsToRuntime(
						disallowedTools,
						target,
					),
				}
			: {}),
		max_output_tokens: subagent.manifest.max_output_tokens,
	};
	const fm = YAML.stringify(fmObj).trim();
	const constrainedNormalizedDoc = `---\n${fm}\n---\n\n${constrainedBody}\n`;

	switch (target) {
		case "claude": {
			const claudeTools = mapCanonicalToolsToRuntime(
				subagent.manifest.tools,
				"claude",
			);
			const claudeDisallowed =
				disallowedTools && disallowedTools.length > 0
					? mapCanonicalToolsToRuntime(disallowedTools, "claude")
					: undefined;
			const claudeFm = YAML.stringify({
				name: subagent.manifest.name,
				description: subagent.manifest.description,
				model: "inherit",
				tools: claudeTools,
				...(claudeDisallowed && claudeDisallowed.length > 0
					? { disallowedTools: claudeDisallowed }
					: {}),
			}).trim();
			return [
				{
					target,
					itemName: name,
					relativePath: `${spec.subagentsDir}/${name}.md`,
					content: `---\n${claudeFm}\n---\n\n${constrainedBody}\n`,
				},
			];
		}

		case "codex": {
			const hasWriteOrShell = subagent.manifest.tools.some(isMutatingOrShellTool);
			const reasoningEffort =
				subagent.manifest.model_tier === "fast"
					? "low"
					: subagent.manifest.model_tier === "reasoning"
						? "high"
						: "medium";
			const codexToml = [
				`name = ${encodeTomlBasicString(name)}`,
				`description = ${encodeTomlBasicString(subagent.manifest.description)}`,
				`model_reasoning_effort = ${encodeTomlBasicString(reasoningEffort)}`,
				`sandbox_mode = ${encodeTomlBasicString(hasWriteOrShell ? "workspace-write" : "read-only")}`,
				`developer_instructions = ${encodeTomlBasicString(constrainedBody)}`,
				"",
			].join("\n");
			return [
				{
					target,
					itemName: name,
					relativePath: `${spec.subagentsDir}/${name}.toml`,
					content: codexToml,
				},
			];
		}

		case "antigravity":
		case "opencode":
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
				tools: mapCanonicalToolsToRuntime(subagent.manifest.tools, target),
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
			const escapedDesc = encodeTomlBasicString(subagent.manifest.description);
			const escapedPrompt = encodeTomlBasicString(constrainedBody);
			const tomlDoc = [
				`name = ${encodeTomlBasicString(name)}`,
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

		case "copilot": {
			const copilotTools = mapCanonicalToolsToRuntime(
				subagent.manifest.tools,
				"copilot",
			);
			const copilotFm = YAML.stringify({
				name: subagent.manifest.name,
				description: subagent.manifest.description,
				tools: copilotTools,
			}).trim();
			return [
				{
					target,
					itemName: name,
					relativePath: `.github/agents/${name}.agent.md`,
					content: `---\n${copilotFm}\n---\n\n${constrainedBody}\n`,
				},
			];
		}

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

