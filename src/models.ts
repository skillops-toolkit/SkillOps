/**
 * Normative Zod v4 schemas and TypeScript domain contracts for the SkillOps NPX Engine.
 *
 * Enforces INV-SKILL-01 through INV-SKILL-05 for both Hybrid Executable Skills (SKILL.md)
 * and Context-Isolated Subagents (SUBAGENT.md / *.agent.md), as well as Token Economy
 * telemetry and Multi-Runtime Transpilation lockfiles.
 */

import YAML from "yaml";
import { z } from "zod";
import { detectInstalledHarnesses } from "./io/bounded-fs.js";

export {
	detectInstalledHarnesses,
	loadSkillOpsConfig,
	loadSkillOpsConfigFromDisk,
	MAX_COMPANION_OR_LOCK_BYTES,
	MAX_CONFIG_FILE_BYTES,
	MAX_MANIFEST_FILE_BYTES,
	parseSkillMdFile,
	parseSubagentMdFile,
	readBoundedUtf8File,
} from "./io/bounded-fs.js";

export const SKILLOPS_VERSION = "1.5.2";
export const MAX_LOCKFILE_ARTIFACTS = 4096;

const MAX_RAW_MANIFEST_BYTES = 256 * 1024;
const MAX_RAW_CONFIG_BYTES = 64 * 1024;
const MAX_INPUT_PATH_CHARS = 256 * 1024;

const SKILL_NAME_REGEX = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SEMVER_REGEX = /^\d+\.\d+\.\d+$/;
const FRONTMATTER_REGEX = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;
const WORD_REGEX = /\S+/g;
const PUNCT_CODE_REGEX = /[{}[\]()<>:;,.=`~@#$%^&*|\\/]/g;

const FORBIDDEN_PROTOTYPE_SEGMENTS = new Set<string>([
	"__proto__",
	"constructor",
	"prototype",
]);

const WINDOWS_RESERVED_DEVICE_STEMS = new Set<string>([
	"CON",
	"PRN",
	"AUX",
	"NUL",
	"CONIN$",
	"CONOUT$",
	"COM1",
	"COM2",
	"COM3",
	"COM4",
	"COM5",
	"COM6",
	"COM7",
	"COM8",
	"COM9",
	"COM\u00B9",
	"COM\u00B2",
	"COM\u00B3",
	"LPT1",
	"LPT2",
	"LPT3",
	"LPT4",
	"LPT5",
	"LPT6",
	"LPT7",
	"LPT8",
	"LPT9",
	"LPT\u00B9",
	"LPT\u00B2",
	"LPT\u00B3",
]);

function hasForbiddenOwnPrototypeKey(obj: object): boolean {
	return (
		Object.hasOwn(obj, "__proto__") ||
		Object.hasOwn(obj, "constructor") ||
		Object.hasOwn(obj, "prototype")
	);
}

/**
 * Validate a single path segment across POSIX and Windows filesystems in O(n) time.
 * Rejects empty, '.', '..', prototype-polluting keys, segments ending in '.' or ' ',
 * control characters, colons/separators/wildcards, and Windows reserved device stems
 * (including superscript COM/LPT variants and device names followed by extensions like 'CON.md').
 */
export function isSafeCrossPlatformPathSegment(segment: string): boolean {
	if (
		typeof segment !== "string" ||
		segment.length === 0 ||
		segment.length > 255
	) {
		return false;
	}
	if (
		segment === "." ||
		segment === ".." ||
		FORBIDDEN_PROTOTYPE_SEGMENTS.has(segment)
	) {
		return false;
	}
	if (segment.endsWith(".") || segment.endsWith(" ")) {
		return false;
	}

	for (let i = 0; i < segment.length; i += 1) {
		const code = segment.charCodeAt(i);
		if (
			code <= 0x1f ||
			code === 0x7f ||
			(code >= 0x80 && code <= 0x9f) ||
			code === 0x2f || // '/'
			code === 0x5c || // '\\'
			code === 0x3a || // ':'
			code === 0x3c || // '<'
			code === 0x3e || // '>'
			code === 0x22 || // '"'
			code === 0x7c || // '|'
			code === 0x3f || // '?'
			code === 0x2a // '*'
		) {
			return false;
		}
	}

	const dotIndex = segment.indexOf(".");
	const rawStem = dotIndex === -1 ? segment : segment.slice(0, dotIndex);
	let stemEnd = rawStem.length;
	while (stemEnd > 0 && rawStem.charCodeAt(stemEnd - 1) === 0x20) {
		stemEnd -= 1;
	}
	if (stemEnd > 0) {
		const normalizedStem = rawStem.slice(0, stemEnd).toUpperCase();
		if (WINDOWS_RESERVED_DEVICE_STEMS.has(normalizedStem)) {
			return false;
		}
	}

	return true;
}

/**
 * Deterministically strip trailing forward slashes in O(n) time without polynomial backtracking.
 */
export function trimTrailingSlashes(value: string): string {
	let end = value.length;
	while (end > 0 && value[end - 1] === "/") {
		end -= 1;
	}
	return end === value.length ? value : value.slice(0, end);
}

/**
 * Deterministically strip leading and trailing forward slashes in O(n) time.
 */
function trimSlashes(value: string): string {
	let start = 0;
	while (start < value.length && value[start] === "/") {
		start += 1;
	}
	return trimTrailingSlashes(value.slice(start));
}

/**
 * Count whitespace-delimited words in text.
 */
export function countWords(text: string): number {
	const matches = text.match(WORD_REGEX);
	return matches ? matches.length : 0;
}

/**
 * Deterministic zero-API token count estimator matching SKILL_CONTRACT.md.
 */
export function estimateTokenCount(text: string): number {
	const stripped = text.trim();
	if (!stripped) {
		return 0;
	}
	const words = countWords(stripped);
	const punctBonus = Math.floor(
		(stripped.match(PUNCT_CODE_REGEX)?.length ?? 0) / 4,
	);
	return Math.max(1, Math.ceil(words * 1.33) + punctBonus);
}

/**
 * Split a Markdown document into [frontmatterDict, markdownBody] with YAML alias amplification disabled.
 */
export function splitFrontmatter(
	rawText: string,
	sourceLabel: string,
): [Record<string, unknown>, string] {
	if (Buffer.byteLength(rawText, "utf-8") > MAX_RAW_MANIFEST_BYTES) {
		throw new Error(
			`Security violation: Document at '${sourceLabel}' exceeds maximum manifest size of ${MAX_RAW_MANIFEST_BYTES} bytes.`,
		);
	}
	const match = FRONTMATTER_REGEX.exec(rawText);
	if (!match) {
		throw new Error(
			`Document at '${sourceLabel}' is missing valid YAML frontmatter delimited by '---'.`,
		);
	}
	const yamlText = match[1] ?? "";
	const body = match[2] ?? "";
	const parsed: unknown = YAML.parse(yamlText, {
		maxAliasCount: 0,
		uniqueKeys: true,
	});
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error(
			`YAML frontmatter in '${sourceLabel}' must evaluate to a key-value mapping.`,
		);
	}
	if (hasForbiddenOwnPrototypeKey(parsed)) {
		throw new Error(
			`Security violation: YAML frontmatter in '${sourceLabel}' contains forbidden prototype keys.`,
		);
	}
	return [parsed as Record<string, unknown>, body];
}

export const ExitCode = {
	SUCCESS: 0,
	ERROR: 1,
	COLLISION_ERROR: 2,
	BUDGET_OR_CONTRACT_ERROR: 3,
	EVAL_REGRESSION_ERROR: 4,
	SECURITY_BOUNDARY_ERROR: 5,
} as const;
export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode];

export const CatalogTrackSchema = z.enum([
	"ai-engineering",
	"python-backend",
	"arch-quality",
	"token-economy",
]);
export type CatalogTrack = z.infer<typeof CatalogTrackSchema>;

export const RuntimeTargetSchema = z.enum([
	"claude",
	"antigravity",
	"cursor",
	"codex",
	"copilot",
	"windsurf",
	"cline",
	"roocode",
	"kilocode",
	"zed",
	"continue",
	"aider",
	"openhands",
	"amp",
	"goose",
	"opencode",
	"kiro",
	"trae",
	"amazonq",
	"junie",
	"gemini",
	"factory",
	"qwen",
	"augment",
	"vibe",
	"warp",
	"crush",
	"idx",
]);
export type RuntimeTarget = z.infer<typeof RuntimeTargetSchema>;

export const CORE_RUNTIME_TARGETS: readonly RuntimeTarget[] = [
	"claude",
	"antigravity",
	"cursor",
	"codex",
	"copilot",
];

export const ALL_RUNTIME_TARGETS: readonly RuntimeTarget[] = [
	"claude",
	"antigravity",
	"cursor",
	"codex",
	"copilot",
	"windsurf",
	"cline",
	"roocode",
	"kilocode",
	"zed",
	"continue",
	"aider",
	"openhands",
	"amp",
	"goose",
	"opencode",
	"kiro",
	"trae",
	"amazonq",
	"junie",
	"gemini",
	"factory",
	"qwen",
	"augment",
	"vibe",
	"warp",
	"crush",
	"idx",
];

export type HarnessCategory =
	| "cli-agent"
	| "ai-ide"
	| "ide-extension"
	| "autonomous-swe";
export type HarnessSkillFormat =
	| "progressive-skill-dir"
	| "mdc-rule"
	| "copilot-instructions"
	| "markdown-rule"
	| "openhands-microagent"
	| "kiro-steering";

export interface RuntimeHarnessSpec {
	readonly id: RuntimeTarget;
	readonly displayName: string;
	readonly vendor: string;
	readonly category: HarnessCategory;
	readonly skillFormat: HarnessSkillFormat;
	readonly skillsDir: string;
	readonly subagentsDir: string;
	readonly detectionPaths: readonly string[];
	readonly alwaysOnFiles: readonly string[];
	readonly mcpConfigPath: string | null;
	readonly supportsMcp: boolean;
}

export const RUNTIME_HARNESS_SPECS: Readonly<
	Record<RuntimeTarget, RuntimeHarnessSpec>
> = {
	claude: {
		id: "claude",
		displayName: "Anthropic Claude Code",
		vendor: "Anthropic",
		category: "cli-agent",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".claude/skills",
		subagentsDir: ".claude/agents",
		detectionPaths: [".claude", "CLAUDE.md", ".mcp.json"],
		alwaysOnFiles: ["CLAUDE.md", ".claude/CLAUDE.md"],
		mcpConfigPath: ".mcp.json",
		supportsMcp: true,
	},
	antigravity: {
		id: "antigravity",
		displayName: "Google Antigravity IDE",
		vendor: "Google DeepMind",
		category: "ai-ide",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".agent/skills",
		subagentsDir: ".agent/agents",
		detectionPaths: [".agent", "GEMINI.md"],
		alwaysOnFiles: ["GEMINI.md"],
		mcpConfigPath: ".agent/mcp_config.json",
		supportsMcp: true,
	},
	cursor: {
		id: "cursor",
		displayName: "Cursor AI IDE",
		vendor: "Anysphere",
		category: "ai-ide",
		skillFormat: "mdc-rule",
		skillsDir: ".cursor/rules",
		subagentsDir: ".cursor/rules",
		detectionPaths: [".cursor", ".cursorrules"],
		alwaysOnFiles: [".cursorrules"],
		mcpConfigPath: ".cursor/mcp.json",
		supportsMcp: true,
	},
	codex: {
		id: "codex",
		displayName: "OpenAI Codex CLI",
		vendor: "OpenAI",
		category: "cli-agent",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".codex/skills",
		subagentsDir: ".codex/agents",
		detectionPaths: [".codex", "AGENTS.md"],
		alwaysOnFiles: ["AGENTS.md"],
		mcpConfigPath: ".codex/config.toml",
		supportsMcp: true,
	},
	copilot: {
		id: "copilot",
		displayName: "GitHub Copilot",
		vendor: "GitHub / Microsoft",
		category: "ide-extension",
		skillFormat: "copilot-instructions",
		skillsDir: ".github/instructions",
		subagentsDir: ".github/agents",
		detectionPaths: [
			".github/copilot-instructions.md",
			".github/instructions",
			".github/prompts",
			".github/agents",
		],
		alwaysOnFiles: [".github/copilot-instructions.md"],
		mcpConfigPath: ".vscode/mcp.json",
		supportsMcp: true,
	},
	windsurf: {
		id: "windsurf",
		displayName: "Windsurf AI IDE",
		vendor: "Codeium / Windsurf",
		category: "ai-ide",
		skillFormat: "markdown-rule",
		skillsDir: ".windsurf/rules",
		subagentsDir: ".windsurf/workflows",
		detectionPaths: [".windsurf", ".windsurfrules"],
		alwaysOnFiles: [".windsurfrules"],
		mcpConfigPath: null,
		supportsMcp: false,
	},
	cline: {
		id: "cline",
		displayName: "Cline Autonomous Coding Agent",
		vendor: "Cline",
		category: "ide-extension",
		skillFormat: "markdown-rule",
		skillsDir: ".clinerules",
		subagentsDir: ".clinerules/workflows",
		detectionPaths: [".clinerules", ".cline"],
		alwaysOnFiles: [".clinerules"],
		mcpConfigPath: null,
		supportsMcp: false,
	},
	roocode: {
		id: "roocode",
		displayName: "Roo Code",
		vendor: "Roo Veterinary",
		category: "ide-extension",
		skillFormat: "markdown-rule",
		skillsDir: ".roo/rules",
		subagentsDir: ".roo/rules-architect",
		detectionPaths: [".roo", ".roorules", ".roomodes"],
		alwaysOnFiles: [".roorules"],
		mcpConfigPath: ".roo/mcp.json",
		supportsMcp: true,
	},
	kilocode: {
		id: "kilocode",
		displayName: "Kilo Code",
		vendor: "Kilo Org",
		category: "ide-extension",
		skillFormat: "markdown-rule",
		skillsDir: ".kilocode/rules",
		subagentsDir: ".kilocode/workflows",
		detectionPaths: [".kilocode", ".kilocoderules", ".kilocodemodes"],
		alwaysOnFiles: [".kilocoderules"],
		mcpConfigPath: ".kilocode/mcp.json",
		supportsMcp: true,
	},
	zed: {
		id: "zed",
		displayName: "Zed AI",
		vendor: "Zed Industries",
		category: "ai-ide",
		skillFormat: "markdown-rule",
		skillsDir: ".zed/rules",
		subagentsDir: ".zed/rules",
		detectionPaths: [".zed", ".rules"],
		alwaysOnFiles: [".rules"],
		mcpConfigPath: ".zed/settings.json",
		supportsMcp: true,
	},
	continue: {
		id: "continue",
		displayName: "Continue.dev",
		vendor: "Continue",
		category: "ide-extension",
		skillFormat: "markdown-rule",
		skillsDir: ".continue/rules",
		subagentsDir: ".continue/prompts",
		detectionPaths: [".continue", ".continuerules"],
		alwaysOnFiles: [".continuerules"],
		mcpConfigPath: ".continue/mcpServers/skillops.yaml",
		supportsMcp: true,
	},
	aider: {
		id: "aider",
		displayName: "Aider AI Pair Programmer",
		vendor: "Aider",
		category: "cli-agent",
		skillFormat: "markdown-rule",
		skillsDir: ".aider/conventions",
		subagentsDir: ".aider/conventions",
		detectionPaths: [".aider", ".aider.conf.yml", "CONVENTIONS.md"],
		alwaysOnFiles: ["CONVENTIONS.md"],
		mcpConfigPath: null,
		supportsMcp: false,
	},
	openhands: {
		id: "openhands",
		displayName: "OpenHands (All Hands AI)",
		vendor: "All Hands AI",
		category: "autonomous-swe",
		skillFormat: "openhands-microagent",
		skillsDir: ".openhands/microagents",
		subagentsDir: ".openhands/microagents",
		detectionPaths: [".openhands"],
		alwaysOnFiles: [".openhands/microagents/repo.md"],
		mcpConfigPath: null,
		supportsMcp: false,
	},
	amp: {
		id: "amp",
		displayName: "Sourcegraph Amp",
		vendor: "Sourcegraph",
		category: "cli-agent",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".amp/skills",
		subagentsDir: ".amp/agents",
		detectionPaths: [".amp", "AGENT.md"],
		alwaysOnFiles: ["AGENT.md"],
		mcpConfigPath: ".amp/settings.json",
		supportsMcp: true,
	},
	goose: {
		id: "goose",
		displayName: "Block Goose",
		vendor: "Block",
		category: "cli-agent",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".goose/skills",
		subagentsDir: ".goose/agents",
		detectionPaths: [".goose", ".goosehints"],
		alwaysOnFiles: [".goosehints"],
		mcpConfigPath: null,
		supportsMcp: false,
	},
	opencode: {
		id: "opencode",
		displayName: "OpenCode CLI",
		vendor: "SST / OpenCode",
		category: "cli-agent",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".opencode/skills",
		subagentsDir: ".opencode/agent",
		detectionPaths: [".opencode", "opencode.json"],
		alwaysOnFiles: [],
		mcpConfigPath: "opencode.json",
		supportsMcp: true,
	},
	kiro: {
		id: "kiro",
		displayName: "AWS Kiro IDE",
		vendor: "Amazon Web Services",
		category: "ai-ide",
		skillFormat: "kiro-steering",
		skillsDir: ".kiro/steering",
		subagentsDir: ".kiro/agents",
		detectionPaths: [".kiro"],
		alwaysOnFiles: [
			".kiro/steering/product.md",
			".kiro/steering/tech.md",
			".kiro/steering/structure.md",
		],
		mcpConfigPath: ".kiro/settings/mcp.json",
		supportsMcp: true,
	},
	trae: {
		id: "trae",
		displayName: "Trae AI IDE",
		vendor: "ByteDance / Trae",
		category: "ai-ide",
		skillFormat: "markdown-rule",
		skillsDir: ".trae/rules",
		subagentsDir: ".trae/agents",
		detectionPaths: [".trae"],
		alwaysOnFiles: [".trae/rules/project_rules.md"],
		mcpConfigPath: null,
		supportsMcp: false,
	},
	amazonq: {
		id: "amazonq",
		displayName: "Amazon Q Developer",
		vendor: "Amazon Web Services",
		category: "ide-extension",
		skillFormat: "markdown-rule",
		skillsDir: ".amazonq/rules",
		subagentsDir: ".amazonq/cli-agents",
		detectionPaths: [".amazonq"],
		alwaysOnFiles: [],
		mcpConfigPath: ".amazonq/mcp.json",
		supportsMcp: true,
	},
	junie: {
		id: "junie",
		displayName: "JetBrains Junie / AI Assistant",
		vendor: "JetBrains",
		category: "ide-extension",
		skillFormat: "markdown-rule",
		skillsDir: ".junie/skills",
		subagentsDir: ".junie/agents",
		detectionPaths: [".junie", ".aiassistant"],
		alwaysOnFiles: [".junie/guidelines.md"],
		mcpConfigPath: null,
		supportsMcp: false,
	},
	gemini: {
		id: "gemini",
		displayName: "Google Gemini CLI",
		vendor: "Google",
		category: "cli-agent",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".gemini/skills",
		subagentsDir: ".gemini/agents",
		detectionPaths: [".gemini", "GEMINI.md"],
		alwaysOnFiles: ["GEMINI.md", ".gemini/GEMINI.md", ".gemini/STYLEGUIDE.md"],
		mcpConfigPath: ".gemini/settings.json",
		supportsMcp: true,
	},
	factory: {
		id: "factory",
		displayName: "Factory AI Droid",
		vendor: "Factory AI",
		category: "cli-agent",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".factory/skills",
		subagentsDir: ".factory/droids",
		detectionPaths: [".factory"],
		alwaysOnFiles: ["AGENTS.md", ".factory/instructions.md"],
		mcpConfigPath: ".factory/mcp.json",
		supportsMcp: true,
	},
	qwen: {
		id: "qwen",
		displayName: "Qwen Code CLI",
		vendor: "Alibaba Cloud / Qwen",
		category: "cli-agent",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".qwen/skills",
		subagentsDir: ".qwen/agents",
		detectionPaths: [".qwen", "QWEN.md"],
		alwaysOnFiles: ["QWEN.md", "AGENTS.md"],
		mcpConfigPath: ".qwen/settings.json",
		supportsMcp: true,
	},
	augment: {
		id: "augment",
		displayName: "Augment Code",
		vendor: "Augment",
		category: "ide-extension",
		skillFormat: "markdown-rule",
		skillsDir: ".augment/rules",
		subagentsDir: ".augment/agents",
		detectionPaths: [".augment", ".augment-guidelines"],
		alwaysOnFiles: [".augment-guidelines", "AGENTS.md"],
		mcpConfigPath: ".augment/settings.json",
		supportsMcp: true,
	},
	vibe: {
		id: "vibe",
		displayName: "Mistral Vibe CLI",
		vendor: "Mistral AI",
		category: "cli-agent",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".vibe/skills",
		subagentsDir: ".vibe/agents",
		detectionPaths: [".vibe"],
		alwaysOnFiles: [".vibe/config.toml", "AGENTS.md"],
		mcpConfigPath: ".vibe/config.toml",
		supportsMcp: true,
	},
	warp: {
		id: "warp",
		displayName: "Warp AI Terminal",
		vendor: "Warp",
		category: "cli-agent",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".warp/skills",
		subagentsDir: ".warp/agents",
		detectionPaths: [".warp", "WARP.md"],
		alwaysOnFiles: ["WARP.md", "AGENTS.md"],
		mcpConfigPath: null,
		supportsMcp: false,
	},
	crush: {
		id: "crush",
		displayName: "Charmbracelet Crush",
		vendor: "Charmbracelet",
		category: "cli-agent",
		skillFormat: "progressive-skill-dir",
		skillsDir: ".crush/skills",
		subagentsDir: ".crush/agents",
		detectionPaths: [".crush", ".crush.json", "CRUSH.md"],
		alwaysOnFiles: ["CRUSH.md", "AGENTS.md"],
		mcpConfigPath: ".crush.json",
		supportsMcp: true,
	},
	idx: {
		id: "idx",
		displayName: "Firebase Studio (Project IDX)",
		vendor: "Google",
		category: "ai-ide",
		skillFormat: "markdown-rule",
		skillsDir: ".idx/rules",
		subagentsDir: ".idx/agents",
		detectionPaths: [".idx"],
		alwaysOnFiles: [".idx/airules.md", "GEMINI.md"],
		mcpConfigPath: ".idx/mcp.json",
		supportsMcp: true,
	},
};

/**
 * Resolve runtime target specifications (`"all"`, `"auto"`, `"core"`, or comma-separated target names)
 * into a deduplicated, validated list of `RuntimeTarget` values.
 */
export function resolveRuntimeTargets(
	rawSpec?: string | readonly string[],
	repoPath?: string,
	fallbackTargets: readonly RuntimeTarget[] = CORE_RUNTIME_TARGETS,
): RuntimeTarget[] {
	if (!rawSpec) {
		return [...fallbackTargets];
	}
	const tokens = (Array.isArray(rawSpec) ? rawSpec : [rawSpec])
		.flatMap((item) => String(item).split(","))
		.map((s) => s.trim().toLowerCase())
		.filter(Boolean);

	if (tokens.length === 0) {
		return [...fallbackTargets];
	}

	const resolved: RuntimeTarget[] = [];
	const pushUnique = (target: RuntimeTarget): void => {
		if (!resolved.includes(target)) {
			resolved.push(target);
		}
	};

	for (const token of tokens) {
		if (
			token === "all" ||
			token === "*" ||
			token === "top20" ||
			token === "top28"
		) {
			for (const t of ALL_RUNTIME_TARGETS) {
				pushUnique(t);
			}
		} else if (token === "core" || token === "default") {
			for (const t of CORE_RUNTIME_TARGETS) {
				pushUnique(t);
			}
		} else if (token === "auto") {
			const detected = repoPath ? detectInstalledHarnesses(repoPath) : [];
			const autoList = detected.length > 0 ? detected : fallbackTargets;
			for (const t of autoList) {
				pushUnique(t);
			}
		} else {
			pushUnique(RuntimeTargetSchema.parse(token));
		}
	}

	return resolved;
}

// ---------------------------------------------------------------------------
// Cross-Platform Lockfile & Harness Boundary Validators
// ---------------------------------------------------------------------------

/**
 * Validate that a lockfile or repository-relative POSIX path cannot escape the repository,
 * reference Windows reserved device stems, or pollute Object.prototype.
 */
export function isSafeLockRelativePath(value: string): boolean {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > 1024 ||
		value.startsWith("/") ||
		value.startsWith("\\") ||
		value.endsWith("/") ||
		value.includes("\0") ||
		value.includes("\\") ||
		value.includes(":")
	) {
		return false;
	}
	const segments = value.split("/");
	if (segments.length === 0 || segments.length > 64) {
		return false;
	}
	for (const segment of segments) {
		if (!isSafeCrossPlatformPathSegment(segment)) {
			return false;
		}
	}
	return true;
}

/**
 * Verify that `relPath` resides strictly beneath the declared harness's `skillsDir`,
 * `subagentsDir`, `.github/prompts/` (when `target === "copilot"`), or equals `"AGENTS.md"`
 * exclusively when `target === "codex"` (and `skillName` is omitted or `"codex-agents-index"`).
 */
export function isAllowedHarnessArtifactPath(
	target: RuntimeTarget,
	relPath: string,
	skillName?: string,
): boolean {
	if (
		typeof target !== "string" ||
		!Object.hasOwn(RUNTIME_HARNESS_SPECS, target) ||
		!isSafeLockRelativePath(relPath)
	) {
		return false;
	}
	if (
		skillName !== undefined &&
		(skillName.length === 0 ||
			skillName.length > 128 ||
			!isSafeCrossPlatformPathSegment(skillName))
	) {
		return false;
	}

	if (relPath === "AGENTS.md") {
		return (
			target === "codex" &&
			(skillName === undefined || skillName === "codex-agents-index")
		);
	}

	const spec = RUNTIME_HARNESS_SPECS[target];
	if (spec.alwaysOnFiles.includes(relPath)) {
		return false;
	}

	const inSkillsDir =
		relPath.startsWith(`${spec.skillsDir}/`) &&
		relPath.length > spec.skillsDir.length + 1;
	const inSubagentsDir =
		relPath.startsWith(`${spec.subagentsDir}/`) &&
		relPath.length > spec.subagentsDir.length + 1;
	const inCopilotPromptsDir =
		target === "copilot" &&
		relPath.startsWith(".github/prompts/") &&
		relPath.length > ".github/prompts/".length;

	return inSkillsDir || inSubagentsDir || inCopilotPromptsDir;
}

// ---------------------------------------------------------------------------
// 1. Skill Manifest Contract (INV-SKILL-01 .. INV-SKILL-03)
// ---------------------------------------------------------------------------

export const RoutingSignalsSchema = z
	.object({
		languages: z.array(z.string().max(256)).max(64).default([]),
		files_any: z.array(z.string().max(256)).max(64).default([]),
		dependencies_any: z.array(z.string().max(256)).max(64).default([]),
		negative_triggers: z.array(z.string().max(512)).max(64).default([]),
	})
	.strict();
export type RoutingSignals = z.infer<typeof RoutingSignalsSchema>;

export const SkillDirectorySchema = z
	.string()
	.min(1)
	.max(MAX_INPUT_PATH_CHARS)
	.transform((val) => trimTrailingSlashes(val.replace(/\\/g, "/")))
	.refine(
		(val) => val.length > 0 && val.length <= 1024 && !val.includes("\0"),
		{
			message:
				"Skill directory path must be a non-empty path (<= 1024 chars) without NUL bytes.",
		},
	);
export type SkillDirectoryPath = z.infer<typeof SkillDirectorySchema>;

export const ScriptEntrypointSchema = z
	.object({
		path: z
			.string()
			.min(1)
			.max(4096)
			.transform((val) => trimSlashes(val.replace(/\\/g, "/")))
			.refine(
				(val) =>
					val.length <= 512 &&
					isSafeLockRelativePath(val) &&
					val.startsWith("scripts/") &&
					(val.endsWith(".py") ||
						val.endsWith(".mjs") ||
						val.endsWith(".js") ||
						val.endsWith(".ts")),
				{
					message:
						"Script entrypoint path must be a safe relative path under 'scripts/' (.py, .mjs, .js, or .ts) without '..', colons, or reserved device names.",
				},
			),
		description: z.string().min(10).max(1024),
	})
	.strict();
export type ScriptEntrypoint = z.infer<typeof ScriptEntrypointSchema>;

export const SkillEntrypointsSchema = z
	.object({
		scripts: z.array(ScriptEntrypointSchema).min(1).max(32),
	})
	.strict();
export type SkillEntrypoints = z.infer<typeof SkillEntrypointsSchema>;

export const SkillManifestSchema = z
	.object({
		name: z
			.string()
			.min(1)
			.max(128)
			.regex(SKILL_NAME_REGEX, {
				message:
					"Skill name must be lowercase kebab-case (e.g., 'mcp-architect').",
			})
			.refine(isSafeCrossPlatformPathSegment, {
				message:
					"Skill name cannot be a reserved cross-platform device stem (e.g., 'con', 'nul', 'aux', 'com1').",
			}),
		description: z
			.string()
			.max(4096)
			.transform((val) => val.trim().replace(/\s+/g, " "))
			.superRefine((cleaned, ctx) => {
				if (!cleaned.startsWith("Use when")) {
					ctx.addIssue({
						code: "custom",
						message:
							"Skill description must start with 'Use when' per SKILL_CONTRACT.md §4.2.",
					});
				}
				const words = countWords(cleaned);
				if (words < 40 || words > 110) {
					ctx.addIssue({
						code: "custom",
						message: `Skill description must contain between 40 and 110 words per INV-SKILL-01 (got ${words} words).`,
					});
				}
				const tokens = estimateTokenCount(cleaned);
				if (tokens > 160) {
					ctx.addIssue({
						code: "custom",
						message: `Skill description exceeds Level 1 budget of 160 tokens per INV-SKILL-01 (estimated ${tokens} tokens).`,
					});
				}
			}),
		version: z.string().max(32).regex(SEMVER_REGEX).default("1.0.0"),
		track: CatalogTrackSchema,
		tags: z.array(z.string().min(1).max(64)).min(1).max(32),
		routing_signals: RoutingSignalsSchema.default({
			languages: [],
			files_any: [],
			dependencies_any: [],
			negative_triggers: [],
		}),
		entrypoints: SkillEntrypointsSchema,
		body_lines: z.number().int().min(0).max(250).default(0),
		body_tokens: z.number().int().min(0).max(1800).default(0),
	})
	.strict();

export type SkillManifestInput = z.input<typeof SkillManifestSchema>;
export type SkillManifest = z.output<typeof SkillManifestSchema> & {
	readonly description_words: number;
	readonly description_tokens: number;
};

export function createSkillManifest(input: unknown): SkillManifest {
	const parsed = SkillManifestSchema.parse(input);
	return {
		...parsed,
		description_words: countWords(parsed.description),
		description_tokens: estimateTokenCount(parsed.description),
	};
}

/**
 * Pure text parser for `SKILL.md` documents (invoked by bounded filesystem readers).
 */
export function parseSkillMdText(
	rawText: string,
	sourceLabel: string = "SKILL.md",
): {
	manifest: SkillManifest;
	markdownBody: string;
	totalLines: number;
} {
	const normalizedPath = sourceLabel.replace(/\\/g, "/");
	const totalLines = rawText.split(/\r?\n/).length;
	const effectiveTotalLines = rawText.endsWith("\n")
		? totalLines - 1
		: totalLines;
	if (effectiveTotalLines > 250) {
		throw new Error(
			`SKILL.md at '${normalizedPath}' has ${effectiveTotalLines} lines, exceeding INV-SKILL-01 maximum of 250 lines.`,
		);
	}
	const [frontmatter, body] = splitFrontmatter(rawText, normalizedPath);
	const bodyLines = body
		? body.endsWith("\n")
			? body.split(/\r?\n/).length - 1
			: body.split(/\r?\n/).length
		: 0;
	const bodyTokens = estimateTokenCount(body);
	const manifest = createSkillManifest({
		...frontmatter,
		body_lines: bodyLines,
		body_tokens: bodyTokens,
	});
	return {
		manifest,
		markdownBody: body,
		totalLines: effectiveTotalLines,
	};
}

// ---------------------------------------------------------------------------
// 2. Subagent Manifest Contract (First-Class High-End Subagents — INV-SKILL-04)
// ---------------------------------------------------------------------------

const FORBIDDEN_WILDCARD_TOOLS = new Set(["*", "all", "any", "**"]);

export const SandboxModeSchema = z.enum(["read-only", "workspace-write"]);
export type SandboxMode = z.infer<typeof SandboxModeSchema>;

export const SubagentManifestSchema = z
	.object({
		name: z
			.string()
			.min(1)
			.max(128)
			.regex(SKILL_NAME_REGEX, {
				message:
					"Subagent name must be lowercase kebab-case (e.g., 'context-scout').",
			})
			.refine(isSafeCrossPlatformPathSegment, {
				message:
					"Subagent name cannot be a reserved cross-platform device stem (e.g., 'con', 'nul', 'aux', 'com1').",
			}),
		description: z
			.string()
			.max(4096)
			.transform((val) => val.trim().replace(/\s+/g, " "))
			.superRefine((cleaned, ctx) => {
				const words = countWords(cleaned);
				if (words < 10 || words > 110) {
					ctx.addIssue({
						code: "custom",
						message: `Subagent description must contain between 10 and 110 words (got ${words} words).`,
					});
				}
				const tokens = estimateTokenCount(cleaned);
				if (tokens > 160) {
					ctx.addIssue({
						code: "custom",
						message: `Subagent description exceeds Level 1 budget of 160 tokens (estimated ${tokens} tokens).`,
					});
				}
			}),
		tools: z
			.array(z.string().min(1).max(64))
			.min(1, {
				message:
					"Subagent must declare an explicit non-empty tool allowlist per INV-SKILL-04.",
			})
			.max(64)
			.superRefine((tools, ctx) => {
				for (const tool of tools) {
					if (FORBIDDEN_WILDCARD_TOOLS.has(tool.trim().toLowerCase())) {
						ctx.addIssue({
							code: "custom",
							message: `Subagent tool allowlist cannot contain wildcard '${tool}' per INV-SKILL-04 least-privilege guarantee.`,
						});
					}
				}
			}),
		disallowed_tools: z.array(z.string().min(1).max(64)).max(64).default([]),
		sandbox_mode: SandboxModeSchema.default("read-only"),
		user_invocable: z.boolean().default(true),
		context_isolation: z.boolean().default(true),
		max_output_tokens: z.number().int().min(50).max(400).default(400),
		model_tier: z.enum(["inherit", "fast", "reasoning"]).default("inherit"),
		tags: z.array(z.string().min(1).max(64)).max(32).default([]),
		system_prompt_lines: z.number().int().min(1).max(180).default(1),
		system_prompt_tokens: z.number().int().min(1).max(1000).default(1),
	})
	.strict();

export type SubagentManifestInput = z.input<typeof SubagentManifestSchema>;
export type SubagentManifest = z.output<typeof SubagentManifestSchema> & {
	readonly description_tokens: number;
};

function normalizeManifestFieldAlias(
	record: Record<string, unknown>,
	canonicalKey: string,
	aliases: readonly string[],
): void {
	for (const alias of aliases) {
		if (Object.hasOwn(record, alias) && !Object.hasOwn(record, canonicalKey)) {
			record[canonicalKey] = record[alias];
			delete record[alias];
		}
	}
}

export function createSubagentManifest(
	input: Record<string, unknown>,
): SubagentManifest {
	const normalized: Record<string, unknown> = { ...input };
	normalizeManifestFieldAlias(normalized, "user_invocable", [
		"user-invocable",
		"userInvocable",
	]);
	normalizeManifestFieldAlias(normalized, "context_isolation", [
		"context-isolation",
		"contextIsolation",
	]);
	normalizeManifestFieldAlias(normalized, "max_output_tokens", [
		"max-output-tokens",
		"maxOutputTokens",
	]);
	normalizeManifestFieldAlias(normalized, "model_tier", [
		"model-tier",
		"modelTier",
	]);
	normalizeManifestFieldAlias(normalized, "disallowed_tools", [
		"disallowed-tools",
		"disallowedTools",
	]);
	normalizeManifestFieldAlias(normalized, "sandbox_mode", [
		"sandbox-mode",
		"sandboxMode",
	]);

	const parsed = SubagentManifestSchema.parse(normalized);
	return {
		...parsed,
		description_tokens: estimateTokenCount(parsed.description),
	};
}

/**
 * Pure text parser for `SUBAGENT.md` / `*.agent.md` documents (invoked by bounded filesystem readers).
 */
export function parseSubagentMdText(
	rawText: string,
	sourceLabel: string = "SUBAGENT.md",
): {
	manifest: SubagentManifest;
	systemPromptBody: string;
} {
	const normalizedPath = sourceLabel.replace(/\\/g, "/");
	const [frontmatter, body] = splitFrontmatter(rawText, normalizedPath);
	const trimmedBody = body.trim();
	const promptLines = trimmedBody ? trimmedBody.split(/\r?\n/).length : 1;
	const promptTokens = Math.max(1, estimateTokenCount(trimmedBody));
	const manifest = createSubagentManifest({
		...frontmatter,
		system_prompt_lines: promptLines,
		system_prompt_tokens: promptTokens,
	});
	return { manifest, systemPromptBody: trimmedBody };
}

// ---------------------------------------------------------------------------
// 3. Multi-Runtime Sync & Lockfile Models
// ---------------------------------------------------------------------------

export const SyncedArtifactSchema = z
	.object({
		target: RuntimeTargetSchema,
		skill_name: z.string().min(1).max(128),
		relative_path: z.string().min(1).max(1024),
		sha256: z
			.string()
			.length(64)
			.regex(/^[0-9a-f]{64}$/),
		action: z.enum([
			"created",
			"updated",
			"unchanged",
			"skipped",
			"removed",
			"planned",
			"conflict",
		]),
	})
	.strict();
export type SyncedArtifact = z.infer<typeof SyncedArtifactSchema>;

export const SafeLockRelativePathSchema = z
	.string()
	.min(1)
	.max(1024)
	.refine(isSafeLockRelativePath, {
		message:
			"Lockfile artifact key/path must be a safe relative POSIX path without leading '/', '..', NUL bytes, reserved device stems, or prototype-polluting segments ('__proto__', 'constructor', 'prototype').",
	});

export const SyncLockEntrySchema = z
	.object({
		target: RuntimeTargetSchema,
		skill_name: z
			.string()
			.min(1)
			.max(128)
			.refine(isSafeCrossPlatformPathSegment, {
				message:
					"Lockfile skill_name must be a safe cross-platform identifier.",
			}),
		relative_path: SafeLockRelativePathSchema,
		sha256: z
			.string()
			.length(64)
			.regex(/^[0-9a-f]{64}$/),
	})
	.strict();
export type SyncLockEntry = z.infer<typeof SyncLockEntrySchema>;

const PlainArtifactsRecordPrecheckSchema = z.custom<
	Record<string, SyncLockEntry>
>(
	(val) => {
		if (typeof val !== "object" || val === null || Array.isArray(val)) {
			return false;
		}
		const proto = Object.getPrototypeOf(val);
		if (proto !== Object.prototype && proto !== null) {
			return false;
		}
		if (Object.getOwnPropertySymbols(val).length > 0) {
			return false;
		}
		const keys = Object.getOwnPropertyNames(val);
		if (keys.length > MAX_LOCKFILE_ARTIFACTS) {
			return false;
		}
		for (const key of keys) {
			if (!isSafeLockRelativePath(key)) {
				return false;
			}
		}
		return true;
	},
	{
		message:
			"Lockfile 'artifacts' must be a plain key-value object (<= 4096 keys) without prototype-polluting keys ('__proto__', 'constructor', 'prototype'), leading '/', NUL bytes, reserved device stems, or '..' segments.",
	},
);

export const SyncLockfileSchema = z
	.object({
		schema_version: z.string().min(1).max(32).default("1.0"),
		skillops_version: z.string().min(1).max(64),
		targets: z.array(RuntimeTargetSchema).max(64).default([]),
		selected_skills: z.array(z.string().min(1).max(128)).max(512).default([]),
		selected_subagents: z
			.array(z.string().min(1).max(128))
			.max(512)
			.default([]),
		total_l1_tokens: z.number().int().min(0).max(10_000_000).default(0),
		artifacts: PlainArtifactsRecordPrecheckSchema.pipe(
			z.record(SafeLockRelativePathSchema, SyncLockEntrySchema),
		).default({}),
	})
	.strict()
	.superRefine((lockfile, ctx) => {
		const keys = Object.getOwnPropertyNames(lockfile.artifacts);
		if (keys.length > MAX_LOCKFILE_ARTIFACTS) {
			ctx.addIssue({
				code: "custom",
				path: ["artifacts"],
				message: `Lockfile 'artifacts' exceeds maximum of ${MAX_LOCKFILE_ARTIFACTS} entries (got ${keys.length}).`,
			});
			return;
		}
		const seenLower = new Map<string, string>();
		for (const key of keys) {
			const lowerKey = key.toLowerCase();
			const priorKey = seenLower.get(lowerKey);
			if (priorKey !== undefined && priorKey !== key) {
				ctx.addIssue({
					code: "custom",
					path: ["artifacts", key],
					message: `Case-insensitive lockfile artifact key collision between '${priorKey}' and '${key}'.`,
				});
			} else {
				seenLower.set(lowerKey, key);
			}

			const entry = lockfile.artifacts[key];
			if (!entry) {
				continue;
			}
			if (key !== entry.relative_path) {
				ctx.addIssue({
					code: "custom",
					path: ["artifacts", key, "relative_path"],
					message: `Lockfile artifact key '${key}' must exactly match entry.relative_path '${entry.relative_path}'.`,
				});
			}
			if (!isAllowedHarnessArtifactPath(entry.target, key, entry.skill_name)) {
				ctx.addIssue({
					code: "custom",
					path: ["artifacts", key],
					message: `Lockfile artifact path '${key}' is outside allowed harness directories for target '${entry.target}'.`,
				});
			}
		}
	});
export type SyncLockfile = z.infer<typeof SyncLockfileSchema>;

export const SyncReportSchema = z
	.object({
		repo_path: z.string().min(1).max(4096),
		catalog_path: z.string().min(1).max(4096),
		targets: z.array(RuntimeTargetSchema).max(64).default([]),
		dry_run: z.boolean().default(false),
		force: z.boolean().default(false),
		artifacts: z.array(SyncedArtifactSchema).max(4096).default([]),
		skipped_existing: z.array(z.string().max(1024)).max(4096).default([]),
		drift_conflicts: z.array(z.string().max(1024)).max(4096).default([]),
		lockfile_path: z.string().min(1).max(4096),
		passed: z.boolean().default(true),
	})
	.strict();
export type SyncReport = z.infer<typeof SyncReportSchema>;

// ---------------------------------------------------------------------------
// 4. Declarative Workspace Configuration (.skillops.yml)
// ---------------------------------------------------------------------------

export const SkillOpsTokenEconomyConfigSchema = z
	.object({
		startup_tax_budget: z.number().int().min(100).max(1_000_000).default(2500),
		max_active_skills: z.number().int().min(1).max(12).default(12),
		max_l1_tokens: z.number().int().min(40).max(1_000_000).default(1500),
		max_similarity: z.number().min(0.1).max(0.99).default(0.78),
	})
	.strict();
export type SkillOpsTokenEconomyConfig = z.infer<
	typeof SkillOpsTokenEconomyConfigSchema
>;

export const SkillOpsDetectedStackConfigSchema = z
	.object({
		languages: z.array(z.string().min(1).max(128)).max(64).default([]),
		frameworks: z.array(z.string().min(1).max(128)).max(64).default([]),
	})
	.strict();
export type SkillOpsDetectedStackConfig = z.infer<
	typeof SkillOpsDetectedStackConfigSchema
>;

export const SkillOpsConfigSchema = z
	.object({
		version: z.string().min(1).max(32).default("1.0"),
		catalog_dir: z
			.string()
			.min(1)
			.max(1024)
			.transform((val) => {
				if (val.startsWith("/") || val.startsWith("\\")) {
					return val;
				}
				const trimmed = trimTrailingSlashes(val);
				return trimmed.startsWith("./") ? trimmed.slice(2) : trimmed;
			})
			.refine(isSafeLockRelativePath, {
				message:
					"catalog_dir must be a safe relative repository path without '..', leading '/', drive colons, backslashes, NUL bytes, or reserved device stems.",
			})
			.default("catalog"),
		token_economy: SkillOpsTokenEconomyConfigSchema.default({
			startup_tax_budget: 2500,
			max_active_skills: 12,
			max_l1_tokens: 1500,
			max_similarity: 0.78,
		}),
		detected_stack: SkillOpsDetectedStackConfigSchema.default({
			languages: [],
			frameworks: [],
		}),
		targets: z
			.array(RuntimeTargetSchema)
			.min(1)
			.max(64)
			.default([...CORE_RUNTIME_TARGETS]),
	})
	.strict();
export type SkillOpsConfig = z.infer<typeof SkillOpsConfigSchema>;

export interface LoadedSkillOpsConfigResult {
	readonly config: SkillOpsConfig | null;
	readonly configPath: string;
	readonly exists: boolean;
	readonly error: string | null;
}

/**
 * Pure YAML parser and schema validator for `.skillops.yml` configuration text,
 * enforcing `{ maxAliasCount: 0, uniqueKeys: true }` and `<= 64 KiB` byte budget.
 */
export function parseSkillOpsConfigText(rawYaml: string): SkillOpsConfig {
	if (Buffer.byteLength(rawYaml, "utf-8") > MAX_RAW_CONFIG_BYTES) {
		throw new Error(
			`Security violation: .skillops.yml exceeds maximum allowed size of ${MAX_RAW_CONFIG_BYTES} bytes.`,
		);
	}
	const parsedYaml: unknown = YAML.parse(rawYaml, {
		maxAliasCount: 0,
		uniqueKeys: true,
	});
	if (
		parsedYaml &&
		typeof parsedYaml === "object" &&
		!Array.isArray(parsedYaml) &&
		hasForbiddenOwnPrototypeKey(parsedYaml)
	) {
		throw new Error(
			"Security violation: .skillops.yml contains forbidden prototype keys.",
		);
	}
	return SkillOpsConfigSchema.parse(parsedYaml);
}

// ---------------------------------------------------------------------------
// 5. Companion Script Output, TDD Evaluation & Benchmark Contracts
//    (SKILL_CONTRACT.md §5 & §6 — INV-SKILL-03 & INV-SKILL-05)
// ---------------------------------------------------------------------------

export const ScriptOutputStatusSchema = z.enum([
	"ok",
	"warn",
	"findings_detected",
	"error",
]);
export type ScriptOutputStatus = z.infer<typeof ScriptOutputStatusSchema>;

export const ScriptOutputSchema = z
	.object({
		skill: z.string().min(1).max(128).regex(SKILL_NAME_REGEX),
		script: z.string().min(1).max(512),
		status: ScriptOutputStatusSchema,
		target: z.string().min(1).max(2048),
		summary: z.union([
			z.record(z.string().max(256), z.unknown()),
			z.string().max(16_384),
		]),
		findings: z
			.array(z.record(z.string().max(256), z.unknown()))
			.max(10_000)
			.default([]),
		data: z.record(z.string().max(256), z.unknown()).optional(),
		metrics: z.record(z.string().max(256), z.unknown()).optional(),
	})
	.strict();
export type ScriptOutput = z.infer<typeof ScriptOutputSchema>;

export const EvalAssertionTypeSchema = z.enum([
	"tool_call_contains",
	"regex_match",
	"regex_not_match",
	"json_field_equals",
	"exit_code_zero",
	"ast_contains",
	"contains",
	"not_contains",
]);
export type EvalAssertionType = z.infer<typeof EvalAssertionTypeSchema>;

export const EvalAssertionSchema = z
	.object({
		id: z.string().min(1).max(128),
		type: EvalAssertionTypeSchema,
		target: z.string().min(1).max(512),
		expected: z.unknown().optional(),
		description: z.string().min(1).max(2048),
	})
	.strict();
export type EvalAssertion = z.infer<typeof EvalAssertionSchema>;

const CanonicalEvalCaseSchema = z
	.object({
		id: z.string().min(1).max(128),
		name: z.string().min(1).max(256),
		prompt: z.string().min(1).max(32_768),
		fixtures: z.array(z.string().min(1).max(1024)).max(64).default([]),
		assertions: z.array(EvalAssertionSchema).min(1).max(128),
	})
	.strict();

const ShorthandEvalCaseSchema = z
	.object({
		id: z.union([
			z.string().min(1).max(128),
			z.number().int().nonnegative().transform(String),
		]),
		name: z.string().min(1).max(256).optional(),
		prompt: z.string().min(1).max(32_768),
		expected_output: z.string().min(1).max(32_768),
		files: z.array(z.string().min(1).max(1024)).max(64).optional(),
		fixtures: z.array(z.string().min(1).max(1024)).max(64).optional(),
		assertions: z
			.array(z.union([EvalAssertionSchema, z.string().min(1).max(2048)]))
			.min(1)
			.max(128),
	})
	.strict()
	.transform((raw) => ({
		id: raw.id,
		name: raw.name ?? raw.prompt.slice(0, 256),
		prompt: raw.prompt,
		fixtures: raw.fixtures ?? raw.files ?? [],
		assertions: raw.assertions.map((assertion, idx) =>
			typeof assertion === "string"
				? {
						id: `${raw.id}-assertion-${idx + 1}`,
						type: "contains" as const,
						target: "output",
						expected: raw.expected_output,
						description: assertion,
					}
				: assertion,
		),
	}));

export const EvalCaseSchema = z.union([
	CanonicalEvalCaseSchema,
	ShorthandEvalCaseSchema,
]);
export type EvalCase = z.infer<typeof EvalCaseSchema>;

export const EvalSuiteSchema = z
	.object({
		skill_name: z
			.string()
			.min(1)
			.max(128)
			.regex(SKILL_NAME_REGEX)
			.refine(isSafeCrossPlatformPathSegment, {
				message:
					"EvalSuite skill_name cannot be a reserved cross-platform device stem.",
			}),
		schema_version: z.string().min(1).max(32).default("1.0"),
		evals: z.array(EvalCaseSchema).min(1).max(128),
	})
	.strict();
export type EvalSuite = z.infer<typeof EvalSuiteSchema>;

export const BenchmarkRunStatsSchema = z
	.object({
		pass_rate_mean: z.number().min(0).max(1),
		pass_rate_stddev: z.number().min(0).max(1).default(0),
		tokens_mean: z.number().min(0).max(10_000_000),
		latency_ms_mean: z.number().min(0).max(86_400_000),
	})
	.strict();
export type BenchmarkRunStats = z.infer<typeof BenchmarkRunStatsSchema>;

export const BenchmarkVerdictSchema = z.enum([
	"CERTIFIED_IMPROVEMENT",
	"NEUTRAL",
	"REJECTED_REGRESSION",
]);
export type BenchmarkVerdict = z.infer<typeof BenchmarkVerdictSchema>;

export const BenchmarkDeltaSchema = z
	.object({
		pass_rate_gain: z.number().min(-1).max(1),
		token_reduction_pct: z.number().min(-100_000).max(100),
		verdict: BenchmarkVerdictSchema,
	})
	.strict();
export type BenchmarkDelta = z.infer<typeof BenchmarkDeltaSchema>;

export const BenchmarkReportSchema = z
	.object({
		skill_name: z
			.string()
			.min(1)
			.max(128)
			.regex(SKILL_NAME_REGEX)
			.refine(isSafeCrossPlatformPathSegment, {
				message:
					"BenchmarkReport skill_name cannot be a reserved cross-platform device stem.",
			}),
		runner: z.string().min(1).max(256),
		timestamp: z.string().max(64).datetime({ offset: true }),
		with_skill: BenchmarkRunStatsSchema,
		without_skill: BenchmarkRunStatsSchema,
		delta: BenchmarkDeltaSchema,
	})
	.strict();
export type BenchmarkReport = z.infer<typeof BenchmarkReportSchema>;
