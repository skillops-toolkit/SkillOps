/**
 * Multi-Runtime Transpiler Facade (`src/sync/adapters.ts`).
 *
 * Re-exports modular sync engine modules under `src/sync/*` while preserving
 * 100% backwards-compatible public and internal test exports.
 */

export {
	renderAiderReadConfig,
	stripManagedAiderReadEntries,
} from "./aider-config.js";
export { type CatalogIndex, loadCatalogIndex } from "./catalog-index.js";
export {
	renderCodexAgentsIndex,
	stripCodexAgentsBlock,
} from "./codex-index.js";
export {
	detectExistingTargetsForItem,
	discoverInstalledArtifactsOnDisk,
	findExistingItemPathInTarget,
} from "./discovery.js";
export {
	formatProjectStatusReport,
	formatSyncReport,
	toPortableReportPath,
} from "./formatters.js";
export {
	computeSha256,
	resolveSafeRepoTargetPath,
} from "./fs-safety.js";
export {
	addSkillOrSubagent,
	cleanSyncedArtifacts,
	inspectProjectStatus,
	removeSkillOrSubagent,
	updateInstalledSkills,
} from "./operations.js";
export { renderSkillFilesForRuntime } from "./renderers/skills.js";
export {
	encodeTomlBasicString,
	mapCanonicalToolsToRuntime,
	renderSubagentFilesForRuntime,
} from "./renderers/subagents.js";
export {
	computeLockfileL1Tokens,
	computeWorkspaceTokenTelemetry,
	DEFAULT_MAX_ALWAYS_ON_TOKENS,
	type HarnessStartupMode,
	isProgressiveHarness,
	type TargetTokenTelemetry,
	type WorkspaceTokenTelemetry,
} from "./telemetry.js";
export type {
	AddOptions,
	ArtifactHealthState,
	CleanOptions,
	DiscoveredInstalledArtifact,
	InstalledArtifactStatus,
	PlannedFile,
	ProjectStatusReport,
	RemoveOptions,
	StatusOptions,
	UpdateOptions,
} from "./types.js";
