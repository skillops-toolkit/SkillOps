import os from "node:os";
import path from "node:path";
import type { RuntimeTarget, SyncReport } from "../models.js";
import { CHARM_PALETTE, fgHex, renderPill } from "../ui/lipgloss.js";
import {
	formatActionBadge,
	formatBadge,
	padVisible,
	renderAiUsageGuide,
	renderHeaderBanner,
	renderNextSteps,
	renderSectionHeader,
	style,
} from "../ui/terminal.js";
import { isGlobalHomePath } from "./fs-safety.js";
import { type ArtifactHealthState, PACKAGE_CATALOG_DIR, type ProjectStatusReport } from "./types.js";

/**
 * Redact OS user home directories, usernames, and host filesystem roots from
 * machine/markdown report outputs (`--json`, `-f md`) while preserving relative structure.
 */
export function toPortableReportPath(
	rawPath: string,
	baseRepoPath?: string,
): string {
	const posix = rawPath.replace(/\\/g, "/").replace(/\/+$/, "") || "/";
	const builtinCatalog = PACKAGE_CATALOG_DIR.replace(/\\/g, "/").replace(/\/+$/, "");
	if (posix === builtinCatalog) {
		return "catalog";
	}
	if (posix.startsWith(`${builtinCatalog}/`)) {
		return `catalog/${posix.slice(builtinCatalog.length + 1)}`;
	}
	if (baseRepoPath) {
		const normBase = baseRepoPath.replace(/\\/g, "/").replace(/\/+$/, "");
		if (posix === normBase) {
			return isGlobalHomePath(baseRepoPath) ? "~" : ".";
		}
		if (posix.startsWith(`${normBase}/`)) {
			const rel = posix.slice(normBase.length + 1);
			return isGlobalHomePath(baseRepoPath) ? `~/${rel}` : rel;
		}
	}
	const candidates = [
		os.homedir(),
		process.env.SKILLOPS_GLOBAL_HOME?.trim() ?? "",
	]
		.filter(Boolean)
		.map((dir) => path.resolve(dir).replace(/\\/g, "/").replace(/\/+$/, ""));
	for (const home of candidates) {
		if (posix === home) {
			return "~";
		}
		if (posix.startsWith(`${home}/`)) {
			return `~/${posix.slice(home.length + 1)}`;
		}
	}
	const redacted = posix
		.replace(/^[A-Za-z]:\/Users\/[^/]+(?=\/|$)/i, "~")
		.replace(/^\/(?:Users|home)\/[^/]+(?=\/|$)/, "~");
	if (redacted !== posix) {
		return redacted;
	}
	if (/^\/(?:tmp|var\/tmp|var\/folders)\//i.test(posix)) {
		return `<tmp>/${path.posix.basename(posix)}`;
	}
	return posix;
}

function formatHealthPill(
	state: ArtifactHealthState,
	colorEnabled?: boolean,
): string {
	switch (state) {
		case "up_to_date":
			return renderPill(" = HEALTHY ", {
				fg: CHARM_PALETTE.inkDark,
				bg: CHARM_PALETTE.mint,
				bold: true,
				colorEnabled,
			});
		case "update_available":
			return renderPill(" ~ OUTDATED", {
				fg: CHARM_PALETTE.inkDark,
				bg: CHARM_PALETTE.amber,
				bold: true,
				colorEnabled,
			});
		case "drift_modified":
			return renderPill(" ! DRIFT   ", {
				fg: CHARM_PALETTE.white,
				bg: CHARM_PALETTE.coral,
				bold: true,
				colorEnabled,
			});
		case "missing_on_disk":
			return renderPill(" ? MISSING ", {
				fg: CHARM_PALETTE.white,
				bg: CHARM_PALETTE.coral,
				bold: true,
				colorEnabled,
			});
		case "untracked_on_disk":
			return renderPill(" + UNTRACK ", {
				fg: CHARM_PALETTE.indigo,
				bg: CHARM_PALETTE.keycapBg,
				bold: true,
				colorEnabled,
			});
	}
}

/**
 * Format a `ProjectStatusReport` into a compact `<= 78 cols` tree, JSON, or Markdown (Issue #201).
 */
export function formatProjectStatusReport(
	report: ProjectStatusReport,
	format: "table" | "json" | "markdown" = "table",
	colorEnabled?: boolean,
): string {
	const isGlobal = isGlobalHomePath(report.repo_path);
	const globalBadge = isGlobal ? " [Global: ~]" : "";

	if (format === "json") {
		const sanitizedReport: ProjectStatusReport = {
			...report,
			repo_path: toPortableReportPath(report.repo_path, report.repo_path),
			catalog_path: toPortableReportPath(report.catalog_path, report.repo_path),
			lockfile_path: toPortableReportPath(report.lockfile_path, report.repo_path),
		};
		return `${JSON.stringify(sanitizedReport, null, 2)}\n`;
	}

	if (format === "markdown") {
		return [
			`## SkillOps Project Status Report${globalBadge}`,
			"",
			`- **Targets**: ${report.targets.length > 0 ? report.targets.map((t) => `\`${t}\``).join(", ") : "none"}`,
			`- **Installed Skills**: \`${report.installed_skills.length}\``,
			`- **Installed Subagents**: \`${report.installed_subagents.length}\``,
			`- **Lockfile Present**: \`${report.lockfile_present}\``,
			`- **Status**: **${report.passed ? "PASS" : "DRIFT DETECTED"}**`,
			"",
			"| Target | Kind | Module | Relative Path | State |",
			"| :--- | :--- | :--- | :--- | :---: |",
			...report.artifacts.map(
				(a) =>
					`| \`${a.target}\` | \`${a.kind}\` | \`${a.itemName}\` | \`${a.relativePath}\` | \`${a.state}\` |`,
			),
			"",
		].join("\n");
	}

	const c = colorEnabled;
	const bar = style.dim("│", c);
	const subtitle = `Project Status & Installed Modules${globalBadge}`;
	const banner = renderHeaderBanner(subtitle, { colorEnabled: c });

	const statusBadge = !report.passed
		? formatBadge("fail", "DRIFT DETECTED", c)
		: report.counts.update_available > 0
			? formatBadge("warn", "UPDATE AVAILABLE", c)
			: formatBadge("pass", "HEALTHY", c);

	const breakdownParts: string[] = [];
	if (report.counts.up_to_date > 0)
		breakdownParts.push(`${report.counts.up_to_date} healthy`);
	if (report.counts.update_available > 0)
		breakdownParts.push(`${report.counts.update_available} outdated`);
	if (report.counts.drift_modified > 0)
		breakdownParts.push(`${report.counts.drift_modified} drift`);
	if (report.counts.missing_on_disk > 0)
		breakdownParts.push(`${report.counts.missing_on_disk} missing`);
	if (report.counts.untracked_on_disk > 0)
		breakdownParts.push(`${report.counts.untracked_on_disk} untracked`);
	const breakdown =
		breakdownParts.length > 0
			? style.dim(` (${breakdownParts.join(", ")})`, c)
			: "";

	const statusLine = `${bar}  ${padVisible(fgHex(CHARM_PALETTE.lavender, style.bold("Status:", c), c), 10, "left")}${statusBadge} ${style.dim("·", c)} ${fgHex(CHARM_PALETTE.white, `${report.artifacts.length} file(s)`, c)}`;
	const healthLine =
		breakdownParts.length > 0
			? `${bar}  ${padVisible(fgHex(CHARM_PALETTE.lavender, style.bold("Health:", c), c), 10, "left")}${style.dim(breakdownParts.join(", "), c)}`
			: "";

	const visibleTargets =
		report.targets.length === 0
			? style.dim("none", c)
			: report.targets.length <= 4
				? report.targets
						.map((t) => style.bold(style.cyan(t, c), c))
						.join(style.dim(", ", c))
				: `${report.targets
						.slice(0, 3)
						.map((t) => style.bold(style.cyan(t, c), c))
						.join(
							style.dim(", ", c),
						)} ${fgHex(CHARM_PALETTE.lavender, `+${report.targets.length - 3} more (${report.targets.length} IDEs)`, c)}`;
	const targetsLine = `${bar}  ${padVisible(fgHex(CHARM_PALETTE.lavender, style.bold("Targets:", c), c), 10, "left")}${visibleTargets}`;

	const totalModules =
		report.installed_skills.length + report.installed_subagents.length;
	const moduleLines: string[] = [
		renderSectionHeader(`Installed Modules (${totalModules})`, c),
	];

	if (totalModules === 0) {
		moduleLines.push(
			`${bar}  ${style.dim("No Skills or Subagents installed in this workspace.", c)}`,
		);
	} else {
		const byItem = new Map<
			string,
			{ kind: "skill" | "subagent"; targets: Set<RuntimeTarget> }
		>();
		for (const a of report.artifacts) {
			let entry = byItem.get(a.itemName);
			if (!entry) {
				entry = { kind: a.kind, targets: new Set<RuntimeTarget>() };
				byItem.set(a.itemName, entry);
			}
			entry.targets.add(a.target);
		}
		for (const [itemName, info] of byItem.entries()) {
			const kindBadge = formatBadge(
				info.kind === "subagent" ? "subagent" : "skill",
				info.kind === "subagent" ? "AGENT" : "SKILL",
				c,
			);
			const targetList = [...info.targets];
			const targetSummary =
				targetList.length <= 3
					? targetList.join(", ")
					: `${targetList.slice(0, 2).join(", ")}, +${targetList.length - 2}`;
			const truncatedItemName =
				itemName.length > 22 ? `${itemName.slice(0, 21)}…` : itemName;
			const paddedName = padVisible(
				fgHex(CHARM_PALETTE.white, style.bold(truncatedItemName, c), c),
				22,
				"left",
			);
			moduleLines.push(
				`${bar}  ${kindBadge} ${paddedName} ${fgHex(CHARM_PALETTE.cyan, targetSummary, c)}`,
			);
		}
	}

	const maxDisplayed = 12;
	const shownArtifacts = report.artifacts.slice(0, maxDisplayed);
	const hiddenCount = Math.max(0, report.artifacts.length - maxDisplayed);

	const artifactLines: string[] = [
		renderSectionHeader(`Runtime Artifacts (${report.artifacts.length})`, c),
	];
	if (report.artifacts.length === 0) {
		artifactLines.push(`${bar}  ${style.dim("No runtime files found.", c)}`);
	} else {
		for (const a of shownArtifacts) {
			const pill = formatHealthPill(a.state, c);
			const targetCol = padVisible(
				fgHex(CHARM_PALETTE.cyan, style.bold(`(${a.target})`, c), c),
				16,
				"left",
			);
			const maxPathCols = 44;
			const shortPath =
				a.relativePath.length > maxPathCols
					? `…${a.relativePath.slice(-(maxPathCols - 1))}`
					: a.relativePath;
			const styledPath =
				a.state === "drift_modified" || a.state === "missing_on_disk"
					? fgHex(CHARM_PALETTE.coral, shortPath, c)
					: a.state === "update_available"
						? fgHex(CHARM_PALETTE.amber, shortPath, c)
						: fgHex(CHARM_PALETTE.white, shortPath, c);
			artifactLines.push(`${bar}  ${pill} ${targetCol} ${styledPath}`);
		}
		if (hiddenCount > 0) {
			artifactLines.push(
				`${bar}  ${fgHex(CHARM_PALETTE.lavender, `… and ${hiddenCount} more runtime file(s) across ${report.targets.length} AI IDEs`, c)}`,
			);
		}
	}

	const nextSteps = renderNextSteps(
		[
			{
				command: "npx skillops-cli add",
				description: "Install Skills or Subagents",
			},
			{
				command: "npx skillops-cli remove",
				description: "Remove installed Skills or Subagents",
			},
		],
		c,
	);

	return [
		banner,
		statusLine,
		healthLine,
		targetsLine,
		...moduleLines,
		...artifactLines,
		nextSteps,
	]
		.filter(Boolean)
		.join("\n");
}


export function formatSyncReport(
	report: SyncReport,
	format: "table" | "json" | "markdown" = "table",
	colorEnabled?: boolean,
): string {
	const isGlobal = isGlobalHomePath(report.repo_path);
	const globalBadge = isGlobal ? " [Global: ~]" : "";
	if (format === "json") {
		const sanitizedReport: SyncReport = {
			...report,
			repo_path: toPortableReportPath(report.repo_path, report.repo_path),
			catalog_path: toPortableReportPath(report.catalog_path, report.repo_path),
			lockfile_path: toPortableReportPath(report.lockfile_path, report.repo_path),
		};
		return `${JSON.stringify(sanitizedReport, null, 2)}\n`;
	}
	if (format === "markdown") {
		return [
			`## SkillOps Multi-Runtime Sync Report${globalBadge}`,
			"",
			`- **Targets**: ${report.targets.map((t) => `\`${t}\``).join(", ")}`,
			`- **Artifacts Synced**: \`${report.artifacts.length}\``,
			`- **Skipped (Already Exists)**: \`${report.skipped_existing.length}\``,
			`- **Drift Conflicts**: \`${report.drift_conflicts.length}\``,
			`- **Status**: **${report.passed ? "PASS" : "CONFLICT"}**`,
			"",
			"| Target | Skill / Subagent | Relative Path | Action |",
			"| :--- | :--- | :--- | :---: |",
			...report.artifacts.map(
				(a) =>
					`| \`${a.target}\` | \`${a.skill_name}\` | \`${a.relative_path}\` | \`${a.action}\` |`,
			),
			"",
		].join("\n");
	}

	const c = colorEnabled;
	const bar = style.dim("│", c);
	const activeArtifacts = report.artifacts.filter(
		(a) =>
			a.action === "created" ||
			a.action === "updated" ||
			a.action === "unchanged",
	);
	const isRemoval =
		report.artifacts.length > 0 &&
		report.artifacts.every((a) => a.action === "removed");
	const isAllSkipped =
		report.artifacts.length > 0 &&
		report.artifacts.every((a) => a.action === "skipped");
	const baseSubtitle = !report.passed
		? "Drift Conflict Detected"
		: report.dry_run
			? "Dry-Run Sync Preview"
			: isRemoval
				? "Skills & Subagents Removed"
				: isAllSkipped
					? "Skills & Subagents Skipped (Already Installed)"
					: "Skills & Subagents Installed";
	const subtitle = `${baseSubtitle}${globalBadge}`;

	const banner = renderHeaderBanner(subtitle, { colorEnabled: c });

	const counts = {
		created: 0,
		updated: 0,
		removed: 0,
		unchanged: 0,
		skipped: 0,
		planned: 0,
		conflict: 0,
	};
	for (const a of report.artifacts) {
		counts[a.action] += 1;
	}
	const countParts: string[] = [];
	if (counts.created > 0) countParts.push(`${counts.created} created`);
	if (counts.updated > 0) countParts.push(`${counts.updated} updated`);
	if (counts.skipped > 0) countParts.push(`${counts.skipped} skipped`);
	if (counts.removed > 0) countParts.push(`${counts.removed} removed`);
	if (counts.planned > 0) countParts.push(`${counts.planned} planned`);
	if (counts.unchanged > 0) countParts.push(`${counts.unchanged} kept`);
	if (counts.conflict > 0) countParts.push(`${counts.conflict} conflict`);
	const breakdown =
		countParts.length > 0 ? style.dim(` (${countParts.join(", ")})`, c) : "";

	const statusBadge = report.passed
		? formatBadge("pass", report.dry_run ? "DRY-RUN" : "PASS", c)
		: formatBadge("fail", "DRIFT CONFLICT", c);
	const statusLine = `${bar}  ${padVisible(fgHex(CHARM_PALETTE.lavender, style.bold("Status:", c), c), 10, "left")}${statusBadge} ${style.dim("·", c)} ${fgHex(CHARM_PALETTE.white, `${report.artifacts.length} file(s)`, c)}${breakdown}`;

	const visibleTargets =
		report.targets.length <= 5
			? report.targets
					.map((t) => style.bold(style.cyan(t, c), c))
					.join(style.dim(", ", c))
			: `${report.targets
					.slice(0, 4)
					.map((t) => style.bold(style.cyan(t, c), c))
					.join(
						style.dim(", ", c),
					)} ${fgHex(CHARM_PALETTE.lavender, `+${report.targets.length - 4} more (${report.targets.length} IDEs)`, c)}`;
	const targetsLine = `${bar}  ${padVisible(fgHex(CHARM_PALETTE.lavender, style.bold("Targets:", c), c), 10, "left")}${visibleTargets}`;

	const maxDisplayed = 12;
	const shownArtifacts = report.artifacts.slice(0, maxDisplayed);
	const hiddenCount = Math.max(0, report.artifacts.length - maxDisplayed);

	const artifactLines: string[] = [
		renderSectionHeader(`Runtime Artifacts (${report.artifacts.length})`, c),
	];
	if (report.artifacts.length === 0) {
		artifactLines.push(`${bar}  ${style.dim("No runtime files matched.", c)}`);
	} else {
		for (const a of shownArtifacts) {
			const badge = formatActionBadge(a.action, c);
			const targetCol = padVisible(
				fgHex(CHARM_PALETTE.cyan, style.bold(`(${a.target})`, c), c),
				13,
				"left",
			);
			const maxPathCols = 47;
			const shortPath =
				a.relative_path.length > maxPathCols
					? `…${a.relative_path.slice(-(maxPathCols - 1))}`
					: a.relative_path;
			const styledPath =
				a.action === "conflict"
					? fgHex(CHARM_PALETTE.coral, shortPath, c)
					: a.action === "removed" || a.action === "skipped"
						? fgHex(CHARM_PALETTE.lavender, shortPath, c)
						: fgHex(CHARM_PALETTE.white, shortPath, c);
			artifactLines.push(`${bar}  ${badge} ${targetCol} ${styledPath}`);
		}
		if (hiddenCount > 0) {
			artifactLines.push(
				`${bar}  ${fgHex(CHARM_PALETTE.lavender, `… and ${hiddenCount} more runtime file(s) across ${report.targets.length} AI IDEs`, c)}`,
			);
		}
	}

	const skippedArtifacts = report.artifacts.filter(
		(a) => a.action === "skipped",
	);
	const skippedLines: string[] = [];
	if (skippedArtifacts.length > 0) {
		skippedLines.push(
			renderSectionHeader(
				`Skipped — Already Exists (${skippedArtifacts.length})`,
				c,
			),
		);
		for (const sItem of skippedArtifacts) {
			const shortRel =
				sItem.relative_path.length > 48
					? `…${sItem.relative_path.slice(-47)}`
					: sItem.relative_path;
			skippedLines.push(
				`${bar}  ${formatBadge("warn", "SKIPPED", c)} ${fgHex(CHARM_PALETTE.cyan, style.bold(`(${sItem.target})`, c), c)} ${fgHex(CHARM_PALETTE.white, sItem.skill_name, c)} ${style.dim(`already exists at ${shortRel}`, c)}`,
			);
		}
		skippedLines.push(
			`${bar}  ${fgHex(CHARM_PALETTE.lavender, "Existing files were preserved and not overwritten. Pass --force to replace them.", c)}`,
		);
	}

	const conflictLines: string[] = [];
	if (report.drift_conflicts.length > 0) {
		conflictLines.push(renderSectionHeader("Drift Conflicts", c));
		for (const cItem of report.drift_conflicts) {
			const shortItem =
				cItem.length > 52 ? `…${cItem.slice(-51)}` : cItem;
			conflictLines.push(
				`${bar}  ${formatBadge("fail", "DRIFT", c)} ${fgHex(CHARM_PALETTE.coral, shortItem, c)}`,
			);
		}
		conflictLines.push(
			`${bar}  ${fgHex(CHARM_PALETTE.amber, "Local changes detected. Re-run with --force to overwrite.", c)}`,
		);
	}

	const isSubagentArtifact = (relPath: string): boolean =>
		relPath.includes("/agents/") ||
		relPath.includes("skillops-agent-") ||
		relPath.endsWith(".agent.md");

	const firstSkill =
		activeArtifacts.find(
			(a) =>
				a.skill_name !== "codex-agents-index" &&
				a.skill_name !== "aider-read-config" &&
				!isSubagentArtifact(a.relative_path),
		)?.skill_name ?? "mcp-architect";
	const firstAgent =
		activeArtifacts.find((a) => isSubagentArtifact(a.relative_path))
			?.skill_name ?? "context-scout";

	const usageBox =
		activeArtifacts.length > 0
			? renderAiUsageGuide(report.targets, [firstSkill], [firstAgent], c)
			: "";

	const nextSteps = renderNextSteps(
		[
			{
				command: "npx skillops-cli add",
				description: "Install more Skills or Subagents",
			},
			{
				command: "npx skillops-cli remove",
				description: "Remove installed Skills or Subagents",
			},
		],
		c,
	);

	return [
		banner,
		statusLine,
		targetsLine,
		...artifactLines,
		...skippedLines,
		...conflictLines,
		usageBox,
		nextSteps,
	]
		.filter(Boolean)
		.join("\n");
}
