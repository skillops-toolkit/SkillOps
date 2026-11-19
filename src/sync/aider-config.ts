import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { isRegularFileNoFollow } from "./fs-safety.js";

const AIDER_MANAGED_PREFIX = ".aider/conventions/";

/**
 * Render `.aider.conf.yml` preserving user-configured keys and custom `read:`
 * entries while synchronizing SkillOps-managed `.aider/conventions/*.md` entries.
 */
export function renderAiderReadConfig(
	existingContent: string | null,
	managedPaths: readonly string[],
): string {
	let parsedObj: Record<string, unknown> = {};
	if (existingContent && existingContent.trim().length > 0) {
		const raw: unknown = YAML.parse(existingContent, {
			maxAliasCount: 0,
			uniqueKeys: true,
		});
		if (raw !== null && raw !== undefined) {
			if (typeof raw !== "object" || Array.isArray(raw)) {
				throw new Error(
					"Existing .aider.conf.yml must evaluate to a YAML mapping.",
				);
			}
			parsedObj = { ...(raw as Record<string, unknown>) };
		}
	}

	const rawRead = parsedObj.read;
	const existingEntries: string[] = Array.isArray(rawRead)
		? rawRead.filter((v): v is string => typeof v === "string")
		: typeof rawRead === "string"
			? [rawRead]
			: [];

	const userEntries = existingEntries.filter(
		(entry) => !entry.replace(/\\/g, "/").startsWith(AIDER_MANAGED_PREFIX),
	);
	const normalizedManaged = [
		...new Set(managedPaths.map((p) => p.replace(/\\/g, "/"))),
	].sort();
	const combined = [...new Set([...userEntries, ...normalizedManaged])];

	if (combined.length > 0) {
		parsedObj.read = combined;
	} else {
		delete parsedObj.read;
	}

	const body =
		Object.keys(parsedObj).length > 0 ? YAML.stringify(parsedObj) : "{}\n";
	return body.endsWith("\n") ? body : `${body}\n`;
}

/**
 * Strip only SkillOps-managed `.aider/conventions/` entries from `.aider.conf.yml`,
 * preserving user settings and custom `read:` entries.
 */
export function stripManagedAiderReadEntries(existingContent: string): string {
	return renderAiderReadConfig(existingContent, []);
}

/**
 * Collect on-disk `.aider/conventions/*.md` paths in `resolvedRepo`, merged with
 * `extraPaths` and excluding any `excludePaths`.
 */
export function collectInstalledAiderConventionPaths(
	resolvedRepo: string,
	extraPaths: readonly string[] = [],
	excludePaths: readonly string[] = [],
): string[] {
	const excludeSet = new Set(excludePaths.map((p) => p.replace(/\\/g, "/")));
	const results = new Set<string>();
	const conventionsDir = path.join(resolvedRepo, ".aider", "conventions");

	if (fs.existsSync(conventionsDir)) {
		try {
			const stat = fs.lstatSync(conventionsDir);
			if (!stat.isSymbolicLink() && stat.isDirectory()) {
				for (const entry of fs.readdirSync(conventionsDir, {
					withFileTypes: true,
				})) {
					if (entry.isSymbolicLink() || !entry.isFile()) {
						continue;
					}
					if (!entry.name.endsWith(".md")) {
						continue;
					}
					const fullPath = path.join(conventionsDir, entry.name);
					if (!isRegularFileNoFollow(fullPath)) {
						continue;
					}
					const relPath = `.aider/conventions/${entry.name}`;
					if (!excludeSet.has(relPath)) {
						results.add(relPath);
					}
				}
			}
		} catch {
			// Ignore unreadable conventions dir
		}
	}

	for (const p of extraPaths) {
		const norm = p.replace(/\\/g, "/");
		if (
			norm.startsWith(AIDER_MANAGED_PREFIX) &&
			norm.endsWith(".md") &&
			!norm.slice(AIDER_MANAGED_PREFIX.length).includes("/") &&
			!excludeSet.has(norm)
		) {
			results.add(norm);
		}
	}

	return [...results].sort();
}
