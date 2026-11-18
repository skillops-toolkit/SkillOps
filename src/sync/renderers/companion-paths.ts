import type { ParsedSkillDirectory } from "../../auditor/parser.js";
import { FRONTMATTER_REGEX, type RuntimeTarget } from "../../models.js";
import { getCachedCompanionFiles } from "../catalog-index.js";
import { type PlannedFile, trimSlashes } from "../types.js";

const BARE_COMPANION_PATH_REGEX =
	/(^|[\s`("'])((?:scripts|references|assets)\/[A-Za-z0-9._/-]+)/gm;
const LEADING_REL_PATH_REGEX = /^[A-Za-z0-9._/-]+/;

function rewriteCatalogPrefixedPaths(
	text: string,
	catalogPrefix: string,
	normalizedRoot: string,
	bundleableSet: ReadonlySet<string>,
): string {
	if (!text.includes(catalogPrefix)) {
		return text;
	}
	const parts = text.split(catalogPrefix);
	let result = parts[0] ?? "";
	for (let i = 1; i < parts.length; i += 1) {
		const chunk = parts[i] ?? "";
		const candidateMatch = LEADING_REL_PATH_REGEX.exec(chunk);
		const candidate = candidateMatch?.[0] ?? "";
		if (candidate && bundleableSet.has(candidate)) {
			result += `${normalizedRoot}/${chunk}`;
		} else {
			result += `${catalogPrefix}${chunk}`;
		}
	}
	return result;
}

export function rewriteBundledSkillPaths(
	text: string,
	parsed: ParsedSkillDirectory,
	companionRootDir: string,
): string {
	const name = parsed.manifest.name;
	const track = parsed.manifest.track;
	const normalizedRoot = trimSlashes(companionRootDir);
	const bundleableSet = new Set<string>(parsed.bundleableFiles);
	const catalogPrefix = `catalog/${track}/${name}/`;
	const afterCatalog = rewriteCatalogPrefixedPaths(
		text,
		catalogPrefix,
		normalizedRoot,
		bundleableSet,
	);
	return afterCatalog.replace(
		BARE_COMPANION_PATH_REGEX,
		(match, prefix: string, relCompanion: string) => {
			if (
				!bundleableSet.has(relCompanion) ||
				relCompanion.startsWith(`${normalizedRoot}/`)
			) {
				return match;
			}
			return `${prefix}${normalizedRoot}/${relCompanion}`;
		},
	);
}

export function rewriteProgressiveSkillRawText(
	rawText: string,
	parsed: ParsedSkillDirectory,
	companionRootDir: string,
): string {
	const fmMatch = FRONTMATTER_REGEX.exec(rawText);
	if (fmMatch) {
		const bodyPart = fmMatch[2] ?? "";
		const fmHeader = rawText.slice(0, rawText.length - bodyPart.length);
		return `${fmHeader}${rewriteBundledSkillPaths(bodyPart, parsed, companionRootDir)}`;
	}
	return rewriteBundledSkillPaths(rawText, parsed, companionRootDir);
}

export function appendCompanionSkillFiles(
	files: PlannedFile[],
	parsed: ParsedSkillDirectory,
	target: RuntimeTarget,
	baseDir: string,
): void {
	const name = parsed.manifest.name;
	const companionFiles = getCachedCompanionFiles(parsed);
	for (const [relFile, content] of companionFiles) {
		files.push({
			target,
			itemName: name,
			relativePath: `${baseDir}/${relFile}`,
			content,
		});
	}
}
