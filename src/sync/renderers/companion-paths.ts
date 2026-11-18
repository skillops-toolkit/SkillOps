import type { ParsedSkillDirectory } from "../../auditor/parser.js";
import type { RuntimeTarget } from "../../models.js";
import { getCachedCompanionFiles } from "../catalog-index.js";
import { type PlannedFile, trimSlashes } from "../types.js";

const BARE_COMPANION_PATH_REGEX =
	/(^|[\s`("'])((?:scripts|references|assets|evals)\/[A-Za-z0-9._/-]+)/gm;

export function rewriteBundledSkillPaths(
	text: string,
	parsed: ParsedSkillDirectory,
	companionRootDir: string,
): string {
	const name = parsed.manifest.name;
	const track = parsed.manifest.track;
	const normalizedRoot = trimSlashes(companionRootDir);
	const catalogPrefix = `catalog/${track}/${name}/`;
	const afterCatalog = text.split(catalogPrefix).join(`${normalizedRoot}/`);
	return afterCatalog.replace(
		BARE_COMPANION_PATH_REGEX,
		(match, prefix: string, relCompanion: string) => {
			if (relCompanion.startsWith(`${normalizedRoot}/`)) {
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
	if (rawText.startsWith("---\n") || rawText.startsWith("---\r\n")) {
		const firstNewline = rawText.indexOf("\n");
		const closingLf = rawText.indexOf("\n---\n", firstNewline);
		const closingCrLf = rawText.indexOf("\r\n---\r\n", firstNewline);
		let splitIdx = -1;
		if (
			closingLf !== -1 &&
			(closingCrLf === -1 || closingLf < closingCrLf)
		) {
			splitIdx = closingLf + "\n---\n".length;
		} else if (closingCrLf !== -1) {
			splitIdx = closingCrLf + "\r\n---\r\n".length;
		}
		if (splitIdx !== -1) {
			const fmHeader = rawText.slice(0, splitIdx);
			const bodyPart = rawText.slice(splitIdx);
			return `${fmHeader}${rewriteBundledSkillPaths(bodyPart, parsed, companionRootDir)}`;
		}
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
