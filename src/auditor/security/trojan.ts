import { makeLongLineFinding } from "./allowlist.js";
import {
	MAX_SCANNED_LINE_LENGTH,
	SCRIPT_ZERO_WIDTH_REGEX,
	type SkillSecurityFinding,
	TROJAN_BIDI_OR_TAG_REGEX,
} from "./constants.js";

/**
 * Scan raw text content for oversized lines (`MAX_SCANNED_LINE_LENGTH`), Trojan-Source
 * bidirectional overrides, LLM Unicode Tag smuggling, and (when `isExecutableScript` is true)
 * zero-width identifier spoofing characters.
 */
export function scanTextForTrojanUnicode(
	relFile: string,
	rawContent: string,
	isExecutableScript: boolean,
): SkillSecurityFinding[] {
	const findings: SkillSecurityFinding[] = [];
	// Strip a leading UTF-8 BOM at index 0 if present; mid-file BOM is still flagged
	const normalized = rawContent.startsWith("\uFEFF")
		? rawContent.slice(1)
		: rawContent;
	const lines = normalized.split(/\r?\n/);

	for (let idx = 0; idx < lines.length; idx++) {
		const line = lines[idx] ?? "";
		const lineNo = idx + 1;

		if (line.length > MAX_SCANNED_LINE_LENGTH) {
			findings.push(makeLongLineFinding(relFile, lineNo, line.length));
			continue;
		}

		const bidiMatch = TROJAN_BIDI_OR_TAG_REGEX.exec(line);
		if (bidiMatch?.[0]) {
			const cp = bidiMatch[0]
				.codePointAt(0)!
				.toString(16)
				.toUpperCase()
				.padStart(4, "0");
			findings.push({
				file: relFile,
				line: lineNo,
				rule: "forbidden-trojan-unicode",
				symbol: `U+${cp}`,
				message: `Forbidden Trojan-Source / invisible control character U+${cp} detected in '${relFile}'.`,
			});
			continue;
		}

		if (isExecutableScript) {
			const zwMatch = SCRIPT_ZERO_WIDTH_REGEX.exec(line);
			if (zwMatch?.[0]) {
				const cp = zwMatch[0]
					.codePointAt(0)!
					.toString(16)
					.toUpperCase()
					.padStart(4, "0");
				findings.push({
					file: relFile,
					line: lineNo,
					rule: "forbidden-trojan-unicode",
					symbol: `U+${cp}`,
					message: `Forbidden zero-width character U+${cp} detected in executable script '${relFile}'.`,
				});
			}
		}
	}

	return findings;
}
