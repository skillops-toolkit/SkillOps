import path from "node:path";
import { makeLongLineFinding } from "./allowlist.js";
import {
	isHexDigitCode,
	MAX_SCANNED_LINE_LENGTH,
	type SkillSecurityFinding,
	type SkillSecurityRuleId,
} from "./constants.js";

const PROMPT_OVERRIDE_TARGETS = new Set([
	"previous",
	"prior",
	"above",
	"earlier",
	"system",
	"developer",
	"safety",
	"guardrail",
	"guardrails",
	"instruction",
	"instructions",
	"prompt",
	"prompts",
	"rule",
	"rules",
	"guideline",
	"guidelines",
	"constraint",
	"constraints",
]);

const OVERRIDE_MODIFIER_PREFIXES = new Set([
	"system",
	"developer",
	"admin",
	"security",
	"safety",
]);

function extractAsciiWordsBounded(text: string, maxChars = 8192): string[] {
	const words: string[] = [];
	const limit = Math.min(text.length, maxChars);
	let current = "";
	for (let i = 0; i < limit; i++) {
		const code = text.charCodeAt(i);
		if (code >= 65 && code <= 90) {
			current += String.fromCharCode(code + 32);
		} else if ((code >= 97 && code <= 122) || (code >= 48 && code <= 57)) {
			current += text[i]!;
		} else if (current.length > 0) {
			words.push(current);
			current = "";
		}
	}
	if (current.length > 0) {
		words.push(current);
	}
	return words;
}

function hasHiddenCommentOverrideDirective(commentBody: string): boolean {
	const words = extractAsciiWordsBounded(commentBody);
	for (let i = 0; i < words.length; i++) {
		const w = words[i]!;
		if (w === "jailbreak" || w === "exfiltrate") {
			return true;
		}
		if (w === "ignore" || w === "disregard" || w === "forget") {
			const windowEnd = Math.min(words.length, i + 5);
			for (let j = i + 1; j < windowEnd; j++) {
				if (PROMPT_OVERRIDE_TARGETS.has(words[j]!)) {
					return true;
				}
			}
		}
		if (w === "override") {
			if (i > 0 && OVERRIDE_MODIFIER_PREFIXES.has(words[i - 1]!)) {
				return true;
			}
			const windowEnd = Math.min(words.length, i + 5);
			for (let j = i + 1; j < windowEnd; j++) {
				if (PROMPT_OVERRIDE_TARGETS.has(words[j]!)) {
					return true;
				}
			}
		}
		if (
			w === "bypass" &&
			i + 1 < words.length &&
			(words[i + 1] === "safety" ||
				words[i + 1] === "security" ||
				words[i + 1] === "guardrails" ||
				words[i + 1] === "guardrail")
		) {
			return true;
		}
		if (
			(w === "new" || w === "reveal" || w === "dump" || w === "leak") &&
			words[i + 1] === "system" &&
			(words[i + 2] === "prompt" || words[i + 2] === "instructions")
		) {
			return true;
		}
		if (
			w === "do" &&
			words[i + 1] === "anything" &&
			words[i + 2] === "now"
		) {
			return true;
		}
	}
	return false;
}

function normalizeUriSchemePrefix(rawTarget: string): string {
	const limit = Math.min(rawTarget.length, 160);
	let decoded = "";
	let i = 0;
	while (i < limit && decoded.length < 48) {
		const ch = rawTarget[i]!;
		const code = ch.charCodeAt(0);
		if (code <= 0x20 || code === 0x7f) {
			i += 1;
			continue;
		}
		// Decode `%XX` percent-encoded ASCII characters
		if (
			ch === "%" &&
			i + 2 < limit &&
			isHexDigitCode(rawTarget.charCodeAt(i + 1)) &&
			isHexDigitCode(rawTarget.charCodeAt(i + 2))
		) {
			const byteVal = Number.parseInt(rawTarget.slice(i + 1, i + 3), 16);
			if (byteVal > 0x20 && byteVal < 0x7f) {
				decoded += String.fromCharCode(byteVal).toLowerCase();
			}
			i += 3;
			continue;
		}
		// Decode numeric/named HTML entities (`&#58;`, `&#x3a;`, `&colon;`)
		if (ch === "&") {
			const semi = rawTarget.indexOf(";", i + 1);
			if (semi !== -1 && semi - i <= 10) {
				const entity = rawTarget.slice(i + 1, semi).toLowerCase();
				if (entity === "colon") {
					decoded += ":";
					i = semi + 1;
					continue;
				}
				if (entity.startsWith("#x")) {
					const hexStr = entity.slice(2);
					if (hexStr.length > 0 && hexStr.length <= 6) {
						const cp = Number.parseInt(hexStr, 16);
						if (!Number.isNaN(cp) && cp > 0x20 && cp < 0x7f) {
							decoded += String.fromCharCode(cp).toLowerCase();
						}
						i = semi + 1;
						continue;
					}
				} else if (entity.startsWith("#")) {
					const decStr = entity.slice(1);
					if (decStr.length > 0 && decStr.length <= 7) {
						const cp = Number.parseInt(decStr, 10);
						if (!Number.isNaN(cp) && cp > 0x20 && cp < 0x7f) {
							decoded += String.fromCharCode(cp).toLowerCase();
						}
						i = semi + 1;
						continue;
					}
				}
			}
		}
		decoded += ch.toLowerCase();
		i += 1;
	}
	return decoded;
}

function classifyMarkdownUriViolation(
	rawTarget: string,
	isImage: boolean,
): { rule: SkillSecurityRuleId; symbol: string; message: string } | null {
	const trimmed = rawTarget.trim();
	if (!trimmed) {
		return null;
	}
	const scheme = normalizeUriSchemePrefix(trimmed);
	if (scheme.startsWith("javascript:")) {
		return {
			rule: "forbidden-prompt-injection",
			symbol: "javascript:",
			message: "Forbidden executable 'javascript:' URI in Markdown content.",
		};
	}
	if (scheme.startsWith("vbscript:")) {
		return {
			rule: "forbidden-prompt-injection",
			symbol: "vbscript:",
			message: "Forbidden executable 'vbscript:' URI in Markdown content.",
		};
	}
	if (scheme.startsWith("data:text/html")) {
		return {
			rule: "forbidden-prompt-injection",
			symbol: "data:text/html",
			message: "Forbidden executable 'data:text/html' URI in Markdown content.",
		};
	}
	if (scheme.startsWith("data:text/javascript")) {
		return {
			rule: "forbidden-prompt-injection",
			symbol: "data:text/javascript",
			message:
				"Forbidden executable 'data:text/javascript' URI in Markdown content.",
		};
	}
	if (scheme.startsWith("data:application/")) {
		return {
			rule: "forbidden-prompt-injection",
			symbol: "data:application/",
			message:
				"Forbidden executable 'data:application/' URI in Markdown content.",
		};
	}
	if (isImage) {
		if (scheme.startsWith("https://")) {
			return {
				rule: "forbidden-external-markdown-image",
				symbol: "https://",
				message:
					"Forbidden external Markdown image URL ('https://'); agent instructions must not embed remote image beacons.",
			};
		}
		if (scheme.startsWith("http://")) {
			return {
				rule: "forbidden-external-markdown-image",
				symbol: "http://",
				message:
					"Forbidden external Markdown image URL ('http://'); agent instructions must not embed remote image beacons.",
			};
		}
		if (scheme.startsWith("//")) {
			return {
				rule: "forbidden-external-markdown-image",
				symbol: "//",
				message:
					"Forbidden protocol-relative external Markdown image URL ('//'); agent instructions must not embed remote image beacons.",
			};
		}
	}
	return null;
}

function maskMarkdownInlineCodeSpans(line: string): string {
	let out = "";
	let i = 0;
	const n = line.length;
	while (i < n) {
		if (line[i] === "\\" && i + 1 < n) {
			out += line.slice(i, i + 2);
			i += 2;
			continue;
		}
		if (line[i] === "`") {
			let tickLen = 0;
			while (i + tickLen < n && line[i + tickLen] === "`") {
				tickLen += 1;
			}
			// Find matching backtick run of identical length
			let closePos = -1;
			let scan = i + tickLen;
			while (scan < n) {
				if (line[scan] === "`") {
					let run = 0;
					while (scan + run < n && line[scan + run] === "`") {
						run += 1;
					}
					if (run === tickLen) {
						closePos = scan;
						break;
					}
					scan += run;
				} else {
					scan += 1;
				}
			}
			if (closePos !== -1) {
				const spanTotal = closePos + tickLen - i;
				out += " ".repeat(spanTotal);
				i = closePos + tickLen;
				continue;
			}
			out += "`".repeat(tickLen);
			i += tickLen;
			continue;
		}
		out += line[i]!;
		i += 1;
	}
	return out;
}

function findLineForOffset(lineStarts: readonly number[], offset: number): number {
	let lo = 0;
	let hi = lineStarts.length - 1;
	while (lo <= hi) {
		const mid = (lo + hi) >>> 1;
		if (lineStarts[mid]! <= offset) {
			lo = mid + 1;
		} else {
			hi = mid - 1;
		}
	}
	return Math.max(1, hi + 1);
}

function parseMarkdownFencePrefix(
	line: string,
): { char: "`" | "~"; count: number; hasRestNonSpace: boolean } | null {
	let idx = 0;
	while (idx < 3 && idx < line.length && line[idx] === " ") {
		idx += 1;
	}
	const ch = line[idx];
	if (ch !== "`" && ch !== "~") {
		return null;
	}
	let count = 0;
	while (idx + count < line.length && line[idx + count] === ch) {
		count += 1;
	}
	if (count < 3) {
		return null;
	}
	const rest = line.slice(idx + count).trim();
	// In CommonMark, backtick info strings cannot contain backticks
	if (ch === "`" && rest.includes("`")) {
		return null;
	}
	return { char: ch, count, hasRestNonSpace: rest.length > 0 };
}

function scanHtmlTagsOnLineForUris(
	relFile: string,
	lineNo: number,
	cleanLine: string,
	findings: SkillSecurityFinding[],
): void {
	let pos = 0;
	const n = cleanLine.length;
	while (pos < n) {
		const lt = cleanLine.indexOf("<", pos);
		if (lt === -1) break;
		const gt = cleanLine.indexOf(">", lt + 1);
		if (gt === -1) break;
		const inner = cleanLine.slice(lt + 1, gt).trim();
		pos = gt + 1;
		if (!inner || inner.startsWith("!") || inner.startsWith("/")) {
			continue;
		}

		// Autolink `<javascript:alert(1)>` or `<data:text/html,...>`
		if (!inner.includes(" ") && !inner.includes("\t") && inner.includes(":")) {
			const autoViolation = classifyMarkdownUriViolation(inner, false);
			if (autoViolation) {
				findings.push({ file: relFile, line: lineNo, ...autoViolation });
			}
			continue;
		}

		// HTML element `<img src="...">` / `<a href="...">` / `<iframe src="...">`
		let tagEnd = 0;
		while (
			tagEnd < inner.length &&
			inner[tagEnd] !== " " &&
			inner[tagEnd] !== "\t" &&
			inner[tagEnd] !== "/"
		) {
			tagEnd += 1;
		}
		const tagName = inner.slice(0, tagEnd).toLowerCase();
		const isImg = tagName === "img";
		let attrIdx = tagEnd;
		while (attrIdx < inner.length) {
			while (
				attrIdx < inner.length &&
				(inner[attrIdx] === " " || inner[attrIdx] === "\t")
			) {
				attrIdx += 1;
			}
			const nameStart = attrIdx;
			while (
				attrIdx < inner.length &&
				inner[attrIdx] !== "=" &&
				inner[attrIdx] !== " " &&
				inner[attrIdx] !== "\t"
			) {
				attrIdx += 1;
			}
			const attrName = inner.slice(nameStart, attrIdx).toLowerCase();
			while (
				attrIdx < inner.length &&
				(inner[attrIdx] === " " || inner[attrIdx] === "\t")
			) {
				attrIdx += 1;
			}
			if (inner[attrIdx] !== "=") {
				continue;
			}
			attrIdx += 1;
			while (
				attrIdx < inner.length &&
				(inner[attrIdx] === " " || inner[attrIdx] === "\t")
			) {
				attrIdx += 1;
			}
			let attrVal = "";
			const quote = inner[attrIdx];
			if (quote === '"' || quote === "'") {
				attrIdx += 1;
				const closeQuote = inner.indexOf(quote, attrIdx);
				if (closeQuote === -1) {
					attrVal = inner.slice(attrIdx);
					attrIdx = inner.length;
				} else {
					attrVal = inner.slice(attrIdx, closeQuote);
					attrIdx = closeQuote + 1;
				}
			} else {
				const valStart = attrIdx;
				while (
					attrIdx < inner.length &&
					inner[attrIdx] !== " " &&
					inner[attrIdx] !== "\t" &&
					inner[attrIdx] !== "/"
				) {
					attrIdx += 1;
				}
				attrVal = inner.slice(valStart, attrIdx);
			}
			if (attrName === "href" || attrName === "src") {
				const v = classifyMarkdownUriViolation(
					attrVal,
					isImg && attrName === "src",
				);
				if (v) {
					findings.push({ file: relFile, line: lineNo, ...v });
				}
			}
		}
	}
}

/**
 * Deterministically scan Markdown instructions (`SKILL.md`, `SUBAGENT.md`, `references/*.md`)
 * in linear O(n) time for HTML-comment override directives, executable `javascript:`/`data:`
 * links, and external Markdown image beacons (`![...](http/https/...)`).
 */
export function scanMarkdownForPromptInjection(
	relFile: string,
	rawContent: string,
): SkillSecurityFinding[] {
	const findings: SkillSecurityFinding[] = [];
	const rawLines = rawContent.split(/\r?\n/);
	const boundedLines: string[] = [];
	const lineStarts: number[] = [];
	let currentOffset = 0;

	for (let idx = 0; idx < rawLines.length; idx++) {
		const rawLine = rawLines[idx] ?? "";
		lineStarts.push(currentOffset);
		if (rawLine.length > MAX_SCANNED_LINE_LENGTH) {
			findings.push(makeLongLineFinding(relFile, idx + 1, rawLine.length));
			boundedLines.push("");
			currentOffset += 1;
		} else {
			boundedLines.push(rawLine);
			currentOffset += rawLine.length + 1;
		}
	}

	const safeDoc = boundedLines.join("\n");

	// 1. Scan single-line and multi-line HTML comments `<!-- ... -->` in O(n) time
	let searchPos = 0;
	while (searchPos < safeDoc.length) {
		const openIdx = safeDoc.indexOf("<!--", searchPos);
		if (openIdx === -1) {
			break;
		}
		const closeIdx = safeDoc.indexOf("-->", openIdx + 4);
		const bodyEnd = closeIdx === -1 ? safeDoc.length : closeIdx;
		const commentBody = safeDoc.slice(openIdx + 4, bodyEnd);
		if (hasHiddenCommentOverrideDirective(commentBody)) {
			const commentLine = findLineForOffset(lineStarts, openIdx);
			findings.push({
				file: relFile,
				line: commentLine,
				rule: "forbidden-prompt-injection",
				symbol: "<!-- prompt-override -->",
				message: `Forbidden prompt-injection override directive hidden inside HTML comment in '${relFile}'.`,
			});
		}
		searchPos = closeIdx === -1 ? safeDoc.length : closeIdx + 3;
	}

	// 2. Scan Markdown links, images, reference definitions, and HTML tags outside code fences/spans
	let fenceChar: "`" | "~" | null = null;
	let fenceCount = 0;
	const refDefinitions = new Map<string, { target: string; line: number }>();
	const refImageUsages: Array<{ refKey: string; line: number }> = [];

	for (let idx = 0; idx < boundedLines.length; idx++) {
		const line = boundedLines[idx]!;
		const lineNo = idx + 1;
		if (!line) continue;

		const fence = parseMarkdownFencePrefix(line);
		if (fence) {
			if (fenceChar === null) {
				fenceChar = fence.char;
				fenceCount = fence.count;
				continue;
			}
			if (
				fence.char === fenceChar &&
				fence.count >= fenceCount &&
				!fence.hasRestNonSpace
			) {
				fenceChar = null;
				fenceCount = 0;
				continue;
			}
		}
		if (fenceChar !== null) {
			continue;
		}

		const cleanLine = maskMarkdownInlineCodeSpans(line);

		// Reference-style link/image definition: `   [id]: https://...`
		const trimmedStart = cleanLine.trimStart();
		const leadingSpaces = cleanLine.length - trimmedStart.length;
		if (leadingSpaces <= 3 && trimmedStart.startsWith("[")) {
			const closeRef = trimmedStart.indexOf("]:");
			if (closeRef > 1) {
				const refId = trimmedStart.slice(1, closeRef).trim().toLowerCase();
				let restTarget = trimmedStart.slice(closeRef + 2).trim();
				if (restTarget.startsWith("<")) {
					const closeAngle = restTarget.indexOf(">");
					restTarget =
						closeAngle !== -1
							? restTarget.slice(1, closeAngle)
							: restTarget.slice(1);
				} else {
					let endTarget = 0;
					while (
						endTarget < restTarget.length &&
						restTarget[endTarget] !== " " &&
						restTarget[endTarget] !== "\t"
					) {
						endTarget += 1;
					}
					restTarget = restTarget.slice(0, endTarget);
				}
				if (refId && restTarget) {
					refDefinitions.set(refId, { target: restTarget, line: lineNo });
					const defViolation = classifyMarkdownUriViolation(restTarget, false);
					if (defViolation) {
						findings.push({ file: relFile, line: lineNo, ...defViolation });
					}
				}
			}
		}

		// Inline links `[label](target)` and images `![alt](target)` / `![alt][ref]`
		let i = 0;
		const n = cleanLine.length;
		while (i < n) {
			if (cleanLine[i] === "\\" && i + 1 < n) {
				i += 2;
				continue;
			}
			if (cleanLine[i] === "[") {
				const isImage =
					i > 0 &&
					cleanLine[i - 1] === "!" &&
					!(i >= 2 && cleanLine[i - 2] === "\\");
				// Find matching unescaped `]`
				let bracketDepth = 1;
				let j = i + 1;
				while (j < n && bracketDepth > 0) {
					if (cleanLine[j] === "\\") {
						j += 2;
						continue;
					}
					if (cleanLine[j] === "[") {
						bracketDepth += 1;
					} else if (cleanLine[j] === "]") {
						bracketDepth -= 1;
						if (bracketDepth === 0) break;
					}
					j += 1;
				}
				if (bracketDepth === 0 && j < n) {
					const labelText = cleanLine.slice(i + 1, j);
					if (j + 1 < n && cleanLine[j + 1] === "(") {
						let k = j + 2;
						while (k < n && (cleanLine[k] === " " || cleanLine[k] === "\t")) {
							k += 1;
						}
						let target = "";
						if (cleanLine[k] === "<") {
							const closeAngle = cleanLine.indexOf(">", k + 1);
							if (closeAngle !== -1) {
								target = cleanLine.slice(k + 1, closeAngle);
								const closeParen = cleanLine.indexOf(")", closeAngle + 1);
								i = closeParen !== -1 ? closeParen + 1 : closeAngle + 1;
							} else {
								i = j + 2;
							}
						} else {
							const targetStart = k;
							let parenDepth = 0;
							while (k < n) {
								const c = cleanLine[k]!;
								if (c === "\\" && k + 1 < n) {
									k += 2;
									continue;
								}
								if (c === "(") {
									parenDepth += 1;
								} else if (c === ")") {
									if (parenDepth === 0) break;
									parenDepth -= 1;
								} else if (
									parenDepth === 0 &&
									(c === " " || c === "\t")
								) {
									break;
								}
								k += 1;
							}
							target = cleanLine.slice(targetStart, k);
							const closeParen = cleanLine.indexOf(")", k);
							i = closeParen !== -1 ? closeParen + 1 : k + 1;
						}
						const violation = classifyMarkdownUriViolation(target, isImage);
						if (violation) {
							findings.push({ file: relFile, line: lineNo, ...violation });
						}
						continue;
					}
					// Reference-style image `![alt][ref]` or `![ref][]` or `![ref]`
					if (isImage) {
						if (j + 1 < n && cleanLine[j + 1] === "[") {
							const closeSecond = cleanLine.indexOf("]", j + 2);
							if (closeSecond !== -1) {
								const rawRef = cleanLine.slice(j + 2, closeSecond).trim();
								const refKey = (rawRef || labelText).trim().toLowerCase();
								if (refKey) {
									refImageUsages.push({ refKey, line: lineNo });
								}
								i = closeSecond + 1;
								continue;
							}
						} else if (cleanLine[j + 1] !== ":") {
							const refKey = labelText.trim().toLowerCase();
							if (refKey) {
								refImageUsages.push({ refKey, line: lineNo });
							}
						}
					}
				}
			}
			i += 1;
		}

		// HTML `<img src="...">` / `<a href="...">` / `<javascript:...>`
		scanHtmlTagsOnLineForUris(relFile, lineNo, cleanLine, findings);
	}

	for (const usage of refImageUsages) {
		const def = refDefinitions.get(usage.refKey);
		if (def) {
			const imgViolation = classifyMarkdownUriViolation(def.target, true);
			if (
				imgViolation &&
				imgViolation.rule === "forbidden-external-markdown-image"
			) {
				findings.push({
					file: relFile,
					line: usage.line,
					...imgViolation,
				});
			}
		}
	}

	return findings;
}

export function shouldScanMarkdownPromptInjection(relFile: string): boolean {
	const normalized = relFile.replace(/\\/g, "/");
	const lower = normalized.toLowerCase();
	const base = path.posix.basename(lower);
	if (base === "skill.md" || base === "subagent.md") {
		return true;
	}
	if (lower.endsWith(".md") || lower.endsWith(".mdc")) {
		if (
			lower.startsWith("references/") ||
			lower.includes("/references/") ||
			lower.startsWith("subagents/") ||
			lower.includes("/subagents/")
		) {
			return true;
		}
	}
	return false;
}
