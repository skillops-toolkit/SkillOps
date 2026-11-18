/**
 * Linear-time JS/TS lexer with Unicode/hex escape decoding (`src/auditor/security/js-ts-lexer.ts`).
 */

import {
	isAsciiAlnumOrUnderscore,
	isAsciiAlphaOrUnderscore,
	isAsciiDigit,
	isHexDigitCode,
} from "./constants.js";

export interface JsToken {
	readonly kind: "ident" | "string" | "punct";
	readonly value: string;
	readonly line: number;
	readonly escaped?: boolean;
}

const JS_REGEX_PRECEDING_PUNCT = new Set([
	"(",
	"[",
	"{",
	"}",
	";",
	",",
	":",
	"=",
	"==",
	"===",
	"!=",
	"!==",
	"!",
	"&",
	"&&",
	"|",
	"||",
	"??",
	"?",
	"~",
	"^",
	"+",
	"-",
	"*",
	"%",
	"<",
	">",
	"<=",
	">=",
	"=>",
]);

const JS_REGEX_PRECEDING_KEYWORDS = new Set([
	"return",
	"throw",
	"case",
	"typeof",
	"void",
	"delete",
	"in",
	"of",
	"instanceof",
	"new",
	"await",
	"yield",
	"do",
	"else",
]);

export const JS_METHOD_MODIFIERS = new Set([
	"async",
	"static",
	"public",
	"private",
	"protected",
	"readonly",
	"override",
	"get",
	"set",
]);

export const JS_EXPR_FORCING_OPERATORS = new Set([
	"=",
	"==",
	"===",
	"!=",
	"!==",
	"(",
	"[",
	":",
	"=>",
	"!",
	"&&",
	"||",
	"?",
	"??",
	"+",
	"-",
	"*",
	"/",
	"%",
	".",
	"?.",
]);

export const JS_EXPR_FORCING_KEYWORDS = new Set([
	"return",
	"throw",
	"await",
	"new",
	"typeof",
	"void",
	"delete",
	"yield",
	"case",
]);

function isJsIdentStart(ch: string): boolean {
	return isAsciiAlphaOrUnderscore(ch) || ch === "$";
}

function isJsIdentPart(ch: string): boolean {
	return isAsciiAlnumOrUnderscore(ch) || ch === "$";
}

function canStartJsRegexLiteral(prev: JsToken | undefined): boolean {
	if (!prev) return true;
	if (prev.kind === "punct") {
		return JS_REGEX_PRECEDING_PUNCT.has(prev.value);
	}
	if (prev.kind === "ident") {
		return JS_REGEX_PRECEDING_KEYWORDS.has(prev.value);
	}
	return false;
}

function decodeJsUnicodeEscape(
	source: string,
	slashIdx: number,
): { decoded: string; nextIdx: number } | null {
	const n = source.length;
	if (source[slashIdx] !== "\\" || source[slashIdx + 1] !== "u") {
		return null;
	}
	const uIdx = slashIdx + 2;
	if (uIdx >= n) {
		return null;
	}
	if (source[uIdx] === "{") {
		let scan = uIdx + 1;
		while (scan < n && isHexDigitCode(source.charCodeAt(scan))) {
			scan += 1;
		}
		if (scan > uIdx + 1 && scan < n && source[scan] === "}") {
			const hexStr = source.slice(uIdx + 1, scan);
			if (hexStr.length <= 8) {
				const cp = Number.parseInt(hexStr, 16);
				if (!Number.isNaN(cp) && cp <= 0x10ffff) {
					return { decoded: String.fromCodePoint(cp), nextIdx: scan + 1 };
				}
			}
		}
		return null;
	}
	if (uIdx + 4 <= n) {
		let allHex = true;
		for (let h = 0; h < 4; h++) {
			if (!isHexDigitCode(source.charCodeAt(uIdx + h))) {
				allHex = false;
				break;
			}
		}
		if (allHex) {
			const cp = Number.parseInt(source.slice(uIdx, uIdx + 4), 16);
			return { decoded: String.fromCharCode(cp), nextIdx: uIdx + 4 };
		}
	}
	return null;
}

function decodeJsStringEscape(
	source: string,
	slashIdx: number,
): { decoded: string; nextIdx: number; lineDelta: number } {
	const n = source.length;
	const k = slashIdx + 1;
	if (k >= n) {
		return { decoded: "\\", nextIdx: k, lineDelta: 0 };
	}
	const esc = source[k]!;
	if (esc === "\n") {
		return { decoded: "", nextIdx: k + 1, lineDelta: 1 };
	}
	if (esc === "\r") {
		if (source[k + 1] === "\n") {
			return { decoded: "", nextIdx: k + 2, lineDelta: 1 };
		}
		return { decoded: "", nextIdx: k + 1, lineDelta: 0 };
	}
	if (
		esc === "x" &&
		k + 2 < n &&
		isHexDigitCode(source.charCodeAt(k + 1)) &&
		isHexDigitCode(source.charCodeAt(k + 2))
	) {
		const cp = Number.parseInt(source.slice(k + 1, k + 3), 16);
		return { decoded: String.fromCodePoint(cp), nextIdx: k + 3, lineDelta: 0 };
	}
	if (esc === "u") {
		const uni = decodeJsUnicodeEscape(source, slashIdx);
		if (uni) {
			return { decoded: uni.decoded, nextIdx: uni.nextIdx, lineDelta: 0 };
		}
	}
	if (esc === "n") return { decoded: "\n", nextIdx: k + 1, lineDelta: 0 };
	if (esc === "r") return { decoded: "\r", nextIdx: k + 1, lineDelta: 0 };
	if (esc === "t") return { decoded: "\t", nextIdx: k + 1, lineDelta: 0 };
	if (esc === "0") return { decoded: "\0", nextIdx: k + 1, lineDelta: 0 };
	return { decoded: esc, nextIdx: k + 1, lineDelta: 0 };
}

export function tokenizeJsOrTs(source: string): JsToken[] {
	const tokens: JsToken[] = [];
	const n = source.length;
	let i = 0;
	let line = 1;
	let braceDepth = 0;
	const templateResumeBraceStack: number[] = [];

	const scanTemplateSegment = (): void => {
		const startLine = line;
		let textVal = "";
		while (i < n) {
			const ch = source[i]!;
			if (ch === "\\") {
				const esc = decodeJsStringEscape(source, i);
				textVal += esc.decoded;
				line += esc.lineDelta;
				i = esc.nextIdx;
				continue;
			}
			if (ch === "`") {
				i += 1;
				tokens.push({ kind: "string", value: textVal, line: startLine });
				return;
			}
			if (ch === "$" && source[i + 1] === "{") {
				tokens.push({ kind: "string", value: textVal, line: startLine });
				tokens.push({ kind: "punct", value: "+", line });
				tokens.push({ kind: "punct", value: "(", line });
				templateResumeBraceStack.push(braceDepth);
				i += 2;
				return;
			}
			if (ch === "\n") {
				line += 1;
			}
			textVal += ch;
			i += 1;
		}
		tokens.push({ kind: "string", value: textVal, line: startLine });
	};

	while (i < n) {
		const ch = source[i]!;
		const next2 = source.slice(i, i + 2);

		if (ch === "\r") {
			i += 1;
			continue;
		}

		if (ch === "\n") {
			line += 1;
			i += 1;
			continue;
		}

		if (ch === " " || ch === "\t" || ch === "\f" || ch === "\v") {
			i += 1;
			continue;
		}

		// Single-line comment
		if (next2 === "//") {
			while (i < n && source[i] !== "\n") {
				i += 1;
			}
			continue;
		}

		// Multi-line comment
		if (next2 === "/*") {
			i += 2;
			while (i < n && source.slice(i, i + 2) !== "*/") {
				if (source[i] === "\n") {
					line += 1;
				}
				i += 1;
			}
			if (i < n) {
				i += 2;
			}
			continue;
		}

		// Single or double quoted string (decoding `\xHH`, `\uHHHH`, `\u{H+}`)
		if (ch === "'" || ch === '"') {
			const quote = ch;
			const startLine = line;
			let val = "";
			i += 1;
			while (i < n && source[i] !== quote && source[i] !== "\n") {
				if (source[i] === "\\") {
					const esc = decodeJsStringEscape(source, i);
					val += esc.decoded;
					line += esc.lineDelta;
					i = esc.nextIdx;
					continue;
				}
				val += source[i]!;
				i += 1;
			}
			if (i < n && source[i] === quote) {
				i += 1;
			}
			tokens.push({ kind: "string", value: val, line: startLine });
			continue;
		}

		// Template literal
		if (ch === "`") {
			i += 1;
			scanTemplateSegment();
			continue;
		}

		// Closing brace of `${ ... }` template expression
		if (
			ch === "}" &&
			templateResumeBraceStack.length > 0 &&
			templateResumeBraceStack[templateResumeBraceStack.length - 1] ===
				braceDepth
		) {
			templateResumeBraceStack.pop();
			tokens.push({ kind: "punct", value: ")", line });
			tokens.push({ kind: "punct", value: "+", line });
			i += 1;
			scanTemplateSegment();
			continue;
		}

		// Regex literal `/.../`
		if (
			ch === "/" &&
			next2 !== "//" &&
			next2 !== "/*" &&
			canStartJsRegexLiteral(tokens[tokens.length - 1])
		) {
			const startLine = line;
			let scan = i + 1;
			let inClass = false;
			let closed = false;
			while (scan < n && source[scan] !== "\n") {
				const rc = source[scan]!;
				if (rc === "\\") {
					scan += 2;
					continue;
				}
				if (rc === "[") {
					inClass = true;
				} else if (rc === "]") {
					inClass = false;
				} else if (rc === "/" && !inClass) {
					closed = true;
					scan += 1;
					while (scan < n && isAsciiAlphaOrUnderscore(source[scan]!)) {
						scan += 1;
					}
					break;
				}
				scan += 1;
			}
			if (closed) {
				tokens.push({ kind: "punct", value: "/regex/", line: startLine });
				i = scan;
				continue;
			}
		}

		// Identifier or keyword (supporting `\uHHHH` and `\u{H+}` Unicode escapes)
		if (isJsIdentStart(ch) || (ch === "\\" && source[i + 1] === "u")) {
			const startLine = line;
			let identVal = "";
			let hadEscape = false;
			let validIdent = true;

			if (ch === "\\") {
				const uni = decodeJsUnicodeEscape(source, i);
				if (uni) {
					identVal += uni.decoded;
					i = uni.nextIdx;
					hadEscape = true;
				} else {
					validIdent = false;
				}
			} else {
				identVal += ch;
				i += 1;
			}

			if (validIdent) {
				while (i < n) {
					const partCh = source[i]!;
					if (isJsIdentPart(partCh)) {
						identVal += partCh;
						i += 1;
					} else if (partCh === "\\" && source[i + 1] === "u") {
						const uni = decodeJsUnicodeEscape(source, i);
						if (!uni) break;
						identVal += uni.decoded;
						i = uni.nextIdx;
						hadEscape = true;
					} else {
						break;
					}
				}
				tokens.push({
					kind: "ident",
					value: identVal,
					line: startLine,
					escaped: hadEscape,
				});
				continue;
			}
		}

		// Numeric literal
		if (isAsciiDigit(ch)) {
			const startLine = line;
			while (i < n && (isJsIdentPart(source[i]!) || source[i] === ".")) {
				i += 1;
			}
			tokens.push({ kind: "punct", value: "0", line: startLine });
			continue;
		}

		// Multi-character operators
		const next3 = source.slice(i, i + 3);
		if (next3 === "===" || next3 === "!==") {
			tokens.push({ kind: "punct", value: next3, line });
			i += 3;
			continue;
		}
		if (
			next2 === "=>" ||
			next2 === "==" ||
			next2 === "!=" ||
			next2 === "<=" ||
			next2 === ">=" ||
			next2 === "&&" ||
			next2 === "||" ||
			next2 === "??" ||
			next2 === "?."
		) {
			tokens.push({ kind: "punct", value: next2, line });
			i += 2;
			continue;
		}

		if (ch === "{") {
			braceDepth += 1;
		} else if (ch === "}" && braceDepth > 0) {
			braceDepth -= 1;
		}

		tokens.push({ kind: "punct", value: ch, line });
		i += 1;
	}

	return tokens;
}
