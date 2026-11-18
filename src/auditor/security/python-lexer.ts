/**
 * Linear-time Python lexer with f-string interpolation support (`src/auditor/security/python-lexer.ts`).
 */

import {
	isAsciiAlnumOrUnderscore,
	isAsciiAlphaOrUnderscore,
	isAsciiDigit,
	isHexDigitCode,
} from "./constants.js";

export interface PyToken {
	readonly kind: "ident" | "string" | "punct" | "newline" | "other";
	readonly value: string;
	readonly line: number;
}

const PYTHON_STRING_PREFIXES = new Set([
	"r",
	"u",
	"b",
	"f",
	"fr",
	"rf",
	"br",
	"rb",
	"t",
	"tr",
	"rt",
]);

function decodePythonStringEscape(
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
	if (esc === "u" && k + 4 < n) {
		const hex4 = source.slice(k + 1, k + 5);
		let allHex = true;
		for (let h = 0; h < 4; h++) {
			if (!isHexDigitCode(hex4.charCodeAt(h))) {
				allHex = false;
				break;
			}
		}
		if (allHex) {
			return {
				decoded: String.fromCharCode(Number.parseInt(hex4, 16)),
				nextIdx: k + 5,
				lineDelta: 0,
			};
		}
	}
	if (esc === "U" && k + 8 < n) {
		const hex8 = source.slice(k + 1, k + 9);
		let allHex = true;
		for (let h = 0; h < 8; h++) {
			if (!isHexDigitCode(hex8.charCodeAt(h))) {
				allHex = false;
				break;
			}
		}
		if (allHex) {
			const cp = Number.parseInt(hex8, 16);
			if (cp <= 0x10ffff) {
				return {
					decoded: String.fromCodePoint(cp),
					nextIdx: k + 9,
					lineDelta: 0,
				};
			}
		}
	}
	// Octal `\ooo` (1..3 octal digits)
	if (esc >= "0" && esc <= "7") {
		let octEnd = k + 1;
		while (
			octEnd < n &&
			octEnd < k + 3 &&
			source[octEnd]! >= "0" &&
			source[octEnd]! <= "7"
		) {
			octEnd += 1;
		}
		const cp = Number.parseInt(source.slice(k, octEnd), 8);
		return {
			decoded: String.fromCodePoint(cp),
			nextIdx: octEnd,
			lineDelta: 0,
		};
	}
	if (esc === "n") return { decoded: "\n", nextIdx: k + 1, lineDelta: 0 };
	if (esc === "r") return { decoded: "\r", nextIdx: k + 1, lineDelta: 0 };
	if (esc === "t") return { decoded: "\t", nextIdx: k + 1, lineDelta: 0 };
	return { decoded: esc, nextIdx: k + 1, lineDelta: 0 };
}

interface ActivePythonFString {
	readonly quote: string;
	readonly isRaw: boolean;
	readonly baseParenDepth: number;
	readonly inFormatSpec: boolean;
}

export function tokenizePython(source: string): PyToken[] {
	const tokens: PyToken[] = [];
	const n = source.length;
	let i = 0;
	let line = 1;
	let parenDepth = 0;
	const fstringStack: ActivePythonFString[] = [];

	const consumePlainPythonString = (startLine: number, isRaw: boolean): void => {
		const next3 = source.slice(i, i + 3);
		const quote =
			next3 === '"""' || next3 === "'''" ? next3 : source[i]!;
		const isTriple = quote.length === 3;
		i += quote.length;
		let val = "";
		while (i < n) {
			if (isTriple ? source.slice(i, i + 3) === quote : source[i] === quote) {
				i += quote.length;
				tokens.push({ kind: "string", value: val, line: startLine });
				return;
			}
			if (!isTriple && source[i] === "\n") {
				tokens.push({ kind: "string", value: val, line: startLine });
				return;
			}
			if (source[i] === "\\") {
				if (isRaw) {
					val += "\\";
					i += 1;
					if (i < n) {
						if (source[i] === "\n") line += 1;
						val += source[i]!;
						i += 1;
					}
				} else {
					const esc = decodePythonStringEscape(source, i);
					val += esc.decoded;
					line += esc.lineDelta;
					i = esc.nextIdx;
				}
				continue;
			}
			if (source[i] === "\n") {
				line += 1;
			}
			val += source[i]!;
			i += 1;
		}
		tokens.push({ kind: "string", value: val, line: startLine });
	};

	const scanFStringLiteralSegment = (quote: string, isRaw: boolean): void => {
		const startLine = line;
		const isTriple = quote.length === 3;
		let val = "";
		while (i < n) {
			if (isTriple ? source.slice(i, i + 3) === quote : source[i] === quote) {
				i += quote.length;
				tokens.push({ kind: "string", value: val, line: startLine });
				return;
			}
			if (!isTriple && source[i] === "\n") {
				tokens.push({ kind: "string", value: val, line: startLine });
				return;
			}
			// Escaped literal braces `{{` and `}}`
			if (source[i] === "{" && source[i + 1] === "{") {
				val += "{";
				i += 2;
				continue;
			}
			if (source[i] === "}" && source[i + 1] === "}") {
				val += "}";
				i += 2;
				continue;
			}
			// Unescaped `{` begins an embedded Python expression
			if (source[i] === "{") {
				i += 1;
				tokens.push({ kind: "string", value: val, line: startLine });
				tokens.push({ kind: "punct", value: "+", line });
				parenDepth += 1;
				tokens.push({ kind: "punct", value: "(", line });
				fstringStack.push({
					quote,
					isRaw,
					baseParenDepth: parenDepth,
					inFormatSpec: false,
				});
				return;
			}
			if (source[i] === "\\") {
				// Named Unicode escape `\N{name}` in non-raw f-strings is NOT an expression
				if (!isRaw && source.slice(i, i + 3) === "\\N{") {
					i += 3;
					while (
						i < n &&
						source[i] !== "}" &&
						source[i] !== "\n" &&
						source[i] !== quote[0]
					) {
						i += 1;
					}
					if (i < n && source[i] === "}") {
						i += 1;
					}
					continue;
				}
				// Do NOT swallow `{` after `\` in Python f-strings (`f"\{expr}"` still evaluates `{expr}`)
				if (source[i + 1] === "{") {
					val += "\\";
					i += 1;
					continue;
				}
				if (isRaw) {
					val += "\\";
					i += 1;
					if (i < n) {
						if (source[i] === "\n") line += 1;
						val += source[i]!;
						i += 1;
					}
				} else {
					const esc = decodePythonStringEscape(source, i);
					val += esc.decoded;
					line += esc.lineDelta;
					i = esc.nextIdx;
				}
				continue;
			}
			if (source[i] === "\n") {
				line += 1;
			}
			val += source[i]!;
			i += 1;
		}
		tokens.push({ kind: "string", value: val, line: startLine });
	};

	const scanFStringFormatSpec = (): void => {
		const parent = fstringStack[fstringStack.length - 1];
		if (!parent) return;
		const isTriple = parent.quote.length === 3;
		while (i < n) {
			if (!isTriple && source[i] === "\n") {
				return;
			}
			// Nested `{expr}` inside format spec (`f"{val:{eval('8')}d}"`)
			if (source[i] === "{") {
				i += 1;
				tokens.push({ kind: "punct", value: "+", line });
				parenDepth += 1;
				tokens.push({ kind: "punct", value: "(", line });
				fstringStack.push({
					quote: parent.quote,
					isRaw: parent.isRaw,
					baseParenDepth: parenDepth,
					inFormatSpec: true,
				});
				return;
			}
			// Closing `}` of the outer f-string interpolation
			if (source[i] === "}") {
				fstringStack.pop();
				if (parenDepth > 0) {
					parenDepth -= 1;
				}
				tokens.push({ kind: "punct", value: ")", line });
				tokens.push({ kind: "punct", value: "+", line });
				i += 1;
				scanFStringLiteralSegment(parent.quote, parent.isRaw);
				return;
			}
			if (source[i] === "\n") {
				line += 1;
			}
			i += 1;
		}
	};

	while (i < n) {
		const ch = source[i]!;

		if (ch === "\r") {
			i += 1;
			continue;
		}

		if (ch === "\n") {
			if (parenDepth === 0) {
				tokens.push({ kind: "newline", value: "\n", line });
			}
			line += 1;
			i += 1;
			continue;
		}

		// Explicit backslash line continuation (`\` followed by optional spaces/CR and `\n`)
		if (ch === "\\") {
			let lookahead = i + 1;
			while (
				lookahead < n &&
				(source[lookahead] === " " ||
					source[lookahead] === "\t" ||
					source[lookahead] === "\r")
			) {
				lookahead += 1;
			}
			if (lookahead < n && source[lookahead] === "\n") {
				line += 1;
				i = lookahead + 1;
				continue;
			}
			i += 1;
			continue;
		}

		if (ch === " " || ch === "\t" || ch === "\f" || ch === "\v") {
			i += 1;
			continue;
		}

		// Handle active f-string interpolation boundaries before normal punctuation
		if (fstringStack.length > 0) {
			const top = fstringStack[fstringStack.length - 1]!;
			if (parenDepth === top.baseParenDepth) {
				if (ch === "}") {
					fstringStack.pop();
					if (parenDepth > 0) {
						parenDepth -= 1;
					}
					tokens.push({ kind: "punct", value: ")", line });
					tokens.push({ kind: "punct", value: "+", line });
					i += 1;
					if (top.inFormatSpec) {
						scanFStringFormatSpec();
					} else {
						scanFStringLiteralSegment(top.quote, top.isRaw);
					}
					continue;
				}
				// `!r` / `!s` / `!a` conversion specifier (distinct from `!=`)
				if (
					ch === "!" &&
					source[i + 1] !== "=" &&
					(source[i + 1] === "r" ||
						source[i + 1] === "s" ||
						source[i + 1] === "a") &&
					(source[i + 2] === ":" || source[i + 2] === "}")
				) {
					i += 2;
					continue;
				}
				// `:format_spec` introducer (distinct from `:=` walrus operator)
				if (ch === ":" && source[i + 1] !== "=" && !top.inFormatSpec) {
					i += 1;
					scanFStringFormatSpec();
					continue;
				}
			}
		}

		// Comment until end of physical line (`\` inside comment never continues the comment)
		if (ch === "#") {
			while (i < n && source[i] !== "\n") {
				i += 1;
			}
			continue;
		}

		if (ch === '"' || ch === "'") {
			consumePlainPythonString(line, false);
			continue;
		}

		if (isAsciiAlphaOrUnderscore(ch)) {
			const start = i;
			const startLine = line;
			while (i < n && isAsciiAlnumOrUnderscore(source[i]!)) {
				i += 1;
			}
			const ident = source.slice(start, i);
			const lowerIdent = ident.toLowerCase();
			if (
				ident.length <= 2 &&
				PYTHON_STRING_PREFIXES.has(lowerIdent) &&
				i < n &&
				(source[i] === '"' || source[i] === "'")
			) {
				const isRaw = lowerIdent.includes("r");
				const isFormatted =
					lowerIdent.includes("f") || lowerIdent.includes("t");
				if (isFormatted) {
					const next3 = source.slice(i, i + 3);
					const quote =
						next3 === '"""' || next3 === "'''" ? next3 : source[i]!;
					i += quote.length;
					scanFStringLiteralSegment(quote, isRaw);
				} else {
					consumePlainPythonString(startLine, isRaw);
				}
				continue;
			}
			tokens.push({ kind: "ident", value: ident, line: startLine });
			continue;
		}

		if (isAsciiDigit(ch)) {
			const startLine = line;
			while (
				i < n &&
				(isAsciiAlnumOrUnderscore(source[i]!) || source[i] === ".")
			) {
				i += 1;
			}
			tokens.push({ kind: "other", value: "0", line: startLine });
			continue;
		}

		if (ch === "(" || ch === "[" || ch === "{") {
			parenDepth += 1;
			tokens.push({ kind: "punct", value: ch, line });
			i += 1;
			continue;
		}

		if (ch === ")" || ch === "]" || ch === "}") {
			if (parenDepth > 0) {
				parenDepth -= 1;
			}
			tokens.push({ kind: "punct", value: ch, line });
			i += 1;
			continue;
		}

		if (
			ch === "." ||
			ch === "," ||
			ch === ";" ||
			ch === ":" ||
			ch === "=" ||
			ch === "*" ||
			ch === "+"
		) {
			if (ch === "=" && source[i + 1] === "=") {
				tokens.push({ kind: "punct", value: "==", line });
				i += 2;
				continue;
			}
			tokens.push({ kind: "punct", value: ch, line });
			i += 1;
			continue;
		}

		tokens.push({ kind: "other", value: ch, line });
		i += 1;
	}

	return tokens;
}
