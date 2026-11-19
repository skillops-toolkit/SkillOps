import path from "node:path";
import { makeLongLineFinding } from "./allowlist.js";
import {
	BASE64_PIPE_INTERPRETERS,
	DEV_SOCKET_REGEX,
	FORBIDDEN_SHELL_NETWORK_COMMANDS,
	FORBIDDEN_SHELL_SUBINTERPRETERS,
	MAX_SCANNED_LINE_LENGTH,
	SHELL_COMMAND_WRAPPERS,
	SHELL_PIPE_INTERPRETERS,
	type SkillSecurityRuleId,
	type SkillSecurityFinding,
} from "./constants.js";

function stripShellInlineCommentAndCheckContinuation(rawLine: string): {
	uncommented: string;
	continuesNext: boolean;
} {
	let inSingle = false;
	let inDouble = false;
	for (let i = 0; i < rawLine.length; i++) {
		const ch = rawLine[i]!;
		if (ch === "\\" && !inSingle) {
			if (i + 1 === rawLine.length) {
				return {
					uncommented: rawLine.slice(0, i),
					continuesNext: true,
				};
			}
			i += 1;
			continue;
		}
		if (ch === "'" && !inDouble) {
			inSingle = !inSingle;
			continue;
		}
		if (ch === '"' && !inSingle) {
			inDouble = !inDouble;
			continue;
		}
		if (
			ch === "#" &&
			!inSingle &&
			!inDouble &&
			(i === 0 || rawLine[i - 1] === " " || rawLine[i - 1] === "\t")
		) {
			return {
				uncommented: rawLine.slice(0, i),
				continuesNext: false,
			};
		}
	}
	return { uncommented: rawLine, continuesNext: false };
}

interface ParsedShellCommand {
	readonly words: string[];
	readonly pipelineId: number;
	readonly pipedToNext: boolean;
}

interface ShellLexerFrame {
	readonly kind: "top" | "$(" | "`" | "<(" | "(";
	readonly resumeQuote: "unquoted" | "double";
	words: string[];
	currentWord: string;
	wordTouched: boolean;
	pipelineId: number;
}

/**
 * Single-pass linear O(n) shell command & substitution parser.
 * Extracts simple commands across pipelines (`|`), chains (`&&`, `||`, `;`, `&`),
 * command substitutions (`$(...)` and backticks, including inside double quotes),
 * process substitutions (`<(...)`, `>(...)`), and subshells (`(...)`).
 */
function parseShellLogicalLineCommands(line: string): ParsedShellCommand[] {
	const commands: ParsedShellCommand[] = [];
	let nextPipelineId = 1;

	let frame: ShellLexerFrame = {
		kind: "top",
		resumeQuote: "unquoted",
		words: [],
		currentWord: "",
		wordTouched: false,
		pipelineId: nextPipelineId++,
	};
	let quoteMode: "unquoted" | "single" | "double" = "unquoted";
	const stack: ShellLexerFrame[] = [];

	const flushWord = (f: ShellLexerFrame): void => {
		if (f.wordTouched) {
			f.words.push(f.currentWord);
			f.currentWord = "";
			f.wordTouched = false;
		}
	};

	const emitCommand = (f: ShellLexerFrame, pipedToNext: boolean): void => {
		flushWord(f);
		if (f.words.length > 0) {
			commands.push({
				words: f.words,
				pipelineId: f.pipelineId,
				pipedToNext,
			});
			f.words = [];
		}
		if (!pipedToNext) {
			f.pipelineId = nextPipelineId++;
		}
	};

	const pushSubshellFrame = (
		kind: "$(" | "`" | "<(" | "(",
		resumeQuote: "unquoted" | "double",
	): void => {
		stack.push(frame);
		frame = {
			kind,
			resumeQuote,
			words: [],
			currentWord: "",
			wordTouched: false,
			pipelineId: nextPipelineId++,
		};
		quoteMode = "unquoted";
	};

	const popSubshellFrame = (): void => {
		emitCommand(frame, false);
		const parent = stack.pop();
		if (parent) {
			quoteMode = parent.resumeQuote;
			frame = parent;
		} else {
			quoteMode = "unquoted";
		}
	};

	for (let i = 0; i < line.length; i++) {
		const ch = line[i]!;

		if (quoteMode === "single") {
			if (ch === "'") {
				quoteMode = "unquoted";
			} else {
				frame.currentWord += ch;
				frame.wordTouched = true;
			}
			continue;
		}

		if (quoteMode === "double") {
			if (ch === '"') {
				quoteMode = "unquoted";
				continue;
			}
			if (ch === "\\" && i + 1 < line.length) {
				const nextCh = line[i + 1]!;
				if (
					nextCh === "$" ||
					nextCh === "`" ||
					nextCh === '"' ||
					nextCh === "\\"
				) {
					frame.currentWord += nextCh;
					frame.wordTouched = true;
					i += 1;
					continue;
				}
				frame.currentWord += ch;
				frame.wordTouched = true;
				continue;
			}
			if (ch === "$" && line[i + 1] === "(") {
				frame.wordTouched = true;
				pushSubshellFrame("$(", "double");
				i += 1;
				continue;
			}
			if (ch === "`") {
				if (frame.kind === "`") {
					popSubshellFrame();
				} else {
					frame.wordTouched = true;
					pushSubshellFrame("`", "double");
				}
				continue;
			}
			frame.currentWord += ch;
			frame.wordTouched = true;
			continue;
		}

		// Unquoted mode
		if (ch === "#" && !frame.wordTouched) {
			break;
		}
		if (ch === "'") {
			quoteMode = "single";
			frame.wordTouched = true;
			continue;
		}
		if (ch === '"') {
			quoteMode = "double";
			frame.wordTouched = true;
			continue;
		}
		if (ch === "\\" && i + 1 < line.length) {
			frame.currentWord += line[i + 1]!;
			frame.wordTouched = true;
			i += 1;
			continue;
		}
		if (ch === "$" && line[i + 1] === "(") {
			frame.wordTouched = true;
			pushSubshellFrame("$(", "unquoted");
			i += 1;
			continue;
		}
		if ((ch === "<" || ch === ">") && line[i + 1] === "(") {
			flushWord(frame);
			pushSubshellFrame("<(", "unquoted");
			i += 1;
			continue;
		}
		if (ch === "(") {
			emitCommand(frame, false);
			pushSubshellFrame("(", "unquoted");
			continue;
		}
		if (ch === ")") {
			if (stack.length > 0 && frame.kind !== "`") {
				popSubshellFrame();
			} else {
				emitCommand(frame, false);
			}
			continue;
		}
		if (ch === "`") {
			if (frame.kind === "`") {
				popSubshellFrame();
			} else {
				frame.wordTouched = true;
				pushSubshellFrame("`", "unquoted");
			}
			continue;
		}
		if (ch === " " || ch === "\t" || ch === "\r") {
			flushWord(frame);
			continue;
		}
		if (ch === "|") {
			if (line[i + 1] === "|") {
				emitCommand(frame, false);
				i += 1;
			} else {
				emitCommand(frame, true);
			}
			continue;
		}
		if (ch === ";" || ch === "&") {
			emitCommand(frame, false);
			if (ch === "&" && line[i + 1] === "&") {
				i += 1;
			}
			continue;
		}
		if (
			(ch === "{" || ch === "}") &&
			!frame.wordTouched &&
			(i + 1 >= line.length ||
				line[i + 1] === " " ||
				line[i + 1] === "\t" ||
				line[i + 1] === ";")
		) {
			emitCommand(frame, false);
			continue;
		}

		frame.currentWord += ch;
		frame.wordTouched = true;
	}

	while (stack.length > 0) {
		popSubshellFrame();
	}
	emitCommand(frame, false);

	return commands;
}

function extractLeadingCommandFromWords(words: readonly string[]): string {
	let idx = 0;
	while (idx < words.length) {
		const w = words[idx]!;
		if (w.includes("=") && !w.startsWith("-")) {
			idx += 1;
			continue;
		}
		const base = path.posix.basename(w.replace(/\\/g, "/")).toLowerCase();
		if (SHELL_COMMAND_WRAPPERS.has(base)) {
			idx += 1;
			while (idx < words.length && words[idx]!.startsWith("-")) {
				const flag = words[idx]!;
				idx += 1;
				if (
					base === "sudo" &&
					(flag === "-u" || flag === "-g") &&
					idx < words.length
				) {
					idx += 1;
				}
			}
			continue;
		}
		if (w.startsWith("-")) {
			idx += 1;
			continue;
		}
		return w;
	}
	return "";
}

export function scanShellScriptContent(
	relFile: string,
	rawContent: string,
): SkillSecurityFinding[] {
	const findings: SkillSecurityFinding[] = [];
	const lines = rawContent.split(/\r?\n/);
	const logicalLines: Array<{ lineNo: number; text: string }> = [];

	// 1. Enforce MAX_SCANNED_LINE_LENGTH and join `\`-continued lines
	let accText = "";
	let accStartLine = 1;
	let inContinuation = false;

	for (let idx = 0; idx < lines.length; idx++) {
		const rawLine = lines[idx] ?? "";
		const lineNo = idx + 1;

		if (rawLine.length > MAX_SCANNED_LINE_LENGTH) {
			findings.push(makeLongLineFinding(relFile, lineNo, rawLine.length));
			accText = "";
			inContinuation = false;
			continue;
		}

		// A comment line starting with `#` never continues onto the next line
		if (!inContinuation && rawLine.trimStart().startsWith("#")) {
			continue;
		}

		const { uncommented, continuesNext } =
			stripShellInlineCommentAndCheckContinuation(rawLine);

		if (!inContinuation) {
			accStartLine = lineNo;
			accText = uncommented;
		} else {
			accText += ` ${uncommented}`;
		}

		if (accText.length > MAX_SCANNED_LINE_LENGTH) {
			findings.push(makeLongLineFinding(relFile, accStartLine, accText.length));
			accText = "";
			inContinuation = continuesNext;
			if (continuesNext) {
				accStartLine = lineNo + 1;
			}
			continue;
		}

		if (continuesNext) {
			inContinuation = true;
		} else {
			if (accText.trim().length > 0) {
				logicalLines.push({ lineNo: accStartLine, text: accText });
			}
			accText = "";
			inContinuation = false;
		}
	}

	if (inContinuation && accText.trim().length > 0) {
		logicalLines.push({ lineNo: accStartLine, text: accText });
	}

	// 2. Scan joined logical lines for pipelines, substitutions, and forbidden commands
	for (const { lineNo, text } of logicalLines) {
		const seenLineSymbols = new Set<string>();
		const pushFindingOnce = (
			rule: SkillSecurityRuleId,
			symbol: string,
			message: string,
		): void => {
			const key = `${rule}:${symbol}`;
			if (!seenLineSymbols.has(key)) {
				seenLineSymbols.add(key);
				findings.push({ file: relFile, line: lineNo, rule, symbol, message });
			}
		};

		const commands = parseShellLogicalLineCommands(text);

		// Pipeline checks (`curl | sh`, `Invoke-WebRequest | iex`, `base64 -d | sh`, including `/bin/sh` & `/usr/bin/env bash`)
		for (let c = 0; c + 1 < commands.length; c++) {
			const left = commands[c]!;
			const right = commands[c + 1]!;
			if (!left.pipedToNext || left.pipelineId !== right.pipelineId) {
				continue;
			}
			const leftBases = left.words.map((w) =>
				path.posix.basename(w.replace(/\\/g, "/")),
			);
			const rightLeadRaw = extractLeadingCommandFromWords(right.words);
			const rightBase = path.posix.basename(rightLeadRaw.replace(/\\/g, "/"));
			const rightLower = rightBase.toLowerCase();

			const downloader = leftBases.find((w) => w === "curl" || w === "wget");
			if (downloader && SHELL_PIPE_INTERPRETERS.has(rightLower)) {
				pushFindingOnce(
					"forbidden-network-import",
					`${downloader} | ${rightBase}`,
					`Forbidden remote pipe execution '${downloader} | ${rightBase}' in Skill shell script.`,
				);
			}

			const psDownloader = leftBases.find((w) => {
				const low = w.toLowerCase();
				return (
					low === "invoke-webrequest" ||
					low === "invoke-restmethod" ||
					low === "iwr" ||
					low === "irm"
				);
			});
			if (
				psDownloader &&
				(rightLower === "iex" ||
					rightLower === "invoke-expression" ||
					rightLower === "pwsh" ||
					rightLower === "powershell")
			) {
				pushFindingOnce(
					"forbidden-network-import",
					psDownloader,
					`Forbidden remote PowerShell execution cradle '${psDownloader}' in Skill script.`,
				);
			}

			const hasBase64 = leftBases.includes("base64");
			const hasDecodeFlag =
				left.words.includes("-d") ||
				left.words.includes("-D") ||
				left.words.includes("--decode");
			if (hasBase64 && hasDecodeFlag && BASE64_PIPE_INTERPRETERS.has(rightLower)) {
				pushFindingOnce(
					"forbidden-dynamic-exec",
					"base64 -d | sh",
					"Forbidden obfuscated base64 pipe execution in Skill shell script.",
				);
			}
		}

		// Reverse shell `/dev/tcp/` or `/dev/udp/`
		const devSockMatch = DEV_SOCKET_REGEX.exec(text);
		if (devSockMatch?.[0]) {
			pushFindingOnce(
				"forbidden-shell-execution",
				devSockMatch[0],
				"Forbidden reverse-shell primitive detected in Skill shell script.",
			);
		}

		// Unconditional command checks across top-level commands, `$(...)`, backticks, and `<(...)`
		for (const cmd of commands) {
			const leadRaw = extractLeadingCommandFromWords(cmd.words);
			if (!leadRaw) continue;
			const leadBase = path.posix.basename(leadRaw.replace(/\\/g, "/"));
			const leadLower = leadBase.toLowerCase();

			if (
				leadLower === "nc" ||
				leadLower === "ncat" ||
				leadLower === "netcat"
			) {
				const hasExecOrListenFlag = cmd.words.some(
					(t) => t === "-e" || t === "-c" || t === "-l",
				);
				if (hasExecOrListenFlag) {
					pushFindingOnce(
						"forbidden-shell-execution",
						leadBase,
						"Forbidden reverse-shell primitive detected in Skill shell script.",
					);
				} else {
					pushFindingOnce(
						"forbidden-network-import",
						leadBase,
						`Forbidden raw socket utility '${leadBase}' in Skill shell script (violates zero-network policy).`,
					);
				}
				continue;
			}

			if (FORBIDDEN_SHELL_NETWORK_COMMANDS.has(leadLower)) {
				pushFindingOnce(
					"forbidden-network-import",
					leadBase,
					`Forbidden outbound network/transfer command '${leadBase}' in Skill shell script (violates zero-network policy).`,
				);
				continue;
			}

			if (
				leadLower === "eval" ||
				leadLower === "iex" ||
				leadLower === "invoke-expression"
			) {
				pushFindingOnce(
					"forbidden-dynamic-exec",
					leadBase,
					`Forbidden dynamic command evaluation '${leadBase}' in Skill shell script.`,
				);
				continue;
			}

			if (FORBIDDEN_SHELL_SUBINTERPRETERS.has(leadLower)) {
				pushFindingOnce(
					"forbidden-shell-execution",
					leadRaw,
					`Forbidden nested shell interpreter invocation '${leadRaw}' in Skill shell script.`,
				);
			}
		}
	}

	return findings;
}
