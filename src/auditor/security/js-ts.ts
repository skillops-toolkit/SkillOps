import { makeLongLineFinding } from "./allowlist.js";
import {
	FORBIDDEN_JS_EXEC_MODULES,
	FORBIDDEN_JS_NETWORK_MODULES,
	FORBIDDEN_JS_SHELL_MODULES,
	FORBIDDEN_PROCESS_METHODS,
	GLOBAL_JS_OBJECTS,
	MAX_SCANNED_LINE_LENGTH,
	type SkillSecurityFinding,
	type SkillSecurityRuleId,
} from "./constants.js";
import {
	JS_EXPR_FORCING_KEYWORDS,
	JS_EXPR_FORCING_OPERATORS,
	JS_METHOD_MODIFIERS,
	type JsToken,
	tokenizeJsOrTs,
} from "./js-ts-lexer.js";

function classifyJsModuleSpecifier(
	rawSpec: string,
): { rule: SkillSecurityRuleId; symbol: string; message: string } | null {
	const trimmed = rawSpec.trim();
	if (!trimmed) return null;
	const lower = trimmed.toLowerCase();
	if (lower.startsWith("data:")) {
		return {
			rule: "forbidden-dynamic-exec",
			symbol: "data:",
			message: `Forbidden 'data:' module specifier '${trimmed.slice(0, 32)}' in Skill script.`,
		};
	}
	if (lower.startsWith("http://") || lower.startsWith("https://")) {
		return {
			rule: "forbidden-network-import",
			symbol: lower.startsWith("https://") ? "https://" : "http://",
			message: `Forbidden remote URL module specifier '${trimmed.slice(0, 48)}' in Skill script.`,
		};
	}

	const withoutNodePrefix = trimmed.startsWith("node:")
		? trimmed.slice(5)
		: trimmed;
	const rootMod = withoutNodePrefix.split("/")[0] ?? "";

	if (FORBIDDEN_JS_SHELL_MODULES.has(rootMod)) {
		return {
			rule: "forbidden-shell-execution",
			symbol: rootMod,
			message: `Forbidden Node.js child process module '${trimmed}' imported in Skill script.`,
		};
	}

	if (FORBIDDEN_JS_EXEC_MODULES.has(rootMod)) {
		return {
			rule: "forbidden-dynamic-exec",
			symbol: rootMod,
			message: `Forbidden Node.js execution/runtime module '${trimmed}' imported in Skill script.`,
		};
	}

	if (FORBIDDEN_JS_NETWORK_MODULES.has(rootMod)) {
		return {
			rule: "forbidden-network-import",
			symbol: rootMod,
			message: `Forbidden outbound network module '${trimmed}' imported in Skill script (violates zero-network policy).`,
		};
	}

	return null;
}

function getCallOpenParenIndex(
	tokens: readonly JsToken[],
	identIdx: number,
): number {
	const next = tokens[identIdx + 1];
	if (next?.kind === "punct" && next.value === "(") {
		return identIdx + 1;
	}
	if (
		next?.kind === "punct" &&
		next.value === "?." &&
		tokens[identIdx + 2]?.kind === "punct" &&
		tokens[identIdx + 2]?.value === "("
	) {
		return identIdx + 2;
	}
	return -1;
}

function getBracketOpenIndex(
	tokens: readonly JsToken[],
	identIdx: number,
): number {
	const next = tokens[identIdx + 1];
	if (next?.kind === "punct" && next.value === "[") {
		return identIdx + 1;
	}
	if (
		next?.kind === "punct" &&
		next.value === "?." &&
		tokens[identIdx + 2]?.kind === "punct" &&
		tokens[identIdx + 2]?.value === "["
	) {
		return identIdx + 2;
	}
	return -1;
}

function findMatchingCloseParen(
	tokens: readonly JsToken[],
	openParenIdx: number,
): number {
	let depth = 1;
	for (let i = openParenIdx + 1; i < tokens.length; i++) {
		const tok = tokens[i]!;
		if (tok.kind === "punct" && tok.value === "(") {
			depth += 1;
		} else if (tok.kind === "punct" && tok.value === ")") {
			depth -= 1;
			if (depth === 0) {
				return i;
			}
		}
	}
	return -1;
}

function findMatchingCloseBracket(
	tokens: readonly JsToken[],
	openBracketIdx: number,
): number {
	let depth = 1;
	for (let i = openBracketIdx + 1; i < tokens.length; i++) {
		const tok = tokens[i]!;
		if (tok.kind === "punct" && tok.value === "[") {
			depth += 1;
		} else if (tok.kind === "punct" && tok.value === "]") {
			depth -= 1;
			if (depth === 0) {
				return i;
			}
		}
	}
	return -1;
}

function findMatchingCloseBrace(
	tokens: readonly JsToken[],
	startIdx: number,
): number {
	let depth = 1;
	for (let i = startIdx; i < tokens.length; i++) {
		const tok = tokens[i]!;
		if (tok.kind === "punct" && tok.value === "{") {
			depth += 1;
		} else if (tok.kind === "punct" && tok.value === "}") {
			depth -= 1;
			if (depth === 0) {
				return i;
			}
		}
	}
	return -1;
}

function isJsMethodOrFunctionDeclaration(
	tokens: readonly JsToken[],
	identIdx: number,
): boolean {
	const prev = tokens[identIdx - 1];
	if (prev?.kind === "ident" && prev.value === "function") {
		return true;
	}
	if (
		prev?.kind === "punct" &&
		prev.value === "*" &&
		tokens[identIdx - 2]?.kind === "ident" &&
		tokens[identIdx - 2]?.value === "function"
	) {
		return true;
	}

	let prefixIdx = identIdx - 1;
	while (
		prefixIdx >= 0 &&
		tokens[prefixIdx]?.kind === "ident" &&
		JS_METHOD_MODIFIERS.has(tokens[prefixIdx]!.value)
	) {
		prefixIdx -= 1;
	}
	const beforePrefix = prefixIdx >= 0 ? tokens[prefixIdx] : undefined;
	if (beforePrefix?.kind === "ident" && beforePrefix.value === "function") {
		return true;
	}
	if (
		beforePrefix?.kind === "punct" &&
		JS_EXPR_FORCING_OPERATORS.has(beforePrefix.value)
	) {
		return false;
	}
	if (
		beforePrefix?.kind === "ident" &&
		JS_EXPR_FORCING_KEYWORDS.has(beforePrefix.value)
	) {
		return false;
	}

	const openParenIdx =
		tokens[identIdx + 1]?.kind === "punct" && tokens[identIdx + 1]?.value === "("
			? identIdx + 1
			: -1;
	if (openParenIdx === -1) {
		return false;
	}
	const closeParenIdx = findMatchingCloseParen(tokens, openParenIdx);
	if (closeParenIdx === -1) {
		return false;
	}

	const afterParen = tokens[closeParenIdx + 1];
	if (afterParen?.kind === "punct" && afterParen.value === "{") {
		return true;
	}

	// Optional TypeScript return type annotation `: ReturnType {`
	if (afterParen?.kind === "punct" && afterParen.value === ":") {
		let angleDepth = 0;
		let parenDepth = 0;
		for (let k = closeParenIdx + 2; k < tokens.length; k++) {
			const t = tokens[k]!;
			if (t.kind === "punct") {
				if (t.value === "<") angleDepth += 1;
				else if (t.value === ">" && angleDepth > 0) angleDepth -= 1;
				else if (t.value === "(") parenDepth += 1;
				else if (t.value === ")" && parenDepth > 0) parenDepth -= 1;
				else if (angleDepth === 0 && parenDepth === 0) {
					if (t.value === "{") return true;
					if (t.value === ";" || t.value === "=" || t.value === ",") {
						return false;
					}
				}
			}
		}
	}

	return false;
}

function isGlobalOrBareMemberAccess(
	tokens: readonly JsToken[],
	identIdx: number,
	jsAliases: ReadonlyMap<string, string>,
): boolean {
	const prev = tokens[identIdx - 1];
	if (!prev || prev.kind !== "punct") {
		return true;
	}
	if (prev.value !== "." && prev.value !== "?.") {
		return true;
	}
	const receiver = tokens[identIdx - 2];
	if (receiver?.kind !== "ident") {
		return false;
	}
	const resolved = jsAliases.get(receiver.value) ?? receiver.value;
	return GLOBAL_JS_OBJECTS.has(resolved);
}

export function scanJsOrTsScriptContent(
	relFile: string,
	rawContent: string,
): SkillSecurityFinding[] {
	const findings: SkillSecurityFinding[] = [];
	const rawLines = rawContent.split(/\r?\n/);
	const sanitizedLines: string[] = [];

	for (let idx = 0; idx < rawLines.length; idx++) {
		const rawLine = rawLines[idx] ?? "";
		if (rawLine.length > MAX_SCANNED_LINE_LENGTH) {
			findings.push(makeLongLineFinding(relFile, idx + 1, rawLine.length));
			sanitizedLines.push("");
		} else {
			sanitizedLines.push(rawLine);
		}
	}

	const tokens = tokenizeJsOrTs(sanitizedLines.join("\n"));
	const jsAliases = new Map<string, string>();

	for (let idx = 0; idx < tokens.length; idx++) {
		const tok = tokens[idx]!;
		const prev = idx > 0 ? tokens[idx - 1] : undefined;

		// Track simple aliases (`const p = process`, `const g = globalThis`, `const R = Reflect`)
		if (
			tok.kind === "ident" &&
			tokens[idx + 1]?.kind === "punct" &&
			tokens[idx + 1]?.value === "=" &&
			tokens[idx + 2]?.kind === "ident"
		) {
			const rhsResolved =
				jsAliases.get(tokens[idx + 2]!.value) ?? tokens[idx + 2]!.value;
			if (
				rhsResolved === "process" ||
				rhsResolved === "Reflect" ||
				rhsResolved === "module" ||
				GLOBAL_JS_OBJECTS.has(rhsResolved)
			) {
				jsAliases.set(tok.value, rhsResolved);
			}
		}

		// Track destructuring from `Reflect` or `process` (`const { apply, construct } = Reflect`)
		if (tok.kind === "punct" && tok.value === "{") {
			const closeBrace = findMatchingCloseBrace(tokens, idx + 1);
			if (
				closeBrace !== -1 &&
				tokens[closeBrace + 1]?.kind === "punct" &&
				tokens[closeBrace + 1]?.value === "=" &&
				tokens[closeBrace + 2]?.kind === "ident"
			) {
				const rhsObj =
					jsAliases.get(tokens[closeBrace + 2]!.value) ??
					tokens[closeBrace + 2]!.value;
				if (rhsObj === "Reflect" || rhsObj === "process") {
					for (let k = idx + 1; k < closeBrace; k++) {
						const propTok = tokens[k]!;
						if (propTok.kind !== "ident") continue;
						const prevProp = tokens[k - 1];
						if (prevProp?.kind === "punct" && prevProp.value === ":") continue;
						if (
							rhsObj === "Reflect" &&
							(propTok.value === "apply" || propTok.value === "construct")
						) {
							findings.push({
								file: relFile,
								line: propTok.line,
								rule: "forbidden-dynamic-exec",
								symbol: `Reflect.${propTok.value}()`,
								message: `Forbidden 'Reflect.${propTok.value}' reflection destructuring in Skill script.`,
							});
						} else if (
							rhsObj === "process" &&
							FORBIDDEN_PROCESS_METHODS.has(propTok.value)
						) {
							findings.push({
								file: relFile,
								line: propTok.line,
								rule: "forbidden-dynamic-exec",
								symbol: `process.${propTok.value}()`,
								message: `Forbidden 'process.${propTok.value}' destructuring in Skill script.`,
							});
						}
					}
				}
			}
		}

		// 1. Static ESM `import "spec"` or `import/export ... from "spec"`
		if (
			tok.kind === "ident" &&
			(tok.value === "import" || tok.value === "from") &&
			tokens[idx + 1]?.kind === "string"
		) {
			const specTok = tokens[idx + 1]!;
			const violation = classifyJsModuleSpecifier(specTok.value);
			if (violation) {
				findings.push({
					file: relFile,
					line: specTok.line,
					...violation,
				});
			}
			continue;
		}

		// 2. Dynamic `import(...)`
		if (tok.kind === "ident" && tok.value === "import") {
			const openParenIdx = getCallOpenParenIndex(tokens, idx);
			const isMember =
				prev?.kind === "punct" && (prev.value === "." || prev.value === "?.");
			if (
				openParenIdx !== -1 &&
				!isMember &&
				!isJsMethodOrFunctionDeclaration(tokens, idx)
			) {
				const argTok = tokens[openParenIdx + 1];
				if (argTok?.kind === "string") {
					const modViolation = classifyJsModuleSpecifier(argTok.value);
					if (modViolation) {
						findings.push({
							file: relFile,
							line: tok.line,
							...modViolation,
						});
					}
				}
				findings.push({
					file: relFile,
					line: tok.line,
					rule: "forbidden-dynamic-exec",
					symbol: "import()",
					message: "Forbidden dynamic 'import()' expression in Skill script.",
				});
				continue;
			}
		}

		// 3. CommonJS `require("spec")`, non-literal `require(x)`, aliased `const r = require`, and `createRequire(...)`
		if (tok.kind === "ident" && tok.value === "require") {
			if (isJsMethodOrFunctionDeclaration(tokens, idx)) {
				continue;
			}
			// Ignore non-destructuring object literal key `{ require: true }`
			if (
				prev?.kind === "punct" &&
				(prev.value === "{" || prev.value === ",") &&
				tokens[idx + 1]?.kind === "punct" &&
				tokens[idx + 1]?.value === ":"
			) {
				const closeBrace = findMatchingCloseBrace(tokens, idx + 1);
				const isDestructuring =
					closeBrace !== -1 &&
					tokens[closeBrace + 1]?.kind === "punct" &&
					tokens[closeBrace + 1]?.value === "=";
				if (!isDestructuring) {
					continue;
				}
			}

			const isMember =
				prev?.kind === "punct" && (prev.value === "." || prev.value === "?.");
			const memberRecvTok = isMember ? tokens[idx - 2] : undefined;
			const resolvedMemberRecv =
				memberRecvTok?.kind === "ident"
					? (jsAliases.get(memberRecvTok.value) ?? memberRecvTok.value)
					: "";
			const isNodeRequire =
				!isMember ||
				resolvedMemberRecv === "module" ||
				GLOBAL_JS_OBJECTS.has(resolvedMemberRecv);

			if (isNodeRequire) {
				const openParenIdx = getCallOpenParenIndex(tokens, idx);
				if (openParenIdx !== -1) {
					const closeParenIdx = findMatchingCloseParen(tokens, openParenIdx);
					const argTok = tokens[openParenIdx + 1];
					const isSingleStaticString =
						argTok?.kind === "string" &&
						(closeParenIdx === openParenIdx + 2 ||
							(tokens[openParenIdx + 2]?.kind === "punct" &&
								tokens[openParenIdx + 2]?.value === "," &&
								closeParenIdx === openParenIdx + 3));
					if (!isSingleStaticString) {
						findings.push({
							file: relFile,
							line: tok.line,
							rule: "forbidden-dynamic-exec",
							symbol: "require()",
							message:
								"Forbidden non-literal dynamic 'require()' call in Skill script.",
						});
					} else {
						const violation = classifyJsModuleSpecifier(argTok.value);
						if (violation) {
							findings.push({
								file: relFile,
								line: tok.line,
								...violation,
							});
						}
					}
				} else if (
					!(prev?.kind === "ident" && prev.value === "typeof") &&
					!(
						prev?.kind === "ident" &&
						(prev.value === "import" || prev.value === "export")
					)
				) {
					findings.push({
						file: relFile,
						line: tok.line,
						rule: "forbidden-dynamic-exec",
						symbol: "require",
						message:
							"Forbidden aliasing or indirect reference to 'require' in Skill script.",
					});
				}
				continue;
			}
		}

		if (tok.kind === "ident" && tok.value === "createRequire") {
			if (!isJsMethodOrFunctionDeclaration(tokens, idx)) {
				findings.push({
					file: relFile,
					line: tok.line,
					rule: "forbidden-dynamic-exec",
					symbol: "createRequire()",
					message:
						"Forbidden dynamic CommonJS loader 'createRequire()' in Skill script.",
				});
				continue;
			}
		}

		// 4. Global `fetch(...)`
		if (tok.kind === "ident" && tok.value === "fetch") {
			const openParenIdx = getCallOpenParenIndex(tokens, idx);
			if (
				openParenIdx !== -1 &&
				isGlobalOrBareMemberAccess(tokens, idx, jsAliases) &&
				!isJsMethodOrFunctionDeclaration(tokens, idx)
			) {
				findings.push({
					file: relFile,
					line: tok.line,
					rule: "forbidden-network-import",
					symbol: "fetch()",
					message:
						"Forbidden outbound network call 'fetch()' in Skill script (violates zero-network policy).",
				});
				continue;
			}
		}

		// 5. `new WebSocket(...)` or `new globalThis.WebSocket(...)`
		if (tok.kind === "ident" && tok.value === "new") {
			const next1 = tokens[idx + 1];
			const resolvedNext1 =
				next1?.kind === "ident"
					? (jsAliases.get(next1.value) ?? next1.value)
					: "";
			const isDirectWs = next1?.kind === "ident" && next1.value === "WebSocket";
			const isGlobalWs =
				GLOBAL_JS_OBJECTS.has(resolvedNext1) &&
				tokens[idx + 2]?.kind === "punct" &&
				(tokens[idx + 2]?.value === "." || tokens[idx + 2]?.value === "?.") &&
				tokens[idx + 3]?.kind === "ident" &&
				tokens[idx + 3]?.value === "WebSocket";
			if (isDirectWs || isGlobalWs) {
				findings.push({
					file: relFile,
					line: tok.line,
					rule: "forbidden-network-import",
					symbol: "WebSocket",
					message:
						"Forbidden outbound WebSocket client 'new WebSocket()' in Skill script (violates zero-network policy).",
				});
				continue;
			}
		}

		// 6. `eval(...)` and `Function(...)` (including indirect `(0, eval)(...)`)
		if (
			tok.kind === "ident" &&
			(tok.value === "eval" || tok.value === "Function")
		) {
			const openParenIdx = getCallOpenParenIndex(tokens, idx);
			const isIndirectEval =
				tok.value === "eval" &&
				prev?.kind === "punct" &&
				prev.value === "," &&
				tokens[idx + 1]?.kind === "punct" &&
				tokens[idx + 1]?.value === ")" &&
				tokens[idx + 2]?.kind === "punct" &&
				tokens[idx + 2]?.value === "(";
			if (
				(openParenIdx !== -1 || isIndirectEval) &&
				isGlobalOrBareMemberAccess(tokens, idx, jsAliases) &&
				!isJsMethodOrFunctionDeclaration(tokens, idx)
			) {
				findings.push({
					file: relFile,
					line: tok.line,
					rule: "forbidden-dynamic-exec",
					symbol: `${tok.value}()`,
					message: `Forbidden dynamic code execution '${tok.value}()' in Skill script.`,
				});
				continue;
			}
		}

		// 7. Function `constructor("...")` prototype-chain lookup (`.constructor(...)`, `(() => {}).constructor`, `.constructor.constructor`)
		if (
			tok.kind === "ident" &&
			tok.value === "constructor" &&
			prev?.kind === "punct" &&
			(prev.value === "." || prev.value === "?.")
		) {
			const prev2 = tokens[idx - 2];
			const calledDirectly = getCallOpenParenIndex(tokens, idx) !== -1;
			const chainedConstructor =
				prev2?.kind === "ident" && prev2.value === "constructor";
			const onGroupedFnOrGlobal =
				(prev2?.kind === "punct" &&
					(prev2.value === ")" || prev2.value === "}")) ||
				(prev2?.kind === "ident" &&
					(prev2.value === "Function" || GLOBAL_JS_OBJECTS.has(prev2.value)));
			if (calledDirectly || chainedConstructor || onGroupedFnOrGlobal) {
				findings.push({
					file: relFile,
					line: tok.line,
					rule: "forbidden-dynamic-exec",
					symbol: "constructor()",
					message:
						"Forbidden dynamic Function 'constructor' lookup in Skill script.",
				});
				continue;
			}
		}

		// 8. `Reflect.apply(...)` and `Reflect.construct(...)`
		const resolvedJsIdent =
			tok.kind === "ident" ? (jsAliases.get(tok.value) ?? tok.value) : "";

		if (
			tok.kind === "ident" &&
			resolvedJsIdent === "Reflect" &&
			tokens[idx + 1]?.kind === "punct" &&
			(tokens[idx + 1]?.value === "." || tokens[idx + 1]?.value === "?.") &&
			tokens[idx + 2]?.kind === "ident" &&
			(tokens[idx + 2]?.value === "apply" ||
				tokens[idx + 2]?.value === "construct")
		) {
			const method = tokens[idx + 2]!.value;
			findings.push({
				file: relFile,
				line: tok.line,
				rule: "forbidden-dynamic-exec",
				symbol: `Reflect.${method}()`,
				message: `Forbidden dynamic invocation 'Reflect.${method}()' in Skill script.`,
			});
			continue;
		}

		// 9. `process.binding`, `process.dlopen`, `process.getBuiltinModule` (including `.getBuiltinModule` on any receiver)
		if (
			tok.kind === "ident" &&
			tok.value === "getBuiltinModule" &&
			prev?.kind === "punct" &&
			(prev.value === "." || prev.value === "?.")
		) {
			findings.push({
				file: relFile,
				line: tok.line,
				rule: "forbidden-dynamic-exec",
				symbol: "process.getBuiltinModule()",
				message:
					"Forbidden Node.js builtin loader 'process.getBuiltinModule()' in Skill script.",
			});
			continue;
		}

		if (
			tok.kind === "ident" &&
			resolvedJsIdent === "process" &&
			tokens[idx + 1]?.kind === "punct" &&
			(tokens[idx + 1]?.value === "." || tokens[idx + 1]?.value === "?.") &&
			tokens[idx + 2]?.kind === "ident" &&
			FORBIDDEN_PROCESS_METHODS.has(tokens[idx + 2]!.value)
		) {
			const method = tokens[idx + 2]!.value;
			findings.push({
				file: relFile,
				line: tok.line,
				rule: "forbidden-dynamic-exec",
				symbol: `process.${method}()`,
				message: `Forbidden Node.js runtime bridge 'process.${method}()' in Skill script.`,
			});
			continue;
		}

		// 10. Computed bracket property indexing (`globalThis["eval"]`, `globalThis["fetch"]`, `process["dlopen"]`, `process["getBuiltinModule"]`, `x["constructor"]`)
		if (
			tok.kind === "punct" &&
			tok.value === "[" &&
			tokens[idx + 1]?.kind === "string" &&
			tokens[idx + 1]?.value === "constructor" &&
			tokens[idx + 2]?.kind === "punct" &&
			tokens[idx + 2]?.value === "]"
		) {
			const prevBeforeBracket =
				prev?.kind === "punct" && prev.value === "?."
					? tokens[idx - 2]
					: prev;
			if (
				prevBeforeBracket &&
				(prevBeforeBracket.kind === "ident" ||
					prevBeforeBracket.kind === "string" ||
					(prevBeforeBracket.kind === "punct" &&
						(prevBeforeBracket.value === ")" ||
							prevBeforeBracket.value === "]" ||
							prevBeforeBracket.value === "}")))
			) {
				findings.push({
					file: relFile,
					line: tok.line,
					rule: "forbidden-dynamic-exec",
					symbol: "constructor()",
					message:
						"Forbidden computed '[\"constructor\"]' property lookup in Skill script.",
				});
			}
		}

		if (tok.kind === "ident") {
			const openBracketIdx = getBracketOpenIndex(tokens, idx);
			if (openBracketIdx !== -1) {
				const closeBracketIdx = findMatchingCloseBracket(tokens, openBracketIdx);
				const isSingleStaticKey =
					closeBracketIdx === openBracketIdx + 2 &&
					tokens[openBracketIdx + 1]?.kind === "string";
				const staticKey = isSingleStaticKey
					? tokens[openBracketIdx + 1]!.value
					: null;

				if (GLOBAL_JS_OBJECTS.has(resolvedJsIdent)) {
					if (staticKey === null) {
						findings.push({
							file: relFile,
							line: tok.line,
							rule: "forbidden-dynamic-exec",
							symbol: `${resolvedJsIdent}[]`,
							message: `Forbidden dynamic computed property access on '${resolvedJsIdent}' in Skill script.`,
						});
					} else if (staticKey === "eval" || staticKey === "Function") {
						findings.push({
							file: relFile,
							line: tok.line,
							rule: "forbidden-dynamic-exec",
							symbol: `${staticKey}()`,
							message: `Forbidden computed '${resolvedJsIdent}["${staticKey}"]' lookup in Skill script.`,
						});
					} else if (
						staticKey === "fetch" ||
						staticKey === "WebSocket" ||
						staticKey === "XMLHttpRequest"
					) {
						findings.push({
							file: relFile,
							line: tok.line,
							rule: "forbidden-network-import",
							symbol: staticKey === "fetch" ? "fetch()" : staticKey,
							message: `Forbidden computed network '${resolvedJsIdent}["${staticKey}"]' lookup in Skill script.`,
						});
					} else if (
						staticKey === "require" ||
						staticKey === "process" ||
						staticKey === "Reflect" ||
						staticKey === "import"
					) {
						findings.push({
							file: relFile,
							line: tok.line,
							rule: "forbidden-dynamic-exec",
							symbol:
								staticKey === "process"
									? "globalThis.process"
									: staticKey,
							message: `Forbidden computed '${resolvedJsIdent}["${staticKey}"]' lookup in Skill script.`,
						});
					}
				} else if (resolvedJsIdent === "process") {
					if (staticKey === null) {
						findings.push({
							file: relFile,
							line: tok.line,
							rule: "forbidden-dynamic-exec",
							symbol: "process[]",
							message:
								"Forbidden dynamic computed property access on 'process' in Skill script.",
						});
					} else if (FORBIDDEN_PROCESS_METHODS.has(staticKey)) {
						findings.push({
							file: relFile,
							line: tok.line,
							rule: "forbidden-dynamic-exec",
							symbol: `process.${staticKey}()`,
							message: `Forbidden computed 'process["${staticKey}"]' lookup in Skill script.`,
						});
					}
				} else if (resolvedJsIdent === "Reflect") {
					if (
						staticKey === null ||
						staticKey === "apply" ||
						staticKey === "construct"
					) {
						const sym =
							staticKey === null ? "Reflect[]" : `Reflect.${staticKey}()`;
						findings.push({
							file: relFile,
							line: tok.line,
							rule: "forbidden-dynamic-exec",
							symbol: sym,
							message: `Forbidden computed '${sym}' lookup in Skill script.`,
						});
					}
				}
			}
		}
	}

	return findings;
}
