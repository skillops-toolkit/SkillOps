import { makeLongLineFinding } from "./allowlist.js";
import {
	DANGEROUS_PYTHON_REFLECTION_ATTRS,
	FORBIDDEN_PYTHON_EXEC_MODULES,
	FORBIDDEN_PYTHON_NETWORK_ROOT_MODULES,
	FORBIDDEN_PYTHON_NETWORK_SUBMODULES,
	FORBIDDEN_PYTHON_OS_CALLS,
	FORBIDDEN_PYTHON_SHELL_MODULES,
	MAX_SCANNED_LINE_LENGTH,
	PYTHON_ALIASABLE_MODULES,
	type SkillSecurityFinding,
	type SkillSecurityRuleId,
} from "./constants.js";
import { type PyToken, tokenizePython } from "./python-lexer.js";

function classifyPythonModuleImport(
	modulePath: string,
	importedNames: readonly string[] = [],
): { rule: SkillSecurityRuleId; symbol: string; message: string } | null {
	const cleanPath = modulePath.trim();
	if (!cleanPath) return null;
	const parts = cleanPath.split(".");
	const rootMod = parts[0] ?? "";
	const firstTwo = parts.slice(0, 2).join(".");

	if (FORBIDDEN_PYTHON_NETWORK_ROOT_MODULES.has(rootMod)) {
		return {
			rule: "forbidden-network-import",
			symbol: rootMod,
			message: `Forbidden outbound network module '${rootMod}' imported in Skill script (violates zero-network policy).`,
		};
	}

	if (FORBIDDEN_PYTHON_NETWORK_SUBMODULES.has(firstTwo)) {
		return {
			rule: "forbidden-network-import",
			symbol: firstTwo,
			message: `Forbidden outbound network client '${firstTwo}' imported in Skill script (violates zero-network policy).`,
		};
	}

	if (rootMod === "urllib" && parts.length === 1) {
		for (const name of importedNames) {
			if (name === "request" || name === "urlopen") {
				return {
					rule: "forbidden-network-import",
					symbol: `urllib.${name}`,
					message: `Forbidden outbound network client 'urllib.${name}' imported in Skill script (violates zero-network policy).`,
				};
			}
		}
	}

	if (rootMod === "http" && parts.length === 1) {
		for (const name of importedNames) {
			if (name === "client") {
				return {
					rule: "forbidden-network-import",
					symbol: "http.client",
					message:
						"Forbidden outbound network client 'http.client' imported in Skill script (violates zero-network policy).",
				};
			}
		}
	}

	if (rootMod === "xmlrpc" && parts.length === 1) {
		for (const name of importedNames) {
			if (name === "client") {
				return {
					rule: "forbidden-network-import",
					symbol: "xmlrpc.client",
					message:
						"Forbidden outbound network client 'xmlrpc.client' imported in Skill script (violates zero-network policy).",
				};
			}
		}
	}

	if (
		(rootMod === "os" || rootMod === "posix" || rootMod === "nt") &&
		parts.length === 1
	) {
		for (const name of importedNames) {
			if (FORBIDDEN_PYTHON_OS_CALLS.has(name)) {
				return {
					rule: "forbidden-shell-execution",
					symbol: `os.${name}()`,
					message: `Forbidden shell execution function 'os.${name}()' imported in Skill script.`,
				};
			}
		}
	}

	if (FORBIDDEN_PYTHON_EXEC_MODULES.has(rootMod)) {
		return {
			rule: "forbidden-dynamic-exec",
			symbol: rootMod,
			message: `Forbidden dynamic execution / unsafe deserialization module '${rootMod}' imported in Skill script.`,
		};
	}

	if (FORBIDDEN_PYTHON_SHELL_MODULES.has(rootMod)) {
		return {
			rule: "forbidden-shell-execution",
			symbol: rootMod,
			message: `Forbidden subprocess/shell module '${rootMod}' imported in Skill script (violates zero-subprocess policy).`,
		};
	}

	return null;
}

function readDottedPythonModule(
	tokens: readonly PyToken[],
	startIdx: number,
): { modulePath: string; nextIdx: number } {
	let idx = startIdx;
	while (
		idx < tokens.length &&
		tokens[idx]?.kind === "punct" &&
		tokens[idx]?.value === "."
	) {
		idx += 1;
	}
	const parts: string[] = [];
	while (idx < tokens.length && tokens[idx]?.kind === "ident") {
		parts.push(tokens[idx]!.value);
		idx += 1;
		if (
			idx < tokens.length &&
			tokens[idx]?.kind === "punct" &&
			tokens[idx]?.value === "."
		) {
			idx += 1;
		} else {
			break;
		}
	}
	return { modulePath: parts.join("."), nextIdx: idx };
}

function splitPythonCallArguments(
	tokens: readonly PyToken[],
	openParenIdx: number,
): { args: PyToken[][]; closeParenIdx: number } {
	let depth = 1;
	let idx = openParenIdx + 1;
	const segments: PyToken[][] = [[]];

	while (idx < tokens.length && depth > 0) {
		const tok = tokens[idx]!;
		if (
			tok.kind === "punct" &&
			(tok.value === "(" || tok.value === "[" || tok.value === "{")
		) {
			depth += 1;
			segments[segments.length - 1]!.push(tok);
		} else if (
			tok.kind === "punct" &&
			(tok.value === ")" || tok.value === "]" || tok.value === "}")
		) {
			depth -= 1;
			if (depth === 0) {
				break;
			}
			segments[segments.length - 1]!.push(tok);
		} else if (depth === 1 && tok.kind === "punct" && tok.value === ",") {
			segments.push([]);
		} else if (tok.kind !== "newline") {
			segments[segments.length - 1]!.push(tok);
		}
		idx += 1;
	}

	const closeParenIdx = depth === 0 ? idx : -1;
	return {
		args: segments.filter((seg) => seg.length > 0),
		closeParenIdx,
	};
}

function analyzePythonCompileArgs(
	tokens: readonly PyToken[],
	openParenIdx: number,
): { argCount: number; hasModeKwarg: boolean } {
	const { args } = splitPythonCallArguments(tokens, openParenIdx);
	let hasModeKwarg = false;
	for (const seg of args) {
		if (
			seg[0]?.kind === "ident" &&
			seg[0].value === "mode" &&
			seg[1]?.kind === "punct" &&
			seg[1].value === "="
		) {
			hasModeKwarg = true;
		}
	}
	return { argCount: args.length, hasModeKwarg };
}

export function scanPythonScriptContent(
	relFile: string,
	rawContent: string,
): SkillSecurityFinding[] {
	const findings: SkillSecurityFinding[] = [];
	const rawLines = rawContent.split(/\r?\n/);
	const sanitizedLines: string[] = [];

	// 1. Enforce MAX_SCANNED_LINE_LENGTH on physical lines and joined backslash-continued lines
	let logicalAccLength = 0;
	let logicalStartLine = 1;
	let inContinuation = false;

	for (let idx = 0; idx < rawLines.length; idx++) {
		const rawLine = rawLines[idx] ?? "";
		const lineNo = idx + 1;

		if (rawLine.length > MAX_SCANNED_LINE_LENGTH) {
			findings.push(makeLongLineFinding(relFile, lineNo, rawLine.length));
			sanitizedLines.push("");
			logicalAccLength = 0;
			inContinuation = false;
			continue;
		}

		const continuesNext =
			rawLine.endsWith("\\") && !rawLine.trimStart().startsWith("#");
		if (!inContinuation) {
			logicalStartLine = lineNo;
			logicalAccLength = rawLine.length;
		} else {
			logicalAccLength += rawLine.length;
		}

		if (logicalAccLength > MAX_SCANNED_LINE_LENGTH) {
			findings.push(
				makeLongLineFinding(relFile, logicalStartLine, logicalAccLength),
			);
			for (let back = logicalStartLine - 1; back < sanitizedLines.length; back++) {
				sanitizedLines[back] = "";
			}
			sanitizedLines.push("");
			if (!continuesNext) {
				logicalAccLength = 0;
				inContinuation = false;
			} else {
				inContinuation = true;
				logicalAccLength = 0;
			}
			continue;
		}

		sanitizedLines.push(rawLine);
		inContinuation = continuesNext;
		if (!continuesNext) {
			logicalAccLength = 0;
		}
	}

	const tokens = tokenizePython(sanitizedLines.join("\n"));
	const moduleAliases = new Map<string, string>();
	const parenContexts: Array<"def_params" | "call_args" | "group"> = [];

	for (let idx = 0; idx < tokens.length; idx++) {
		const tok = tokens[idx]!;
		const prev = idx > 0 ? tokens[idx - 1] : undefined;

		if (tok.kind === "punct") {
			if (tok.value === "(") {
				const prev2 = idx > 1 ? tokens[idx - 2] : undefined;
				if (
					prev?.kind === "ident" &&
					prev2?.kind === "ident" &&
					prev2.value === "def"
				) {
					parenContexts.push("def_params");
				} else if (
					prev?.kind === "ident" ||
					(prev?.kind === "punct" &&
						(prev.value === ")" || prev.value === "]"))
				) {
					parenContexts.push("call_args");
				} else {
					parenContexts.push("group");
				}
				continue;
			}
			if (tok.value === ")" && parenContexts.length > 0) {
				parenContexts.pop();
				continue;
			}
		}

		const isStmtStart =
			!prev ||
			prev.kind === "newline" ||
			(prev.kind === "punct" && (prev.value === ";" || prev.value === ":"));

		// 1. `from <module> import <symbols>`
		if (tok.kind === "ident" && tok.value === "from" && isStmtStart) {
			const { modulePath, nextIdx } = readDottedPythonModule(tokens, idx + 1);
			if (
				tokens[nextIdx]?.kind === "ident" &&
				tokens[nextIdx]?.value === "import"
			) {
				const importedSymbols: string[] = [];
				let scanIdx = nextIdx + 1;
				let paren = 0;
				let expectSymbol = true;
				let lastSymbol = "";
				while (scanIdx < tokens.length) {
					const cur = tokens[scanIdx]!;
					if (cur.kind === "newline" && paren === 0) break;
					if (cur.kind === "punct" && cur.value === ";" && paren === 0) break;
					if (cur.kind === "punct" && cur.value === "(") {
						paren += 1;
						scanIdx += 1;
						continue;
					}
					if (cur.kind === "punct" && cur.value === ")") {
						paren = Math.max(0, paren - 1);
						scanIdx += 1;
						continue;
					}
					if (cur.kind === "punct" && cur.value === ",") {
						expectSymbol = true;
						lastSymbol = "";
						scanIdx += 1;
						continue;
					}
					if (cur.kind === "ident" && cur.value === "as") {
						const aliasTok = tokens[scanIdx + 1];
						if (
							aliasTok?.kind === "ident" &&
							lastSymbol &&
							PYTHON_ALIASABLE_MODULES.has(lastSymbol) &&
							!modulePath
						) {
							moduleAliases.set(aliasTok.value, lastSymbol);
						}
						expectSymbol = false;
						scanIdx += 2;
						continue;
					}
					if (expectSymbol && cur.kind === "ident") {
						importedSymbols.push(cur.value);
						lastSymbol = cur.value;
						expectSymbol = false;
					}
					scanIdx += 1;
				}

				const violation = classifyPythonModuleImport(
					modulePath,
					importedSymbols,
				);
				if (violation) {
					findings.push({
						file: relFile,
						line: tok.line,
						...violation,
					});
				}
				idx = scanIdx - 1;
				continue;
			}
		}

		// 2. `import <mod1>, <mod2> as alias`
		if (tok.kind === "ident" && tok.value === "import" && isStmtStart) {
			let scanIdx = idx + 1;
			while (scanIdx < tokens.length) {
				const cur = tokens[scanIdx]!;
				if (cur.kind === "newline") break;
				if (cur.kind === "punct" && cur.value === ";") break;
				if (cur.kind === "punct" && cur.value === ",") {
					scanIdx += 1;
					continue;
				}
				if (cur.kind === "ident") {
					const { modulePath, nextIdx } = readDottedPythonModule(
						tokens,
						scanIdx,
					);
					const violation = classifyPythonModuleImport(modulePath);
					if (violation) {
						findings.push({
							file: relFile,
							line: cur.line,
							...violation,
						});
					}
					const rootMod = modulePath.split(".")[0] ?? "";
					scanIdx = nextIdx;
					if (
						tokens[scanIdx]?.kind === "ident" &&
						tokens[scanIdx]?.value === "as"
					) {
						const aliasTok = tokens[scanIdx + 1];
						if (
							aliasTok?.kind === "ident" &&
							PYTHON_ALIASABLE_MODULES.has(rootMod)
						) {
							moduleAliases.set(aliasTok.value, rootMod);
						}
						scanIdx += 2;
					}
					continue;
				}
				scanIdx += 1;
			}
			idx = scanIdx - 1;
			continue;
		}

		// Track local variable aliasing (`my_os = os`, `my_os = (os,)[0]`, `b = __builtins__`)
		if (
			isStmtStart &&
			tok.kind === "ident" &&
			tokens[idx + 1]?.kind === "punct" &&
			tokens[idx + 1]?.value === "="
		) {
			let rhsScan = idx + 2;
			let rhsDepth = 0;
			while (rhsScan < tokens.length) {
				const rt = tokens[rhsScan]!;
				if (rt.kind === "newline" && rhsDepth === 0) break;
				if (rt.kind === "punct") {
					if (rt.value === ";" && rhsDepth === 0) break;
					if (rt.value === "(" || rt.value === "[" || rt.value === "{") {
						rhsDepth += 1;
					} else if (
						(rt.value === ")" || rt.value === "]" || rt.value === "}") &&
						rhsDepth > 0
					) {
						rhsDepth -= 1;
					}
				}
				if (rt.kind === "ident") {
					const beforeRt = tokens[rhsScan - 1];
					const afterRt = tokens[rhsScan + 1];
					const isAttrChainOrCall =
						(beforeRt?.kind === "punct" && beforeRt.value === ".") ||
						(afterRt?.kind === "punct" &&
							(afterRt.value === "." || afterRt.value === "("));
					const resolvedRhs = moduleAliases.get(rt.value) ?? rt.value;
					if (!isAttrChainOrCall && PYTHON_ALIASABLE_MODULES.has(resolvedRhs)) {
						moduleAliases.set(tok.value, resolvedRhs);
						break;
					}
				}
				rhsScan += 1;
			}
		}

		const resolvedIdent =
			tok.kind === "ident"
				? (moduleAliases.get(tok.value) ?? tok.value)
				: "";

		// 3. Attribute network calls `urllib.request` / `urllib.urlopen` (including aliases)
		if (
			tok.kind === "ident" &&
			resolvedIdent === "urllib" &&
			tokens[idx + 1]?.kind === "punct" &&
			tokens[idx + 1]?.value === "." &&
			tokens[idx + 2]?.kind === "ident" &&
			(tokens[idx + 2]?.value === "request" ||
				tokens[idx + 2]?.value === "urlopen")
		) {
			const alreadyReported = findings.some(
				(f) => f.line === tok.line && f.rule === "forbidden-network-import",
			);
			if (!alreadyReported) {
				findings.push({
					file: relFile,
					line: tok.line,
					rule: "forbidden-network-import",
					symbol: "urllib.request",
					message:
						"Forbidden outbound network call via 'urllib.request' in Skill script (violates zero-network policy).",
				});
			}
			continue;
		}

		// 4. Dynamic execution builtins: `eval()`, `exec()`, `__import__()` (including `b.eval()` on aliased `builtins`)
		if (
			tok.kind === "ident" &&
			(tok.value === "eval" ||
				tok.value === "exec" ||
				tok.value === "__import__") &&
			tokens[idx + 1]?.kind === "punct" &&
			tokens[idx + 1]?.value === "("
		) {
			const isAttr = prev?.kind === "punct" && prev.value === ".";
			const prev2 = idx > 1 ? tokens[idx - 2] : undefined;
			const resolvedRecv =
				isAttr && prev2?.kind === "ident"
					? (moduleAliases.get(prev2.value) ?? prev2.value)
					: "";
			const isBuiltinsAttr =
				resolvedRecv === "builtins" || resolvedRecv === "__builtins__";
			const isDef = prev?.kind === "ident" && prev.value === "def";
			if ((!isAttr || isBuiltinsAttr) && !isDef) {
				findings.push({
					file: relFile,
					line: tok.line,
					rule: "forbidden-dynamic-exec",
					symbol: `${tok.value}()`,
					message: `Forbidden dynamic code execution call '${tok.value}()' in Skill script.`,
				});
			}
			continue;
		}

		// 5. 3-arg dynamic `compile(source, filename, mode)` (allows 1/2-arg `from re import compile`)
		if (
			tok.kind === "ident" &&
			tok.value === "compile" &&
			tokens[idx + 1]?.kind === "punct" &&
			tokens[idx + 1]?.value === "("
		) {
			const isAttr = prev?.kind === "punct" && prev.value === ".";
			const prev2 = idx > 1 ? tokens[idx - 2] : undefined;
			const resolvedRecv =
				isAttr && prev2?.kind === "ident"
					? (moduleAliases.get(prev2.value) ?? prev2.value)
					: "";
			const isBuiltinsAttr =
				resolvedRecv === "builtins" || resolvedRecv === "__builtins__";
			const isDef = prev?.kind === "ident" && prev.value === "def";
			if ((!isAttr || isBuiltinsAttr) && !isDef) {
				const { argCount, hasModeKwarg } = analyzePythonCompileArgs(
					tokens,
					idx + 1,
				);
				if (argCount >= 3 || hasModeKwarg || isBuiltinsAttr) {
					findings.push({
						file: relFile,
						line: tok.line,
						rule: "forbidden-dynamic-exec",
						symbol: "compile()",
						message:
							"Forbidden dynamic code compilation 'compile()' in Skill script.",
					});
				}
			}
			continue;
		}

		// 6. Dynamic reflection: `getattr(...)`, `globals()`, `locals()`, `vars(...)`
		if (
			tok.kind === "ident" &&
			tok.value === "getattr" &&
			tokens[idx + 1]?.kind === "punct" &&
			tokens[idx + 1]?.value === "("
		) {
			const isAttr = prev?.kind === "punct" && prev.value === ".";
			const prev2 = idx > 1 ? tokens[idx - 2] : undefined;
			const resolvedRecv =
				isAttr && prev2?.kind === "ident"
					? (moduleAliases.get(prev2.value) ?? prev2.value)
					: "";
			const isBuiltinsAttr =
				resolvedRecv === "builtins" || resolvedRecv === "__builtins__";
			const isDef = prev?.kind === "ident" && prev.value === "def";
			if ((!isAttr || isBuiltinsAttr) && !isDef) {
				const { args } = splitPythonCallArguments(tokens, idx + 1);
				let matchedBuiltinsTarget = "";
				let matchedModuleTarget = "";
				if (args[0]) {
					for (const argTok of args[0]) {
						if (argTok.kind !== "ident") continue;
						const resolved = moduleAliases.get(argTok.value) ?? argTok.value;
						if (resolved === "__builtins__" || resolved === "builtins") {
							matchedBuiltinsTarget = resolved;
							break;
						}
						if (
							!matchedModuleTarget &&
							(resolved === "os" ||
								resolved === "posix" ||
								resolved === "nt" ||
								resolved === "sys" ||
								resolved === "urllib")
						) {
							matchedModuleTarget = resolved;
						}
					}
				}

				if (matchedBuiltinsTarget) {
					findings.push({
						file: relFile,
						line: tok.line,
						rule: "forbidden-dynamic-exec",
						symbol: `getattr(${matchedBuiltinsTarget})`,
						message: `Forbidden dynamic builtins lookup 'getattr(${matchedBuiltinsTarget}, ...)' in Skill script.`,
					});
				} else if (matchedModuleTarget) {
					const label =
						matchedModuleTarget === "sys"
							? "getattr(sys)"
							: matchedModuleTarget === "urllib"
								? "getattr(urllib)"
								: "getattr(os)";
					findings.push({
						file: relFile,
						line: tok.line,
						rule: "forbidden-dynamic-exec",
						symbol: label,
						message: `Forbidden dynamic module reflection '${label}' in Skill script.`,
					});
				} else {
					const secondArg = args[1];
					const isSingleStaticStringAttr =
						secondArg !== undefined &&
						secondArg.length === 1 &&
						secondArg[0]?.kind === "string";
					const literalAttr = isSingleStaticStringAttr
						? secondArg[0]!.value
						: "";
					if (
						!isSingleStaticStringAttr ||
						DANGEROUS_PYTHON_REFLECTION_ATTRS.has(literalAttr)
					) {
						findings.push({
							file: relFile,
							line: tok.line,
							rule: "forbidden-dynamic-exec",
							symbol: "getattr()",
							message:
								"Forbidden dynamic attribute reflection 'getattr()' targeting a non-literal or dangerous capability in Skill script.",
						});
					}
				}
			}
			continue;
		}

		if (
			tok.kind === "ident" &&
			(tok.value === "globals" || tok.value === "locals") &&
			tokens[idx + 1]?.kind === "punct" &&
			tokens[idx + 1]?.value === "("
		) {
			const isAttr = prev?.kind === "punct" && prev.value === ".";
			const isDef = prev?.kind === "ident" && prev.value === "def";
			if (!isAttr && !isDef) {
				findings.push({
					file: relFile,
					line: tok.line,
					rule: "forbidden-dynamic-exec",
					symbol: `${tok.value}()`,
					message: `Forbidden namespace reflection '${tok.value}()' in Skill script.`,
				});
			}
			continue;
		}

		if (
			tok.kind === "ident" &&
			tok.value === "vars" &&
			tokens[idx + 1]?.kind === "punct" &&
			tokens[idx + 1]?.value === "("
		) {
			const isAttr = prev?.kind === "punct" && prev.value === ".";
			const isDef = prev?.kind === "ident" && prev.value === "def";
			if (!isAttr && !isDef) {
				const { args, closeParenIdx } = splitPythonCallArguments(
					tokens,
					idx + 1,
				);
				const afterCall =
					closeParenIdx !== -1 ? tokens[closeParenIdx + 1] : undefined;
				const hasDangerousVarTarget =
					args[0] !== undefined &&
					args[0].some(
						(t) =>
							t.kind === "ident" &&
							PYTHON_ALIASABLE_MODULES.has(
								moduleAliases.get(t.value) ?? t.value,
							),
					);
				const isUnpackedArg =
					args[0]?.[0]?.kind === "punct" && args[0][0].value === "*";
				const isIndexed =
					afterCall?.kind === "punct" &&
					(afterCall.value === "[" || afterCall.value === ".");
				if (
					args.length === 0 ||
					isIndexed ||
					isUnpackedArg ||
					hasDangerousVarTarget
				) {
					findings.push({
						file: relFile,
						line: tok.line,
						rule: "forbidden-dynamic-exec",
						symbol: "vars()",
						message:
							"Forbidden namespace dictionary reflection 'vars()' in Skill script.",
					});
				}
			}
			continue;
		}

		// Direct `__builtins__`, `__globals__`, `__subclasses__`, or `sys.modules[...]` access
		if (
			tok.kind === "ident" &&
			resolvedIdent === "__builtins__" &&
			tokens[idx + 1]?.kind === "punct" &&
			(tokens[idx + 1]?.value === "[" || tokens[idx + 1]?.value === ".")
		) {
			findings.push({
				file: relFile,
				line: tok.line,
				rule: "forbidden-dynamic-exec",
				symbol: "__builtins__",
				message:
					"Forbidden direct '__builtins__' dictionary access in Skill script.",
			});
			continue;
		}

		if (
			tok.kind === "ident" &&
			(tok.value === "__globals__" || tok.value === "__subclasses__")
		) {
			findings.push({
				file: relFile,
				line: tok.line,
				rule: "forbidden-dynamic-exec",
				symbol: tok.value,
				message: `Forbidden Python internal introspection attribute '${tok.value}' in Skill script.`,
			});
			continue;
		}

		if (
			tok.kind === "ident" &&
			resolvedIdent === "sys" &&
			tokens[idx + 1]?.kind === "punct" &&
			tokens[idx + 1]?.value === "." &&
			tokens[idx + 2]?.kind === "ident" &&
			tokens[idx + 2]?.value === "modules" &&
			tokens[idx + 3]?.kind === "punct" &&
			(tokens[idx + 3]?.value === "[" || tokens[idx + 3]?.value === ".")
		) {
			findings.push({
				file: relFile,
				line: tok.line,
				rule: "forbidden-dynamic-exec",
				symbol: "sys.modules",
				message:
					"Forbidden dynamic module registry lookup 'sys.modules' in Skill script.",
			});
			continue;
		}

		// 7. Unsafe OS shell calls: `os.system()`, `os.popen()`, `os.spawn*()`, `os.exec*()` (including aliases & `__import__('os').system()`)
		if (
			tok.kind === "ident" &&
			(resolvedIdent === "os" ||
				resolvedIdent === "posix" ||
				resolvedIdent === "nt") &&
			tokens[idx + 1]?.kind === "punct" &&
			tokens[idx + 1]?.value === "." &&
			tokens[idx + 2]?.kind === "ident" &&
			FORBIDDEN_PYTHON_OS_CALLS.has(tokens[idx + 2]!.value)
		) {
			const fnName = tokens[idx + 2]!.value;
			findings.push({
				file: relFile,
				line: tok.line,
				rule: "forbidden-shell-execution",
				symbol: `os.${fnName}()`,
				message: `Forbidden shell execution reference 'os.${fnName}()' in Skill script.`,
			});
			continue;
		}

		// 8. `shell=...` keyword argument (`shell=True` or any non-`False`/`None` expression inside call arguments)
		if (
			tok.kind === "ident" &&
			tok.value === "shell" &&
			tokens[idx + 1]?.kind === "punct" &&
			tokens[idx + 1]?.value === "="
		) {
			const rhsTok = tokens[idx + 2];
			if (rhsTok?.kind === "ident" && rhsTok.value === "True") {
				findings.push({
					file: relFile,
					line: tok.line,
					rule: "forbidden-shell-execution",
					symbol: "shell=True",
					message:
						"Forbidden 'shell=True' in process invocation; companion scripts must remain shell-free.",
				});
				continue;
			}

			const inCallArgs =
				parenContexts.length > 0 &&
				parenContexts[parenContexts.length - 1] === "call_args" &&
				prev?.kind === "punct" &&
				(prev.value === "(" || prev.value === ",");
			if (inCallArgs) {
				// Collect RHS tokens up to `,` or matching `)` at current call depth
				const rhsTokens: PyToken[] = [];
				let scan = idx + 2;
				let innerDepth = 0;
				while (scan < tokens.length) {
					const t = tokens[scan]!;
					if (
						t.kind === "punct" &&
						(t.value === "(" || t.value === "[" || t.value === "{")
					) {
						innerDepth += 1;
						rhsTokens.push(t);
					} else if (
						t.kind === "punct" &&
						(t.value === ")" || t.value === "]" || t.value === "}")
					) {
						if (innerDepth === 0) break;
						innerDepth -= 1;
						rhsTokens.push(t);
					} else if (innerDepth === 0 && t.kind === "punct" && t.value === ",") {
						break;
					} else if (t.kind !== "newline") {
						rhsTokens.push(t);
					}
					scan += 1;
				}
				const isSafeLiteralFalseOrNone =
					rhsTokens.length === 1 &&
					rhsTokens[0]?.kind === "ident" &&
					(rhsTokens[0].value === "False" || rhsTokens[0].value === "None");
				if (!isSafeLiteralFalseOrNone) {
					findings.push({
						file: relFile,
						line: tok.line,
						rule: "forbidden-shell-execution",
						symbol: "shell=True",
						message:
							"Forbidden non-False 'shell=...' argument in process invocation; companion scripts must remain shell-free.",
					});
				}
			}
		}
	}

	return findings;
}
