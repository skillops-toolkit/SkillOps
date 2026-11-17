/**
 * Deterministic Security Scanner for Hybrid Executable Skills & Subagents (`src/auditor/security.ts`).
 *
 * Enforces SkillOps Security Charter Principles I, II, III, V, VI and Lagune Defense Plan controls:
 * - Blocks outbound network/exfiltration clients, subprocess spawning, and dynamic execution in Python
 *   (`urllib.request`, `urllib2`, `urllib3`, `http.client`, `httplib`, `socket`, `socketserver`,
 *   `requests`, `httpx`, `aiohttp`, `ftplib`, `smtplib`, `poplib`, `imaplib`, `ssl`, `telnetlib`,
 *   `xmlrpc.client`, `paramiko`, `websocket`, `websockets`, `webbrowser`, `subprocess`,
 *   `_posixsubprocess`, `asyncio`, `multiprocessing`, `pty`, `commands`, `eval`, `exec`, `__import__`,
 *   `importlib`, `builtins`, `runpy`, `code`, `codeop`, `zipimport`, `pickle`, `marshal`, `shelve`,
 *   `ctypes`, `cffi`, 3-arg `compile()`, `getattr` reflection, `globals()`, `locals()`, `vars()`,
 *   module aliases, and `f`-string `{...}` interpolations) while allowing offline stdlib helpers
 *   (`urllib.parse`, `urllib.error`, `http.server`, `from re import compile` + `compile(r'...')`,
 *   `def eval()`, and `model.eval()`).
 * - Blocks dangerous Node/Web primitives and obfuscations in JS/TS (`child_process`, `vm`,
 *   `worker_threads`, `module`, `inspector`, `v8`, `wasi`, `net`, `http`, `https`, `http2`, `tls`,
 *   `dgram`, `dns`, `undici`, `\xHH`/`\uHHHH`/`\u{H+}` escaped identifiers and module specifiers,
 *   non-literal or aliased `require`, dynamic `import()`, `eval()`, `Function()`, `.constructor()`,
 *   `Reflect.apply`, `Reflect.construct`, `process.binding()`, `process.dlopen()`,
 *   `process.getBuiltinModule()`, and computed bracket indexing on globals/`process`/`Reflect`)
 *   while allowing class methods (`async eval(...) { ... }`).
 * - Blocks outbound network/transfer commands (`curl`, `wget`, `Invoke-WebRequest`, `iwr`, `nc`,
 *   `ncat`, `socat`, `ssh`, `scp`), dynamic `eval`, subshell/process substitutions (`$(...)`,
 *   backticks, `<(...)`), `\`-continued pipelines, forbidden `.ps1`/`.bat`/`.cmd` scripts, and
 *   unexpected `#!` shebang companion files.
 * - Blocks prompt-injection overrides hidden in HTML comments (`<!-- ... -->`), executable
 *   `javascript:` / `data:` Markdown links, and external Markdown image beacons (`![...](https://...)`)
 *   across `SKILL.md`, `SUBAGENT.md`, and `references/*.md`.
 * - Enforces `MAX_SCANNED_LINE_LENGTH` and strictly linear O(n) scanning with zero polynomial regexes.
 * - Never trusts inline comments inside scanned files; maintainer exceptions are loaded exclusively
 *   from a canonical symlink-free `.skillops-security-allowlist.json` inside the built-in package root.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { discoverSkillDirectories, discoverSubagentFiles } from "./parser.js";

export const MAX_SCANNED_LINE_LENGTH = 4096;
export const MAX_SCANNED_FILE_BYTES = 2 * 1024 * 1024;
const MAX_ALLOWLIST_BYTES = 1_048_576;

export type SkillSecurityRuleId =
	| "forbidden-network-import"
	| "forbidden-dynamic-exec"
	| "forbidden-shell-execution"
	| "forbidden-trojan-unicode"
	| "forbidden-symlink"
	| "forbidden-binary-file"
	| "forbidden-path-traversal"
	| "suspicious-long-line"
	| "oversized-file"
	| "forbidden-prompt-injection"
	| "forbidden-external-markdown-image";

const VALID_RULE_IDS: ReadonlySet<SkillSecurityRuleId> = new Set([
	"forbidden-network-import",
	"forbidden-dynamic-exec",
	"forbidden-shell-execution",
	"forbidden-trojan-unicode",
	"forbidden-symlink",
	"forbidden-binary-file",
	"forbidden-path-traversal",
	"suspicious-long-line",
	"oversized-file",
	"forbidden-prompt-injection",
	"forbidden-external-markdown-image",
]);

export interface SkillSecurityFinding {
	readonly file: string;
	readonly line: number;
	readonly rule: SkillSecurityRuleId;
	readonly symbol: string;
	readonly message: string;
}

export interface SkillSecurityAuditReport {
	readonly targetDir: string;
	readonly passed: boolean;
	readonly scannedFiles: string[];
	readonly findings: SkillSecurityFinding[];
}

export interface SecurityAllowlistEntry {
	readonly relative_path: string;
	readonly rule: SkillSecurityRuleId;
	readonly sha256: string;
	readonly reason?: string;
}

export interface SecurityAllowlistFile {
	readonly version: string;
	readonly exceptions: readonly SecurityAllowlistEntry[];
}

export interface SecurityAuditOptions {
	readonly allowlistPath?: string;
	readonly allowOverrides?: boolean;
}

/**
 * Python root modules that are unconditionally forbidden because they open network
 * connections, TLS sockets, mail/FTP sessions, or external browser windows.
 */
const FORBIDDEN_PYTHON_NETWORK_ROOT_MODULES = new Set([
	"urllib2",
	"urllib3",
	"httplib",
	"socket",
	"socketserver",
	"ssl",
	"requests",
	"httpx",
	"aiohttp",
	"ftplib",
	"smtplib",
	"poplib",
	"imaplib",
	"telnetlib",
	"paramiko",
	"websocket",
	"websockets",
	"webbrowser",
]);

/**
 * Dotted Python submodules that perform outbound network requests, kept distinct from
 * benign sibling submodules such as `urllib.parse`, `urllib.error`, or `http.server`.
 */
const FORBIDDEN_PYTHON_NETWORK_SUBMODULES = new Set([
	"urllib.request",
	"urllib.urlopen",
	"http.client",
	"xmlrpc.client",
]);

const FORBIDDEN_PYTHON_EXEC_MODULES = new Set([
	"pickle",
	"cPickle",
	"marshal",
	"shelve",
	"ctypes",
	"cffi",
	"importlib",
	"builtins",
	"runpy",
	"code",
	"codeop",
	"zipimport",
]);

const FORBIDDEN_PYTHON_SHELL_MODULES = new Set([
	"pty",
	"commands",
	"subprocess",
	"_posixsubprocess",
	"asyncio",
	"multiprocessing",
]);

const FORBIDDEN_PYTHON_OS_CALLS = new Set([
	"system",
	"popen",
	"spawnl",
	"spawnle",
	"spawnlp",
	"spawnlpe",
	"spawnv",
	"spawnve",
	"spawnvp",
	"spawnvpe",
	"posix_spawn",
	"posix_spawnp",
	"execl",
	"execle",
	"execlp",
	"execpe",
	"execlpe",
	"execv",
	"execve",
	"execvp",
	"execvpe",
	"fork",
	"forkpty",
]);

const DANGEROUS_PYTHON_REFLECTION_ATTRS = new Set([
	...FORBIDDEN_PYTHON_OS_CALLS,
	"eval",
	"exec",
	"compile",
	"__import__",
	"__builtins__",
	"builtins",
	"__globals__",
	"__subclasses__",
	"__loader__",
	"__spec__",
	"modules",
	"urlopen",
	"urlretrieve",
	"open_code",
]);

const PYTHON_ALIASABLE_MODULES = new Set([
	"os",
	"posix",
	"nt",
	"sys",
	"builtins",
	"__builtins__",
	"urllib",
]);

const FORBIDDEN_JS_SHELL_MODULES = new Set(["child_process"]);

const FORBIDDEN_JS_EXEC_MODULES = new Set([
	"vm",
	"worker_threads",
	"module",
	"inspector",
	"v8",
	"wasi",
]);

const FORBIDDEN_JS_NETWORK_MODULES = new Set([
	"net",
	"http",
	"https",
	"http2",
	"tls",
	"dgram",
	"dns",
	"undici",
]);

const GLOBAL_JS_OBJECTS = new Set(["globalThis", "global", "window", "self"]);

const FORBIDDEN_PROCESS_METHODS = new Set([
	"binding",
	"dlopen",
	"getBuiltinModule",
	"mainModule",
	"_load",
]);

const SHELL_PIPE_INTERPRETERS = new Set([
	"sh",
	"bash",
	"zsh",
	"dash",
	"ksh",
	"python",
	"python2",
	"python3",
	"node",
	"perl",
	"ruby",
	"eval",
	"pwsh",
	"powershell",
]);

const BASE64_PIPE_INTERPRETERS = new Set([
	"sh",
	"bash",
	"zsh",
	"dash",
	"ksh",
	"python",
	"python2",
	"python3",
	"node",
	"eval",
	"pwsh",
	"powershell",
]);

const FORBIDDEN_SHELL_NETWORK_COMMANDS = new Set([
	"curl",
	"wget",
	"invoke-webrequest",
	"invoke-restmethod",
	"iwr",
	"irm",
	"socat",
	"ssh",
	"scp",
	"sftp",
	"ftp",
	"telnet",
]);

const FORBIDDEN_SHELL_SUBINTERPRETERS = new Set([
	"sh",
	"bash",
	"zsh",
	"dash",
	"ksh",
	"pwsh",
	"powershell",
]);

const SHELL_COMMAND_WRAPPERS = new Set([
	"sudo",
	"env",
	"command",
	"builtin",
	"nohup",
	"time",
	"exec",
]);

const IGNORED_SCAN_DIRS = new Set([
	".git",
	"__pycache__",
	"node_modules",
	".pytest_cache",
	".ruff_cache",
	".mypy_cache",
]);

const IGNORED_SCAN_FILES = new Set([".DS_Store", "Thumbs.db", "desktop.ini"]);

/**
 * Opaque compiled binary and archive extensions forbidden inside curated Skill and catalog directories
 * because they cannot be audited line-by-line in GitHub Pull Request diffs.
 */
export const FORBIDDEN_BINARY_AND_ARCHIVE_EXTENSIONS = new Set([
	".exe",
	".dll",
	".so",
	".dylib",
	".bin",
	".wasm",
	".pyc",
	".pyo",
	".pyd",
	".msi",
	".scr",
	".com",
	".jar",
	".class",
	".zip",
	".tar",
	".gz",
	".tgz",
	".7z",
	".rar",
	".bz2",
	".xz",
]);

const NON_TEXT_MEDIA_EXTENSIONS = new Set([
	".png",
	".jpg",
	".jpeg",
	".gif",
	".webp",
	".ico",
	".bmp",
	".pdf",
	".woff",
	".woff2",
	".ttf",
	".otf",
	".eot",
	".mp3",
	".mp4",
	".wav",
	".ogg",
	".webm",
]);

const PYTHON_SCRIPT_EXTENSIONS = new Set([".py", ".pyw"]);

const SHELL_SCRIPT_EXTENSIONS = new Set([".sh", ".bash", ".zsh", ".ksh"]);

const JS_TS_SCRIPT_EXTENSIONS = new Set([
	".mjs",
	".js",
	".cjs",
	".mts",
	".cts",
	".ts",
	".tsx",
	".jsx",
]);

const FORBIDDEN_COMPANION_SCRIPT_EXTENSIONS = new Set([
	".ps1",
	".bat",
	".cmd",
]);

const EXECUTABLE_SCRIPT_EXTENSIONS = new Set([
	...PYTHON_SCRIPT_EXTENSIONS,
	...SHELL_SCRIPT_EXTENSIONS,
	...JS_TS_SCRIPT_EXTENSIONS,
	...FORBIDDEN_COMPANION_SCRIPT_EXTENSIONS,
]);

const KNOWN_TEXT_EXTENSIONS = new Set([
	".md",
	".mdc",
	...EXECUTABLE_SCRIPT_EXTENSIONS,
	".json",
	".yaml",
	".yml",
	".toml",
	".txt",
	".ini",
	".cfg",
	".xml",
	".svg",
	".html",
	".css",
]);

/**
 * Trojan-Source (CVE-2021-42574) bidirectional control characters, mid-file BOM (`U+FEFF`),
 * and LLM ASCII-smuggling Unicode Tag characters (`U+E0000..U+E007F`), forbidden across ALL UTF-8 text files.
 */
const TROJAN_BIDI_OR_TAG_REGEX =
	/[\u0000\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u{E0000}-\u{E007F}]/u;

/**
 * Zero-width characters forbidden inside executable scripts where they can spoof identifiers
 * or hide payload boundaries.
 */
const SCRIPT_ZERO_WIDTH_REGEX = /[\u200B-\u200D\u2060-\u2064\uFEFF]/u;

const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;
const DEV_SOCKET_REGEX = /\/dev\/(?:tcp|udp)\//;

function trimLeadingSlashes(value: string): string {
	let idx = 0;
	while (idx < value.length && value[idx] === "/") {
		idx += 1;
	}
	return idx === 0 ? value : value.slice(idx);
}

function hasUnsafePathSyntax(rawPath: string): boolean {
	for (let i = 0; i < rawPath.length; i++) {
		const code = rawPath.charCodeAt(i);
		if (code < 0x20 || code === 0x7f) {
			return true;
		}
		if (rawPath[i] === ":") {
			const isWindowsDrivePrefix =
				i === 1 &&
				((rawPath.charCodeAt(0) >= 65 && rawPath.charCodeAt(0) <= 90) ||
					(rawPath.charCodeAt(0) >= 97 && rawPath.charCodeAt(0) <= 122));
			if (!isWindowsDrivePrefix) {
				return true;
			}
		}
	}
	return false;
}

function resolveBuiltinPackageRoot(): string {
	const moduleDir = path.dirname(fileURLToPath(import.meta.url));
	const parentOne = path.resolve(moduleDir, "..");
	if (fs.existsSync(path.join(parentOne, "package.json"))) {
		return parentOne;
	}
	return path.resolve(moduleDir, "..", "..");
}

function isPathInsideBuiltinCatalog(resolvedTarget: string): boolean {
	const pkgRoot = resolveBuiltinPackageRoot();
	const builtinCatalog = path.join(pkgRoot, "catalog");
	if (!fs.existsSync(builtinCatalog) || !fs.existsSync(resolvedTarget)) {
		return false;
	}
	try {
		const realBuiltin = fs.realpathSync(builtinCatalog);
		const realTarget = fs.realpathSync(resolvedTarget);
		if (realTarget === realBuiltin) {
			return true;
		}
		const rel = path.relative(realBuiltin, realTarget);
		return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
	} catch {
		return false;
	}
}

/**
 * Verify that an allowlist file resides strictly inside `pkgRoot` with zero symbolic-link
 * ancestor segments (`lstatSync`) and canonical `realpathSync` containment.
 */
function resolveSafeAllowlistFile(
	rawCandidatePath: string,
	pkgRoot: string,
): string | null {
	if (!rawCandidatePath || hasUnsafePathSyntax(rawCandidatePath)) {
		return null;
	}
	const resolvedPkg = path.resolve(pkgRoot);
	const resolvedCandidate = path.resolve(rawCandidatePath);
	if (!fs.existsSync(resolvedPkg) || !fs.existsSync(resolvedCandidate)) {
		return null;
	}

	try {
		const pkgLstat = fs.lstatSync(resolvedPkg);
		if (pkgLstat.isSymbolicLink() || !pkgLstat.isDirectory()) {
			return null;
		}
		const realPkg = fs.realpathSync(resolvedPkg);
		const lexicalRel = path.relative(resolvedPkg, resolvedCandidate);
		if (
			lexicalRel === "" ||
			lexicalRel.startsWith("..") ||
			path.isAbsolute(lexicalRel)
		) {
			return null;
		}

		// Walk every ancestor segment from `resolvedPkg` down to `resolvedCandidate`
		const segments = lexicalRel.split(path.sep).filter(Boolean);
		let current = resolvedPkg;
		for (const seg of segments) {
			current = path.join(current, seg);
			const st = fs.lstatSync(current);
			if (st.isSymbolicLink()) {
				return null;
			}
		}

		const finalStat = fs.lstatSync(resolvedCandidate);
		if (
			finalStat.isSymbolicLink() ||
			!finalStat.isFile() ||
			finalStat.size > MAX_ALLOWLIST_BYTES
		) {
			return null;
		}

		const realCandidate = fs.realpathSync(resolvedCandidate);
		const canonicalRel = path.relative(realPkg, realCandidate);
		if (
			canonicalRel === "" ||
			canonicalRel.startsWith("..") ||
			path.isAbsolute(canonicalRel)
		) {
			return null;
		}

		return realCandidate;
	} catch {
		return null;
	}
}

type BoundedFileReadResult =
	| { readonly ok: true; readonly buffer: Buffer }
	| { readonly ok: false; readonly finding: SkillSecurityFinding };

/**
 * Safely read a regular, non-symlink file bounded by `maxBytes`.
 * Verifies `lstatSync` before opening, opens with `O_RDONLY | O_NOFOLLOW` where available,
 * re-verifies `fstatSync(fd)` on the open descriptor, and reads at most `maxBytes + 1` bytes
 * to prevent heap exhaustion or concurrent TOCTOU file growth.
 */
function readBoundedRegularFile(
	fullPath: string,
	relFile: string,
	contextLabel: string,
	maxBytes: number = MAX_SCANNED_FILE_BYTES,
): BoundedFileReadResult {
	let lstat: fs.Stats;
	try {
		lstat = fs.lstatSync(fullPath);
	} catch {
		return {
			ok: false,
			finding: {
				file: relFile,
				line: 1,
				rule: "forbidden-binary-file",
				symbol: "unreadable-file",
				message: `Unable to stat file '${relFile}' in ${contextLabel}.`,
			},
		};
	}

	if (lstat.isSymbolicLink()) {
		return {
			ok: false,
			finding: {
				file: relFile,
				line: 1,
				rule: "forbidden-symlink",
				symbol: "symlink",
				message: `Forbidden symbolic link '${relFile}' in ${contextLabel}.`,
			},
		};
	}

	if (!lstat.isFile()) {
		return {
			ok: false,
			finding: {
				file: relFile,
				line: 1,
				rule: "forbidden-binary-file",
				symbol: "non-regular-file",
				message: `Forbidden non-regular file '${relFile}' in ${contextLabel}.`,
			},
		};
	}

	if (lstat.size > maxBytes) {
		return {
			ok: false,
			finding: {
				file: relFile,
				line: 1,
				rule: "oversized-file",
				symbol: `>${maxBytes}B`,
				message: `File '${relFile}' (${lstat.size} bytes) exceeds maximum scanned file size (${maxBytes} bytes).`,
			},
		};
	}

	const openFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
	let fd: number;
	try {
		fd = fs.openSync(fullPath, openFlags);
	} catch {
		return {
			ok: false,
			finding: {
				file: relFile,
				line: 1,
				rule: "forbidden-symlink",
				symbol: "unopenable-file",
				message: `Refusing to scan '${relFile}' in ${contextLabel}: failed to open regular file safely.`,
			},
		};
	}

	try {
		const fstat = fs.fstatSync(fd);
		if (!fstat.isFile()) {
			return {
				ok: false,
				finding: {
					file: relFile,
					line: 1,
					rule: "forbidden-binary-file",
					symbol: "non-regular-file",
					message: `Forbidden non-regular file '${relFile}' in ${contextLabel}.`,
				},
			};
		}

		if (fstat.size > maxBytes) {
			return {
				ok: false,
				finding: {
					file: relFile,
					line: 1,
					rule: "oversized-file",
					symbol: `>${maxBytes}B`,
					message: `File '${relFile}' (${fstat.size} bytes) exceeds maximum scanned file size (${maxBytes} bytes).`,
				},
			};
		}

		const maxToRead = maxBytes + 1;
		const initialCap = Math.min(Math.max(fstat.size + 1, 64), maxToRead);
		let buf = Buffer.allocUnsafe(initialCap);
		let totalRead = 0;

		while (totalRead < maxToRead) {
			if (totalRead === buf.length) {
				const nextCap = Math.min(buf.length * 2, maxToRead);
				const grown = Buffer.allocUnsafe(nextCap);
				buf.copy(grown, 0, 0, totalRead);
				buf = grown;
			}
			const bytesRead = fs.readSync(
				fd,
				buf,
				totalRead,
				buf.length - totalRead,
				null,
			);
			if (bytesRead === 0) {
				break;
			}
			totalRead += bytesRead;
		}

		if (totalRead > maxBytes) {
			return {
				ok: false,
				finding: {
					file: relFile,
					line: 1,
					rule: "oversized-file",
					symbol: `>${maxBytes}B`,
					message: `File '${relFile}' exceeds maximum scanned file size (${maxBytes} bytes) during read.`,
				},
			};
		}

		return { ok: true, buffer: buf.subarray(0, totalRead) };
	} finally {
		fs.closeSync(fd);
	}
}

function loadBuiltinAllowlistEntries(
	resolvedTarget: string,
	options?: SecurityAuditOptions,
): SecurityAllowlistEntry[] {
	if (options?.allowOverrides === false) {
		return [];
	}
	if (!isPathInsideBuiltinCatalog(resolvedTarget)) {
		return [];
	}
	const pkgRoot = resolveBuiltinPackageRoot();
	const rawCandidate = options?.allowlistPath
		? options.allowlistPath
		: path.join(pkgRoot, ".skillops-security-allowlist.json");
	const safeAllowlistPath = resolveSafeAllowlistFile(rawCandidate, pkgRoot);
	if (!safeAllowlistPath) {
		return [];
	}
	try {
		const bounded = readBoundedRegularFile(
			safeAllowlistPath,
			".skillops-security-allowlist.json",
			"allowlist",
			MAX_ALLOWLIST_BYTES,
		);
		if (!bounded.ok) {
			return [];
		}
		const raw = bounded.buffer.toString("utf-8");
		const parsed = JSON.parse(raw) as {
			exceptions?: Array<{
				relative_path?: unknown;
				rule?: unknown;
				rule_id?: unknown;
				sha256?: unknown;
				reason?: unknown;
			}>;
		};
		if (!Array.isArray(parsed.exceptions)) {
			return [];
		}
		const entries: SecurityAllowlistEntry[] = [];
		for (const item of parsed.exceptions) {
			const relPath =
				typeof item?.relative_path === "string"
					? trimLeadingSlashes(item.relative_path.replace(/\\/g, "/"))
					: "";
			const ruleVal =
				typeof item?.rule === "string"
					? item.rule
					: typeof item?.rule_id === "string"
						? item.rule_id
						: "";
			const sha =
				typeof item?.sha256 === "string" ? item.sha256.toLowerCase() : "";
			if (
				relPath &&
				!relPath.includes("..") &&
				VALID_RULE_IDS.has(ruleVal as SkillSecurityRuleId) &&
				SHA256_HEX_REGEX.test(sha)
			) {
				entries.push({
					relative_path: relPath,
					rule: ruleVal as SkillSecurityRuleId,
					sha256: sha,
					reason: typeof item?.reason === "string" ? item.reason : undefined,
				});
			}
		}
		return entries;
	} catch {
		return [];
	}
}

function isFindingCoveredByAllowlist(
	entries: readonly SecurityAllowlistEntry[],
	fullFilePath: string,
	rule: SkillSecurityRuleId,
	fileSha256: string,
): boolean {
	if (entries.length === 0 || !SHA256_HEX_REGEX.test(fileSha256)) {
		return false;
	}
	try {
		const pkgRoot = fs.realpathSync(resolveBuiltinPackageRoot());
		const builtinCatalog = fs.realpathSync(path.join(pkgRoot, "catalog"));
		const realFile = fs.realpathSync(fullFilePath);
		const relToPkg = path.relative(pkgRoot, realFile).replace(/\\/g, "/");
		const relToCatalog = path
			.relative(builtinCatalog, realFile)
			.replace(/\\/g, "/");
		if (
			relToCatalog === "" ||
			relToCatalog.startsWith("..") ||
			path.isAbsolute(relToCatalog)
		) {
			return false;
		}

		for (const entry of entries) {
			if (
				entry.rule === rule &&
				entry.sha256 === fileSha256 &&
				(entry.relative_path === relToPkg ||
					entry.relative_path === relToCatalog)
			) {
				return true;
			}
		}
		return false;
	} catch {
		return false;
	}
}

function makeLongLineFinding(
	relFile: string,
	lineNo: number,
	actualLength: number,
): SkillSecurityFinding {
	return {
		file: relFile,
		line: lineNo,
		rule: "suspicious-long-line",
		symbol: `line>${MAX_SCANNED_LINE_LENGTH}`,
		message: `Line ${lineNo} in '${relFile}' exceeds maximum scanned line length (${actualLength} > ${MAX_SCANNED_LINE_LENGTH}).`,
	};
}

export function hasForbiddenBinaryExtension(filename: string): string | null {
	const lower = filename.toLowerCase();
	if (lower.endsWith(".tar.gz")) {
		return ".tar.gz";
	}
	const ext = path.extname(lower);
	if (FORBIDDEN_BINARY_AND_ARCHIVE_EXTENSIONS.has(ext)) {
		return ext;
	}
	return null;
}

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

function isHexDigitCode(code: number): boolean {
	return (
		(code >= 48 && code <= 57) ||
		(code >= 65 && code <= 70) ||
		(code >= 97 && code <= 102)
	);
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

function shouldScanMarkdownPromptInjection(relFile: string): boolean {
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

interface PyToken {
	readonly kind: "ident" | "string" | "punct" | "newline" | "other";
	readonly value: string;
	readonly line: number;
}

function isAsciiAlphaOrUnderscore(ch: string): boolean {
	const code = ch.charCodeAt(0);
	return (
		(code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95
	);
}

function isAsciiAlnumOrUnderscore(ch: string): boolean {
	const code = ch.charCodeAt(0);
	return (
		(code >= 48 && code <= 57) ||
		(code >= 65 && code <= 90) ||
		(code >= 97 && code <= 122) ||
		code === 95
	);
}

function isAsciiDigit(ch: string): boolean {
	const code = ch.charCodeAt(0);
	return code >= 48 && code <= 57;
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

function tokenizePython(source: string): PyToken[] {
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

interface JsToken {
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

const JS_METHOD_MODIFIERS = new Set([
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

const JS_EXPR_FORCING_OPERATORS = new Set([
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

const JS_EXPR_FORCING_KEYWORDS = new Set([
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

function tokenizeJsOrTs(source: string): JsToken[] {
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

function extractShebangLine(rawContent: string): string | null {
	const normalized = rawContent.startsWith("\uFEFF")
		? rawContent.slice(1)
		: rawContent;
	if (!normalized.startsWith("#!")) {
		return null;
	}
	const nl = normalized.indexOf("\n");
	const firstLine = (nl === -1 ? normalized : normalized.slice(0, nl)).trim();
	return firstLine.slice(0, 256);
}

function scanScriptByExtensionOrShebang(
	relFile: string,
	ext: string,
	shebangLine: string | null,
	rawContent: string,
): SkillSecurityFinding[] {
	if (PYTHON_SCRIPT_EXTENSIONS.has(ext)) {
		return scanPythonScriptContent(relFile, rawContent);
	}
	if (SHELL_SCRIPT_EXTENSIONS.has(ext)) {
		return scanShellScriptContent(relFile, rawContent);
	}
	if (JS_TS_SCRIPT_EXTENSIONS.has(ext)) {
		return scanJsOrTsScriptContent(relFile, rawContent);
	}
	if (FORBIDDEN_COMPANION_SCRIPT_EXTENSIONS.has(ext)) {
		return [
			{
				file: relFile,
				line: 1,
				rule: "forbidden-shell-execution",
				symbol: ext,
				message: `Forbidden Windows/PowerShell companion script extension '${ext}' in '${relFile}'.`,
			},
			...scanShellScriptContent(relFile, rawContent),
		];
	}
	if (shebangLine !== null) {
		const lowerShebang = shebangLine.toLowerCase();
		let payloadFindings: SkillSecurityFinding[];
		if (lowerShebang.includes("python")) {
			payloadFindings = scanPythonScriptContent(relFile, rawContent);
		} else if (
			lowerShebang.includes("node") ||
			lowerShebang.includes("deno") ||
			lowerShebang.includes("bun") ||
			lowerShebang.includes("ts-node") ||
			lowerShebang.includes("tsx")
		) {
			payloadFindings = scanJsOrTsScriptContent(relFile, rawContent);
		} else {
			payloadFindings = scanShellScriptContent(relFile, rawContent);
		}
		return [
			{
				file: relFile,
				line: 1,
				rule: "forbidden-shell-execution",
				symbol: "#!",
				message: `Forbidden '#!' shebang executable header in non-standard companion file '${relFile}'.`,
			},
			...payloadFindings,
		];
	}
	return [];
}

interface WalkedSecurityTree {
	readonly candidateTextFiles: string[];
	readonly structuralFindings: SkillSecurityFinding[];
}

function walkSkillSecurityTree(
	rootDir: string,
	currentDir: string = rootDir,
): WalkedSecurityTree {
	if (!fs.existsSync(currentDir)) {
		return { candidateTextFiles: [], structuralFindings: [] };
	}

	const rootStat = fs.lstatSync(currentDir);
	if (rootStat.isSymbolicLink()) {
		const rel =
			path.relative(rootDir, currentDir).replace(/\\/g, "/") || ".";
		return {
			candidateTextFiles: [],
			structuralFindings: [
				{
					file: rel,
					line: 1,
					rule: "forbidden-symlink",
					symbol: "symlink",
					message: `Forbidden symbolic link '${rel}' inside Skill directory.`,
				},
			],
		};
	}

	if (!rootStat.isDirectory()) {
		return { candidateTextFiles: [], structuralFindings: [] };
	}

	const candidateTextFiles: string[] = [];
	const structuralFindings: SkillSecurityFinding[] = [];
	const entries = fs.readdirSync(currentDir, { withFileTypes: true });

	for (const entry of entries) {
		const fullPath = path.join(currentDir, entry.name);
		const relFile = path.relative(rootDir, fullPath).replace(/\\/g, "/");
		const entryLstat = fs.lstatSync(fullPath);

		if (entry.isSymbolicLink() || entryLstat.isSymbolicLink()) {
			structuralFindings.push({
				file: relFile,
				line: 1,
				rule: "forbidden-symlink",
				symbol: "symlink",
				message: `Forbidden symbolic link '${relFile}' inside Skill directory.`,
			});
			continue;
		}

		if (entryLstat.isDirectory()) {
			if (IGNORED_SCAN_DIRS.has(entry.name)) {
				continue;
			}
			const child = walkSkillSecurityTree(rootDir, fullPath);
			candidateTextFiles.push(...child.candidateTextFiles);
			structuralFindings.push(...child.structuralFindings);
			continue;
		}

		if (!entryLstat.isFile()) {
			structuralFindings.push({
				file: relFile,
				line: 1,
				rule: "forbidden-binary-file",
				symbol: "non-regular-file",
				message: `Forbidden non-regular file '${relFile}' inside Skill directory.`,
			});
			continue;
		}

		if (IGNORED_SCAN_FILES.has(entry.name)) {
			continue;
		}

		const forbiddenExt = hasForbiddenBinaryExtension(entry.name);
		if (forbiddenExt) {
			structuralFindings.push({
				file: relFile,
				line: 1,
				rule: "forbidden-binary-file",
				symbol: forbiddenExt,
				message: `Forbidden binary or archive file '${relFile}' (${forbiddenExt}) inside Skill directory.`,
			});
			continue;
		}

		const ext = path.extname(entry.name).toLowerCase();
		if (NON_TEXT_MEDIA_EXTENSIONS.has(ext)) {
			continue;
		}

		candidateTextFiles.push(fullPath);
	}

	return {
		candidateTextFiles: candidateTextFiles.sort(),
		structuralFindings,
	};
}

function decodeUtf8TextIfApplicable(
	rawBuffer: Buffer,
	ext: string,
): string | null {
	if (KNOWN_TEXT_EXTENSIONS.has(ext) || EXECUTABLE_SCRIPT_EXTENSIONS.has(ext)) {
		return rawBuffer.toString("utf-8");
	}
	try {
		return new TextDecoder("utf-8", { fatal: true }).decode(rawBuffer);
	} catch {
		return null;
	}
}

/**
 * Audit a single Skill directory for forbidden network exfiltration, dynamic code execution,
 * unsafe shell primitives, prompt-injection Markdown directives, Trojan-Source hidden Unicode,
 * symbolic links, and forbidden binary files.
 */
export function auditSkillSecurity(
	skillDir: string,
	options?: SecurityAuditOptions,
): SkillSecurityAuditReport {
	const resolvedSkillDir = path.resolve(skillDir);
	const allowlistEntries = loadBuiltinAllowlistEntries(
		resolvedSkillDir,
		options,
	);
	const { candidateTextFiles, structuralFindings } =
		walkSkillSecurityTree(resolvedSkillDir);
	const scannedFiles: string[] = [];
	const findings: SkillSecurityFinding[] = [...structuralFindings];

	for (const fullPath of candidateTextFiles) {
		const relFile = path
			.relative(resolvedSkillDir, fullPath)
			.replace(/\\/g, "/");
		const ext = path.extname(fullPath).toLowerCase();
		const isKnownExecutableExt = EXECUTABLE_SCRIPT_EXTENSIONS.has(ext);

		const boundedRead = readBoundedRegularFile(
			fullPath,
			relFile,
			"Skill directory",
		);
		if (!boundedRead.ok) {
			if (isKnownExecutableExt) {
				scannedFiles.push(relFile);
			}
			findings.push(boundedRead.finding);
			continue;
		}
		const rawBuffer = boundedRead.buffer;
		const rawContent = decodeUtf8TextIfApplicable(rawBuffer, ext);
		if (rawContent === null) {
			if (isKnownExecutableExt) {
				scannedFiles.push(relFile);
			}
			continue;
		}

		const nonStandardShebang = isKnownExecutableExt
			? null
			: extractShebangLine(rawContent);
		const isExecutableScript =
			isKnownExecutableExt || nonStandardShebang !== null;
		if (isExecutableScript) {
			scannedFiles.push(relFile);
		}

		const fileSha256 =
			allowlistEntries.length > 0
				? crypto.createHash("sha256").update(rawBuffer).digest("hex")
				: "";

		const fileFindings: SkillSecurityFinding[] = [];
		const longLineSeen = new Set<number>();

		for (const tf of scanTextForTrojanUnicode(
			relFile,
			rawContent,
			isExecutableScript,
		)) {
			if (tf.rule === "suspicious-long-line") {
				longLineSeen.add(tf.line);
			}
			fileFindings.push(tf);
		}

		if (shouldScanMarkdownPromptInjection(relFile)) {
			for (const mf of scanMarkdownForPromptInjection(relFile, rawContent)) {
				if (mf.rule === "suspicious-long-line" && longLineSeen.has(mf.line)) {
					continue;
				}
				fileFindings.push(mf);
			}
		}

		if (isExecutableScript) {
			const scriptFindings = scanScriptByExtensionOrShebang(
				relFile,
				ext,
				nonStandardShebang,
				rawContent,
			);
			for (const sf of scriptFindings) {
				if (sf.rule === "suspicious-long-line" && longLineSeen.has(sf.line)) {
					continue;
				}
				fileFindings.push(sf);
			}
		}

		for (const item of fileFindings) {
			if (
				fileSha256 &&
				isFindingCoveredByAllowlist(
					allowlistEntries,
					fullPath,
					item.rule,
					fileSha256,
				)
			) {
				continue;
			}
			findings.push(item);
		}
	}

	return {
		targetDir: resolvedSkillDir.replace(/\\/g, "/"),
		passed: findings.length === 0,
		scannedFiles,
		findings,
	};
}

interface NonSkillCatalogAuditResult {
	readonly findings: SkillSecurityFinding[];
	readonly scannedFiles: string[];
	readonly auditedFilePaths: Set<string>;
}

/**
 * Audit all non-skill directories and sibling files under `catalogRoot` (such as
 * `catalog/subagents/**` and track root folders) for symbolic links, forbidden binary
 * extensions, unexpected executable scripts / `#!` shebangs, Trojan Unicode, and
 * Markdown prompt-injection / image-beacon payloads.
 */
function auditNonSkillCatalogTree(
	catalogRoot: string,
	coveredSkillDirs: ReadonlySet<string>,
	allowlistEntries: readonly SecurityAllowlistEntry[],
	currentDir: string = catalogRoot,
	auditedFilePaths: Set<string> = new Set(),
): NonSkillCatalogAuditResult {
	if (!fs.existsSync(currentDir)) {
		return { findings: [], scannedFiles: [], auditedFilePaths };
	}

	const findings: SkillSecurityFinding[] = [];
	const scannedFiles: string[] = [];
	const rootStat = fs.lstatSync(currentDir);

	if (rootStat.isSymbolicLink()) {
		const rel =
			path.relative(catalogRoot, currentDir).replace(/\\/g, "/") || ".";
		return {
			findings: [
				{
					file: rel,
					line: 1,
					rule: "forbidden-symlink",
					symbol: "symlink",
					message: `Forbidden symbolic link '${rel}' in catalog directory.`,
				},
			],
			scannedFiles,
			auditedFilePaths,
		};
	}

	if (!rootStat.isDirectory()) {
		return { findings, scannedFiles, auditedFilePaths };
	}

	const entries = fs
		.readdirSync(currentDir, { withFileTypes: true })
		.sort((a, b) => a.name.localeCompare(b.name));

	for (const entry of entries) {
		const fullPath = path.join(currentDir, entry.name);
		const resolvedFull = path.resolve(fullPath);
		if (coveredSkillDirs.has(resolvedFull)) {
			continue;
		}
		const rel = path.relative(catalogRoot, fullPath).replace(/\\/g, "/");
		const entryLstat = fs.lstatSync(fullPath);

		if (entry.isSymbolicLink() || entryLstat.isSymbolicLink()) {
			findings.push({
				file: rel,
				line: 1,
				rule: "forbidden-symlink",
				symbol: "symlink",
				message: `Forbidden symbolic link '${rel}' in catalog directory.`,
			});
			continue;
		}

		if (entryLstat.isDirectory()) {
			if (IGNORED_SCAN_DIRS.has(entry.name)) {
				continue;
			}
			const child = auditNonSkillCatalogTree(
				catalogRoot,
				coveredSkillDirs,
				allowlistEntries,
				fullPath,
				auditedFilePaths,
			);
			findings.push(...child.findings);
			scannedFiles.push(...child.scannedFiles);
			continue;
		}

		if (!entryLstat.isFile()) {
			findings.push({
				file: rel,
				line: 1,
				rule: "forbidden-binary-file",
				symbol: "non-regular-file",
				message: `Forbidden non-regular file '${rel}' in catalog directory.`,
			});
			continue;
		}

		if (IGNORED_SCAN_FILES.has(entry.name)) {
			continue;
		}

		auditedFilePaths.add(resolvedFull);

		const forbiddenExt = hasForbiddenBinaryExtension(entry.name);
		if (forbiddenExt) {
			findings.push({
				file: rel,
				line: 1,
				rule: "forbidden-binary-file",
				symbol: forbiddenExt,
				message: `Forbidden binary or archive file '${rel}' (${forbiddenExt}) in catalog directory.`,
			});
			continue;
		}

		const ext = path.extname(entry.name).toLowerCase();
		if (NON_TEXT_MEDIA_EXTENSIONS.has(ext)) {
			continue;
		}

		const isKnownScriptExt = EXECUTABLE_SCRIPT_EXTENSIONS.has(ext);
		const boundedRead = readBoundedRegularFile(
			fullPath,
			rel,
			"catalog directory",
		);
		if (!boundedRead.ok) {
			if (isKnownScriptExt) {
				scannedFiles.push(rel);
				if (!FORBIDDEN_COMPANION_SCRIPT_EXTENSIONS.has(ext)) {
					findings.push({
						file: rel,
						line: 1,
						rule: "forbidden-shell-execution",
						symbol: ext,
						message: `Forbidden unexpected executable script '${rel}' outside a Skill directory.`,
					});
				}
			}
			findings.push(boundedRead.finding);
			continue;
		}
		const rawBuffer = boundedRead.buffer;
		const rawContent = decodeUtf8TextIfApplicable(rawBuffer, ext);
		if (rawContent === null) {
			if (isKnownScriptExt) {
				scannedFiles.push(rel);
				findings.push({
					file: rel,
					line: 1,
					rule: "forbidden-shell-execution",
					symbol: ext,
					message: `Forbidden unexpected executable script '${rel}' outside a Skill directory.`,
				});
			}
			continue;
		}

		const shebangLine = isKnownScriptExt ? null : extractShebangLine(rawContent);
		const isExecutable = isKnownScriptExt || shebangLine !== null;
		if (isExecutable) {
			scannedFiles.push(rel);
		}

		const fileSha256 =
			allowlistEntries.length > 0
				? crypto.createHash("sha256").update(rawBuffer).digest("hex")
				: "";

		const fileFindings: SkillSecurityFinding[] = [];
		const longLineSeen = new Set<number>();

		for (const tf of scanTextForTrojanUnicode(rel, rawContent, isExecutable)) {
			if (tf.rule === "suspicious-long-line") {
				longLineSeen.add(tf.line);
			}
			fileFindings.push(tf);
		}

		if (
			shouldScanMarkdownPromptInjection(rel) ||
			ext === ".md" ||
			ext === ".mdc"
		) {
			for (const mf of scanMarkdownForPromptInjection(rel, rawContent)) {
				if (mf.rule === "suspicious-long-line" && longLineSeen.has(mf.line)) {
					continue;
				}
				fileFindings.push(mf);
			}
		}

		if (isKnownScriptExt) {
			if (!FORBIDDEN_COMPANION_SCRIPT_EXTENSIONS.has(ext)) {
				fileFindings.push({
					file: rel,
					line: 1,
					rule: "forbidden-shell-execution",
					symbol: ext,
					message: `Forbidden unexpected executable script '${rel}' outside a Skill directory.`,
				});
			}
			for (const sf of scanScriptByExtensionOrShebang(
				rel,
				ext,
				null,
				rawContent,
			)) {
				if (sf.rule === "suspicious-long-line" && longLineSeen.has(sf.line)) {
					continue;
				}
				fileFindings.push(sf);
			}
		} else if (shebangLine !== null) {
			for (const sf of scanScriptByExtensionOrShebang(
				rel,
				ext,
				shebangLine,
				rawContent,
			)) {
				if (sf.rule === "suspicious-long-line" && longLineSeen.has(sf.line)) {
					continue;
				}
				fileFindings.push(sf);
			}
		}

		for (const item of fileFindings) {
			if (
				fileSha256 &&
				isFindingCoveredByAllowlist(
					allowlistEntries,
					fullPath,
					item.rule,
					fileSha256,
				)
			) {
				continue;
			}
			findings.push(item);
		}
	}

	return { findings, scannedFiles, auditedFilePaths };
}

/**
 * Audit every Skill directory, Subagent definition, and non-skill folder under `catalogDir`
 * for security violations.
 */
export function auditCatalogSecurity(
	catalogDir: string,
	options?: SecurityAuditOptions,
): SkillSecurityAuditReport {
	const resolvedCatalog = path.resolve(catalogDir);
	const allowlistEntries = loadBuiltinAllowlistEntries(
		resolvedCatalog,
		options,
	);
	const skillDirs = discoverSkillDirectories(resolvedCatalog);
	const coveredSkillDirs = new Set(skillDirs.map((d) => path.resolve(d)));

	const nonSkillResult = auditNonSkillCatalogTree(
		resolvedCatalog,
		coveredSkillDirs,
		allowlistEntries,
	);
	const scannedFiles: string[] = [...nonSkillResult.scannedFiles];
	const findings: SkillSecurityFinding[] = [...nonSkillResult.findings];

	for (const skillDir of skillDirs) {
		const report = auditSkillSecurity(skillDir, options);
		const skillRelPrefix = path
			.relative(resolvedCatalog, skillDir)
			.replace(/\\/g, "/");
		for (const sf of report.scannedFiles) {
			scannedFiles.push(`${skillRelPrefix}/${sf}`);
		}
		for (const f of report.findings) {
			findings.push({
				...f,
				file: `${skillRelPrefix}/${f.file}`,
			});
		}
	}

	// Ensure any discovered SUBAGENT.md not already audited above is still checked
	const subagentFiles = discoverSubagentFiles(resolvedCatalog);
	for (const saFullPath of subagentFiles) {
		const resolvedSa = path.resolve(saFullPath);
		if (nonSkillResult.auditedFilePaths.has(resolvedSa)) {
			continue;
		}
		let insideCoveredSkill = false;
		for (const covered of coveredSkillDirs) {
			const relToSkill = path.relative(covered, resolvedSa);
			if (
				relToSkill !== "" &&
				!relToSkill.startsWith("..") &&
				!path.isAbsolute(relToSkill)
			) {
				insideCoveredSkill = true;
				break;
			}
		}
		if (insideCoveredSkill) {
			continue;
		}

		const relFile = path
			.relative(resolvedCatalog, saFullPath)
			.replace(/\\/g, "/");
		const boundedRead = readBoundedRegularFile(
			saFullPath,
			relFile,
			"Subagent definition",
		);
		if (!boundedRead.ok) {
			findings.push(boundedRead.finding);
			continue;
		}
		const rawBuffer = boundedRead.buffer;
		const rawContent = rawBuffer.toString("utf-8");
		const fileSha256 =
			allowlistEntries.length > 0
				? crypto.createHash("sha256").update(rawBuffer).digest("hex")
				: "";
		const longLineSeen = new Set<number>();
		const saFindings: SkillSecurityFinding[] = [];
		for (const tf of scanTextForTrojanUnicode(relFile, rawContent, false)) {
			if (tf.rule === "suspicious-long-line") {
				longLineSeen.add(tf.line);
			}
			saFindings.push(tf);
		}
		for (const mf of scanMarkdownForPromptInjection(relFile, rawContent)) {
			if (mf.rule === "suspicious-long-line" && longLineSeen.has(mf.line)) {
				continue;
			}
			saFindings.push(mf);
		}
		for (const item of saFindings) {
			if (
				fileSha256 &&
				isFindingCoveredByAllowlist(
					allowlistEntries,
					saFullPath,
					item.rule,
					fileSha256,
				)
			) {
				continue;
			}
			findings.push(item);
		}
	}

	return {
		targetDir: resolvedCatalog.replace(/\\/g, "/"),
		passed: findings.length === 0,
		scannedFiles,
		findings,
	};
}
