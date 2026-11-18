/**
 * Shared constants, rule identifiers, and security limits (`src/auditor/security/constants.ts`).
 */

export const MAX_SCANNED_LINE_LENGTH = 4096;
export const MAX_SCANNED_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_ALLOWLIST_BYTES = 1_048_576;

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

export const VALID_RULE_IDS: ReadonlySet<SkillSecurityRuleId> = new Set([
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
export const FORBIDDEN_PYTHON_NETWORK_ROOT_MODULES = new Set([
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
export const FORBIDDEN_PYTHON_NETWORK_SUBMODULES = new Set([
	"urllib.request",
	"urllib.urlopen",
	"http.client",
	"xmlrpc.client",
]);

export const FORBIDDEN_PYTHON_EXEC_MODULES = new Set([
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

export const FORBIDDEN_PYTHON_SHELL_MODULES = new Set([
	"pty",
	"commands",
	"subprocess",
	"_posixsubprocess",
	"asyncio",
	"multiprocessing",
]);

export const FORBIDDEN_PYTHON_OS_CALLS = new Set([
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

export const DANGEROUS_PYTHON_REFLECTION_ATTRS = new Set([
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

export const PYTHON_ALIASABLE_MODULES = new Set([
	"os",
	"posix",
	"nt",
	"sys",
	"builtins",
	"__builtins__",
	"urllib",
]);

export const FORBIDDEN_JS_SHELL_MODULES = new Set(["child_process"]);

export const FORBIDDEN_JS_EXEC_MODULES = new Set([
	"vm",
	"worker_threads",
	"module",
	"inspector",
	"v8",
	"wasi",
]);

export const FORBIDDEN_JS_NETWORK_MODULES = new Set([
	"net",
	"http",
	"https",
	"http2",
	"tls",
	"dgram",
	"dns",
	"undici",
]);

export const GLOBAL_JS_OBJECTS = new Set(["globalThis", "global", "window", "self"]);

export const FORBIDDEN_PROCESS_METHODS = new Set([
	"binding",
	"dlopen",
	"getBuiltinModule",
	"mainModule",
	"_load",
]);

export const SHELL_PIPE_INTERPRETERS = new Set([
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

export const BASE64_PIPE_INTERPRETERS = new Set([
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

export const FORBIDDEN_SHELL_NETWORK_COMMANDS = new Set([
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

export const FORBIDDEN_SHELL_SUBINTERPRETERS = new Set([
	"sh",
	"bash",
	"zsh",
	"dash",
	"ksh",
	"pwsh",
	"powershell",
]);

export const SHELL_COMMAND_WRAPPERS = new Set([
	"sudo",
	"env",
	"command",
	"builtin",
	"nohup",
	"time",
	"exec",
]);

export const IGNORED_SCAN_DIRS = new Set([
	".git",
	"__pycache__",
	"node_modules",
	".pytest_cache",
	".ruff_cache",
	".mypy_cache",
]);

export const IGNORED_SCAN_FILES = new Set([".DS_Store", "Thumbs.db", "desktop.ini"]);

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

export const NON_TEXT_MEDIA_EXTENSIONS = new Set([
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

export const PYTHON_SCRIPT_EXTENSIONS = new Set([".py", ".pyw"]);

export const SHELL_SCRIPT_EXTENSIONS = new Set([".sh", ".bash", ".zsh", ".ksh"]);

export const JS_TS_SCRIPT_EXTENSIONS = new Set([
	".mjs",
	".js",
	".cjs",
	".mts",
	".cts",
	".ts",
	".tsx",
	".jsx",
]);

export const FORBIDDEN_COMPANION_SCRIPT_EXTENSIONS = new Set([
	".ps1",
	".bat",
	".cmd",
]);

export const EXECUTABLE_SCRIPT_EXTENSIONS = new Set([
	...PYTHON_SCRIPT_EXTENSIONS,
	...SHELL_SCRIPT_EXTENSIONS,
	...JS_TS_SCRIPT_EXTENSIONS,
	...FORBIDDEN_COMPANION_SCRIPT_EXTENSIONS,
]);

export const KNOWN_TEXT_EXTENSIONS = new Set([
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
export const TROJAN_BIDI_OR_TAG_REGEX =
	/[\u0000\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u{E0000}-\u{E007F}]/u;

/**
 * Zero-width characters forbidden inside executable scripts where they can spoof identifiers
 * or hide payload boundaries.
 */
export const SCRIPT_ZERO_WIDTH_REGEX = /[\u200B-\u200D\u2060-\u2064\uFEFF]/u;

export const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;
export const DEV_SOCKET_REGEX = /\/dev\/(?:tcp|udp)\//;

export function isHexDigitCode(code: number): boolean {
	return (
		(code >= 48 && code <= 57) ||
		(code >= 65 && code <= 70) ||
		(code >= 97 && code <= 102)
	);
}

export function isAsciiAlphaOrUnderscore(ch: string): boolean {
	const code = ch.charCodeAt(0);
	return (
		(code >= 65 && code <= 90) ||
		(code >= 97 && code <= 122) ||
		code === 95
	);
}

export function isAsciiAlnumOrUnderscore(ch: string): boolean {
	const code = ch.charCodeAt(0);
	return (
		(code >= 48 && code <= 57) ||
		(code >= 65 && code <= 90) ||
		(code >= 97 && code <= 122) ||
		code === 95
	);
}

export function isAsciiDigit(ch: string): boolean {
	const code = ch.charCodeAt(0);
	return code >= 48 && code <= 57;
}
