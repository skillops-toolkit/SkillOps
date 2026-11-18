import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
	FORBIDDEN_BINARY_AND_ARCHIVE_EXTENSIONS,
	MAX_ALLOWLIST_BYTES,
	MAX_SCANNED_FILE_BYTES,
	MAX_SCANNED_LINE_LENGTH,
	type SecurityAllowlistEntry,
	type SecurityAllowlistFile,
	type SecurityAuditOptions,
	SHA256_HEX_REGEX,
	type SkillSecurityFinding,
	type SkillSecurityRuleId,
	VALID_RULE_IDS,
} from "./constants.js";

export function trimLeadingSlashes(value: string): string {
	let idx = 0;
	while (idx < value.length && value[idx] === "/") {
		idx += 1;
	}
	return idx === 0 ? value : value.slice(idx);
}

export function hasUnsafePathSyntax(rawPath: string): boolean {
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

export function resolveBuiltinPackageRoot(): string {
	let current = path.dirname(fileURLToPath(import.meta.url));
	for (let depth = 0; depth < 4; depth++) {
		current = path.resolve(current, "..");
		if (fs.existsSync(path.join(current, "package.json"))) {
			return current;
		}
	}
	return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
}

export function isPathInsideBuiltinCatalog(resolvedTarget: string): boolean {
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
export function resolveSafeAllowlistFile(
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

export type BoundedFileReadResult =
	| { readonly ok: true; readonly buffer: Buffer }
	| { readonly ok: false; readonly finding: SkillSecurityFinding };

/**
 * Safely read a regular, non-symlink file bounded by `maxBytes`.
 * Verifies `lstatSync` before opening, opens with `O_RDONLY | O_NOFOLLOW` where available,
 * re-verifies `fstatSync(fd)` on the open descriptor, and reads at most `maxBytes + 1` bytes
 * to prevent heap exhaustion or concurrent TOCTOU file growth.
 */
export function readBoundedRegularFile(
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

export function loadBuiltinAllowlistEntries(
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

export function isFindingCoveredByAllowlist(
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

export function makeLongLineFinding(
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
