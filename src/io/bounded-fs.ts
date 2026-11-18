/**
 * Bounded, symlink-safe UTF-8 filesystem readers for SkillOps manifests,
 * workspace configuration (.skillops.yml), evaluation suites, and lockfiles.
 *
 * Enforces Charter Principles II & V:
 * - Symbolic links are rejected via lstatSync + O_NOFOLLOW (where supported).
 * - File byte size is verified on both lstatSync and the opened file descriptor (fstatSync)
 *   before allocating heap buffers, plus a +1 byte read probe to prevent concurrent growth TOCTOU.
 */

import fs from "node:fs";
import {
	ALL_RUNTIME_TARGETS,
	type LoadedSkillOpsConfigResult,
	parseSkillMdText,
	parseSkillOpsConfigText,
	parseSubagentMdText,
	RUNTIME_HARNESS_SPECS,
	type RuntimeTarget,
	type SkillManifest,
	type SubagentManifest,
	trimTrailingSlashes,
} from "../models.js";

/** Maximum byte size for `.skillops.yml` workspace configuration (64 KiB). */
export const MAX_CONFIG_FILE_BYTES = 64 * 1024;

/** Maximum byte size for `SKILL.md`, `SUBAGENT.md`, `evals.json`, and `benchmark.json` (256 KiB). */
export const MAX_MANIFEST_FILE_BYTES = 256 * 1024;

/** Maximum byte size for companion scripts, references, and `.skillops-lock.json` (2 MiB). */
export const MAX_COMPANION_OR_LOCK_BYTES = 2 * 1024 * 1024;

/**
 * Read a UTF-8 regular file strictly bounded to `maxBytes` without following symbolic links
 * or allocating unbounded heap buffers.
 */
export function readBoundedUtf8File(
	filePath: string,
	maxBytes: number,
	label?: string,
): string {
	if (!Number.isInteger(maxBytes) || maxBytes <= 0) {
		throw new RangeError(
			`maxBytes must be a positive integer (got ${String(maxBytes)}).`,
		);
	}

	const displayLabel = label ?? filePath.replace(/\\/g, "/");
	const lstat = fs.lstatSync(filePath);

	if (lstat.isSymbolicLink()) {
		throw new Error(
			`Security violation: '${displayLabel}' cannot be a symbolic link.`,
		);
	}
	if (!lstat.isFile()) {
		throw new Error(
			`Security violation: '${displayLabel}' must be a regular file.`,
		);
	}
	if (lstat.size > maxBytes) {
		throw new Error(
			`Security violation: '${displayLabel}' size (${lstat.size} bytes) exceeds maximum allowed limit of ${maxBytes} bytes.`,
		);
	}

	const openFlags =
		fs.constants.O_RDONLY |
		(typeof fs.constants.O_NOFOLLOW === "number" ? fs.constants.O_NOFOLLOW : 0);

	let fd: number;
	try {
		fd = fs.openSync(filePath, openFlags);
	} catch (err) {
		const code = (err as NodeJS.ErrnoException | undefined)?.code;
		if (code === "ELOOP" || code === "EMLINK") {
			throw new Error(
				`Security violation: '${displayLabel}' cannot be a symbolic link.`,
			);
		}
		throw err;
	}

	try {
		const fstat = fs.fstatSync(fd);
		if (fstat.isSymbolicLink() || !fstat.isFile()) {
			throw new Error(
				`Security violation: '${displayLabel}' must be a regular file.`,
			);
		}
		if (
			lstat.ino !== 0 &&
			fstat.ino !== 0 &&
			(lstat.dev !== fstat.dev || lstat.ino !== fstat.ino)
		) {
			throw new Error(
				`Security violation: File identity changed while opening '${displayLabel}'.`,
			);
		}
		if (fstat.size > maxBytes) {
			throw new Error(
				`Security violation: '${displayLabel}' size (${fstat.size} bytes) exceeds maximum allowed limit of ${maxBytes} bytes.`,
			);
		}

		const initialCap =
			fstat.size > 0
				? Math.min(fstat.size, maxBytes)
				: Math.min(8192, maxBytes);
		const scratch = Buffer.allocUnsafe(
			Math.min(65536, Math.max(initialCap, 1) + 1),
		);
		const chunks: Buffer[] = [];
		let totalBytes = 0;

		while (true) {
			const remainingProbeAllowance = maxBytes - totalBytes + 1;
			const toRead = Math.min(scratch.length, remainingProbeAllowance);
			const bytesRead = fs.readSync(fd, scratch, 0, toRead, null);
			if (bytesRead === 0) {
				break;
			}
			totalBytes += bytesRead;
			if (totalBytes > maxBytes) {
				throw new Error(
					`Security violation: '${displayLabel}' exceeds maximum allowed limit of ${maxBytes} bytes.`,
				);
			}
			chunks.push(Buffer.from(scratch.subarray(0, bytesRead)));
		}

		if (chunks.length === 0) {
			return "";
		}
		const combined =
			chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks, totalBytes);
		return combined.toString("utf-8");
	} finally {
		fs.closeSync(fd);
	}
}

/**
 * Deterministically detect which of the 28 AI coding agent harnesses have configuration
 * directories or instruction files present in `repoPath` (ignoring symbolic links).
 */
export function detectInstalledHarnesses(repoPath: string): RuntimeTarget[] {
	const normalizedRoot = trimTrailingSlashes(repoPath.replace(/\\/g, "/"));
	const detected: RuntimeTarget[] = [];

	for (const target of ALL_RUNTIME_TARGETS) {
		const spec = RUNTIME_HARNESS_SPECS[target];
		const hasMatch = spec.detectionPaths.some((relPath) => {
			try {
				const lstat = fs.lstatSync(`${normalizedRoot}/${relPath}`);
				return !lstat.isSymbolicLink();
			} catch {
				return false;
			}
		});
		if (hasMatch) {
			detected.push(target);
		}
	}

	return detected;
}

/**
 * Parse and validate a `SKILL.md` file from disk using bounded, symlink-safe I/O.
 */
export function parseSkillMdFile(filePath: string): SkillManifest {
	const normalizedPath = filePath.replace(/\\/g, "/");
	const rawText = readBoundedUtf8File(
		filePath,
		MAX_MANIFEST_FILE_BYTES,
		normalizedPath,
	);
	return parseSkillMdText(rawText, normalizedPath).manifest;
}

/**
 * Parse and validate a `SUBAGENT.md` / `*.agent.md` file from disk using bounded, symlink-safe I/O.
 */
export function parseSubagentMdFile(filePath: string): {
	manifest: SubagentManifest;
	systemPromptBody: string;
} {
	const normalizedPath = filePath.replace(/\\/g, "/");
	const rawText = readBoundedUtf8File(
		filePath,
		MAX_MANIFEST_FILE_BYTES,
		normalizedPath,
	);
	return parseSubagentMdText(rawText, normalizedPath);
}

/**
 * Load and validate `.skillops.yml` from a repository root if present,
 * rejecting symbolic links and files exceeding 64 KiB (`MAX_CONFIG_FILE_BYTES`).
 */
export function loadSkillOpsConfigFromDisk(
	repoPath: string,
): LoadedSkillOpsConfigResult {
	const configPath = `${trimTrailingSlashes(repoPath.replace(/\\/g, "/"))}/.skillops.yml`;
	let lstat: fs.Stats;
	try {
		lstat = fs.lstatSync(configPath);
	} catch (err) {
		const code = (err as NodeJS.ErrnoException | undefined)?.code;
		if (code === "ENOENT" || code === "ENOTDIR") {
			return {
				config: null,
				configPath,
				exists: false,
				error: null,
			};
		}
		const message = err instanceof Error ? err.message : String(err);
		return {
			config: null,
			configPath,
			exists: true,
			error: message,
		};
	}

	if (lstat.isSymbolicLink()) {
		return {
			config: null,
			configPath,
			exists: true,
			error: `Security violation: '${configPath}' cannot be a symbolic link.`,
		};
	}
	if (!lstat.isFile()) {
		return {
			config: null,
			configPath,
			exists: false,
			error: null,
		};
	}

	try {
		const rawYaml = readBoundedUtf8File(
			configPath,
			MAX_CONFIG_FILE_BYTES,
			configPath,
		);
		const validated = parseSkillOpsConfigText(rawYaml);
		return {
			config: validated,
			configPath,
			exists: true,
			error: null,
		};
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			config: null,
			configPath,
			exists: true,
			error: message,
		};
	}
}

export const loadSkillOpsConfig = loadSkillOpsConfigFromDisk;
