import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
	isAllowedHarnessArtifactPath,
	type RuntimeTarget,
	type SyncLockEntry,
	type SyncLockfile,
	SyncLockfileSchema,
} from "../models.js";

export interface LoadLockfileOptions {
	/** When true (`--force`), allow falling back to `null` if `.skillops-lock.json` JSON/schema is malformed. */
	readonly allowMalformedRecovery?: boolean;
}

export function assertAllowedHarnessArtifactPath(
	target: RuntimeTarget,
	relPath: string,
	skillName?: string,
): void {
	if (!isAllowedHarnessArtifactPath(target, relPath, skillName)) {
		throw new Error(
			`Security violation: Path '${relPath}' is outside allowed harness directories for target '${target}'.`,
		);
	}
}

export const FORBIDDEN_PROTOTYPE_KEYS = new Set([
	"__proto__",
	"constructor",
	"prototype",
]);

export function hasPrototypeKeySegment(key: string): boolean {
	if (FORBIDDEN_PROTOTYPE_KEYS.has(key)) {
		return true;
	}
	const parts = key.replace(/\\/g, "/").split("/");
	return parts.some((part) => FORBIDDEN_PROTOTYPE_KEYS.has(part));
}

export function createNullProtoArtifactsMap(
	source?: Record<string, SyncLockEntry>,
): Record<string, SyncLockEntry> {
	const map = Object.create(null) as Record<string, SyncLockEntry>;
	if (!source) {
		return map;
	}
	for (const key of Object.getOwnPropertyNames(source)) {
		if (hasPrototypeKeySegment(key)) {
			throw new Error(
				`Security violation: Forbidden prototype key '${key}' in .skillops-lock.json.`,
			);
		}
		const val = source[key];
		if (val) {
			map[key] = val;
		}
	}
	return map;
}

export function getLockArtifact(
	artifacts: Record<string, SyncLockEntry> | undefined,
	relPath: string,
): SyncLockEntry | undefined {
	if (!artifacts || hasPrototypeKeySegment(relPath)) {
		return undefined;
	}
	return Object.hasOwn(artifacts, relPath) ? artifacts[relPath] : undefined;
}

export function loadExistingLockfile(
	lockfilePath: string,
	options: LoadLockfileOptions = {},
): SyncLockfile | null {
	let stat: fs.Stats;
	try {
		stat = fs.lstatSync(lockfilePath);
	} catch (err) {
		if ((err as NodeJS.ErrnoException)?.code === "ENOENT") {
			return null;
		}
		throw err;
	}
	const displayPath = lockfilePath.replace(/\\/g, "/");
	if (stat.isSymbolicLink() || !stat.isFile()) {
		throw new Error(
			`Security violation: Lockfile '${displayPath}' must be a regular non-symlink file.`,
		);
	}

	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(lockfilePath, "utf-8")) as unknown;
	} catch (err) {
		if (options.allowMalformedRecovery) {
			return null;
		}
		const reason = err instanceof Error ? err.message : String(err);
		throw new Error(
			`Corrupt or invalid lockfile '${displayPath}': malformed JSON (${reason}). Inspect the file or pass '--force' to recover.`,
		);
	}
	if (
		raw &&
		typeof raw === "object" &&
		"artifacts" in raw &&
		raw.artifacts &&
		typeof raw.artifacts === "object" &&
		!Array.isArray(raw.artifacts)
	) {
		for (const key of Object.getOwnPropertyNames(raw.artifacts)) {
			if (hasPrototypeKeySegment(key)) {
				throw new Error(
					`Security violation: Forbidden prototype key '${key}' in lockfile '${displayPath}'.`,
				);
			}
		}
	}
	try {
		const parsed = SyncLockfileSchema.parse(raw);
		return {
			...parsed,
			artifacts: createNullProtoArtifactsMap(parsed.artifacts),
		};
	} catch (err) {
		if (options.allowMalformedRecovery) {
			return null;
		}
		const reason = err instanceof Error ? err.message : String(err);
		throw new Error(
			`Corrupt or invalid lockfile '${displayPath}': schema validation failed (${reason}). Inspect the file or pass '--force' to recover.`,
		);
	}
}

/**
 * Persist `.skillops-lock.json` atomically via a unique temporary sibling file and `renameSync`.
 */
export function writeLockfileAtomically(
	lockfilePath: string,
	lockData: SyncLockfile,
): void {
	try {
		const existingStat = fs.lstatSync(lockfilePath);
		if (existingStat.isSymbolicLink()) {
			throw new Error(
				`Security violation: Refusing to write through symbolic link lockfile '${lockfilePath.replace(/\\/g, "/")}'.`,
			);
		}
	} catch (err) {
		if ((err as NodeJS.ErrnoException)?.code !== "ENOENT") {
			throw err;
		}
	}
	const dir = path.dirname(lockfilePath);
	fs.mkdirSync(dir, { recursive: true });
	const tmpName = `.skillops-lock.json.tmp.${process.pid}.${crypto.randomBytes(6).toString("hex")}`;
	const tmpPath = path.join(dir, tmpName);
	const serialized = `${JSON.stringify(lockData, null, 2)}\n`;
	try {
		fs.writeFileSync(tmpPath, serialized, "utf-8");
		fs.renameSync(tmpPath, lockfilePath);
	} catch (err) {
		try {
			if (fs.existsSync(tmpPath)) {
				fs.unlinkSync(tmpPath);
			}
		} catch {
			// Ignore cleanup error
		}
		throw err;
	}
}
