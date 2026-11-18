import fs from "node:fs";
import { type SyncLockEntry, type SyncLockfile, SyncLockfileSchema } from "../models.js";

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

export function loadExistingLockfile(lockfilePath: string): SyncLockfile | null {
	if (!fs.existsSync(lockfilePath) || !fs.statSync(lockfilePath).isFile()) {
		return null;
	}
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(lockfilePath, "utf-8")) as unknown;
	} catch {
		return null;
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
					`Security violation: Forbidden prototype key '${key}' in lockfile '${lockfilePath.replace(/\\/g, "/")}'.`,
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
	} catch {
		return null;
	}
}
