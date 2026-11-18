import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function trimTrailingSlashes(val: string): string {
	let end = val.length;
	while (end > 1 && val.charCodeAt(end - 1) === 47) {
		end -= 1;
	}
	return val.slice(0, end);
}

export function computeSha256(content: string): string {
	return crypto.createHash("sha256").update(content, "utf-8").digest("hex");
}

export function collectFilesRecursively(
	dirFullPath: string,
	resolvedRepo: string,
): string[] {
	if (!fs.existsSync(dirFullPath) || !fs.statSync(dirFullPath).isDirectory()) {
		return [];
	}
	const results: string[] = [];
	const entries = fs.readdirSync(dirFullPath, { withFileTypes: true });
	for (const entry of entries) {
		if (entry.isFile()) {
			const fullEntry = path.join(dirFullPath, entry.name);
			results.push(path.relative(resolvedRepo, fullEntry).replace(/\\/g, "/"));
		}
	}
	for (const entry of entries) {
		if (entry.isDirectory()) {
			const fullEntry = path.join(dirFullPath, entry.name);
			results.push(...collectFilesRecursively(fullEntry, resolvedRepo));
		}
	}
	return results;
}

export function removeEmptyDirsRecursively(dirFullPath: string): void {
	if (!fs.existsSync(dirFullPath) || !fs.statSync(dirFullPath).isDirectory()) {
		return;
	}
	for (const entry of fs.readdirSync(dirFullPath, { withFileTypes: true })) {
		if (entry.isDirectory()) {
			removeEmptyDirsRecursively(path.join(dirFullPath, entry.name));
		}
	}
	try {
		if (fs.readdirSync(dirFullPath).length === 0) {
			fs.rmdirSync(dirFullPath);
		}
	} catch {
		// Ignore
	}
}

/**
 * Resolve a repository-relative path and enforce strict containment inside `resolvedRepo`,
 * rejecting control characters, NTFS stream colons, absolute paths, `..` traversal,
 * and symbolic link / junction ancestors.
 */
export function resolveSafeRepoTargetPath(
	resolvedRepo: string,
	relativePath: string,
	precomputedCanonicalRepo?: string | null,
): string {
	const cleanRoot = path.resolve(resolvedRepo);
	const canonicalRepo =
		precomputedCanonicalRepo !== undefined
			? precomputedCanonicalRepo
			: fs.existsSync(cleanRoot)
				? fs.realpathSync(cleanRoot)
				: null;
	const boundaryLabel = cleanRoot.replace(/\\/g, "/");
	const rejectEscape = (): never => {
		throw new Error(
			`Security violation: Planned artifact path '${relativePath}' escapes target repository boundary '${boundaryLabel}'.`,
		);
	};
	if (
		!relativePath ||
		relativePath.startsWith("/") ||
		relativePath.startsWith("\\") ||
		path.isAbsolute(relativePath)
	) {
		return rejectEscape();
	}
	for (let i = 0; i < relativePath.length; i++) {
		const code = relativePath.charCodeAt(i);
		if (code < 32 || code === 127 || code === 58) {
			return rejectEscape();
		}
	}
	const fullPath = path.resolve(cleanRoot, relativePath);
	const relToRepo = path.relative(cleanRoot, fullPath);
	if (
		!relToRepo ||
		relToRepo === "." ||
		relToRepo.startsWith("..") ||
		path.isAbsolute(relToRepo)
	) {
		return rejectEscape();
	}

	let currentSeg = cleanRoot;
	let deepestExistingAncestor = cleanRoot;
	for (const seg of relToRepo.split(path.sep)) {
		if (!seg || seg === ".") {
			continue;
		}
		currentSeg = path.join(currentSeg, seg);
		let stat: fs.Stats;
		try {
			stat = fs.lstatSync(currentSeg);
		} catch {
			break;
		}
		if (stat.isSymbolicLink()) {
			throw new Error(
				`Security violation: Symbolic link '${relativePath}' escapes target repository boundary '${boundaryLabel}'.`,
			);
		}
		deepestExistingAncestor = currentSeg;
	}

	if (canonicalRepo !== null) {
		const canonicalAncestor = fs.existsSync(deepestExistingAncestor)
			? fs.realpathSync(deepestExistingAncestor)
			: canonicalRepo;
		const canonicalRel = path.relative(canonicalRepo, canonicalAncestor);
		if (canonicalRel.startsWith("..") || path.isAbsolute(canonicalRel)) {
			return rejectEscape();
		}
	}

	return fullPath;
}

export function pruneEmptyParentDirs(filePath: string, stopAtRepoRoot: string): void {
	const normalizedStop = path.resolve(stopAtRepoRoot);
	let currentDir = path.dirname(path.resolve(filePath));
	while (
		currentDir.startsWith(normalizedStop) &&
		currentDir !== normalizedStop
	) {
		if (!fs.existsSync(currentDir)) {
			currentDir = path.dirname(currentDir);
			continue;
		}
		try {
			const entries = fs.readdirSync(currentDir);
			if (entries.length > 0) {
				break;
			}
			fs.rmdirSync(currentDir);
			currentDir = path.dirname(currentDir);
		} catch {
			break;
		}
	}
}

export function isGlobalHomePath(repoPath: string): boolean {
	try {
		const normalizedRepo = trimTrailingSlashes(
			path.resolve(repoPath).replace(/\\/g, "/"),
		);
		const envHome = process.env.SKILLOPS_GLOBAL_HOME?.trim();
		const homeDir = envHome ? path.resolve(envHome) : os.homedir();
		const normalizedHome = trimTrailingSlashes(
			path.resolve(homeDir).replace(/\\/g, "/"),
		);
		return normalizedRepo === normalizedHome;
	} catch {
		return false;
	}
}
