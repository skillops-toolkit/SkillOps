import type { ParsedSkillDirectory, ParsedSubagentFile } from "./parser.js";

export const DEFAULT_SEMANTIC_COLLISION_THRESHOLD = 0.65;

export interface SemanticCollisionPair {
	readonly item_a: string;
	readonly kind_a: "skill" | "subagent";
	readonly item_b: string;
	readonly kind_b: "skill" | "subagent";
	readonly similarity: number;
	readonly trigram_jaccard: number;
	readonly tfidf_cosine: number;
	readonly routing_overlap: number;
	readonly shared_tokens: string[];
}

export interface SemanticCollisionReport {
	readonly threshold: number;
	readonly pairs_checked: number;
	readonly collisions: SemanticCollisionPair[];
	readonly passed: boolean;
}

interface CollisionCandidate {
	readonly name: string;
	readonly kind: "skill" | "subagent";
	readonly positiveText: string;
	readonly tokens: string[];
	readonly trigrams: Set<string>;
	readonly routingSignals: Set<string>;
}

const STOPWORDS = new Set([
	"a",
	"an",
	"and",
	"are",
	"as",
	"at",
	"be",
	"by",
	"for",
	"from",
	"in",
	"into",
	"is",
	"it",
	"of",
	"on",
	"or",
	"that",
	"the",
	"this",
	"to",
	"use",
	"used",
	"using",
	"when",
	"with",
]);

const NEGATIVE_TRIGGER_BOUNDARY =
	/\b(?:do\s+not\s+(?:trigger|use)|never\s+(?:trigger|use)|not\s+for)\b/i;

/**
 * Extract the positive trigger portion of a Skill/Subagent description before any
 * negative-boundary guard clause ("Do not trigger...", "Do NOT use...", etc.).
 */
export function extractPositiveTriggerText(description: string): string {
	const trimmed = description.trim();
	const match = NEGATIVE_TRIGGER_BOUNDARY.exec(trimmed);
	const positive =
		match && match.index > 0 ? trimmed.slice(0, match.index) : trimmed;
	return positive
		.toLowerCase()
		.replace(/[^a-z0-9\s-]/g, " ")
		.replace(/\s+/g, " ")
		.trim();
}

function tokenizePositiveText(normalized: string): string[] {
	if (!normalized) {
		return [];
	}
	return normalized
		.split(/[\s-]+/)
		.filter((tok) => tok.length >= 2 && !STOPWORDS.has(tok));
}

function buildCharTrigrams(normalized: string): Set<string> {
	const compact = normalized.replace(/\s+/g, " ");
	const grams = new Set<string>();
	if (compact.length < 3) {
		if (compact.length > 0) {
			grams.add(compact);
		}
		return grams;
	}
	for (let i = 0; i <= compact.length - 3; i += 1) {
		grams.add(compact.slice(i, i + 3));
	}
	return grams;
}

function computeSetJaccard(a: Set<string>, b: Set<string>): number {
	if (a.size === 0 && b.size === 0) {
		return 0;
	}
	let intersection = 0;
	const [smaller, larger] = a.size <= b.size ? [a, b] : [b, a];
	for (const item of smaller) {
		if (larger.has(item)) {
			intersection += 1;
		}
	}
	const union = a.size + b.size - intersection;
	return union === 0 ? 0 : intersection / union;
}

function buildIdfTable(candidates: readonly CollisionCandidate[]): Map<string, number> {
	const docFreq = new Map<string, number>();
	for (const candidate of candidates) {
		const uniqueTokens = new Set(candidate.tokens);
		for (const token of uniqueTokens) {
			docFreq.set(token, (docFreq.get(token) ?? 0) + 1);
		}
	}
	const n = Math.max(1, candidates.length);
	const idf = new Map<string, number>();
	for (const [token, df] of docFreq.entries()) {
		idf.set(token, Math.log((n + 1) / (df + 1)) + 1);
	}
	return idf;
}

function buildTfIdfVector(
	tokens: readonly string[],
	idf: ReadonlyMap<string, number>,
): Map<string, number> {
	const counts = new Map<string, number>();
	for (const token of tokens) {
		counts.set(token, (counts.get(token) ?? 0) + 1);
	}
	const total = Math.max(1, tokens.length);
	const vec = new Map<string, number>();
	for (const [token, count] of counts.entries()) {
		const weight = (count / total) * (idf.get(token) ?? 1);
		vec.set(token, weight);
	}
	return vec;
}

function computeVectorCosine(
	vecA: ReadonlyMap<string, number>,
	vecB: ReadonlyMap<string, number>,
): number {
	if (vecA.size === 0 || vecB.size === 0) {
		return 0;
	}
	let dot = 0;
	let normA = 0;
	let normB = 0;
	for (const [k, v] of vecA.entries()) {
		normA += v * v;
		const bVal = vecB.get(k);
		if (bVal !== undefined) {
			dot += v * bVal;
		}
	}
	for (const v of vecB.values()) {
		normB += v * v;
	}
	const denom = Math.sqrt(normA) * Math.sqrt(normB);
	return denom === 0 ? 0 : dot / denom;
}

function collectCandidateSignals(
	globs: readonly string[] = [],
	keywords: readonly string[] = [],
	stacks: readonly string[] = [],
): Set<string> {
	const signals = new Set<string>();
	for (const g of globs) {
		signals.add(`glob:${g.toLowerCase().trim()}`);
	}
	for (const k of keywords) {
		signals.add(`kw:${k.toLowerCase().trim()}`);
	}
	for (const s of stacks) {
		signals.add(`stack:${s.toLowerCase().trim()}`);
	}
	return signals;
}

function roundScore(value: number): number {
	return Math.round(value * 10_000) / 10_000;
}

/**
 * Detect pairwise semantic routing collisions across all catalog Skills and Subagents
 * (INV-SKILL-04) using character-trigram Jaccard, TF-IDF cosine, and routing signal overlap.
 */
export function detectSemanticCollisions(
	skills: readonly ParsedSkillDirectory[],
	subagents: readonly ParsedSubagentFile[],
	options: { readonly threshold?: number } = {},
): SemanticCollisionReport {
	const threshold =
		options.threshold !== undefined &&
		Number.isFinite(options.threshold) &&
		options.threshold > 0 &&
		options.threshold <= 1
			? options.threshold
			: DEFAULT_SEMANTIC_COLLISION_THRESHOLD;

	const candidates: CollisionCandidate[] = [
		...skills.map((s) => {
			const positiveText = extractPositiveTriggerText(s.manifest.description);
			return {
				name: s.manifest.name,
				kind: "skill" as const,
				positiveText,
				tokens: tokenizePositiveText(positiveText),
				trigrams: buildCharTrigrams(positiveText),
				routingSignals: collectCandidateSignals(
					s.manifest.routing_signals.active_file_globs,
					s.manifest.routing_signals.languages,
					s.manifest.routing_signals.dependencies_any,
				),
			};
		}),
		...subagents.map((sa) => {
			const positiveText = extractPositiveTriggerText(sa.manifest.description);
			return {
				name: sa.manifest.name,
				kind: "subagent" as const,
				positiveText,
				tokens: tokenizePositiveText(positiveText),
				trigrams: buildCharTrigrams(positiveText),
				routingSignals: new Set<string>(),
			};
		}),
	].sort((a, b) =>
		`${a.kind}:${a.name}`.localeCompare(`${b.kind}:${b.name}`),
	);

	const idf = buildIdfTable(candidates);
	const vectors = candidates.map((c) => buildTfIdfVector(c.tokens, idf));
	const collisions: SemanticCollisionPair[] = [];
	let pairsChecked = 0;

	for (let i = 0; i < candidates.length; i += 1) {
		const a = candidates[i];
		const vecA = vectors[i];
		if (!a || !vecA) {
			continue;
		}
		for (let j = i + 1; j < candidates.length; j += 1) {
			const b = candidates[j];
			const vecB = vectors[j];
			if (!b || !vecB) {
				continue;
			}
			pairsChecked += 1;

			const trigramJaccard = computeSetJaccard(a.trigrams, b.trigrams);
			const tfidfCosine = computeVectorCosine(vecA, vecB);
			const hasRouting =
				a.routingSignals.size > 0 || b.routingSignals.size > 0;
			const routingOverlap = hasRouting
				? computeSetJaccard(a.routingSignals, b.routingSignals)
				: 0;

			const similarity = hasRouting
				? 0.45 * trigramJaccard + 0.4 * tfidfCosine + 0.15 * routingOverlap
				: 0.5 * trigramJaccard + 0.5 * tfidfCosine;

			if (similarity >= threshold) {
				const tokenSetB = new Set(b.tokens);
				const sharedTokens = [...new Set(a.tokens)]
					.filter((t) => tokenSetB.has(t))
					.sort()
					.slice(0, 8);

				collisions.push({
					item_a: a.name,
					kind_a: a.kind,
					item_b: b.name,
					kind_b: b.kind,
					similarity: roundScore(similarity),
					trigram_jaccard: roundScore(trigramJaccard),
					tfidf_cosine: roundScore(tfidfCosine),
					routing_overlap: roundScore(routingOverlap),
					shared_tokens: sharedTokens,
				});
			}
		}
	}

	collisions.sort(
		(a, b) =>
			b.similarity - a.similarity ||
			a.item_a.localeCompare(b.item_a) ||
			a.item_b.localeCompare(b.item_b),
	);

	return {
		threshold,
		pairs_checked: pairsChecked,
		collisions,
		passed: collisions.length === 0,
	};
}
