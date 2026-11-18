/**
 * Charmbracelet Lip Gloss & Bubbles Inspired Terminal Styling Engine (`src/ui/lipgloss.ts`).
 *
 * Zero-dependency TypeScript implementation of Lip Gloss TrueColor (24-bit RGB)
 * palettes, background pills, Bubbles paginator dots, keycap status bars, and
 * ANSI-aware horizontal block composition (`joinHorizontal`).
 */

import {
	bgHex,
	CHARM_PALETTE,
	type CharmColorKey,
	fgHex,
	hexToRgb,
	isColorEnabled,
	padVisible,
	type PillOptions,
	renderPill,
	visibleLength,
} from "./palette.js";

export {
	bgHex,
	CHARM_PALETTE,
	type CharmColorKey,
	fgHex,
	hexToRgb,
	type PillOptions,
	renderPill,
};

const ESC = String.fromCharCode(27);

/**
 * Render a Charm `bubbles/help` style keybinding hint (`key action`).
 */
export function renderKeycap(
	keyLabel: string,
	actionLabel: string,
	colorEnabled?: boolean,
): string {
	const useColor = colorEnabled ?? isColorEnabled();
	if (!useColor) {
		return `${keyLabel} ${actionLabel}`;
	}
	const keyStyled = `${ESC}[1m${fgHex(CHARM_PALETTE.lavender, keyLabel, true)}${ESC}[22m`;
	const actionStyled = fgHex(CHARM_PALETTE.muted, actionLabel, true);
	return `${keyStyled} ${actionStyled}`;
}

/**
 * Render Charm `bubbles/paginator` style pagination dots (`• ◦ ◦`).
 */
export function renderPaginationDots(
	currentPage: number,
	totalPages: number,
	colorEnabled?: boolean,
): string {
	const safeTotal = Math.max(1, Math.min(12, totalPages));
	const safeCurrent = Math.max(0, Math.min(safeTotal - 1, currentPage));
	const useColor = colorEnabled ?? isColorEnabled();
	const dots: string[] = [];
	for (let i = 0; i < safeTotal; i++) {
		if (i === safeCurrent) {
			dots.push(
				useColor
					? `${ESC}[1m${fgHex(CHARM_PALETTE.hotPink, "•", true)}${ESC}[22m`
					: "•",
			);
		} else {
			dots.push(useColor ? fgHex(CHARM_PALETTE.muted, "◦", true) : "◦");
		}
	}
	return dots.join(" ");
}

/**
 * Compose two multi-line blocks horizontally (`lipgloss.JoinHorizontal`).
 */
export function joinHorizontal(
	align: "top" | "center" | "bottom",
	leftBlock: string,
	rightBlock: string,
	gap = 2,
): string {
	const leftLines = leftBlock.split("\n");
	const rightLines = rightBlock.split("\n");
	const totalRows = Math.max(leftLines.length, rightLines.length);
	const leftWidth = leftLines.reduce(
		(max, line) => Math.max(max, visibleLength(line)),
		0,
	);
	const gapStr = " ".repeat(Math.max(0, gap));

	const padBlockLines = (lines: string[]): string[] => {
		const diff = totalRows - lines.length;
		if (diff <= 0) {
			return lines;
		}
		if (align === "bottom") {
			return [...Array.from({ length: diff }, () => ""), ...lines];
		}
		if (align === "center") {
			const top = Math.floor(diff / 2);
			const bottom = diff - top;
			return [
				...Array.from({ length: top }, () => ""),
				...lines,
				...Array.from({ length: bottom }, () => ""),
			];
		}
		return [...lines, ...Array.from({ length: diff }, () => "")];
	};

	const paddedLeft = padBlockLines(leftLines);
	const paddedRight = padBlockLines(rightLines);

	const out: string[] = [];
	for (let i = 0; i < totalRows; i++) {
		const l = padVisible(paddedLeft[i] ?? "", leftWidth, "left");
		const r = paddedRight[i] ?? "";
		out.push(r.length > 0 ? `${l}${gapStr}${r}` : l.trimEnd());
	}
	return out.join("\n");
}
