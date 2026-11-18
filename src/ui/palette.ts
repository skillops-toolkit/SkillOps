/**
 * Shared ANSI color palette, TTY detection, and visible-width primitives (`src/ui/palette.ts`).
 *
 * Extracted to eliminate circular imports between `src/ui/lipgloss.ts` and `src/ui/terminal.ts`.
 */

const ESC = String.fromCharCode(27);
const ANSI_ESCAPE_REGEX = new RegExp(`${ESC}\\[[0-9;]*m`, "g");

/**
 * SkillOps Soot, Chalk & Electric Lime TrueColor palette (aligned with SkillOps-Web).
 */
export const CHARM_PALETTE = {
	indigo: "#DAFA9C",
	fuchsia: "#DAFA9C",
	hotPink: "#DAFA9C",
	mint: "#DAFA9C",
	amber: "#E5C07B",
	coral: "#FF5F56",
	cyan: "#FFFFFF",
	lavender: "#A8A8A8",
	white: "#FFFFFF",
	muted: "#6C6C6C",
	subtle: "#454545",
	surface: "#1A1A1A",
	keycapBg: "#242424",
	inkDark: "#0F0F0F",
} as const;

export type CharmColorKey = keyof typeof CHARM_PALETTE;

export interface ColorOverrideOptions {
	readonly env?: NodeJS.ProcessEnv;
	readonly isTTY?: boolean;
}

/**
 * Determine whether ANSI terminal colors should be emitted.
 * Respects https://no-color.org (`NO_COLOR`), `FORCE_COLOR`, `TERM=dumb`, and `stdout.isTTY`.
 */
export function isColorEnabled(options?: ColorOverrideOptions): boolean {
	const env = options?.env ?? process.env;
	const isTTY = options?.isTTY ?? Boolean(process.stdout?.isTTY);

	if (env.NO_COLOR !== undefined && env.NO_COLOR !== "") {
		return false;
	}
	if (env.FORCE_COLOR !== undefined) {
		const val = env.FORCE_COLOR.trim().toLowerCase();
		if (val === "0" || val === "false") {
			return false;
		}
		if (val === "1" || val === "2" || val === "3" || val === "true") {
			return true;
		}
	}
	if (env.TERM === "dumb") {
		return false;
	}
	return isTTY;
}

/**
 * Strip all ANSI SGR escape sequences from a string.
 */
export function stripAnsi(text: string): string {
	return text.replace(ANSI_ESCAPE_REGEX, "");
}

/**
 * Compute visible character width of a string ignoring ANSI color codes.
 */
export function visibleLength(text: string): number {
	return Array.from(stripAnsi(text)).length;
}

/**
 * Pad a potentially ANSI-styled string to a target visible width.
 */
export function padVisible(
	text: string,
	width: number,
	align: "left" | "right" | "center" = "left",
): string {
	const len = visibleLength(text);
	if (len >= width) {
		return text;
	}
	const diff = width - len;
	if (align === "right") {
		return `${" ".repeat(diff)}${text}`;
	}
	if (align === "center") {
		const left = Math.floor(diff / 2);
		const right = diff - left;
		return `${" ".repeat(left)}${text}${" ".repeat(right)}`;
	}
	return `${text}${" ".repeat(diff)}`;
}

/**
 * Parse a `#RRGGBB` or `#RGB` hex color string into an `[r, g, b]` tuple.
 */
export function hexToRgb(hex: string): readonly [number, number, number] {
	const cleaned = hex.trim().replace(/^#/, "");
	if (cleaned.length === 3) {
		const r = Number.parseInt(`${cleaned[0]}${cleaned[0]}`, 16);
		const g = Number.parseInt(`${cleaned[1]}${cleaned[1]}`, 16);
		const b = Number.parseInt(`${cleaned[2]}${cleaned[2]}`, 16);
		return [
			Number.isNaN(r) ? 255 : r,
			Number.isNaN(g) ? 255 : g,
			Number.isNaN(b) ? 255 : b,
		];
	}
	const r = Number.parseInt(cleaned.slice(0, 2), 16);
	const g = Number.parseInt(cleaned.slice(2, 4), 16);
	const b = Number.parseInt(cleaned.slice(4, 6), 16);
	return [
		Number.isNaN(r) ? 255 : r,
		Number.isNaN(g) ? 255 : g,
		Number.isNaN(b) ? 255 : b,
	];
}

/**
 * Apply 24-bit TrueColor foreground (`\x1b[38;2;R;G;Bm`) when color is enabled.
 */
export function fgHex(hex: string, text: string, enabled?: boolean): string {
	const useColor = enabled ?? isColorEnabled();
	if (!useColor || text.length === 0) {
		return text;
	}
	const [r, g, b] = hexToRgb(hex);
	return `${ESC}[38;2;${r};${g};${b}m${text}${ESC}[39m`;
}

/**
 * Apply 24-bit TrueColor background (`\x1b[48;2;R;G;Bm`) when color is enabled.
 */
export function bgHex(hex: string, text: string, enabled?: boolean): string {
	const useColor = enabled ?? isColorEnabled();
	if (!useColor || text.length === 0) {
		return text;
	}
	const [r, g, b] = hexToRgb(hex);
	return `${ESC}[48;2;${r};${g};${b}m${text}${ESC}[49m`;
}

export interface PillOptions {
	readonly fg?: string;
	readonly bg?: string;
	readonly bold?: boolean;
	readonly colorEnabled?: boolean;
}

/**
 * Render a Lip Gloss background pill badge without altering visible character length.
 */
export function renderPill(text: string, options?: PillOptions): string {
	const useColor = options?.colorEnabled ?? isColorEnabled();
	if (!useColor || text.length === 0) {
		return text;
	}
	const bg = options?.bg ?? CHARM_PALETTE.indigo;
	const isLimeBg = bg.toUpperCase() === CHARM_PALETTE.indigo;
	const fg =
		options?.fg ?? (isLimeBg ? CHARM_PALETTE.inkDark : CHARM_PALETTE.white);
	const bold = options?.bold ?? true;
	let styled = fgHex(fg, text, true);
	styled = bgHex(bg, styled, true);
	if (bold) {
		styled = `${ESC}[1m${styled}${ESC}[22m`;
	}
	return styled;
}
