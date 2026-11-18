import { defineConfig } from "tsup";

export default defineConfig({
	entry: {
		index: "src/index.ts",
		cli: "src/cli.ts",
	},
	format: ["esm"],
	dts: {
		entry: "src/index.ts",
	},
	splitting: true,
	clean: true,
	sourcemap: false,
	target: "node20",
});
