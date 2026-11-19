import { ALL_RUNTIME_TARGETS } from "../models.js";

export const SUPPORTED_COMPLETION_SHELLS = [
	"bash",
	"zsh",
	"fish",
	"pwsh",
] as const;

export type CompletionShell = (typeof SUPPORTED_COMPLETION_SHELLS)[number];

export const COMPLETION_SUBCOMMANDS = [
	"add",
	"remove",
	"status",
	"update",
	"audit",
	"doctor",
	"completions",
] as const;

export const COMPLETION_FLAGS = [
	"--targets",
	"--repo",
	"--global",
	"--all",
	"--auto",
	"--dry-run",
	"--force",
	"--strict",
	"--catalog",
	"--format",
	"--json",
	"--help",
	"--version",
] as const;

export function isSupportedCompletionShell(
	value: string,
): value is CompletionShell {
	return (SUPPORTED_COMPLETION_SHELLS as readonly string[]).includes(value);
}

/**
 * Generate a deterministic shell completion script for bash, zsh, fish, or PowerShell (pwsh).
 */
export function generateShellCompletions(shell: CompletionShell): string {
	const subcommands = COMPLETION_SUBCOMMANDS.join(" ");
	const flags = COMPLETION_FLAGS.join(" ");
	const targets = ALL_RUNTIME_TARGETS.join(" ");

	switch (shell) {
		case "bash":
			return [
				"# bash completion for skillops / skillops-cli",
				"_skillops_completions() {",
				'  local cur prev',
				'  cur="${COMP_WORDS[COMP_CWORD]}"',
				'  prev="${COMP_WORDS[COMP_CWORD-1]}"',
				`  local subcommands="${subcommands}"`,
				`  local flags="${flags}"`,
				`  local targets="${targets}"`,
				'  if [[ ${COMP_CWORD} -eq 1 ]]; then',
				'    COMPREPLY=( $(compgen -W "${subcommands} ${flags}" -- "${cur}") )',
				"    return 0",
				"  fi",
				'  case "${prev}" in',
				"    --targets|--target|-t|--harness|--harnesses)",
				'      COMPREPLY=( $(compgen -W "${targets} all" -- "${cur}") )',
				"      return 0",
				"      ;;",
				"    completions)",
				'      COMPREPLY=( $(compgen -W "bash zsh fish pwsh" -- "${cur}") )',
				"      return 0",
				"      ;;",
				"  esac",
				'  COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )',
				"}",
				"complete -F _skillops_completions skillops skillops-cli",
				"",
			].join("\n");

		case "zsh":
			return [
				"#compdef skillops skillops-cli",
				"# zsh completion for skillops / skillops-cli",
				"_skillops() {",
				"  local -a subcommands targets flags",
				`  subcommands=(${COMPLETION_SUBCOMMANDS.map((c) => `'${c}'`).join(" ")})`,
				`  targets=(${ALL_RUNTIME_TARGETS.map((t) => `'${t}'`).join(" ")} 'all')`,
				`  flags=(${COMPLETION_FLAGS.map((f) => `'${f}'`).join(" ")})`,
				"  if (( CURRENT == 2 )); then",
				"    _describe 'command' subcommands",
				"    return",
				"  fi",
				'  case "${words[CURRENT-1]}" in',
				"    --targets|--target|-t|--harness|--harnesses)",
				"      _describe 'target' targets",
				"      return",
				"      ;;",
				"    completions)",
				"      local -a shells=(bash zsh fish pwsh)",
				"      _describe 'shell' shells",
				"      return",
				"      ;;",
				"  esac",
				"  _describe 'flag' flags",
				"}",
				"compdef _skillops skillops skillops-cli",
				"",
			].join("\n");

		case "fish":
			return [
				"# fish completion for skillops / skillops-cli",
				...COMPLETION_SUBCOMMANDS.map(
					(cmd) =>
						`complete -c skillops -n "__fish_use_subcommand" -a "${cmd}"`,
				),
				...COMPLETION_SUBCOMMANDS.map(
					(cmd) =>
						`complete -c skillops-cli -n "__fish_use_subcommand" -a "${cmd}"`,
				),
				...COMPLETION_FLAGS.map(
					(flag) =>
						`complete -c skillops -l "${flag.replace(/^--/, "")}"`,
				),
				`complete -c skillops -l targets -r -f -a "${targets} all"`,
				'complete -c skillops -n "__fish_seen_subcommand_from completions" -f -a "bash zsh fish pwsh"',
				"",
			].join("\n");

		case "pwsh":
			return [
				"# PowerShell completion for skillops / skillops-cli",
				`$SkillOpsSubcommands = @(${COMPLETION_SUBCOMMANDS.map((c) => `'${c}'`).join(", ")})`,
				`$SkillOpsTargets = @(${ALL_RUNTIME_TARGETS.map((t) => `'${t}'`).join(", ")}, 'all')`,
				`$SkillOpsFlags = @(${COMPLETION_FLAGS.map((f) => `'${f}'`).join(", ")})`,
				"$SkillOpsShells = @('bash', 'zsh', 'fish', 'pwsh')",
				"Register-ArgumentCompleter -Native -CommandName @('skillops', 'skillops-cli') -ScriptBlock {",
				"  param($wordToComplete, $commandAst, $cursorPosition)",
				"  $tokens = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }",
				"  $prev = if ($tokens.Count -ge 2) { $tokens[$tokens.Count - 2] } else { '' }",
				"  $candidates = if ($prev -in @('--targets', '--target', '-t', '--harness', '--harnesses')) {",
				"    $SkillOpsTargets",
				"  } elseif ($prev -eq 'completions') {",
				"    $SkillOpsShells",
				"  } elseif ($tokens.Count -le 2) {",
				"    $SkillOpsSubcommands + $SkillOpsFlags",
				"  } else {",
				"    $SkillOpsFlags",
				"  }",
				"  $candidates | Where-Object { $_ -like \"$wordToComplete*\" } | ForEach-Object {",
				"    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)",
				"  }",
				"}",
				"",
			].join("\n");
	}
}
