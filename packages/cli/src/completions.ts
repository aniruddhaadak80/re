// Shell completion scripts for bash, zsh, fish and PowerShell, generated from the live command list,
// so new package commands complete without editing this file. The program name is a parameter (the
// CLI passes the name it was started as), so an alias such as a renamed binary completes too.
//
//   source <(revlens completions bash)
//   revlens completions zsh > "${fpath[1]}/_revlens"
//   revlens completions fish > ~/.config/fish/completions/revlens.fish
//   revlens completions powershell | Out-String | Invoke-Expression

export const SHELLS = ['bash', 'zsh', 'fish', 'powershell'] as const;
export type Shell = (typeof SHELLS)[number];

export interface CompletionSpec {
  /** program names to register, the first is the main one */
  programs: string[];
  commands: { name: string; summary: string; sub?: { name: string; summary: string }[] }[];
  /** global flags without the leading dashes */
  flags: string[];
  /** values offered after --format and --output-format */
  formats: string[];
}

const WORD = /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/;
/** Keep only names that are safe to paste into any shell script unquoted. */
function clean(spec: CompletionSpec): CompletionSpec {
  const ok = (s: string) => WORD.test(s) && s.length <= 64;
  const text = (s: string) => s.replace(/[^\x20-\x7e]/g, ' ').replace(/['"`$\\]/g, '').slice(0, 90).trim();
  return {
    programs: spec.programs.filter(ok),
    commands: spec.commands.filter((c) => ok(c.name)).map((c) => ({ name: c.name, summary: text(c.summary), sub: c.sub?.filter((s) => ok(s.name)).map((s) => ({ name: s.name, summary: text(s.summary) })) })),
    flags: spec.flags.filter(ok),
    formats: spec.formats.filter(ok),
  };
}

const fnName = (p: string) => `_${p.replace(/[^A-Za-z0-9_]/g, '_')}_complete`;

function bash(s: CompletionSpec): string {
  const main = s.programs[0]!;
  const fn = fnName(main);
  const subs = s.commands.filter((c) => c.sub?.length);
  return [
    `# bash completion for ${s.programs.join(', ')}`,
    `${fn}() {`,
    '  local cur prev cmd',
    '  cur="${COMP_WORDS[COMP_CWORD]}"',
    '  prev="${COMP_WORDS[COMP_CWORD-1]}"',
    '  cmd="${COMP_WORDS[1]}"',
    `  case "$prev" in`,
    `    --format|--output-format) COMPREPLY=( $(compgen -W "${s.formats.join(' ')}" -- "$cur") ); return 0 ;;`,
    `    --out|--rules|--settings-file|--evidence-out|--ledger) COMPREPLY=( $(compgen -f -- "$cur") ); return 0 ;;`,
    `    completions) COMPREPLY=( $(compgen -W "${SHELLS.join(' ')}" -- "$cur") ); return 0 ;;`,
    '  esac',
    '  if [[ "$cur" == -* ]]; then',
    `    COMPREPLY=( $(compgen -W "${s.flags.map((f) => '--' + f).join(' ')}" -- "$cur") ); return 0`,
    '  fi',
    '  if [[ $COMP_CWORD -eq 1 ]]; then',
    `    COMPREPLY=( $(compgen -W "${s.commands.map((c) => c.name).join(' ')}" -- "$cur") ); return 0`,
    '  fi',
    '  if [[ $COMP_CWORD -eq 2 ]]; then',
    '    case "$cmd" in',
    ...subs.map((c) => `      ${c.name}) COMPREPLY=( $(compgen -W "${c.sub!.map((x) => x.name).join(' ')}" -- "$cur") $(compgen -f -- "$cur") ); return 0 ;;`),
    ...(s.commands.some((c) => c.name === 'help') ? [`      help) COMPREPLY=( $(compgen -W "${subs.map((c) => c.name).join(' ')}" -- "$cur") ); return 0 ;;`] : []),
    '    esac',
    '  fi',
    '  COMPREPLY=( $(compgen -f -- "$cur") )',
    '}',
    ...s.programs.map((p) => `complete -o filenames -F ${fn} ${p}`),
    '',
  ].join('\n');
}

function zsh(s: CompletionSpec): string {
  const main = s.programs[0]!;
  const q = (t: string) => t.replace(/:/g, '\\:');
  const subs = s.commands.filter((c) => c.sub?.length);
  return [
    `#compdef ${s.programs.join(' ')}`,
    `# zsh completion for ${s.programs.join(', ')}`,
    `_${main.replace(/[^A-Za-z0-9_]/g, '_')}() {`,
    '  local -a commands flags',
    '  commands=(',
    ...s.commands.map((c) => `    '${c.name}:${q(c.summary)}'`),
    '  )',
    `  flags=(${s.flags.map((f) => `'--${f}'`).join(' ')})`,
    '  case "${words[CURRENT-1]}" in',
    `    --format|--output-format) _values 'format' ${s.formats.join(' ')}; return ;;`,
    '    --out|--rules|--settings-file|--evidence-out|--ledger) _files; return ;;',
    `    completions) _values 'shell' ${SHELLS.join(' ')}; return ;;`,
    '  esac',
    '  if [[ "${words[CURRENT]}" == -* ]]; then compadd -a flags; return; fi',
    '  if (( CURRENT == 2 )); then _describe -t commands command commands; return; fi',
    '  if (( CURRENT == 3 )); then',
    '    case "${words[2]}" in',
    ...subs.map((c) => `      ${c.name}) local -a sub; sub=(${c.sub!.map((x) => `'${x.name}:${q(x.summary)}'`).join(' ')}); _describe -t sub subcommand sub; _files; return ;;`),
    '    esac',
    '  fi',
    '  _files',
    '}',
    `compdef _${main.replace(/[^A-Za-z0-9_]/g, '_')} ${s.programs.join(' ')}`,
    '',
  ].join('\n');
}

function fish(s: CompletionSpec): string {
  const L = [`# fish completion for ${s.programs.join(', ')}`];
  const fq = (t: string) => `'${t.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
  const top = s.commands.map((c) => c.name).join(' ');
  for (const p of s.programs) {
    L.push(`complete -c ${p} -f`);
    for (const c of s.commands) L.push(`complete -c ${p} -n "not __fish_seen_subcommand_from ${top}" -a ${c.name} -d ${fq(c.summary)}`);
    for (const c of s.commands) for (const x of c.sub ?? []) L.push(`complete -c ${p} -n "__fish_seen_subcommand_from ${c.name}" -a ${x.name} -d ${fq(x.summary)}`);
    L.push(`complete -c ${p} -n "__fish_seen_subcommand_from completions" -a "${SHELLS.join(' ')}"`);
    for (const f of s.flags) L.push(`complete -c ${p} -l ${f}`);
    L.push(`complete -c ${p} -l format -x -a "${s.formats.join(' ')}"`);
    L.push(`complete -c ${p} -l output-format -x -a "${s.formats.join(' ')}"`);
    L.push(`complete -c ${p} -n "__fish_seen_subcommand_from ${top}" -F`);
  }
  return L.join('\n') + '\n';
}

function powershell(s: CompletionSpec): string {
  const arr = (xs: string[]) => `@(${xs.map((x) => `'${x}'`).join(', ')})`;
  const subs = s.commands.filter((c) => c.sub?.length);
  return [
    `# PowerShell completion for ${s.programs.join(', ')}`,
    `$__cmds = ${arr(s.commands.map((c) => c.name))}`,
    `$__flags = ${arr(s.flags.map((f) => '--' + f))}`,
    `$__formats = ${arr(s.formats)}`,
    `$__shells = ${arr([...SHELLS])}`,
    '$__subs = @{',
    ...subs.map((c) => `  '${c.name}' = ${arr(c.sub!.map((x) => x.name))}`),
    '}',
    `Register-ArgumentCompleter -Native -CommandName ${arr(s.programs)} -ScriptBlock {`,
    '  param($wordToComplete, $commandAst, $cursorPosition)',
    '  $words = @($commandAst.CommandElements | ForEach-Object { $_.ToString() })',
    '  $count = $words.Count',
    "  if ($wordToComplete -eq '') { $count = $count + 1 }",
    '  $prev = if ($count -ge 2) { $words[$count - 2] } else { "" }',
    '  $list = @()',
    "  if ($prev -eq '--format' -or $prev -eq '--output-format') { $list = $__formats }",
    "  elseif ($prev -eq 'completions') { $list = $__shells }",
    "  elseif ($wordToComplete.StartsWith('-')) { $list = $__flags }",
    '  elseif ($count -le 2) { $list = $__cmds }',
    '  elseif ($count -eq 3 -and $__subs.ContainsKey($words[1])) { $list = $__subs[$words[1]] }',
    '  $list | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, \'ParameterValue\', $_) }',
    '}',
    '',
  ].join('\n');
}

/** The completion script for one shell. */
export function completionScript(shell: Shell, spec: CompletionSpec): string {
  const s = clean(spec);
  if (!s.programs.length) throw new Error('no usable program name for completions');
  switch (shell) {
    case 'bash': return bash(s);
    case 'zsh': return zsh(s);
    case 'fish': return fish(s);
    case 'powershell': return powershell(s);
  }
}
