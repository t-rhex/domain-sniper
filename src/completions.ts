export function bashCompletions(): string {
  return `# domain-sniper bash completions
_domain_sniper() {
  local cur prev opts
  COMPREPLY=()
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"
  opts="--file --auto-register --headless --json --concurrency --help --version completions suggest portfolio config"

  case "\${prev}" in
    --file|-f)
      COMPREPLY=( $(compgen -f -- "\${cur}") )
      return 0
      ;;
    completions)
      COMPREPLY=( $(compgen -W "bash zsh fish" -- "\${cur}") )
      return 0
      ;;
  esac

  COMPREPLY=( $(compgen -W "\${opts}" -- "\${cur}") )
}
complete -F _domain_sniper domain-sniper
`;
}

export function zshCompletions(): string {
  return `#compdef domain-sniper

_domain-sniper() {
  _arguments \\
    '-f[Path to file with domains]:file:_files' \\
    '--file[Path to file with domains]:file:_files' \\
    '-a[Automatically register available domains]' \\
    '--auto-register[Automatically register available domains]' \\
    '--headless[Run in non-interactive mode]' \\
    '--json[Output results as JSON]' \\
    '-c[Concurrent lookups]:number' \\
    '--concurrency[Concurrent lookups]:number' \\
    '--help[Show help]' \\
    '--version[Show version]' \\
    '*:domain:' \\
    '1:command:(completions suggest portfolio config)'
}

_domain-sniper
`;
}

export function fishCompletions(): string {
  return `# domain-sniper fish completions
complete -c domain-sniper -l file -s f -r -F -d "Path to file with domains"
complete -c domain-sniper -l auto-register -s a -d "Auto-register available domains"
complete -c domain-sniper -l headless -d "Non-interactive mode"
complete -c domain-sniper -l json -d "Output results as JSON"
complete -c domain-sniper -l concurrency -s c -r -d "Concurrent lookups"
complete -c domain-sniper -l help -d "Show help"
complete -c domain-sniper -l version -d "Show version"
complete -c domain-sniper -n "__fish_use_subcommand" -a completions -d "Generate shell completions"
complete -c domain-sniper -n "__fish_use_subcommand" -a suggest -d "Generate domain suggestions"
complete -c domain-sniper -n "__fish_use_subcommand" -a portfolio -d "Manage domain portfolio"
complete -c domain-sniper -n "__fish_use_subcommand" -a config -d "View or edit configuration"
complete -c domain-sniper -n "__fish_seen_subcommand_from completions" -a "bash zsh fish"
`;
}
