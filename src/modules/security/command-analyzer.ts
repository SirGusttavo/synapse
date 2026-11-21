import type { PermissionLevel } from "../../core/types.js";

export interface CommandAnalysisResult {
  level: PermissionLevel;
  reasons: string[];
  detectedRisks: string[];
  normalizedCommand: string;
  matchedAllowlist: boolean;
}

const DENIED_RULES: ReadonlyArray<{ risk: string; reason: string; pattern: RegExp }> = [
  {
    risk: "privilege_escalation",
    reason: "Privileged execution is blocked by default",
    pattern: /\b(sudo|gsudo|runas)\b|Start-Process\b[^\r\n;]*-v(?:erb)?\s+['"]?RunAs['"]?/i,
  },
  {
    risk: "powershell_obfuscation",
    reason:
      "Encoded, dynamically compiled or dynamically evaluated PowerShell commands are blocked by default",
    pattern:
      /(?:^|\s)-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand|ec)\b|\b(?:Invoke-Expression|iex|Invoke-Command|icm|Add-Type)\b|\[(?:System\.Management\.Automation\.)?scriptblock\]::Create\b/i,
  },
  {
    risk: "git_destructive_history",
    reason:
      "Destructive Git operations (--force, --hard, +refspec, clean -fd, dangerous -c hooks) are blocked by default",
    pattern:
      /\bgit\b[^\r\n]*(?:\bpush\b[^\r\n]*(?:--force(?!-with-lease)|-f\b|\s\+[^\s]+)|\breset\b[^\r\n]*--hard\b|\bclean\b[^\r\n]*(?:-[a-z]*f[a-z]*d|-[a-z]*d[a-z]*f)|\s-c\s+['"]?(?:core\.hooksPath|core\.sshCommand|core\.pager|core\.fsmonitor)=)/i,
  },
  {
    risk: "indiscriminate_deletion",
    reason: "Indiscriminate recursive deletion or disk-wiping command is blocked by default",
    pattern:
      /\b(?:Format-Volume|Clear-Disk|Remove-Partition)\b|\b(?:rm|Remove-Item|ri|del|erase|rd|rmdir)\b[^\r\n]*(?:(?:-(?:rf|fr)\b)|(?:-Recurse\b[^\r\n]*-Force\b)|(?:-Force\b[^\r\n]*-Recurse\b)|(?:\/s\b[^\r\n]*\/q\b)|(?:\/q\b[^\r\n]*\/s\b))[^\r\n]*(?:[*]|\\$|\/$|[A-Za-z]:\\(?:\s|$)|\.\.)/i,
  },
  {
    risk: "credential_access",
    reason:
      "Direct access to credentials, secrets or sensitive environment variables is blocked by default",
    pattern:
      /(?:Get-ChildItem|Get-Item|Get-Content|gci|gi|gc|cat|type|ls|dir)\s+env:|\[(?:System\.)?Environment\]::GetEnvironmentVariable(?:s)?\b|(?:\$env:(?:[A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Za-z0-9_]*))|\bcmdkey\s+\/list\b|(?:^|[\s"'\\/])(?:\.env(?!\.example|\.sample|\.template)|id_rsa|id_ed25519)(?:$|[\s"'])/i,
  },
];

const HUMAN_APPROVAL_RULES: ReadonlyArray<{ risk: string; reason: string; pattern: RegExp }> = [
  {
    risk: "git_push",
    reason: "Publishing commits with git push requires explicit human approval",
    pattern: /\bgit\b[^\r\n]*\bpush\b/i,
  },
  {
    risk: "git_branch_or_tag_delete",
    reason: "Deleting Git branches or tags requires explicit human approval",
    pattern:
      /\bgit\b[^\r\n]*(?:\bbranch\b[^\r\n]*(?:-[dD]\b|--delete\b)|\btag\b[^\r\n]*(?:-d\b|--delete\b))/i,
  },
  {
    risk: "file_or_directory_deletion",
    reason: "Deleting files or directories requires explicit human approval (D-06)",
    pattern: /\b(?:Remove-Item|ri|rm|del|erase|rmdir|rd)\b/i,
  },
  {
    risk: "system_admin_change",
    reason: "System, service, execution policy or registry changes require human approval",
    pattern:
      /\b(?:Set-ExecutionPolicy|New-Service|Stop-Service|Remove-Service|Set-ItemProperty|reg(?:\.exe)?|sc(?:\.exe)?|net\s+user|net\s+localgroup)\b|\[(?:System\.)?Environment\]::SetEnvironmentVariable/i,
  },
];

const CONDITIONAL_RULES: ReadonlyArray<{ risk: string; reason: string; pattern: RegExp }> = [
  {
    risk: "multiline_command",
    reason: "Multi-line commands cannot be auto-approved and require review",
    pattern: /[\r\n]/,
  },
  {
    risk: "shell_chaining_or_redirection",
    reason:
      "Command contains chaining, piping, call/dot operators, subexpressions, blocks or redirection",
    pattern: /(?:&&|\|\||[;|<>`&(){}]|\$\(|@\(|(?:^|\s)\.\s+)/,
  },
  {
    risk: "workspace_path_escape_argument",
    reason: "Command references parent traversal (..), absolute drive or UNC path in arguments",
    pattern: /(?:^|[\s"'=])(?:\.\.(?:[\\/]|$)|[A-Za-z]:[\\/]|[/\\]{2})/,
  },
  {
    risk: "package_installation",
    reason: "Installing external dependencies requires review/approval",
    pattern: /\b(?:npm|pnpm|yarn)\s+(?:i|install|add)\b|\b(?:pip|winget|choco)\s+install\b/i,
  },
  {
    risk: "network_transfer",
    reason: "Network request or external script download detected",
    pattern: /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|curl|wget)\b/i,
  },
  {
    risk: "git_mutation",
    reason: "Git write operation requires conditional validation",
    pattern:
      /\bgit\b[^\r\n]*\b(?:commit|merge|pull|clone|checkout|switch|rebase|cherry-pick|stash|add|init|reset)\b/i,
  },
];

function normalizeSingleLine(command: string): string {
  return command.trim().replace(/[ \t]+/g, " ");
}

function matchesAllowlist(normalizedCommand: string, allowedCommands: readonly string[]): boolean {
  const lower = normalizedCommand.toLowerCase();

  for (const rawAllowed of allowedCommands) {
    const allowed = normalizeSingleLine(rawAllowed).toLowerCase();
    if (allowed.length === 0) {
      continue;
    }
    if (lower === allowed || lower.startsWith(`${allowed} `)) {
      return true;
    }
  }

  return false;
}

export function analyzeShellCommand(
  command: string,
  allowedCommands: readonly string[],
): CommandAnalysisResult {
  const rawTrimmed = command.trim();
  const normalizedCommand = normalizeSingleLine(rawTrimmed);
  const reasons: string[] = [];
  const detectedRisks: string[] = [];

  if (normalizedCommand.length === 0 || command.includes("\0")) {
    return {
      level: "DENIED",
      reasons: ["Empty or null-byte command is not allowed"],
      detectedRisks: ["invalid_command"],
      normalizedCommand,
      matchedAllowlist: false,
    };
  }

  // Strip PowerShell backtick escapes only for detection matching so `I`e`x` cannot evade rules
  const deobfuscated = rawTrimmed.replace(/`([A-Za-z])/g, "$1");

  // 1. Check hard-blocked rules first (cannot be bypassed by allowlist or backticks)
  for (const rule of DENIED_RULES) {
    if (rule.pattern.test(rawTrimmed) || rule.pattern.test(deobfuscated)) {
      detectedRisks.push(rule.risk);
      reasons.push(rule.reason);
    }
  }
  if (detectedRisks.length > 0) {
    return {
      level: "DENIED",
      reasons,
      detectedRisks,
      normalizedCommand,
      matchedAllowlist: false,
    };
  }

  // 2. Check human-approval rules
  for (const rule of HUMAN_APPROVAL_RULES) {
    if (rule.pattern.test(rawTrimmed) || rule.pattern.test(deobfuscated)) {
      detectedRisks.push(rule.risk);
      reasons.push(rule.reason);
    }
  }
  if (detectedRisks.length > 0) {
    return {
      level: "HUMAN_APPROVAL",
      reasons,
      detectedRisks,
      normalizedCommand,
      matchedAllowlist: false,
    };
  }

  // 3. Check conditional risks on RAW command (preserves \r/\n and catches (), {}, &, .., C:\)
  for (const rule of CONDITIONAL_RULES) {
    if (rule.pattern.test(rawTrimmed)) {
      detectedRisks.push(rule.risk);
      reasons.push(rule.reason);
    }
  }
  if (detectedRisks.length > 0) {
    return {
      level: "CONDITIONAL",
      reasons,
      detectedRisks,
      normalizedCommand,
      matchedAllowlist: false,
    };
  }

  // 4. Only pure, single-line, workspace-local commands matching allowlist are AUTO
  const allowlisted = matchesAllowlist(normalizedCommand, allowedCommands);
  if (allowlisted) {
    return {
      level: "AUTO",
      reasons: ["Command matches configured workspace allowlist with no risky operators"],
      detectedRisks: [],
      normalizedCommand,
      matchedAllowlist: true,
    };
  }

  // 5. Escalate unrecognized commands
  return {
    level: "CONDITIONAL",
    reasons: ["Command is not in the configured automatic allowlist"],
    detectedRisks: ["unlisted_command"],
    normalizedCommand,
    matchedAllowlist: false,
  };
}
