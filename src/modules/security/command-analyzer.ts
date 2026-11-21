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
    pattern: /\b(sudo|gsudo|runas)\b|Start-Process\b[^;\n]*-Verb\s+['"]?RunAs['"]?/i,
  },
  {
    risk: "powershell_obfuscation",
    reason: "Encoded or dynamically evaluated PowerShell commands are blocked by default",
    pattern: /(?:^|\s)-(?:enc|encodedcommand|ec)\b|\b(?:Invoke-Expression|iex)\b/i,
  },
  {
    risk: "git_destructive_history",
    reason: "Destructive Git operations (--force, --hard, clean -fd) are blocked by default",
    pattern:
      /\bgit\s+(?:push\b[^\n]*(?:--force(?!-with-lease)|-f\b)|reset\b[^\n]*--hard\b|clean\b[^\n]*-[a-z]*f[a-z]*d|clean\b[^\n]*-[a-z]*d[a-z]*f)/i,
  },
  {
    risk: "indiscriminate_deletion",
    reason: "Indiscriminate recursive deletion or disk-wiping command is blocked by default",
    pattern:
      /\b(?:Format-Volume|Clear-Disk|Remove-Partition)\b|\b(?:rm|Remove-Item|ri|del|erase|rd|rmdir)\b[^\n]*(?:(?:-(?:rf|fr)\b)|(?:-Recurse\b[^\n]*-Force\b)|(?:-Force\b[^\n]*-Recurse\b)|(?:\/s\b[^\n]*\/q\b)|(?:\/q\b[^\n]*\/s\b))[^\n]*(?:[*]|\\$|\/$|[A-Za-z]:\\(?:\s|$)|\.\.)/i,
  },
  {
    risk: "credential_access",
    reason:
      "Direct access to credentials, secrets or sensitive environment variables is blocked by default",
    pattern:
      /(?:Get-ChildItem|gci|ls|dir)\s+env:|(?:\$env:(?:[A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z0-9_]*))|\bcmdkey\s+\/list\b|(?:^|[\s"'\\/])(?:\.env(?!\.example|\.sample)|id_rsa|id_ed25519)(?:$|[\s"'])/i,
  },
];

const HUMAN_APPROVAL_RULES: ReadonlyArray<{ risk: string; reason: string; pattern: RegExp }> = [
  {
    risk: "git_push",
    reason: "Publishing commits with git push requires explicit human approval",
    pattern: /\bgit\s+push\b/i,
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
    risk: "shell_chaining_or_redirection",
    reason: "Command contains chaining, piping, subexpressions or redirection operators",
    pattern: /(?:&&|\|\||[;|<>`]|\$\()/,
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
    pattern: /\bgit\s+(?:commit|merge|pull|clone|checkout|rebase|cherry-pick|tag)\b/i,
  },
];

function stripRedundantWhitespace(command: string): string {
  return command.trim().replace(/\s+/g, " ");
}

function matchesAllowlist(normalizedCommand: string, allowedCommands: readonly string[]): boolean {
  const lower = normalizedCommand.toLowerCase();

  for (const rawAllowed of allowedCommands) {
    const allowed = stripRedundantWhitespace(rawAllowed).toLowerCase();
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
  const normalizedCommand = stripRedundantWhitespace(command);
  const reasons: string[] = [];
  const detectedRisks: string[] = [];

  if (normalizedCommand.length === 0) {
    return {
      level: "DENIED",
      reasons: ["Empty command is not allowed"],
      detectedRisks: ["empty_command"],
      normalizedCommand,
      matchedAllowlist: false,
    };
  }

  // 1. Check hard-blocked rules first (cannot be bypassed by allowlist)
  for (const rule of DENIED_RULES) {
    if (rule.pattern.test(normalizedCommand)) {
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
    if (rule.pattern.test(normalizedCommand)) {
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

  // 3. Check conditional risks (chaining/redirection defeats simple prefix allowlist!)
  for (const rule of CONDITIONAL_RULES) {
    if (rule.pattern.test(normalizedCommand)) {
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

  // 4. Only pure, unchained commands matching the configured allowlist are AUTO
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

  // 5. Default-deny / escalate unrecognized commands
  return {
    level: "CONDITIONAL",
    reasons: ["Command is not in the configured automatic allowlist"],
    detectedRisks: ["unlisted_command"],
    normalizedCommand,
    matchedAllowlist: false,
  };
}
