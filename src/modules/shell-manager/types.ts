export interface ShellInvocation {
  executable: string;
  args: string[];
}

export interface ShellDetectionResult {
  available: boolean;
  executable: string;
  version: string | null;
}

export interface IShellAdapter {
  readonly id: string;
  readonly displayName: string;
  detect(): Promise<ShellDetectionResult>;
  buildInvocation(command: string): Promise<ShellInvocation>;
}
