// Types for the generated tool manifest (src/generated/tool-manifest.ts).
export type ParamType = 'string' | 'number' | 'boolean' | 'array' | 'object';
export interface ManifestParam { type: ParamType; description: string; optional?: boolean }
export interface ManifestTool { name: string; group: string; description: string; inputSchema: Record<string, ManifestParam> }
export interface ToolManifest {
  version: string;
  groups: { id: string; npm: string; title: string; tools: number; commands: number }[];
  packages: { id: string; npm: string; title: string; summary: string; analyzers: string[] }[];
  tools: ManifestTool[];
  effects: Record<string, { writes?: boolean; network?: boolean; executes?: boolean }>;
  analyzers: { id: string; title: string; description: string; package: string }[];
}
