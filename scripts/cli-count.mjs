// Counts CLI commands from the same registries the CLI uses: the core commands below (aliases such as scan and
// serve-mcp are not counted), the top level bridge commands and every package command group.
import { TOOL_GROUPS, TOP_LEVEL_COMMANDS } from '../packages/engine/dist/node.js';

export const CORE_CLI_COMMANDS = ['analyze', 'diff', 'verify', 'rules', 'sbom', 'sarif', 'analyzers', 'tools', 'mcp'];
export const CLI_COMMANDS_BY_GROUP = {
  core: CORE_CLI_COMMANDS,
  setup: TOP_LEVEL_COMMANDS.map((c) => c.name),
  ...Object.fromEntries(TOOL_GROUPS.filter((g) => g.commands.length).map((g) => [g.id, g.commands.map((c) => c.name)])),
};
export const CLI_COMMAND_COUNT = Object.values(CLI_COMMANDS_BY_GROUP).reduce((n, l) => n + l.length, 0);
