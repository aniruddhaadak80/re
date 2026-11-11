// Helper for tools.test.ts: runs one CLI command in a child process so its stdout does not mix with the test reporter.
import { CLI_COMMANDS } from '../src/node.js';
const [name, ...rest] = process.argv.slice(2);
const c = CLI_COMMANDS.find((x) => x.name === name);
if (!c) { process.stderr.write(`unknown command ${name}\n`); process.exit(3); }
c.run(rest).then((code) => { process.exitCode = code; });
