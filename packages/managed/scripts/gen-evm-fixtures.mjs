// Compile OpenZeppelin contracts (MIT) with solc-js and write runtime bytecode plus solc's own
// reference outputs (method identifiers, opcodes). Dev only.
// Usage: node gen-evm-fixtures.mjs <dir with node_modules/solc and @openzeppelin/contracts> <outdir>
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const [dir, outdir] = process.argv.slice(2);
const require = createRequire(join(dir, 'package.json'));
const solc = require('solc');
const sources = {
  'RevToken.sol': { content: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
contract RevToken is ERC20 {
    constructor() ERC20("RevLens Token", "REVL") { _mint(msg.sender, 1000000 * 10 ** decimals()); }
}` },
  'RevProxy.sol': { content: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
contract RevProxy is ERC1967Proxy {
    constructor(address impl) ERC1967Proxy(impl, "") {}
}` },
};
const input = { language: 'Solidity', sources, settings: { optimizer: { enabled: true, runs: 200 }, outputSelection: { '*': { '*': ['evm.deployedBytecode.object', 'evm.deployedBytecode.opcodes', 'evm.methodIdentifiers', 'metadata'] } } } };
const findImports = (p) => { try { return { contents: readFileSync(join(dir, 'node_modules', p), 'utf8') }; } catch { return { error: 'not found ' + p }; } };
const out = JSON.parse(solc.compile(JSON.stringify(input), { import: findImports }));
for (const e of out.errors ?? []) if (e.severity === 'error') throw new Error(e.formattedMessage);
const ref = { solcVersion: solc.version(), contracts: {} };
for (const [file, name] of [['RevToken.sol', 'RevToken'], ['RevProxy.sol', 'RevProxy']]) {
  const c = out.contracts[file][name];
  writeFileSync(join(outdir, `${name}.runtime.hex`), c.evm.deployedBytecode.object + '\n');
  ref.contracts[name] = { methodIdentifiers: c.evm.methodIdentifiers, opcodes: c.evm.deployedBytecode.opcodes, compiler: JSON.parse(c.metadata).compiler.version, size: c.evm.deployedBytecode.object.length / 2 };
}
writeFileSync(join(outdir, 'evm.ref.json'), JSON.stringify(ref, null, 1));
console.log(ref.solcVersion, Object.keys(ref.contracts));
