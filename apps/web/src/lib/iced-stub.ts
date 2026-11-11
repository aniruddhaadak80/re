// Browser stand in for iced-x86. Its npm build is for Node (it reads its .wasm through fs), so the
// web app leaves it out and @revlens/disasm decodes x86 with Capstone instead.
const stub: Record<string, never> = {};
export default stub;
