const mc = window.navigator.modelContext;
function listTodos() { return [...document.querySelectorAll('#list li')].map((li) => li.textContent); }
if (mc) {
  mc.provideContext({
    tools: [
      { name: 'list_todos', description: 'List all todos', inputSchema: { type: 'object', properties: {} }, execute: async () => ({ content: [{ type: 'text', text: JSON.stringify(listTodos()) }] }) },
      { name: 'clear_done', description: 'Remove finished todos', inputSchema: { type: 'object', properties: { confirm: { type: 'boolean' } }, required: ['confirm'] }, execute: async () => ({ content: [] }) },
    ],
  });
  mc.unregisterTool('legacy_tool');
}
