const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('fixtureApi', {
  readFile: (p) => ipcRenderer.invoke('read-file', p),
  openLink: (url) => ipcRenderer.send('open-link', url),
  version: () => ipcRenderer.invoke('app-version'),
  ipcRenderer,
});
