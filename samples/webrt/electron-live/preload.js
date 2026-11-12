// Exposes a narrow bridge to the page. Written for RevLens (MIT).
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('fixture', { ping: (who) => ipcRenderer.invoke('fixture:ping', who), version: () => ipcRenderer.invoke('fixture:version') });
