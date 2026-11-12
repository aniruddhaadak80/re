// RevLens Electron scenario fixture: one window from a local file, a preload bridge with one IPC call,
// and a fetch to the API URL given in REVLENS_FIXTURE_API. Written for RevLens (MIT).
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('node:path');

function versionInfo(name) { return { name, electron: process.versions.electron, pid: process.pid }; }

ipcMain.handle('fixture:ping', (_e, who) => `pong from main to ${who}`);
ipcMain.handle('fixture:version', () => versionInfo('fixture'));

app.whenReady().then(() => {
  const win = new BrowserWindow({ width: 900, height: 600, show: false, title: 'RevLens fixture', webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  win.loadFile(path.join(__dirname, 'index.html'), { query: { api: process.env.REVLENS_FIXTURE_API || '' } });
});
app.on('window-all-closed', () => app.quit());
