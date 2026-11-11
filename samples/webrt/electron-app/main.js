const { app, BrowserWindow, ipcMain, shell, protocol } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
      webSecurity: false,
      enableRemoteModule: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  win.loadURL('https://app.revlens-fixture.example/');
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });
  return win;
}

function createSafeWindow() {
  return new BrowserWindow({ webPreferences: { contextIsolation: true, sandbox: true, preload: path.join(__dirname, 'preload.js') } });
}

ipcMain.handle('read-file', async (_event, p) => fs.promises.readFile(p, 'utf8'));
ipcMain.on('open-link', (_event, url) => shell.openExternal(url));
ipcMain.handle('app-version', () => app.getVersion());

protocol.registerSchemesAsPrivileged([{ scheme: 'fixture', privileges: { standard: true, secure: true } }]);

app.whenReady().then(() => {
  protocol.registerFileProtocol('fixture', (request, callback) => callback({ path: request.url.slice(10) }));
  autoUpdater.setFeedURL({ url: 'https://updates.revlens-fixture.example/feed' });
  autoUpdater.checkForUpdatesAndNotify();
  createWindow();
  createSafeWindow();
});
