# Electron playbook

Electron apps bundle Chromium, Node.js and the app code, usually in `resources/app.asar`.

## Recognise
- An `app.asar` file, an `electron.asar` next to it, or `Electron Framework` inside a macOS app.

## First pass
1. `web_asar_list` lists the archive. `web_asar_extract` writes it to a folder you choose.
2. `web_electron_audit` checks `BrowserWindow` options (`nodeIntegration`, `contextIsolation`, `sandbox`, `webSecurity`), preload scripts, IPC handlers, custom protocols and the Electron fuses.
3. Read `package.json` inside the archive for the main script, version and dependencies; `sbom` lists the components.

## Code
1. Follow the JS bundle playbook for the main process and renderer bundles.
2. Look at every `ipcMain.handle` and `ipcMain.on`; a handler that runs shell commands or opens paths from renderer input is a common bug.
3. `web_node_inspect` and `web_cdp_targets` connect to a running app with debugging enabled. They start or reach processes, so only use them with permission.

## Verify
- Cite the path inside the ASAR and the line or offset in that file.
