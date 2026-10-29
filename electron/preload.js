const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('bkSecurity', {
  getStatus: () => ipcRenderer.invoke('backend:status'),
  restartBackend: () => ipcRenderer.invoke('backend:restart'),
  getCredentialStatus: () => ipcRenderer.invoke('credentials:status'),
  initializeCredentials: (credentials) =>
    ipcRenderer.invoke('credentials:initialize', credentials),
  repairCredentials: () =>
    ipcRenderer.invoke('credentials:repair')
});
