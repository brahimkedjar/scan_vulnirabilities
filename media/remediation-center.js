"use strict";

(() => {
  const vscode = acquireVsCodeApi();
  const actions = new Set([
    "preview",
    "approve",
    "apply",
    "cancel",
    "viewDiff",
    "copyPatch",
    "openFile",
    "rescan",
  ]);
  for (const button of document.querySelectorAll(
    "button[data-remediation-center-action]",
  )) {
    button.addEventListener("click", () => {
      const action = button.dataset.remediationCenterAction;
      if (action === undefined || !actions.has(action)) return;
      const message = { type: "remediationCenterAction", action };
      const rowId = button.dataset.rowId;
      if (rowId !== undefined) message.rowId = rowId;
      if (action === "viewDiff" || action === "copyPatch" || action === "openFile") {
        const fileIndex = Number(button.dataset.fileIndex);
        if (!Number.isSafeInteger(fileIndex) || fileIndex < 0 || fileIndex >= 10) {
          return;
        }
        message.fileIndex = fileIndex;
      }
      vscode.postMessage(message);
    });
  }
})();
