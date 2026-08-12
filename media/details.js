"use strict";

(() => {
  const vscode = acquireVsCodeApi();

  for (const button of document.querySelectorAll(
    "button[data-reference-index]",
  )) {
    button.addEventListener("click", () => {
      const referenceIndex = Number(button.dataset.referenceIndex);
      if (Number.isSafeInteger(referenceIndex) && referenceIndex >= 0) {
        vscode.postMessage({ type: "openAdvisory", referenceIndex });
      }
    });
  }

  const remediationActions = new Set([
    "preview",
    "approve",
    "apply",
    "cancel",
    "viewDiff",
    "copyPatch",
    "openFile",
  ]);
  for (const button of document.querySelectorAll(
    "button[data-remediation-action]",
  )) {
    button.addEventListener("click", () => {
      const action = button.dataset.remediationAction;
      if (action === undefined || !remediationActions.has(action)) return;
      const message = { type: "remediationAction", action };
      if (action === "viewDiff" || action === "copyPatch" || action === "openFile") {
        const fileIndex = Number(button.dataset.remediationFileIndex);
        if (!Number.isSafeInteger(fileIndex) || fileIndex < 0 || fileIndex >= 20) {
          return;
        }
        message.fileIndex = fileIndex;
      }
      vscode.postMessage(message);
    });
  }
})();
