"use strict";

(() => {
  const vscode = acquireVsCodeApi();
  const allowedActions = new Set([
    "scanWorkspace",
    "refreshScan",
    "showVulnerabilities",
    "reviewFixes",
    "showRemediationHistory",
  ]);

  for (const button of document.querySelectorAll("button[data-action]")) {
    button.addEventListener("click", () => {
      const action = button.dataset.action;
      if (action !== undefined && allowedActions.has(action)) {
        vscode.postMessage({ type: "action", action });
      }
    });
  }

  const filterButtons = document.querySelectorAll(
    "button[data-ecosystem-filter]",
  );
  const filterableRows = document.querySelectorAll(
    "[data-ecosystem-group]",
  );
  for (const button of filterButtons) {
    button.addEventListener("click", () => {
      const selected = button.dataset.ecosystemFilter;
      if (selected === undefined) return;
      for (const candidate of filterButtons) {
        candidate.setAttribute(
          "aria-pressed",
          String(candidate === button),
        );
      }
      for (const row of filterableRows) {
        row.hidden =
          selected !== "all" && row.dataset.ecosystemGroup !== selected;
      }
    });
  }
})();
