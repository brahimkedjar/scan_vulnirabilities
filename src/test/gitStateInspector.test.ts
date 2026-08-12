import assert from "node:assert/strict";
import test from "node:test";

import type * as vscode from "vscode";

import {
  gitStateInspectorFromExtension,
  VsCodeGitStateInspector,
} from "../remediation/apply/GitStateInspector";

function uri(path: string): vscode.Uri {
  return {
    scheme: "file",
    path,
    fsPath: path,
    toString: () => `file://${path}`,
  } as vscode.Uri;
}

function inspector(
  indexStatuses: readonly number[] = [],
  workingStatuses: readonly number[] = [],
  mergeStatuses: readonly number[] = [],
): VsCodeGitStateInspector {
  const target = uri("/workspace/package.json");
  const changes = (
    statuses: readonly number[],
  ): Array<{ uri: vscode.Uri; status: number }> =>
    statuses.map((status) => ({ uri: target, status }));
  return new VsCodeGitStateInspector({
    repositories: [
      {
        rootUri: uri("/workspace"),
        state: {
          indexChanges: changes(indexStatuses),
          workingTreeChanges: changes(workingStatuses),
          mergeChanges: changes(mergeStatuses),
        },
      },
    ],
  });
}

void test("blocks modified, untracked, conflicted, and partially staged targets", () => {
  assert.equal(inspector([], [5]).assess(uri("/workspace/package.json")).state, "modified");
  assert.equal(inspector([], [7]).assess(uri("/workspace/package.json")).state, "untracked");
  assert.equal(inspector([], [], [16]).assess(uri("/workspace/package.json")).state, "conflicted");
  assert.equal(inspector([0], [5]).assess(uri("/workspace/package.json")).state, "partially-staged");
  for (const assessment of [
    inspector([], [5]),
    inspector([], [7]),
    inspector([], [], [16]),
    inspector([0], [5]),
  ]) {
    assert.equal(assessment.assess(uri("/workspace/package.json")).blocked, true);
  }
});

void test("uses the deepest repository and leaves clean targets eligible", () => {
  const target = uri("/workspace/packages/app/package-lock.json");
  const subject = new VsCodeGitStateInspector({
    repositories: [
      {
        rootUri: uri("/workspace"),
        state: {
          indexChanges: [{ uri: target, status: 0 }],
          workingTreeChanges: [],
          mergeChanges: [],
        },
      },
      {
        rootUri: uri("/workspace/packages/app"),
        state: {
          indexChanges: [],
          workingTreeChanges: [],
          mergeChanges: [],
        },
      },
    ],
  });
  assert.deepEqual(subject.assess(target), {
    available: true,
    state: "clean",
    blocked: false,
    fingerprint: JSON.stringify([
      "file:///workspace/packages/app",
      "file:///workspace/packages/app/package-lock.json",
      "clean",
      [],
    ]),
  });
});

void test("does not activate Git and reports unavailable state fail-neutrally", () => {
  let getApiCalls = 0;
  const inactive = gitStateInspectorFromExtension({
    isActive: false,
    exports: {
      getAPI: () => {
        getApiCalls += 1;
        return { repositories: [] };
      },
    },
  });
  assert.equal(inactive.assess(uri("/workspace/package.json")).state, "unavailable");
  assert.equal(getApiCalls, 0);
});

void test("projects already-active Git state changes without invoking Git operations", () => {
  let stateListener: (() => unknown) | undefined;
  let observations = 0;
  const subject = new VsCodeGitStateInspector({
    repositories: [
      {
        rootUri: uri("/workspace"),
        state: {
          indexChanges: [],
          workingTreeChanges: [],
          mergeChanges: [],
          onDidChange: (listener) => {
            stateListener = listener;
            return { dispose: () => { stateListener = undefined; } };
          },
        },
      },
    ],
  });
  const subscription = subject.onDidChange(() => {
    observations += 1;
  });
  stateListener?.();
  assert.equal(observations, 1);
  subscription.dispose();
  subject.dispose();
  assert.equal(stateListener, undefined);
});
