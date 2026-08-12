import * as vscode from "vscode";

const SCHEME = "dependency-remediation-preview";
const MAXIMUM_ENTRIES = 16;
const MAXIMUM_CONTENT_CHARACTERS = 512 * 1024;

interface DiffEntry {
  readonly before: vscode.Uri;
  readonly after: vscode.Uri;
}

/** Read-only in-memory documents used by VS Code's native diff editor. */
export class RemediationDiffProvider
  implements vscode.TextDocumentContentProvider, vscode.Disposable
{
  private readonly contents = new Map<string, string>();
  private readonly entries = new Map<string, DiffEntry>();
  private readonly registration: vscode.Disposable;

  public constructor() {
    this.registration = vscode.workspace.registerTextDocumentContentProvider(
      SCHEME,
      this,
    );
  }

  public provideTextDocumentContent(uri: vscode.Uri): string | undefined {
    return this.contents.get(uri.toString());
  }

  public register(
    previewId: string,
    fileIndex: number,
    before: string,
    after: string,
  ): DiffEntry | undefined {
    if (
      !/^[A-Za-z0-9_-]{1,128}$/u.test(previewId) ||
      !Number.isSafeInteger(fileIndex) ||
      fileIndex < 0 ||
      fileIndex >= 20 ||
      before.length + after.length > MAXIMUM_CONTENT_CHARACTERS
    ) {
      return undefined;
    }
    while (this.entries.size >= MAXIMUM_ENTRIES) {
      const oldest = this.entries.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.revoke(oldest);
    }
    this.revoke(previewId);
    const beforeUri = vscode.Uri.from({
      scheme: SCHEME,
      path: `/${previewId}/${fileIndex.toString()}/before`,
    });
    const afterUri = vscode.Uri.from({
      scheme: SCHEME,
      path: `/${previewId}/${fileIndex.toString()}/after`,
    });
    this.contents.set(beforeUri.toString(), before);
    this.contents.set(afterUri.toString(), after);
    const entry = Object.freeze({ before: beforeUri, after: afterUri });
    this.entries.set(previewId, entry);
    return entry;
  }

  public async show(
    previewId: string,
    title: string,
  ): Promise<boolean> {
    const entry = this.entries.get(previewId);
    if (entry === undefined) return false;
    await vscode.commands.executeCommand(
      "vscode.diff",
      entry.before,
      entry.after,
      title.slice(0, 256),
      { preview: true },
    );
    return true;
  }

  public revoke(previewId: string): void {
    const entry = this.entries.get(previewId);
    if (entry === undefined) return;
    this.contents.delete(entry.before.toString());
    this.contents.delete(entry.after.toString());
    this.entries.delete(previewId);
  }

  public clear(): void {
    this.contents.clear();
    this.entries.clear();
  }

  public dispose(): void {
    this.clear();
    this.registration.dispose();
  }
}
