const vscode = require('vscode');

const DEFAULT_ENDPOINT = 'http://127.0.0.1:8787/_sentinel/playground/analyze';

function extractPromptFromEditor() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    return '';
  }
  const selection = editor.selection;
  const selectedText = editor.document.getText(selection);
  if (selectedText && selectedText.trim()) {
    return selectedText;
  }
  return editor.document.getText();
}

async function requestPlaygroundScan(prompt, endpoint) {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify({ prompt }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const code = String(body.error || response.statusText || 'unknown_error');
    throw new Error(`Sentinel scan failed (${response.status}): ${code}`);
  }
  return body;
}

function formatSummary(payload) {
  const summary = payload && payload.summary ? payload.summary : {};
  return [
    `Risk: ${String(summary.risk || 'unknown')}`,
    `Engines evaluated: ${Number(summary.engines_evaluated || 0)}`,
    `Detections: ${Number(summary.detections || 0)}`,
    `Block eligible: ${Number(summary.block_eligible || 0)}`,
  ].join(' | ');
}

function activate(context) {
  const output = vscode.window.createOutputChannel('Sentinel Protocol');

  const disposable = vscode.commands.registerCommand('sentinelProtocol.scanPrompt', async () => {
    try {
      let prompt = extractPromptFromEditor();
      if (!prompt || !prompt.trim()) {
        prompt = await vscode.window.showInputBox({
          title: 'Sentinel Prompt Scan',
          prompt: 'Paste prompt text to scan locally via Sentinel',
          ignoreFocusOut: true,
        });
      }

      if (!prompt || !prompt.trim()) {
        vscode.window.showWarningMessage('Sentinel scan skipped: empty prompt.');
        return;
      }

      const endpoint = vscode.workspace.getConfiguration('sentinelProtocol').get('playgroundEndpoint', DEFAULT_ENDPOINT);
      const result = await requestPlaygroundScan(prompt, String(endpoint || DEFAULT_ENDPOINT));
      const summary = formatSummary(result);

      output.appendLine(`[${new Date().toISOString()}] ${summary}`);
      output.appendLine(JSON.stringify(result, null, 2));
      output.appendLine('');
      output.show(true);

      vscode.window.showInformationMessage(`Sentinel scan complete: ${summary}`);
    } catch (error) {
      const message = String(error && error.message ? error.message : error);
      output.appendLine(`[${new Date().toISOString()}] ERROR ${message}`);
      output.show(true);
      vscode.window.showErrorMessage(`Sentinel scan failed: ${message}`);
    }
  });

  context.subscriptions.push(disposable, output);
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
};
