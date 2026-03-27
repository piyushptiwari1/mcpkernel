import * as vscode from "vscode";
import * as cp from "child_process";
import * as path from "path";

let gatewayProcess: cp.ChildProcess | undefined;
let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;
let diagnosticCollection: vscode.DiagnosticCollection;
let serversTreeProvider: MCPServersTreeProvider;
let findingsTreeProvider: SecurityFindingsTreeProvider;

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel("MCPKernel");
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("mcpkernel");
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.text = "$(shield) MCPKernel";
  statusBarItem.tooltip = "MCPKernel Security Gateway — Click for status";
  statusBarItem.command = "mcpkernel.status";

  // Show status bar if .mcpkernel/ exists
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (workspaceRoot) {
    const fs = require("fs");
    if (fs.existsSync(path.join(workspaceRoot, ".mcpkernel"))) {
      statusBarItem.show();
    }
  }

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("mcpkernel.init", cmdInit),
    vscode.commands.registerCommand("mcpkernel.serve", cmdServe),
    vscode.commands.registerCommand("mcpkernel.stop", cmdStop),
    vscode.commands.registerCommand("mcpkernel.status", cmdStatus),
    vscode.commands.registerCommand(
      "mcpkernel.validatePolicy",
      cmdValidatePolicy
    ),
    vscode.commands.registerCommand("mcpkernel.scan", cmdScan),
    vscode.commands.registerCommand("mcpkernel.auditQuery", cmdAuditQuery),
    vscode.commands.registerCommand("mcpkernel.traceList", cmdTraceList),
    vscode.commands.registerCommand("mcpkernel.addServer", cmdAddServer),
    vscode.commands.registerCommand("mcpkernel.discover", cmdDiscover),
    vscode.commands.registerCommand("mcpkernel.poisonScan", cmdPoisonScan),
    vscode.commands.registerCommand(
      "mcpkernel.refreshDiscovery",
      cmdRefreshDiscovery
    ),
    statusBarItem,
    outputChannel,
    diagnosticCollection
  );

  // Register tree views
  serversTreeProvider = new MCPServersTreeProvider();
  findingsTreeProvider = new SecurityFindingsTreeProvider();
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider(
      "mcpkernel.discoveredServers",
      serversTreeProvider
    ),
    vscode.window.registerTreeDataProvider(
      "mcpkernel.securityFindings",
      findingsTreeProvider
    )
  );

  // Auto-validate policy files on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration("mcpkernel");
      if (!config.get<boolean>("autoValidatePolicy", true)) {
        return;
      }
      if (
        doc.languageId === "yaml" &&
        (doc.fileName.includes("policies") ||
          doc.fileName.includes(".mcpkernel"))
      ) {
        validatePolicyFile(doc.uri);
      }
    })
  );

  outputChannel.appendLine("MCPKernel extension activated");
}

export function deactivate() {
  if (gatewayProcess) {
    gatewayProcess.kill();
    gatewayProcess = undefined;
  }
}

// ---------------------------------------------------------------------------
// Helper: run mcpkernel CLI
// ---------------------------------------------------------------------------
function getMcpkernelPath(): string {
  return (
    vscode.workspace
      .getConfiguration("mcpkernel")
      .get<string>("pythonPath") || "mcpkernel"
  );
}

function runCli(
  args: string[],
  cwd?: string
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const proc = cp.spawn(getMcpkernelPath(), args, {
      cwd: cwd || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
      shell: true,
    });
    let stdout = "";
    let stderr = "";
    proc.stdout?.on("data", (d: Buffer) => (stdout += d.toString()));
    proc.stderr?.on("data", (d: Buffer) => (stderr += d.toString()));
    proc.on("close", (code) =>
      resolve({ stdout, stderr, code: code ?? 1 })
    );
    proc.on("error", (err) =>
      resolve({ stdout, stderr: err.message, code: 1 })
    );
  });
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------
async function cmdInit() {
  const preset = await vscode.window.showQuickPick(
    ["standard", "permissive", "strict"],
    { placeHolder: "Select policy preset" }
  );
  if (!preset) {
    return;
  }

  const result = await runCli(["init", "--preset", preset]);
  if (result.code === 0) {
    vscode.window.showInformationMessage(
      `MCPKernel initialized with '${preset}' preset`
    );
    statusBarItem.show();
    outputChannel.appendLine(result.stdout);
  } else {
    vscode.window.showErrorMessage(`MCPKernel init failed: ${result.stderr}`);
    outputChannel.appendLine(result.stderr);
  }
}

async function cmdServe() {
  if (gatewayProcess) {
    vscode.window.showWarningMessage("MCPKernel gateway is already running");
    return;
  }

  const config = vscode.workspace.getConfiguration("mcpkernel");
  const host = config.get<string>("gatewayHost", "127.0.0.1");
  const port = config.get<number>("gatewayPort", 8000);

  const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  gatewayProcess = cp.spawn(
    getMcpkernelPath(),
    ["serve", "--host", host, "--port", port.toString()],
    { cwd, shell: true }
  );

  gatewayProcess.stdout?.on("data", (d: Buffer) => {
    outputChannel.appendLine(d.toString());
  });
  gatewayProcess.stderr?.on("data", (d: Buffer) => {
    outputChannel.appendLine(`[stderr] ${d.toString()}`);
  });
  gatewayProcess.on("close", (code) => {
    gatewayProcess = undefined;
    statusBarItem.text = "$(shield) MCPKernel";
    statusBarItem.backgroundColor = undefined;
    outputChannel.appendLine(`Gateway exited with code ${code}`);
  });

  statusBarItem.text = "$(shield) MCPKernel: Running";
  statusBarItem.backgroundColor = new vscode.ThemeColor(
    "statusBarItem.warningBackground"
  );
  vscode.window.showInformationMessage(
    `MCPKernel gateway started on ${host}:${port}`
  );
  outputChannel.show(true);
}

async function cmdStop() {
  if (!gatewayProcess) {
    vscode.window.showWarningMessage("MCPKernel gateway is not running");
    return;
  }
  gatewayProcess.kill();
  gatewayProcess = undefined;
  statusBarItem.text = "$(shield) MCPKernel";
  statusBarItem.backgroundColor = undefined;
  vscode.window.showInformationMessage("MCPKernel gateway stopped");
}

async function cmdStatus() {
  const result = await runCli(["status"]);
  if (result.code === 0) {
    outputChannel.clear();
    outputChannel.appendLine("=== MCPKernel Status ===\n");
    outputChannel.appendLine(result.stdout);
    if (gatewayProcess) {
      outputChannel.appendLine(
        `\nGateway: Running (PID ${gatewayProcess.pid})`
      );
    } else {
      outputChannel.appendLine("\nGateway: Stopped");
    }
    outputChannel.show(true);
  } else {
    vscode.window.showErrorMessage(
      "MCPKernel not configured in this workspace. Run MCPKernel: Initialize Project first."
    );
  }
}

async function cmdValidatePolicy() {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== "yaml") {
    vscode.window.showWarningMessage("Open a YAML policy file first");
    return;
  }
  await validatePolicyFile(editor.document.uri);
}

async function validatePolicyFile(uri: vscode.Uri) {
  const result = await runCli(["validate-policy", uri.fsPath]);
  diagnosticCollection.delete(uri);

  if (result.code === 0) {
    vscode.window.showInformationMessage("Policy file is valid");
    diagnosticCollection.set(uri, []);
  } else {
    // Parse errors from CLI output
    const diagnostics: vscode.Diagnostic[] = [];
    const lines = (result.stdout + result.stderr).split("\n");
    for (const line of lines) {
      if (line.includes("Error") || line.includes("error")) {
        diagnostics.push(
          new vscode.Diagnostic(
            new vscode.Range(0, 0, 0, 100),
            line.trim(),
            vscode.DiagnosticSeverity.Error
          )
        );
      }
    }
    if (diagnostics.length === 0) {
      diagnostics.push(
        new vscode.Diagnostic(
          new vscode.Range(0, 0, 0, 100),
          `Policy validation failed: ${result.stderr || result.stdout}`,
          vscode.DiagnosticSeverity.Error
        )
      );
    }
    diagnosticCollection.set(uri, diagnostics);
    vscode.window.showErrorMessage(
      `Policy validation failed — see Problems panel`
    );
  }
}

async function cmdScan() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("Open a Python file first");
    return;
  }

  const result = await runCli(["scan", editor.document.uri.fsPath]);
  outputChannel.clear();
  outputChannel.appendLine("=== MCPKernel Taint Scan ===\n");
  outputChannel.appendLine(result.stdout);
  if (result.stderr) {
    outputChannel.appendLine(result.stderr);
  }
  outputChannel.show(true);

  if (result.stdout.includes("No taint")) {
    vscode.window.showInformationMessage("No taint issues found");
  } else {
    vscode.window.showWarningMessage(
      "Taint issues detected — see Output panel"
    );
  }
}

async function cmdAuditQuery() {
  const format = await vscode.window.showQuickPick(
    ["table", "json", "cef", "csv"],
    { placeHolder: "Select output format" }
  );
  if (!format) {
    return;
  }

  const result = await runCli(["audit-query", "--format", format]);
  outputChannel.clear();
  outputChannel.appendLine("=== MCPKernel Audit Log ===\n");
  outputChannel.appendLine(result.stdout);
  outputChannel.show(true);
}

async function cmdTraceList() {
  const result = await runCli(["trace-list"]);
  outputChannel.clear();
  outputChannel.appendLine("=== MCPKernel Execution Traces ===\n");
  outputChannel.appendLine(result.stdout);
  outputChannel.show(true);
}

async function cmdAddServer() {
  const name = await vscode.window.showInputBox({
    prompt: "Server name (e.g., filesystem)",
    placeHolder: "my-server",
  });
  if (!name) {
    return;
  }

  const url = await vscode.window.showInputBox({
    prompt: "Server URL",
    placeHolder: "http://localhost:3000/mcp",
  });
  if (!url) {
    return;
  }

  const result = await runCli(["add-server", name, url]);
  if (result.code === 0) {
    vscode.window.showInformationMessage(
      `Added upstream server '${name}' at ${url}`
    );
  } else {
    vscode.window.showErrorMessage(
      `Failed to add server: ${result.stderr}`
    );
  }
}

// ---------------------------------------------------------------------------
// New commands: Discover, Poison Scan, Refresh Discovery
// ---------------------------------------------------------------------------

interface DiscoveredServer {
  name: string;
  client: string;
  config_path: string;
  transport: string;
  command?: string;
  url?: string;
  warnings?: string[];
}

interface PoisonFinding {
  tool: string;
  server: string;
  category: string;
  severity: string;
  message: string;
  pattern?: string;
}

async function cmdDiscover() {
  const result = await runCli(["discover", "--json"]);
  if (result.code !== 0) {
    vscode.window.showErrorMessage(
      `Discovery failed: ${result.stderr || "Unknown error"}`
    );
    outputChannel.appendLine(result.stderr);
    return;
  }

  try {
    const configs = JSON.parse(result.stdout);
    serversTreeProvider.update(configs);
    outputChannel.clear();
    outputChannel.appendLine("=== MCP Config Discovery ===\n");
    outputChannel.appendLine(
      `Found ${configs.length} configuration source(s)\n`
    );
    for (const cfg of configs) {
      outputChannel.appendLine(
        `  ${cfg.client}: ${cfg.config_path} (${(cfg.servers || []).length} server(s))`
      );
      for (const srv of cfg.servers || []) {
        outputChannel.appendLine(
          `    - ${srv.name} [${srv.transport || "stdio"}]`
        );
        if (srv.warnings) {
          for (const w of srv.warnings) {
            outputChannel.appendLine(`      ⚠ ${w}`);
          }
        }
      }
    }
    outputChannel.show(true);
    vscode.window.showInformationMessage(
      `Discovered ${configs.length} MCP config source(s)`
    );
  } catch {
    outputChannel.clear();
    outputChannel.appendLine("=== MCP Config Discovery ===\n");
    outputChannel.appendLine(result.stdout);
    outputChannel.show(true);
  }
}

async function cmdPoisonScan() {
  const result = await runCli(["poison-scan", "--json"]);
  if (result.code !== 0 && !result.stdout) {
    vscode.window.showErrorMessage(
      `Poison scan failed: ${result.stderr || "Unknown error"}`
    );
    outputChannel.appendLine(result.stderr);
    return;
  }

  try {
    const report = JSON.parse(result.stdout);
    const findings: PoisonFinding[] = report.findings || [];
    findingsTreeProvider.update(findings);
    outputChannel.clear();
    outputChannel.appendLine("=== Tool Poisoning Scan ===\n");

    if (findings.length === 0) {
      outputChannel.appendLine("No poisoning findings detected.");
      vscode.window.showInformationMessage(
        "No tool poisoning issues detected"
      );
    } else {
      outputChannel.appendLine(`Found ${findings.length} issue(s):\n`);
      for (const f of findings) {
        const icon =
          f.severity === "CRITICAL"
            ? "🔴"
            : f.severity === "HIGH"
              ? "🟠"
              : f.severity === "MEDIUM"
                ? "🟡"
                : "🔵";
        outputChannel.appendLine(
          `  ${icon} [${f.severity}] ${f.tool} (${f.server}): ${f.message}`
        );
      }
      vscode.window.showWarningMessage(
        `Tool poisoning scan found ${findings.length} issue(s) — see Output panel`
      );
    }
    outputChannel.show(true);
  } catch {
    outputChannel.clear();
    outputChannel.appendLine("=== Tool Poisoning Scan ===\n");
    outputChannel.appendLine(result.stdout);
    outputChannel.show(true);
  }
}

async function cmdRefreshDiscovery() {
  await cmdDiscover();
}

// ---------------------------------------------------------------------------
// TreeView providers
// ---------------------------------------------------------------------------

class MCPServersTreeProvider
  implements vscode.TreeDataProvider<vscode.TreeItem>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<
    vscode.TreeItem | undefined
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private configs: Array<{
    client: string;
    config_path: string;
    servers: DiscoveredServer[];
  }> = [];

  update(
    configs: Array<{
      client: string;
      config_path: string;
      servers: DiscoveredServer[];
    }>
  ) {
    this.configs = configs;
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: vscode.TreeItem): vscode.TreeItem[] {
    if (!element) {
      if (this.configs.length === 0) {
        const item = new vscode.TreeItem(
          "Run Discover to scan for MCP configs"
        );
        item.iconPath = new vscode.ThemeIcon("info");
        return [item];
      }
      return this.configs.map((c) => {
        const item = new vscode.TreeItem(
          c.client,
          vscode.TreeItemCollapsibleState.Expanded
        );
        item.description = `${(c.servers || []).length} server(s)`;
        item.tooltip = c.config_path;
        item.iconPath = new vscode.ThemeIcon("remote-explorer");
        item.contextValue = "mcpClient";
        return item;
      });
    }

    const cfg = this.configs.find((c) => c.client === element.label);
    if (!cfg) {
      return [];
    }
    return (cfg.servers || []).map((s) => {
      const item = new vscode.TreeItem(s.name);
      item.description = s.transport || "stdio";
      item.tooltip = s.command || s.url || "";
      item.iconPath = new vscode.ThemeIcon("server-process");
      return item;
    });
  }
}

class SecurityFindingsTreeProvider
  implements vscode.TreeDataProvider<vscode.TreeItem>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<
    vscode.TreeItem | undefined
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private findings: PoisonFinding[] = [];

  update(findings: PoisonFinding[]) {
    this.findings = findings;
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(): vscode.TreeItem[] {
    if (this.findings.length === 0) {
      const item = new vscode.TreeItem("Run Poison Scan to check for issues");
      item.iconPath = new vscode.ThemeIcon("info");
      return [item];
    }
    return this.findings.map((f) => {
      const icon =
        f.severity === "CRITICAL" || f.severity === "HIGH"
          ? "error"
          : f.severity === "MEDIUM"
            ? "warning"
            : "info";
      const item = new vscode.TreeItem(
        `${f.tool}: ${f.message}`,
        vscode.TreeItemCollapsibleState.None
      );
      item.description = `[${f.severity}] ${f.server}`;
      item.tooltip = f.pattern || f.message;
      item.iconPath = new vscode.ThemeIcon(icon);
      return item;
    });
  }
}
