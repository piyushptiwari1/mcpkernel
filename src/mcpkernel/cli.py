"""MCPKernel CLI — Typer-based command interface."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer

from mcpkernel import __version__

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mcpkernel.policy.engine import PolicyRule

app = typer.Typer(
    name="mcpkernel",
    help="The mandatory, deterministic MCP/A2A gateway.",
    no_args_is_help=True,
    add_completion=True,
)


# ── Proxy ──────────────────────────────────────────────────────────────
@app.command()
def serve(
    host: Annotated[str | None, typer.Option(help="Bind address")] = None,
    port: Annotated[int | None, typer.Option(help="Bind port")] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c", help="Config YAML path")] = None,
    log_level: Annotated[str, typer.Option(help="Log level")] = "info",
    transport: Annotated[str, typer.Option(help="Transport: http or stdio")] = "http",
) -> None:
    """Start the MCPKernel proxy gateway."""
    from mcpkernel.config import load_config
    from mcpkernel.utils import configure_logging

    configure_logging(level=log_level)
    settings = load_config(config_path=config)
    if host is not None:
        settings.proxy.host = host
    if port is not None:
        settings.proxy.port = port

    if transport == "stdio":
        from mcpkernel.proxy.server import start_stdio_server

        asyncio.run(start_stdio_server(settings))
    else:
        from mcpkernel.proxy.server import start_proxy_server

        start_proxy_server(settings)


# ── Policy ─────────────────────────────────────────────────────────────
@app.command()
def validate_policy(
    path: Annotated[Path, typer.Argument(help="Policy YAML file or directory")],
) -> None:
    """Validate policy YAML files."""
    from mcpkernel.policy.loader import load_policy_dir, load_policy_file

    try:
        rules = load_policy_dir(path) if path.is_dir() else load_policy_file(path)
        typer.echo(f"✓ Loaded {len(rules)} valid rules from {path}")
        for rule in rules:
            typer.echo(f"  [{rule.id}] {rule.name} → {rule.action.value}")
    except Exception as exc:
        typer.echo(f"✗ Validation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


# ── DEE / Trace ────────────────────────────────────────────────────────
@app.command()
def trace_list(
    db: Annotated[str, typer.Option(help="Trace DB path")] = "mcpkernel_traces.db",
    limit: Annotated[int, typer.Option(help="Max entries")] = 20,
) -> None:
    """List recent execution traces."""
    from mcpkernel.dee.trace_store import TraceStore

    async def _run() -> None:
        store = TraceStore(db_path=db)
        await store.open()
        traces = await store.list_traces(limit=limit)
        if not traces:
            typer.echo("No traces found.")
            return
        for t in traces:
            typer.echo(
                f"  {t['trace_id'][:12]}… | {t['tool_name']:20s} | "
                f"in={t['input_hash'][:8]}… out={t['output_hash'][:8]}… | "
                f"{t['duration_seconds']:.3f}s"
            )
        await store.close()

    asyncio.run(_run())


@app.command()
def trace_export(
    trace_id: Annotated[str, typer.Argument(help="Trace ID to export")],
    db: Annotated[str, typer.Option(help="Trace DB path")] = "mcpkernel_traces.db",
) -> None:
    """Export a single trace as JSON."""
    from mcpkernel.dee.trace_store import TraceStore

    async def _run() -> None:
        store = TraceStore(db_path=db)
        await store.open()
        data = await store.export_trace(trace_id)
        if data is None:
            typer.echo(f"Trace {trace_id} not found", err=True)
            raise typer.Exit(code=1)
        typer.echo(data)
        await store.close()

    asyncio.run(_run())


@app.command()
def replay(
    trace_id: Annotated[str, typer.Argument(help="Trace ID to replay")],
    db: Annotated[str, typer.Option(help="Trace DB path")] = "mcpkernel_traces.db",
) -> None:
    """Replay a trace and check for drift."""
    from mcpkernel.dee.replay import replay as replay_trace
    from mcpkernel.dee.replay import validate_replay_integrity
    from mcpkernel.dee.trace_store import TraceStore

    async def _run() -> None:
        store = TraceStore(db_path=db)
        await store.open()
        original = await store.get(trace_id)
        if original is None:
            typer.echo(f"Trace {trace_id} not found", err=True)
            raise typer.Exit(code=1)

        # Need sandbox backend for replay
        from mcpkernel.config import load_config
        from mcpkernel.sandbox import create_backend

        settings = load_config()
        backend = create_backend(settings.sandbox)
        new_trace = await replay_trace(trace_id, store, backend.execute_code)
        match = await validate_replay_integrity(trace_id, new_trace, store)

        status = "✓ MATCH" if match else "✗ DRIFT DETECTED"
        typer.echo(f"{status}")
        typer.echo(f"  Original output hash: {original['output_hash']}")
        typer.echo(f"  Replay output hash:   {new_trace.output_hash}")
        await store.close()

    asyncio.run(_run())


# ── Audit ──────────────────────────────────────────────────────────────
@app.command()
def audit_query(
    db: Annotated[str, typer.Option(help="Audit DB path")] = "mcpkernel_audit.db",
    event_type: Annotated[str | None, typer.Option(help="Filter by event type")] = None,
    tool_name: Annotated[str | None, typer.Option(help="Filter by tool name")] = None,
    limit: Annotated[int, typer.Option(help="Max entries")] = 20,
    export_format: Annotated[str, typer.Option(help="Export format: jsonl, csv, cef")] = "jsonl",
) -> None:
    """Query audit logs."""
    from mcpkernel.audit.exporter import AuditExportFormat, export_audit_logs
    from mcpkernel.audit.logger import AuditLogger

    async def _run() -> None:
        logger = AuditLogger(db_path=db)
        await logger.initialize()
        entries = await logger.query(event_type=event_type, tool_name=tool_name, limit=limit)
        if not entries:
            typer.echo("No audit entries found.")
            return

        fmt = AuditExportFormat(export_format)
        output = export_audit_logs(entries, format=fmt)
        typer.echo(output)
        await logger.close()

    asyncio.run(_run())


@app.command()
def audit_verify(
    db: Annotated[str, typer.Option(help="Audit DB path")] = "mcpkernel_audit.db",
) -> None:
    """Verify audit log integrity (tamper detection)."""
    from mcpkernel.audit.logger import AuditLogger

    async def _run() -> None:
        logger = AuditLogger(db_path=db)
        await logger.initialize()
        result = await logger.verify_integrity()
        if result["integrity_valid"]:
            typer.echo(f"✓ Integrity valid — {result['total_entries']} entries verified")
        else:
            typer.echo(
                f"✗ TAMPERED — {result['tampered_entries']}/{result['total_entries']} entries modified",
                err=True,
            )
            raise typer.Exit(code=1)
        await logger.close()

    asyncio.run(_run())


# ── Taint ──────────────────────────────────────────────────────────────
@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Python file to static-analyze")],
) -> None:
    """Static taint analysis on a Python file."""
    from mcpkernel.taint.static_analysis import Severity, static_taint_analysis

    if not path.exists():
        typer.echo(f"File not found: {path}", err=True)
        raise typer.Exit(code=1)

    code = path.read_text()
    report = static_taint_analysis(code)

    if report.is_clean:
        typer.echo(f"✓ No dangerous patterns found in {path}")
        return

    typer.echo(f"Found {len(report.findings)} issue(s) in {path}:")
    for f in report.findings:
        icon = "🔴" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "🟡"
        typer.echo(f"  {icon} [{f.rule_id}] L{f.line}:{f.col} {f.message}")

    if report.has_critical:
        raise typer.Exit(code=1)


# ── Registry ───────────────────────────────────────────────────────────
@app.command()
def registry_search(
    query: Annotated[str, typer.Argument(help="Search query (e.g. 'filesystem', 'git')")],
    limit: Annotated[int, typer.Option(help="Max results")] = 20,
    config: Annotated[Path | None, typer.Option("-c", "--config", help="Config YAML path")] = None,
) -> None:
    """Search the MCP Server Registry for servers."""
    from mcpkernel.config import load_config
    from mcpkernel.integrations.registry import MCPRegistry, RegistryConfig

    settings = load_config(config_path=config)
    reg_config = RegistryConfig(
        registry_url=settings.registry.registry_url,
        cache_ttl_seconds=settings.registry.cache_ttl_seconds,
        timeout_seconds=settings.registry.timeout_seconds,
    )

    async def _run() -> None:
        registry = MCPRegistry(config=reg_config)
        try:
            servers = await registry.search(query, limit=limit)
            if not servers:
                typer.echo(f"No servers found for '{query}'")
                return
            typer.echo(f"Found {len(servers)} server(s) matching '{query}':\n")
            for s in servers:
                typer.echo(f"  {s.display_name}")
                if s.description:
                    typer.echo(f"    {s.description[:80]}")
                if s.transport:
                    typer.echo(f"    Transports: {', '.join(s.transport)}")
                if s.install_command:
                    typer.echo(f"    Install: {s.install_command}")
                typer.echo()
        finally:
            await registry.close()

    asyncio.run(_run())


@app.command()
def registry_list(
    limit: Annotated[int, typer.Option(help="Max results")] = 30,
    config: Annotated[Path | None, typer.Option("-c", "--config", help="Config YAML path")] = None,
) -> None:
    """List available servers from the MCP Server Registry."""
    from mcpkernel.config import load_config
    from mcpkernel.integrations.registry import MCPRegistry, RegistryConfig

    settings = load_config(config_path=config)
    reg_config = RegistryConfig(
        registry_url=settings.registry.registry_url,
        cache_ttl_seconds=settings.registry.cache_ttl_seconds,
        timeout_seconds=settings.registry.timeout_seconds,
    )

    async def _run() -> None:
        registry = MCPRegistry(config=reg_config)
        try:
            servers = await registry.list_servers(limit=limit)
            if not servers:
                typer.echo("No servers found in registry.")
                return
            typer.echo(f"MCP Server Registry — {len(servers)} server(s):\n")
            for s in servers:
                cats = f" [{', '.join(s.categories)}]" if s.categories else ""
                typer.echo(f"  {s.display_name}{cats}")
        finally:
            await registry.close()

    asyncio.run(_run())


# ── Agent Scan ─────────────────────────────────────────────────────────
@app.command()
def agent_scan(
    target: Annotated[Path, typer.Argument(help="Directory or config file to scan")],
    output: Annotated[Path | None, typer.Option("-o", "--output", help="Export generated policy rules")] = None,
    config: Annotated[Path | None, typer.Option("-c", "--config", help="Config YAML path")] = None,
) -> None:
    """Run Snyk agent-scan on MCP configs and generate policy rules."""
    from mcpkernel.config import load_config
    from mcpkernel.integrations.agent_scan import AgentScanConfig as ASConfig
    from mcpkernel.integrations.agent_scan import AgentScanner

    settings = load_config(config_path=config)
    as_config = ASConfig(
        binary_name=settings.agent_scan.binary_name,
        timeout_seconds=settings.agent_scan.timeout_seconds,
        auto_generate_policy=settings.agent_scan.auto_generate_policy,
    )

    scanner = AgentScanner(config=as_config)
    if not scanner.available:
        typer.echo(
            "✗ agent-scan not found on PATH.\n  Install: npm install -g @anthropic/agent-scan",
            err=True,
        )
        raise typer.Exit(code=1)

    async def _run() -> None:
        if target.is_dir():
            report = await scanner.scan_directory(target)
        else:
            report = await scanner.scan_config(target)

        if not report.findings:
            typer.echo("✓ No issues found.")
            return

        typer.echo(f"Found {len(report.findings)} issue(s):\n")
        for f in report.findings:
            icon = "🔴" if f.severity in ("critical", "high") else "🟡"
            typer.echo(f"  {icon} [{f.severity.upper()}] {f.title}")
            if f.server_name:
                typer.echo(f"    Server: {f.server_name}")
            if f.tool_name:
                typer.echo(f"    Tool: {f.tool_name}")
            if f.remediation:
                typer.echo(f"    Fix: {f.remediation}")
            typer.echo()

        if settings.agent_scan.auto_generate_policy:
            rules = scanner.report_to_policy_rules(report)
            typer.echo(f"Generated {len(rules)} policy rule(s) from findings.")

            if output:
                _export_scan_rules_yaml(rules, output)
                typer.echo(f"  Exported to {output}")

        if report.has_blockers:
            raise typer.Exit(code=1)

    asyncio.run(_run())


# ── Langfuse ───────────────────────────────────────────────────────────
@app.command()
def langfuse_export(
    db: Annotated[str, typer.Option(help="Audit DB path")] = "mcpkernel_audit.db",
    limit: Annotated[int, typer.Option(help="Max entries to export")] = 100,
    config: Annotated[Path | None, typer.Option("-c", "--config", help="Config YAML path")] = None,
) -> None:
    """Export audit entries to Langfuse."""
    from mcpkernel.audit.logger import AuditLogger
    from mcpkernel.config import load_config
    from mcpkernel.integrations.langfuse import LangfuseConfig as LFConfig
    from mcpkernel.integrations.langfuse import LangfuseExporter

    settings = load_config(config_path=config)
    lf = settings.langfuse
    if not lf.enabled or not lf.public_key or not lf.secret_key:
        typer.echo(
            "✗ Langfuse not configured. Set MCPKERNEL_LANGFUSE__ENABLED=true,\n"
            "  MCPKERNEL_LANGFUSE__PUBLIC_KEY and MCPKERNEL_LANGFUSE__SECRET_KEY.",
            err=True,
        )
        raise typer.Exit(code=1)

    lf_config = LFConfig(
        enabled=True,
        public_key=lf.public_key,
        secret_key=lf.secret_key,
        host=lf.host,
        project_name=lf.project_name,
        batch_size=lf.batch_size,
        flush_interval_seconds=lf.flush_interval_seconds,
        max_retries=lf.max_retries,
        timeout_seconds=lf.timeout_seconds,
    )

    async def _run() -> None:
        audit_logger = AuditLogger(db_path=db)
        await audit_logger.initialize()
        entries = await audit_logger.query(limit=limit)
        if not entries:
            typer.echo("No audit entries to export.")
            return

        exporter = LangfuseExporter(config=lf_config)
        await exporter.start()
        try:
            await exporter.export_audit_entries(entries)
            await exporter.flush()
            typer.echo(f"✓ Exported {len(entries)} audit entries to Langfuse ({lf.host})")
        finally:
            await exporter.shutdown()

        await audit_logger.close()

    asyncio.run(_run())


# ── Info / Config ──────────────────────────────────────────────────────
@app.command()
def version() -> None:
    """Print MCPKernel version."""
    typer.echo(f"mcpkernel {__version__}")


@app.command()
def quickstart(
    preset: Annotated[str, typer.Option("--preset", "-p", help="Policy preset")] = "standard",
) -> None:
    """One-command demo — init, show config, and verify the pipeline works."""
    from mcpkernel.presets import get_preset_rules, list_presets

    available = list_presets()
    if preset not in available:
        typer.echo(f"✗ Unknown preset '{preset}'. Available: {', '.join(available)}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"🚀 MCPKernel Quickstart (preset: {preset})")
    typer.echo("=" * 50)

    # Show what the preset does
    typer.echo(f"\n📋 Policy: {available[preset]}")
    rules = get_preset_rules(preset)
    for r in rules:
        typer.echo(f"   [{r.action.value:>7s}] {r.name}")

    # Verify pipeline wiring
    typer.echo("\n🔧 Verifying pipeline...")

    async def _verify() -> None:
        from mcpkernel.api import MCPKernelProxy

        proxy = MCPKernelProxy(policy=preset, taint=True, audit=True)
        await proxy.start()
        typer.echo(f"   ✓ {len(proxy.hooks)} hooks loaded: {', '.join(proxy.hooks)}")
        await proxy.stop()
        typer.echo("   ✓ Pipeline start/stop OK")

    asyncio.run(_verify())

    # Show Python usage
    typer.echo("\n📦 Python usage:")
    typer.echo("   from mcpkernel import MCPKernelProxy")
    typer.echo("")
    typer.echo('   async with MCPKernelProxy(upstream=["http://localhost:3000/mcp"]) as proxy:')
    typer.echo('       result = await proxy.call_tool("my_tool", {"arg": "value"})')
    typer.echo("")
    typer.echo("✓ Ready! Run 'mcpkernel init' to set up a project, or use the Python API directly.")


@app.command()
def status(
    config: Annotated[Path | None, typer.Option("--config", "-c", help="Config YAML path")] = None,
) -> None:
    """Show current MCPKernel status — config, hooks, policy, and upstream servers."""
    from mcpkernel.config import load_config

    try:
        settings = load_config(config_path=config)
    except Exception:
        typer.echo("⚠ No config found. Run 'mcpkernel init' first or provide --config.")
        raise typer.Exit(code=1)  # noqa: B904

    typer.echo(f"MCPKernel v{__version__} — Status")
    typer.echo("=" * 45)

    # Proxy
    typer.echo(f"  Proxy:   {settings.proxy.host}:{settings.proxy.port}")

    # Policy
    typer.echo(f"  Policy:  default_action={settings.policy.default_action}")
    for p in settings.policy.policy_paths:
        exists = "✓" if Path(p).exists() else "✗ MISSING"
        typer.echo(f"           {p} [{exists}]")

    # Features
    taint_mode = getattr(settings.taint, "mode", "off")
    typer.echo(f"  Taint:   {taint_mode}")
    typer.echo(f"  Audit:   {'enabled' if settings.audit.enabled else 'disabled'}")
    typer.echo(f"  DEE:     {'enabled' if settings.dee.enabled else 'disabled'}")
    typer.echo(f"  Context: {'enabled' if settings.context.enabled else 'disabled'}")

    # Upstream
    if settings.upstream:
        typer.echo(f"  Upstream ({len(settings.upstream)}):")
        for srv in settings.upstream:
            typer.echo(f"    • {srv.name}: {srv.url} [{srv.transport}]")
    else:
        typer.echo("  Upstream: none configured")

    # Auth
    auth_type = "api_key" if settings.auth.api_keys else "none"
    typer.echo(f"  Auth:    {auth_type}")

    typer.echo("")
    typer.echo("Run 'mcpkernel serve' to start the proxy.")


@app.command()
def presets() -> None:
    """List available policy presets and their rules."""
    from mcpkernel.presets import get_preset_rules, list_presets

    available_presets = list_presets()
    typer.echo("Available policy presets:")
    typer.echo("=" * 50)
    for name, desc in available_presets.items():
        typer.echo(f"\n  {name}")
        typer.echo(f"  {desc}")
        try:
            rules = get_preset_rules(name)
            for r in rules:
                typer.echo(f"    [{r.action.value:>7s}] {r.name}")
        except ValueError:
            typer.echo("    (uses external YAML policy files)")


@app.command()
def config_show(
    config: Annotated[Path | None, typer.Option("--config", "-c", help="Config YAML path")] = None,
) -> None:
    """Show effective configuration."""
    from mcpkernel.config import load_config

    settings = load_config(config_path=config)
    typer.echo(settings.model_dump_json(indent=2))


@app.command()
def init(
    directory: Annotated[Path, typer.Argument(help="Project directory")] = Path("."),
    preset: Annotated[
        str, typer.Option("--preset", "-p", help="Policy preset: permissive, standard, strict")
    ] = "standard",
) -> None:
    """Initialize MCPKernel in a project directory."""
    from mcpkernel.presets import get_preset_rules, list_presets

    available = list_presets()
    if preset not in available:
        typer.echo(f"✗ Unknown preset '{preset}'. Available: {', '.join(available)}", err=True)
        raise typer.Exit(code=1)

    config_dir = directory / ".mcpkernel"
    config_dir.mkdir(parents=True, exist_ok=True)

    preset_info = available[preset]
    default_action = "deny" if preset == "strict" else ("allow" if preset == "permissive" else "audit")

    # Create default config
    config_file = config_dir / "config.yaml"
    if not config_file.exists():
        config_file.write_text(
            f"# MCPKernel configuration (preset: {preset})\n"
            f"# {preset_info}\n"
            "# See https://github.com/piyushptiwari1/mcpkernel for docs\n\n"
            "proxy:\n"
            "  host: 127.0.0.1\n"
            "  port: 8000\n"
            "\n"
            "# Upstream MCP servers to proxy to\n"
            "# Add servers with: mcpkernel add-server <name> <url>\n"
            "upstream: []\n"
            "\n"
            "policy:\n"
            "  policy_paths:\n"
            "    - .mcpkernel/policies/default.yaml\n"
            f"  default_action: {default_action}\n"
            "\n"
            "taint:\n"
            "  mode: light\n"
            "\n"
            "dee:\n"
            "  enabled: true\n"
            "  store_path: .mcpkernel/traces.db\n"
            "\n"
            "audit:\n"
            "  enabled: true\n"
            "  log_path: .mcpkernel/audit.db\n"
            "\n"
            "observability:\n"
            "  log_level: INFO\n"
            "  metrics_enabled: true\n"
        )

    # Create policies dir with preset rules
    policies_dir = config_dir / "policies"
    policies_dir.mkdir(exist_ok=True)

    default_policy = policies_dir / "default.yaml"
    if not default_policy.exists():
        rules = get_preset_rules(preset)
        _export_preset_rules_yaml(rules, default_policy)

    typer.echo(f"✓ Initialized MCPKernel in {config_dir} (preset: {preset})")
    typer.echo(f"  Config: {config_file}")
    typer.echo(f"  Policies: {policies_dir}")
    typer.echo(f"  Preset: {preset} — {preset_info}")
    typer.echo("")
    typer.echo("Next steps:")
    typer.echo("  1. Add an upstream MCP server:")
    typer.echo("     mcpkernel add-server myserver http://localhost:3000/mcp")
    typer.echo("  2. Start the proxy:")
    typer.echo("     mcpkernel serve -c .mcpkernel/config.yaml")


@app.command()
def add_server(
    name: Annotated[str, typer.Argument(help="Server name (e.g. 'filesystem', 'github')")],
    url: Annotated[str, typer.Argument(help="Server URL (e.g. 'http://localhost:3000/mcp')")],
    transport: Annotated[str, typer.Option(help="Transport: streamable_http, sse, stdio")] = "streamable_http",
    config: Annotated[Path, typer.Option("-c", "--config", help="Config YAML path")] = Path(".mcpkernel/config.yaml"),
) -> None:
    """Add an upstream MCP server to the configuration."""
    import yaml

    if not config.exists():
        typer.echo(f"Config not found: {config}. Run 'mcpkernel init' first.", err=True)
        raise typer.Exit(code=1)

    with open(config) as f:
        data = yaml.safe_load(f) or {}

    if "upstream" not in data or not isinstance(data["upstream"], list):
        data["upstream"] = []

    # Check for duplicate names
    for srv in data["upstream"]:
        if srv.get("name") == name:
            typer.echo(f"Server '{name}' already exists in config. Remove it first.", err=True)
            raise typer.Exit(code=1)

    server_entry: dict[str, Any] = {
        "name": name,
        "url": url,
        "transport": transport,
    }
    data["upstream"].append(server_entry)

    with open(config, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    typer.echo(f"✓ Added server '{name}' ({transport}) → {url}")
    typer.echo(f"  Config: {config}")


@app.command()
def test_connection(
    config: Annotated[Path | None, typer.Option("-c", "--config", help="Config YAML path")] = None,
) -> None:
    """Test connectivity to all configured upstream MCP servers."""
    from mcpkernel.config import load_config
    from mcpkernel.proxy.upstream import UpstreamConnection

    settings = load_config(config_path=config)

    if not settings.upstream:
        typer.echo("No upstream servers configured. Use 'mcpkernel add-server' first.")
        raise typer.Exit(code=1)

    async def _run() -> None:
        all_ok = True
        for srv_config in settings.upstream:
            conn = UpstreamConnection(srv_config)
            try:
                await conn.connect()
                tools = conn.tool_names
                typer.echo(f"  ✓ {srv_config.name} — {len(tools)} tools: {', '.join(sorted(tools))}")
                await conn.disconnect()
            except Exception as exc:
                typer.echo(f"  ✗ {srv_config.name} — {exc}", err=True)
                all_ok = False

        if not all_ok:
            raise typer.Exit(code=1)

    asyncio.run(_run())


# ── Agent Manifest Integration ────────────────────────────────────────
@app.command()
def manifest_import(
    repo_path: Annotated[Path, typer.Argument(help="Path to a repository with agent.yaml")],
    output: Annotated[Path | None, typer.Option("-o", "--output", help="Output policy YAML file")] = None,
) -> None:
    """Import an agent manifest definition and generate MCPKernel policy rules."""
    from mcpkernel.agent_manifest.loader import load_agent_manifest
    from mcpkernel.agent_manifest.policy_bridge import manifest_to_policy_rules

    try:
        definition = load_agent_manifest(repo_path)
    except Exception as exc:
        typer.echo(f"✗ Failed to load agent manifest: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    rules = manifest_to_policy_rules(definition)

    typer.echo(f"✓ Loaded agent manifest: {definition.name} v{definition.version}")
    typer.echo(f"  Description: {definition.description}")
    if definition.compliance:
        typer.echo(f"  Risk tier: {definition.compliance.risk_tier}")
        typer.echo(f"  Frameworks: {', '.join(definition.compliance.frameworks) or 'none'}")
    typer.echo(f"  Generated {len(rules)} MCPKernel policy rule(s):")
    for rule in rules:
        typer.echo(f"    [{rule.id}] {rule.name} → {rule.action.value}")

    if output:
        _export_rules_yaml(rules, output)
        typer.echo(f"  Exported to {output}")


@app.command()
def manifest_validate(
    repo_path: Annotated[Path, typer.Argument(help="Path to a repository with agent.yaml")],
) -> None:
    """Validate an agent manifest definition and its tool schemas."""
    from mcpkernel.agent_manifest.loader import load_agent_manifest
    from mcpkernel.agent_manifest.tool_validator import ToolSchemaValidator

    try:
        definition = load_agent_manifest(repo_path)
    except Exception as exc:
        typer.echo(f"✗ Validation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    validator = ToolSchemaValidator(definition)

    typer.echo(f"✓ agent.yaml valid: {definition.name} v{definition.version}")
    if definition.soul_md:
        typer.echo(f"  SOUL.md: {len(definition.soul_md)} chars")
    if definition.rules_md:
        typer.echo(f"  RULES.md: {len(definition.rules_md)} chars")
    typer.echo(f"  Skills: {len(definition.skills)}")
    typer.echo(f"  Tools declared: {len(definition.tools_list)}")
    typer.echo(f"  Tool schemas loaded: {len(definition.tool_schemas)}")
    if definition.hooks:
        typer.echo(f"  Hooks: {len(definition.hooks)}")
    if definition.sub_agents:
        typer.echo(f"  Sub-agents: {len(definition.sub_agents)}")

    if validator.known_tools:
        typer.echo("  Tool schemas:")
        for tool_name in validator.known_tools:
            read_only = "read-only" if validator.is_read_only(tool_name) else "read-write"
            confirm = " (confirmation required)" if validator.requires_confirmation(tool_name) else ""
            typer.echo(f"    • {tool_name} [{read_only}]{confirm}")

    if definition.compliance:
        typer.echo(f"  Compliance: risk_tier={definition.compliance.risk_tier}")
    else:
        typer.echo("  Compliance: not configured")


def _export_scan_rules_yaml(rules: list[dict[str, Any]], output_path: Path) -> None:
    """Export agent-scan generated rules as a YAML policy file."""
    import yaml

    data = {"rules": rules}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def _export_rules_yaml(rules: Sequence[PolicyRule], output_path: Path) -> None:
    """Export policy rules as a YAML file compatible with MCPKernel policy loader."""
    import yaml

    data = {
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "action": r.action.value,
                "priority": r.priority,
                "tool_patterns": r.tool_patterns,
                "argument_patterns": r.argument_patterns,
                "taint_labels": r.taint_labels,
                "owasp_asi_id": r.owasp_asi_id,
                "conditions": r.conditions,
            }
            for r in rules
        ]
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# Reuse the same format for preset rules export
_export_preset_rules_yaml = _export_rules_yaml


if __name__ == "__main__":
    app()
