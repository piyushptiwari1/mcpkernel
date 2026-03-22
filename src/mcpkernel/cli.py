"""MCPKernel CLI — Typer-based command interface."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from mcpkernel import __version__

app = typer.Typer(
    name="mcpkernel",
    help="The mandatory, deterministic MCP/A2A gateway.",
    no_args_is_help=True,
    add_completion=True,
)


# ── Proxy ──────────────────────────────────────────────────────────────
@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Bind port")] = 8000,
    config: Annotated[Path | None, typer.Option("--config", "-c", help="Config YAML path")] = None,
    log_level: Annotated[str, typer.Option(help="Log level")] = "info",
) -> None:
    """Start the MCPKernel proxy gateway."""
    from mcpkernel.config import load_config
    from mcpkernel.proxy.server import start_proxy_server
    from mcpkernel.utils import configure_logging

    configure_logging(level=log_level)
    settings = load_config(config_path=config)
    settings.proxy.host = host
    settings.proxy.port = port

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


# ── Info / Config ──────────────────────────────────────────────────────
@app.command()
def version() -> None:
    """Print MCPKernel version."""
    typer.echo(f"mcpkernel {__version__}")


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
) -> None:
    """Initialize MCPKernel in a project directory."""
    config_dir = directory / ".mcpkernel"
    config_dir.mkdir(parents=True, exist_ok=True)

    # Create default config
    config_file = config_dir / "config.yaml"
    if not config_file.exists():
        config_file.write_text(
            "# MCPKernel configuration\n"
            "# See https://github.com/piyushptiwari1/mcpkernel for docs\n\n"
            "proxy:\n"
            "  host: 127.0.0.1\n"
            "  port: 8000\n"
            "\n"
            "sandbox:\n"
            "  backend: docker\n"
            "  timeout_seconds: 30\n"
            "\n"
            "policy:\n"
            "  policy_dir: .mcpkernel/policies\n"
            "\n"
            "observability:\n"
            "  log_level: info\n"
            "  metrics_enabled: true\n"
        )

    # Create policies dir with default policy
    policies_dir = config_dir / "policies"
    policies_dir.mkdir(exist_ok=True)

    default_policy = policies_dir / "default.yaml"
    if not default_policy.exists():
        default_policy.write_text(
            "# Default MCPKernel policy\n"
            "rules:\n"
            "  - id: DEFAULT-001\n"
            "    name: Block eval/exec\n"
            "    description: Block dynamic code execution\n"
            "    action: deny\n"
            "    tool_patterns:\n"
            "      - '.*'\n"
            "    taint_labels:\n"
            "      - untrusted_external\n"
        )

    typer.echo(f"✓ Initialized MCPKernel in {config_dir}")
    typer.echo(f"  Config: {config_file}")
    typer.echo(f"  Policies: {policies_dir}")


if __name__ == "__main__":
    app()
