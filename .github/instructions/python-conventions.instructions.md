---
description: "Use when writing or modifying Python code in MCPKernel. Covers async patterns, type hints, structlog logging, error handling, and module conventions."
applyTo: "src/**/*.py"
---

# MCPKernel Python Conventions

## Async-First
- All I/O-bound functions must be `async def`
- Use `asyncio.gather()` for concurrent operations
- Never use blocking I/O in async functions (use `aiofiles`, `aiohttp`, etc.)

## Type Hints
- All public functions and methods must have type annotations
- Use `from __future__ import annotations` for forward references
- Use `Optional[X]` not `X | None` (Python 3.10 compatibility)

## Logging
- Use `structlog` — NOT stdlib `logging`
- Get logger: `logger = structlog.get_logger(__name__)`
- Include context: `logger.info("action_description", key=value)`

## Error Handling
- Define custom exceptions per package in `exceptions.py`
- Catch specific exceptions, not broad `Exception`
- For async retry: use exponential backoff with jitter

## Imports
- stdlib → third-party → local (separated by blank lines)
- Use absolute imports: `from mcpkernel.policy.engine import PolicyEngine`
