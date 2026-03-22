"""eBPF probe manager — BCC-based syscall monitoring with graceful fallback."""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from mcpkernel.utils import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

logger = get_logger(__name__)


class SyscallType(StrEnum):
    CONNECT = "connect"
    SENDTO = "sendto"
    OPEN = "open"
    WRITE = "write"
    EXECVE = "execve"
    READ = "read"


@dataclass
class ProbeEvent:
    """An event captured by an eBPF probe."""

    syscall: SyscallType
    pid: int
    comm: str
    timestamp: float
    details: dict[str, Any] = field(default_factory=dict)


# BCC program source — monitors key syscalls in sandbox processes
_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    int syscall_nr;
    u64 ts;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.syscall_nr = 42;  // connect
    evt.ts = bpf_ktime_get_ns();
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.syscall_nr = 59;  // execve
    evt.ts = bpf_ktime_get_ns();
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.syscall_nr = 257;  // openat
    evt.ts = bpf_ktime_get_ns();
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

_SYSCALL_MAP = {42: SyscallType.CONNECT, 59: SyscallType.EXECVE, 257: SyscallType.OPEN}


class EBPFProbe:
    """Manage eBPF probes for syscall monitoring.

    Falls back gracefully to no-op when BCC is unavailable or unprivileged.
    """

    def __init__(self) -> None:
        self._bpf: Any | None = None
        self._running = False
        self._events: list[ProbeEvent] = []
        self._callbacks: list[Callable[[ProbeEvent], None]] = []
        self._available = self._check_availability()

    @property
    def available(self) -> bool:
        return self._available

    def _check_availability(self) -> bool:
        """Check if BCC is installed and we have sufficient privileges."""
        if os.geteuid() != 0:
            logger.info("eBPF probes require root — falling back to no-op")
            return False
        try:
            from bcc import BPF  # noqa: F401

            return True
        except ImportError:
            logger.info("BCC not installed — eBPF probes unavailable")
            return False

    def on_event(self, callback: Callable[[ProbeEvent], None]) -> None:
        """Register a callback for probe events."""
        self._callbacks.append(callback)

    async def start(self) -> None:
        """Start eBPF probes. No-op if unavailable."""
        if not self._available:
            logger.info("eBPF probes disabled — running in passive mode")
            return

        from bcc import BPF

        self._bpf = BPF(text=_BPF_PROGRAM)
        self._running = True
        logger.info("eBPF probes started")

        # Start polling in background
        asyncio.get_event_loop().run_in_executor(None, self._poll_loop)

    def _poll_loop(self) -> None:
        """Poll perf buffer for events (runs in thread)."""
        if not self._bpf:
            return

        def _handle_event(cpu: int, data: bytes, size: int) -> None:
            assert self._bpf is not None
            event = self._bpf["events"].event(data)
            syscall = _SYSCALL_MAP.get(event.syscall_nr)
            if syscall:
                pe = ProbeEvent(
                    syscall=syscall,
                    pid=event.pid,
                    comm=event.comm.decode("utf-8", errors="replace"),
                    timestamp=time.time(),
                    details={"uid": event.uid},
                )
                self._events.append(pe)
                for cb in self._callbacks:
                    cb(pe)

        self._bpf["events"].open_perf_buffer(_handle_event)
        while self._running:
            self._bpf.perf_buffer_poll(timeout=100)

    async def stop(self) -> None:
        """Stop eBPF probes."""
        self._running = False
        if self._bpf:
            self._bpf.cleanup()
            self._bpf = None
        logger.info("eBPF probes stopped")

    @property
    def events(self) -> list[ProbeEvent]:
        return list(self._events)

    def clear_events(self) -> None:
        self._events.clear()
