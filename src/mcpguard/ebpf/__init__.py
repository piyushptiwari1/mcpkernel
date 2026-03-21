"""eBPF syscall monitoring — optional kernel-level taint & network enforcement."""

from mcpguard.ebpf.probe import EBPFProbe, ProbeEvent
from mcpguard.ebpf.redirector import NetworkRedirector

__all__ = [
    "EBPFProbe",
    "NetworkRedirector",
    "ProbeEvent",
]
