"""eBPF syscall monitoring — optional kernel-level taint & network enforcement."""

from mcpkernel.ebpf.probe import EBPFProbe, ProbeEvent
from mcpkernel.ebpf.redirector import NetworkRedirector

__all__ = [
    "EBPFProbe",
    "NetworkRedirector",
    "ProbeEvent",
]
