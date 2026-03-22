"""Network redirect enforcement — block/allow egress per policy."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from mcpkernel.utils import get_logger

logger = get_logger(__name__)


@dataclass
class EgressRule:
    """A network egress rule for sandbox processes."""

    allowed_domains: set[str] = field(default_factory=set)
    allowed_cidrs: list[str] = field(default_factory=list)
    blocked_ports: set[int] = field(default_factory=lambda: {25, 445, 3389})
    allow_dns: bool = True


class NetworkRedirector:
    """Enforce network egress policy at the proxy level.

    When eBPF is available, this can hook into kernel-level connect()
    probes.  Otherwise falls back to application-level domain checking.
    """

    def __init__(self, rules: EgressRule | None = None) -> None:
        self._rules = rules or EgressRule()

    def check_egress(self, host: str, port: int) -> bool:
        """Check if an outbound connection is allowed.

        Returns True if the connection should proceed.
        """
        # Block prohibited ports
        if port in self._rules.blocked_ports:
            logger.warning("egress blocked — prohibited port", host=host, port=port)
            return False

        # Allow DNS if enabled
        if port == 53 and self._rules.allow_dns:
            return True

        # Check domain allowlist
        if (
            self._rules.allowed_domains
            and host not in self._rules.allowed_domains
            and not any(host.endswith(f".{d}") for d in self._rules.allowed_domains)
        ):
            logger.warning("egress blocked — domain not in allowlist", host=host)
            return False

        # Check CIDR allowlist (if IP address)
        if self._rules.allowed_cidrs:
            try:
                addr = ipaddress.ip_address(host)
                if not any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in self._rules.allowed_cidrs):
                    logger.warning("egress blocked — IP not in allowed CIDRs", host=host)
                    return False
            except ValueError:
                pass  # Not an IP, already checked as domain

        return True

    def update_rules(self, rules: EgressRule) -> None:
        self._rules = rules
        logger.info("egress rules updated", domains=len(rules.allowed_domains))
