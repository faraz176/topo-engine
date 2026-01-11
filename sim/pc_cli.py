from __future__ import annotations

from dataclasses import dataclass
from typing import List
import shlex
import ipaddress

from .core import TopologySim


@dataclass
class PCResult:
    output: str = ""
    prompt: str = ""


@dataclass
class PCContext:
    sim: TopologySim
    uid: str

    def prompt(self) -> str:
        return f"{self.uid}> "


class PCCLIEngine:
    """Very small 'PC' style CLI.

    Purpose: configure host IP/subnet/gateway/DNS and run ping/traceroute.
    This intentionally does NOT enforce IOS/PDF authority gating.
    """

    def __init__(self, sim: TopologySim):
        self.sim = sim

    def new_context(self, uid: str) -> PCContext:
        return PCContext(sim=self.sim, uid=uid)

    def execute(self, ctx: PCContext, line: str) -> PCResult:
        raw = (line or "").rstrip("\n")
        stripped = raw.strip()
        if stripped == "":
            return PCResult(output="", prompt=ctx.prompt())

        # Help
        if stripped == "?" or stripped.endswith(" ?"):
            return PCResult(output=self._help(), prompt=ctx.prompt())

        try:
            argv = shlex.split(stripped)
        except Exception:
            argv = stripped.split()

        cmd = (argv[0] if argv else "").lower()

        if cmd in ("exit", "quit"):
            return PCResult(output="__CLOSE__", prompt=ctx.prompt())

        dev = ctx.sim.devices.get(ctx.uid)
        if dev is None:
            return PCResult(output="% Device not found.", prompt=ctx.prompt())

        # Configure IP on Eth0
        if cmd in ("ip", "ipconfig"):
            if len(argv) < 3:
                return PCResult(output="% Usage: ip <ip> <mask> [gateway]", prompt=ctx.prompt())
            ip_s, mask_s = argv[1], argv[2]
            gw_s = argv[3] if len(argv) >= 4 else None
            try:
                ipaddress.IPv4Address(ip_s)
                ipaddress.IPv4Address(mask_s)
                if gw_s is not None:
                    ipaddress.IPv4Address(gw_s)
            except Exception:
                return PCResult(output="% Invalid IP address.", prompt=ctx.prompt())

            itf = ctx.sim.ensure_interface(ctx.uid, "Eth0")
            itf.admin_up = True
            itf.ip = ip_s
            itf.mask = mask_s

            if gw_s is not None:
                dev.host_gateway = gw_s
                self._sync_default_route(dev)

            ctx.sim.recompute()
            return PCResult(output="", prompt=ctx.prompt())

        if cmd in ("gateway", "gw"):
            if len(argv) != 2:
                return PCResult(output="% Usage: gateway <ip>", prompt=ctx.prompt())
            try:
                ipaddress.IPv4Address(argv[1])
            except Exception:
                return PCResult(output="% Invalid IP address.", prompt=ctx.prompt())
            dev.host_gateway = argv[1]
            self._sync_default_route(dev)
            ctx.sim.recompute()
            return PCResult(output="", prompt=ctx.prompt())

        if cmd == "dns":
            if len(argv) != 2:
                return PCResult(output="% Usage: dns <ip>", prompt=ctx.prompt())
            try:
                ipaddress.IPv4Address(argv[1])
            except Exception:
                return PCResult(output="% Invalid IP address.", prompt=ctx.prompt())
            dev.host_dns = argv[1]
            return PCResult(output="", prompt=ctx.prompt())

        if cmd in ("show", "showip", "show-ip"):
            itf = dev.interfaces.get("Eth0")
            ip_s = itf.ip if itf else None
            mask_s = itf.mask if itf else None
            lines = [f"{ctx.uid} configuration:"]
            lines.append(f"  Interface: Eth0")
            lines.append(f"  IP Address: {ip_s or 'unset'}")
            lines.append(f"  Subnet Mask: {mask_s or 'unset'}")
            lines.append(f"  Default Gateway: {dev.host_gateway or 'unset'}")
            lines.append(f"  DNS Server: {dev.host_dns or 'unset'}")
            return PCResult(output="\n".join(lines), prompt=ctx.prompt())

        if cmd == "ping":
            if len(argv) < 2:
                return PCResult(output="% Usage: ping <ip>", prompt=ctx.prompt())
            dst = argv[1]
            lines = ctx.sim.ping(ctx.uid, dst)
            return PCResult(output="\n".join(lines), prompt=ctx.prompt())

        if cmd in ("traceroute", "tracert"):
            if len(argv) < 2:
                return PCResult(output="% Usage: traceroute <ip>", prompt=ctx.prompt())
            dst = argv[1]
            lines = ctx.sim.traceroute(ctx.uid, dst)
            return PCResult(output="\n".join(lines), prompt=ctx.prompt())

        return PCResult(output="% Unknown command.", prompt=ctx.prompt())

    def _help(self) -> str:
        return "\n".join(
            [
                "ip <ip> <mask> [gateway]",
                "gateway <ip>",
                "dns <ip>",
                "show",
                "ping <ip>",
                "traceroute <ip>",
                "exit",
            ]
        )

    def _sync_default_route(self, dev) -> None:
        # Maintain exactly one default route (0.0.0.0/0) for hosts.
        dev.static_routes = [
            (p, m, nh)
            for (p, m, nh) in dev.static_routes
            if not (str(p) == "0.0.0.0" and str(m) == "0.0.0.0")
        ]
        if dev.host_gateway:
            dev.static_routes.append(("0.0.0.0", "0.0.0.0", dev.host_gateway))
