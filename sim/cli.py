from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple
import shlex
import re

from .core import TopologySim, ACLRule
from .authority import AuthorityModel


class CLIError(Exception):
    pass


AMBIGUOUS_COMMAND = "% Ambiguous command."


@dataclass
class CLIResult:
    output: str = ""
    prompt: str = ""


@dataclass
class CLIContext:
    sim: TopologySim
    uid: str

    privileged: bool = False
    mode: str = "exec"  # exec|config|config-if|config-router|config-acl|config-vlan
    current_if: Optional[str] = None
    current_router: Optional[str] = None
    current_acl: Optional[str] = None
    current_vlan: Optional[int] = None

    def hostname(self) -> str:
        return self.uid

    def prompt(self) -> str:
        hn = self.hostname()
        if self.mode == "exec":
            return f"{hn}{'#' if self.privileged else '>'} "
        if self.mode == "config":
            return f"{hn}(config)# "
        if self.mode == "config-if":
            return f"{hn}(config-if)# "
        if self.mode == "config-router":
            return f"{hn}(config-router)# "
        if self.mode == "config-acl":
            return f"{hn}(config-ext-nacl)# "
        if self.mode == "config-vlan":
            return f"{hn}(config-vlan)# "
        return f"{hn}> "


CommandHandler = Callable[[CLIContext, List[str], str], str]


class CLIEngine:
    """Cisco-like CLI engine.

    Parses a line, updates device state through TopologySim, returns text output.
    """

    def __init__(self, sim: TopologySim, authority: Optional[AuthorityModel] = None):
        self.sim = sim
        self.authority = authority

    def new_context(self, uid: str) -> CLIContext:
        return CLIContext(sim=self.sim, uid=uid)

    def execute(self, ctx: CLIContext, line: str) -> CLIResult:
        raw = (line or "").rstrip("\n")
        stripped = raw.strip()
        if stripped == "":
            return CLIResult(output="", prompt=ctx.prompt())

        # Help
        if stripped == "?":
            return CLIResult(output=self._help(ctx, ""), prompt=ctx.prompt())
        if stripped.endswith(" ?"):
            prefix = stripped[:-2].rstrip()
            # Important: autocomplete relies on help, and IOS-style abbreviations should work
            # for help exactly like they do for execution (e.g., "sh run" -> "show running-config").
            try:
                try:
                    p_argv = shlex.split(prefix)
                except Exception:
                    p_argv = prefix.split()
                if p_argv:
                    p_argv = self._normalize_argv(ctx, p_argv)
                    prefix = " ".join(p_argv)
            except CLIError as e:
                return CLIResult(output=str(e), prompt=ctx.prompt())
            except Exception:
                pass
            return CLIResult(output=self._help(ctx, prefix), prompt=ctx.prompt())

        # Tokenize
        try:
            argv = shlex.split(stripped)
        except Exception:
            argv = stripped.split()

        try:
            argv = self._normalize_argv(ctx, argv)
        except CLIError as e:
            return CLIResult(output=str(e), prompt=ctx.prompt())

        cmd = argv[0].lower()

        # IOS-like: allow "do <exec-cmd>" inside config modes.
        if cmd == "do" and ctx.mode.startswith("config"):
            if len(argv) < 2:
                return CLIResult(output="% Incomplete command.", prompt=ctx.prompt())
            saved_priv = ctx.privileged
            saved_mode = ctx.mode
            saved_if = ctx.current_if
            saved_router = ctx.current_router
            saved_acl = ctx.current_acl
            saved_vlan = ctx.current_vlan

            try:
                # Execute as if typed in EXEC mode, without changing persistent mode.
                ctx.mode = "exec"

                exec_argv = self._normalize_argv(ctx, list(argv[1:]))
                if not exec_argv:
                    return CLIResult(output="% Incomplete command.", prompt=ctx.prompt())

                # Apply the same scope gate to the exec subcommand.
                if not self._is_supported_command(ctx, exec_argv):
                    out = "% Command not supported in this simulator."
                else:
                    out = self._dispatch(ctx, exec_argv[0].lower(), exec_argv, " ".join(exec_argv))
            except CLIError as e:
                out = str(e)
            except Exception:
                out = "% Invalid input detected at '^' marker."
            finally:
                ctx.privileged = saved_priv
                ctx.mode = saved_mode
                ctx.current_if = saved_if
                ctx.current_router = saved_router
                ctx.current_acl = saved_acl
                ctx.current_vlan = saved_vlan

            return CLIResult(output=out, prompt=ctx.prompt())

        if not self._is_supported_command(ctx, argv):
            return CLIResult(output="% Command not supported in this simulator.", prompt=ctx.prompt())

        try:
            out = self._dispatch(ctx, cmd, argv, stripped)
        except CLIError as e:
            out = str(e)
        except Exception:
            out = "% Invalid input detected at '^' marker."

        return CLIResult(output=out, prompt=ctx.prompt())

    def _expand_unique_prefix(self, token: str, candidates: List[str]) -> str:
        t = token.lower()
        if t in candidates:
            return t
        matches = [c for c in candidates if c.startswith(t)]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise CLIError(AMBIGUOUS_COMMAND)
        return t

    def _normalize_argv(self, ctx: Optional[CLIContext], argv: List[str]) -> List[str]:
        if not argv:
            return argv

        # Expand first keyword like IOS does (unique prefix), but scoped to the current mode.
        # This avoids ambiguity like "sh" (show vs shutdown) by only considering commands valid
        # in the current mode.
        if ctx is not None:
            first_words = set()
            for c in self._commands_for_mode(ctx):
                w = (c.split() or [""])[0].strip().lower()
                if w:
                    first_words.add(w)
            keywords = sorted(first_words)
        else:
            keywords = [
                "enable",
                "disable",
                "configure",
                "show",
                "ping",
                "traceroute",
                "do",
                "exit",
                "end",
                "interface",
                "router",
                "ip",
                "vlan",
                "channel-group",
                "name",
                "no",
                "shutdown",
                "switchport",
                "network",
                "permit",
                "deny",
            ]
        argv = list(argv)
        argv[0] = self._expand_unique_prefix(argv[0], keywords)

        # Normalize multi-token abbreviations that must happen BEFORE scope gating.
        argv = self._normalize_no_argv(ctx, argv)
        argv = self._normalize_interface_argv(ctx, argv)

        # Normalize common abbreviations in-place for later matching.
        if argv[0] == "configure":
            # accept "conf" and keep second token stable
            if len(argv) >= 2 and argv[1].lower() in ("t", "term", "terminal"):
                argv[1] = "terminal"

        if argv[0] == "show":
            argv = self._normalize_show_argv(argv)

        # Alias: "conf" is commonly typed; treat as configure
        if argv[0] == "conf":
            argv[0] = "configure"
        return argv

    def _normalize_no_argv(self, ctx: Optional[CLIContext], argv: List[str]) -> List[str]:
        if not argv or argv[0].lower() != "no" or len(argv) < 2:
            return argv

        argv = list(argv)
        sub = argv[1]

        # IOS supports abbreviations like "no shut".
        # Candidate set is intentionally small and mode-aware.
        mode = getattr(ctx, "mode", "exec") if ctx is not None else "exec"
        if mode == "config-if":
            candidates = ["shutdown", "ip", "channel-group"]
        elif mode.startswith("config"):
            candidates = ["shutdown", "ip", "channel-group"]
        else:
            candidates = ["shutdown", "ip", "channel-group"]

        argv[1] = self._expand_unique_prefix(sub, candidates)
        return argv

    def _normalize_interface_argv(self, ctx: Optional[CLIContext], argv: List[str]) -> List[str]:
        # Normalize "interface <ifname>" in config mode.
        if not argv or argv[0].lower() != "interface" or len(argv) != 2:
            return argv

        if ctx is None:
            return argv

        uid = ctx.uid
        dev = ctx.sim.devices.get(uid)
        if dev is None:
            return argv

        argv = list(argv)
        argv[1] = self._normalize_ifname(dev.kind, argv[1])
        return argv

    def _normalize_ifname(self, kind: str, ifname: str) -> str:
        """IOS-like interface shortname normalization.

        Examples:
        - g0/0, gi0/0, gig0/0 -> Gi0/0
        - f0/1, fa0/1 -> Fa0/1

        This prevents accidental creation of duplicate interfaces (e.g., g0/0 vs Gi0/0).
        """

        s = (ifname or "").strip()
        low = s.lower()

        def split_subif(name: str) -> tuple[str, str]:
            # Preserve subinterface suffix like ".10".
            m = re.match(r"^([^\.]+)(\.(\d+))$", name)
            if m:
                return m.group(1), m.group(2)
            return name, ""

        base, suffix = split_subif(low)

        # Already canonical-ish
        m = re.match(r"^(gi)\s*(\d+/\d+)$", base)
        if m:
            return f"Gi{m.group(2)}{suffix}"
        m = re.match(r"^(fa)\s*(\d+/\d+)$", base)
        if m:
            return f"Fa{m.group(2)}{suffix}"

        # Abbreviations
        m = re.match(r"^(g|gi|gig|giga|gigabitethernet)\s*(\d+/\d+)$", base)
        if m:
            return f"Gi{m.group(2)}{suffix}"
        m = re.match(r"^(f|fa|fastethernet)\s*(\d+/\d+)$", base)
        if m:
            return f"Fa{m.group(2)}{suffix}"

        # If user typed just "g0/0" and this is a router-like device, prefer Gi.
        if kind == "router":
            m = re.match(r"^g(\d+/\d+)$", base)
            if m:
                return f"Gi{m.group(1)}{suffix}"
        if kind == "switch":
            m = re.match(r"^f(\d+/\d+)$", base)
            if m:
                return f"Fa{m.group(1)}{suffix}"

        return s

    def _normalize_show_argv(self, argv: List[str]) -> List[str]:
        # IOS supports abbreviation/prefix matching for show keywords.
        if len(argv) < 2:
            return argv

        argv = list(argv)

        # 1st arg: show <something>
        show_targets = [
            "running-config",
            "run",
            "ip",
            "vlan",
            "interfaces",
            "mac",
            "spanning-tree",
            "etherchannel",
            "access-lists",
        ]
        argv[1] = self._expand_unique_prefix(argv[1], show_targets)

        # Normalize common aliases
        if argv[1] == "run":
            argv[1] = "running-config"

        # show ip ...
        if argv[1] == "ip" and len(argv) >= 3:
            ip_targets = ["interface", "route", "ospf", "protocols"]
            argv[2] = self._expand_unique_prefix(argv[2], ip_targets)
            if argv[2] == "interface" and len(argv) >= 4:
                argv[3] = self._expand_unique_prefix(argv[3], ["brief"])
            if argv[2] == "ospf" and len(argv) >= 4:
                argv[3] = self._expand_unique_prefix(argv[3], ["neighbor"])

        # show vlan brief
        if argv[1] == "vlan" and len(argv) >= 3:
            argv[2] = self._expand_unique_prefix(argv[2], ["brief"])

        # show interfaces trunk
        if argv[1] == "interfaces" and len(argv) >= 3:
            argv[2] = self._expand_unique_prefix(argv[2], ["trunk"])

        # show mac address-table
        if argv[1] == "mac" and len(argv) >= 3:
            argv[2] = self._expand_unique_prefix(argv[2], ["address-table"])

        # show etherchannel summary
        if argv[1] == "etherchannel" and len(argv) >= 3:
            argv[2] = self._expand_unique_prefix(argv[2], ["summary"])

        return argv

    def _is_supported_command(self, ctx: CLIContext, argv: List[str]) -> bool:
        """Hard governance: only allow commands we explicitly simulate.

        If an AuthorityModel is provided, it is the source of truth (PDF-driven).
        Otherwise, fall back to the built-in allowlist.
        """

        if not argv:
            return True

        if self.authority is not None:
            return self.authority.is_command_in_scope(argv)

        # Fallback allowlist (legacy behavior).
        cmd = argv[0].lower()
        top = {
            "enable",
            "disable",
            "configure",
            "show",
            "ping",
            "traceroute",
            "exit",
            "end",
            "interface",
            "router",
            "ip",
            "vlan",
            "shutdown",
            "no",
            "encapsulation",
            "router-id",
            "switchport",
            "channel-group",
            "network",
            "permit",
            "deny",
            "name",
            "do",
        }
        if cmd not in top:
            return False
        if cmd == "show":
            if len(argv) >= 2 and argv[1] in ("run", "running-config", "access-lists", "spanning-tree"):
                return True
            if len(argv) >= 3 and argv[1:3] in (
                ["ip", "route"],
                ["ip", "protocols"],
                ["vlan", "brief"],
                ["interfaces", "trunk"],
                ["mac", "address-table"],
                ["etherchannel", "summary"],
            ):
                return True
            if len(argv) >= 4 and argv[1:4] in (
                ["ip", "interface", "brief"],
                ["ip", "ospf", "neighbor"],
            ):
                return True
            return False
        return True

    def _help(self, ctx: CLIContext, prefix: str) -> str:
        p = prefix.lower().strip()
        cmds = self._commands_for_mode(ctx)
        if not p:
            return "\n".join(cmds)
        return "\n".join([c for c in cmds if c.startswith(p)]) or "% No help for that"

    def _commands_for_mode(self, ctx: CLIContext) -> List[str]:
        # Minimal help set
        base = [
            "enable",
            "disable",
            "configure terminal",
            "exit",
            "show running-config",
            "show run",
            "show ip interface brief",
            "show ip route",
            "show ip ospf neighbor",
            "show ip protocols",
            "show vlan brief",
            "show interfaces trunk",
            "show mac address-table",
            "show spanning-tree",
            "show etherchannel summary",
            "show access-lists",
            "ping <ip>",
            "traceroute <ip>",
        ]
        if ctx.mode.startswith("config"):
            base.extend([
                "interface <name>",
                "router ospf <id>",
                "ip access-list extended <name>",
                "ip route <prefix> <mask> <next-hop>",
                "vlan <id>",
                "encapsulation dot1q <vlan>",
                "do <exec-command>",
                "end",
            ])
        if ctx.mode == "config-if":
            base.extend([
                "ip address <ip> <mask>",
                "shutdown",
                "no shutdown",
                "switchport mode access|trunk",
                "switchport access vlan <vlan>",
                "switchport trunk allowed vlan <list>",
                "channel-group <id> mode active|passive|on",
                "no channel-group",
                "ip access-group <name> in|out",
                "no ip access-group in|out",
            ])
        if ctx.mode == "config-router":
            base.extend([
                "network <ip> <wildcard> area <area>",
                "router-id <id>",
            ])
        if ctx.mode == "config-acl":
            base.extend([
                "permit icmp any any",
                "deny icmp any any",
                "permit ip any any",
                "deny ip any any",
            ])
        return sorted(set(base))

    def _dispatch(self, ctx: CLIContext, cmd: str, argv: List[str], raw: str) -> str:
        # EXEC / PRIV EXEC
        if cmd in ("enable", "en"):
            ctx.privileged = True
            return ""
        if cmd == "disable":
            ctx.privileged = False
            ctx.mode = "exec"
            ctx.current_if = None
            ctx.current_router = None
            ctx.current_acl = None
            ctx.current_vlan = None
            return ""

        if cmd in ("configure",):
            if len(argv) >= 2 and argv[1].lower().startswith("t"):
                if not ctx.privileged:
                    raise CLIError("% Insufficient privileges")
                ctx.mode = "config"
                ctx.current_if = None
                ctx.current_router = None
                ctx.current_acl = None
                ctx.current_vlan = None
                return ""

        if cmd == "end":
            if ctx.mode == "exec":
                raise CLIError("% Invalid input detected at '^' marker.")
            ctx.mode = "exec"
            ctx.current_if = None
            ctx.current_router = None
            ctx.current_acl = None
            ctx.current_vlan = None
            return ""

        if cmd == "exit":
            if ctx.mode == "exec":
                return "__CLOSE__"  # UI handles closing
            if ctx.mode == "config":
                ctx.mode = "exec"
            else:
                ctx.mode = "config"
            ctx.current_if = None if ctx.mode != "config-if" else ctx.current_if
            ctx.current_router = None if ctx.mode != "config-router" else ctx.current_router
            ctx.current_acl = None if ctx.mode != "config-acl" else ctx.current_acl
            ctx.current_vlan = None if ctx.mode != "config-vlan" else ctx.current_vlan
            return ""

        if cmd == "show":
            if ctx.mode != "exec":
                raise CLIError("% Invalid input detected at '^' marker.")
            return self._cmd_show(ctx, argv)

        if cmd == "ping":
            if ctx.mode != "exec":
                raise CLIError("% Invalid input detected at '^' marker.")
            if len(argv) < 2:
                raise CLIError("% Usage: ping <ip>")
            # Be tolerant of extra tokens (some users type a netmask or other args).
            lines = ctx.sim.ping(ctx.uid, argv[1])
            return "\n".join(lines)

        if cmd == "traceroute":
            if ctx.mode != "exec":
                raise CLIError("% Invalid input detected at '^' marker.")
            if len(argv) != 2:
                raise CLIError("% Usage: traceroute <ip>")
            lines = ctx.sim.traceroute(ctx.uid, argv[1])
            return "\n".join(lines)

        # CONFIG modes
        if ctx.mode.startswith("config"):
            if cmd == "interface":
                if len(argv) != 2:
                    raise CLIError("% Invalid input detected at '^' marker.")
                ifname = argv[1]
                ctx.sim.ensure_interface(ctx.uid, ifname)
                ctx.mode = "config-if"
                ctx.current_if = ifname
                ctx.current_router = None
                ctx.current_acl = None
                ctx.sim.recompute()
                return ""

            if cmd == "vlan":
                if len(argv) != 2:
                    raise CLIError("% Incomplete command.")
                dev = ctx.sim.devices[ctx.uid]
                if dev.kind != "switch":
                    raise CLIError("% Command only valid on switches")
                try:
                    vid = int(argv[1])
                except Exception:
                    raise CLIError("% Invalid input detected at '^' marker.")
                dev.ensure_vlan(vid)
                ctx.mode = "config-vlan"
                ctx.current_vlan = vid
                ctx.current_if = None
                ctx.current_router = None
                ctx.current_acl = None
                ctx.sim.recompute()
                return ""

            if cmd == "router":
                if len(argv) >= 3 and argv[1].lower() == "ospf":
                    pid = argv[2]
                    dev = ctx.sim.devices[ctx.uid]
                    dev.ospf.enabled = True
                    dev.ospf.process_id = str(pid)
                    ctx.mode = "config-router"
                    ctx.current_router = str(pid)
                    ctx.current_if = None
                    ctx.current_acl = None
                    ctx.sim.recompute()
                    return ""

            if cmd == "ip" and len(argv) >= 2 and argv[1].lower() == "route":
                if len(argv) != 5:
                    raise CLIError("% Invalid input detected at '^' marker.")
                prefix, mask, nh = argv[2], argv[3], argv[4]
                dev = ctx.sim.devices[ctx.uid]
                dev.static_routes.append((prefix, mask, nh))
                ctx.sim.recompute()
                return ""

            if cmd == "ip" and len(argv) >= 4 and argv[1].lower() == "access-list" and argv[2].lower() == "extended":
                name = argv[3]
                dev = ctx.sim.devices[ctx.uid]
                dev.acls.setdefault(name, [])
                ctx.mode = "config-acl"
                ctx.current_acl = name
                ctx.current_if = None
                ctx.current_router = None
                ctx.sim.recompute()
                return ""

        if ctx.mode == "config-if":
            return self._cmd_config_if(ctx, argv)

        if ctx.mode == "config-router":
            return self._cmd_config_router(ctx, argv)

        if ctx.mode == "config-acl":
            return self._cmd_config_acl(ctx, argv)

        if ctx.mode == "config-vlan":
            return self._cmd_config_vlan(ctx, argv)

        raise CLIError("% Invalid input detected at '^' marker.")

    def _cmd_show(self, ctx: CLIContext, argv: List[str]) -> str:
        # Accept: show run | show running-config | sh run
        if len(argv) >= 2 and argv[1] in ("run", "running-config"):
            return ctx.sim.show_running_config(ctx.uid)
        # Accept: show ip interface brief | show ip int brief | show ip int br
        if len(argv) >= 4 and argv[1:4] == ["ip", "interface", "brief"]:
            return ctx.sim.show_ip_interface_brief(ctx.uid)
        if len(argv) >= 3 and argv[1:3] == ["ip", "route"]:
            return ctx.sim.show_ip_route(ctx.uid)
        if len(argv) >= 4 and argv[1:4] == ["ip", "ospf", "neighbor"]:
            return ctx.sim.show_ospf_neighbor(ctx.uid)
        if len(argv) >= 3 and argv[1:3] == ["ip", "protocols"]:
            return ctx.sim.show_ip_protocols(ctx.uid)
        if len(argv) >= 3 and argv[1:3] == ["vlan", "brief"]:
            return ctx.sim.show_vlan_brief(ctx.uid)
        if len(argv) >= 3 and argv[1:3] == ["interfaces", "trunk"]:
            return ctx.sim.show_interfaces_trunk(ctx.uid)
        if len(argv) >= 3 and argv[1:3] == ["mac", "address-table"]:
            return ctx.sim.show_mac_address_table(ctx.uid)
        if len(argv) >= 2 and argv[1] == "spanning-tree":
            return ctx.sim.show_spanning_tree(ctx.uid)
        if len(argv) >= 3 and argv[1:3] == ["etherchannel", "summary"]:
            return ctx.sim.show_etherchannel_summary(ctx.uid)
        if len(argv) >= 2 and argv[1] == "access-lists":
            return ctx.sim.show_access_lists(ctx.uid)
        raise CLIError("% Invalid input detected at '^' marker.")

    def _cmd_config_if(self, ctx: CLIContext, argv: List[str]) -> str:
        if ctx.current_if is None:
            raise CLIError("% Invalid input detected at '^' marker.")
        dev = ctx.sim.devices[ctx.uid]
        itf = dev.interfaces[ctx.current_if]

        cmd = argv[0].lower()
        if cmd == "ip" and len(argv) == 4 and argv[1].lower() == "address":
            itf.ip = argv[2]
            itf.mask = argv[3]
            ctx.sim.recompute()
            return ""

        # Router-on-a-stick (simulated): accept dot1q encapsulation on subinterfaces.
        # We infer VLAN from the subinterface suffix (e.g., Gi0/0.10) for forwarding.
        if cmd == "encapsulation" and len(argv) >= 3 and argv[1].lower() == "dot1q":
            # Validate VLAN token when present, but do not require it.
            if len(argv) >= 3:
                try:
                    int(argv[2])
                except Exception:
                    raise CLIError("% Invalid input detected at '^' marker.")
            ctx.sim.recompute()
            return ""

        if cmd == "shutdown":
            itf.admin_up = False
            ctx.sim.recompute()
            return ""
        if cmd == "no" and len(argv) >= 2 and argv[1].lower() == "shutdown":
            itf.admin_up = True
            ctx.sim.recompute()
            return ""

        if cmd == "switchport" and len(argv) >= 3 and argv[1].lower() == "mode":
            mode = argv[2].lower()
            if mode not in ("access", "trunk"):
                raise CLIError("% Invalid input detected at '^' marker.")
            itf.mode = mode
            ctx.sim.recompute()
            return ""

        if cmd == "switchport" and len(argv) >= 4 and argv[1:3] == ["access", "vlan"]:
            itf.mode = "access"
            itf.access_vlan = int(argv[3])
            dev.ensure_vlan(itf.access_vlan)
            ctx.sim.recompute()
            return ""

        if cmd == "switchport" and len(argv) >= 5 and argv[1:4] == ["trunk", "allowed", "vlan"]:
            itf.mode = "trunk"

            op = "set"  # set|add|remove
            vlan_list = argv[4]
            if vlan_list.lower() in ("add", "remove") and len(argv) >= 6:
                op = vlan_list.lower()
                vlan_list = argv[5]

            parsed = set()
            for part in vlan_list.split(","):
                part = part.strip()
                if not part:
                    continue
                if "-" in part:
                    a, b = part.split("-", 1)
                    for v in range(int(a), int(b) + 1):
                        parsed.add(v)
                else:
                    parsed.add(int(part))

            if op == "add":
                itf.trunk_vlans = set(itf.trunk_vlans) | parsed
            elif op == "remove":
                itf.trunk_vlans = set(itf.trunk_vlans) - parsed
            else:
                itf.trunk_vlans = parsed

            for v in itf.trunk_vlans:
                dev.ensure_vlan(v)
            ctx.sim.recompute()
            return ""

        if cmd == "channel-group" and len(argv) >= 4 and argv[2].lower() == "mode":
            try:
                gid = int(argv[1])
            except Exception:
                raise CLIError("% Invalid input detected at '^' marker.")
            mode = argv[3].lower()
            if mode not in ("active", "passive", "on"):
                raise CLIError("% Invalid input detected at '^' marker.")
            itf.channel_group = gid
            itf.channel_mode = mode
            ctx.sim.recompute()
            return ""

        if cmd == "no" and len(argv) == 2 and argv[1].lower() == "channel-group":
            itf.channel_group = None
            itf.channel_mode = None
            ctx.sim.recompute()
            return ""

        if cmd == "ip" and len(argv) == 4 and argv[1].lower() == "access-group":
            name = argv[2]
            direction = argv[3].lower()
            if direction not in ("in", "out"):
                raise CLIError("% Invalid input detected at '^' marker.")
            if name not in dev.acls:
                raise CLIError("% Access list not found")
            if direction == "in":
                itf.acl_in = name
            else:
                itf.acl_out = name
            ctx.sim.recompute()
            return ""

        if cmd == "no" and len(argv) == 3 and argv[1].lower() == "ip" and argv[2].lower().startswith("access-group"):
            raise CLIError("% Invalid input detected at '^' marker.")

        if cmd == "no" and len(argv) == 4 and argv[1:3] == ["ip", "access-group"]:
            direction = argv[3].lower()
            if direction == "in":
                itf.acl_in = None
            elif direction == "out":
                itf.acl_out = None
            else:
                raise CLIError("% Invalid input detected at '^' marker.")
            ctx.sim.recompute()
            return ""

        raise CLIError("% Invalid input detected at '^' marker.")

    def _cmd_config_vlan(self, ctx: CLIContext, argv: List[str]) -> str:
        if ctx.current_vlan is None:
            raise CLIError("% Invalid input detected at '^' marker.")
        dev = ctx.sim.devices[ctx.uid]
        if dev.kind != "switch":
            raise CLIError("% Command only valid on switches")
        cmd = argv[0].lower()
        if cmd == "name" and len(argv) >= 2:
            name = " ".join(argv[1:])
            dev.vlans[int(ctx.current_vlan)] = name
            ctx.sim.recompute()
            return ""
        raise CLIError("% Invalid input detected at '^' marker.")

    def _cmd_config_router(self, ctx: CLIContext, argv: List[str]) -> str:
        dev = ctx.sim.devices[ctx.uid]
        if argv[0].lower() == "network" and len(argv) == 5 and argv[3].lower() == "area":
            net_ip, wildcard, area = argv[1], argv[2], argv[4]
            dev.ospf.networks.append((net_ip, wildcard, area))
            ctx.sim.recompute()
            return ""
        if argv[0].lower() == "router-id" and len(argv) == 2:
            rid = argv[1]
            # Validate IPv4 address
            try:
                import ipaddress

                ipaddress.IPv4Address(rid)
            except Exception:
                raise CLIError("% Invalid input detected at '^' marker.")

            # Enforce uniqueness per process among routers with explicit router-id.
            for other_uid, other in ctx.sim.devices.items():
                if other_uid == ctx.uid or other.kind != "router" or not other.ospf.enabled:
                    continue
                if str(other.ospf.process_id) != str(dev.ospf.process_id):
                    continue
                if other.ospf.router_id == rid:
                    raise CLIError("% Duplicate router-id in this OSPF process")

            dev.ospf.router_id = rid
            ctx.sim.recompute()
            return ""
        raise CLIError("% Invalid input detected at '^' marker.")

    def _cmd_config_acl(self, ctx: CLIContext, argv: List[str]) -> str:
        dev = ctx.sim.devices[ctx.uid]
        if not ctx.current_acl:
            raise CLIError("% Invalid input detected at '^' marker.")
        name = ctx.current_acl

        if len(argv) != 4:
            raise CLIError("% Invalid input detected at '^' marker.")

        action = argv[0].lower()
        proto = argv[1].lower()
        src = argv[2].lower()
        dst = argv[3].lower()

        if action not in ("permit", "deny"):
            raise CLIError("% Invalid input detected at '^' marker.")
        if proto not in ("ip", "icmp"):
            raise CLIError("% Invalid input detected at '^' marker.")
        if src != "any":
            raise CLIError("% Only 'any' supported in this build")
        if dst != "any":
            raise CLIError("% Only 'any' supported in this build")

        dev.acls.setdefault(name, []).append(ACLRule(action=action, protocol=proto, src="any", dst="any"))
        ctx.sim.recompute()
        return ""
