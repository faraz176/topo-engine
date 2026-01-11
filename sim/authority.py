from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Set
import os
import re


_NOT_SUPPORTED = "% Command not supported in this simulator."


@dataclass(frozen=True)
class AuthorityModel:
    """PDF-derived authority model.

    This is a *scope gate*: it decides whether a command is in-scope (implied by CCNA/ENCOR topic lists).

    It intentionally does not perform mode validation. Mode mismatches should still look IOS-like
    ("% Invalid input detected at '^' marker.") and are handled elsewhere.
    """

    topics_text: str
    enabled_capabilities: Set[str]

    @staticmethod
    def from_text(text: str) -> "AuthorityModel":
        text = text or ""
        caps = _derive_capabilities(text)
        return AuthorityModel(topics_text=text, enabled_capabilities=caps)

    @staticmethod
    def from_pdfs(paths: Iterable[str]) -> "AuthorityModel":
        text = extract_text_from_pdfs(paths)
        return AuthorityModel.from_text(text)

    def is_command_in_scope(self, argv: List[str]) -> bool:
        if not argv:
            return True

        cmd = (argv[0] or "").lower()

        # Base IOS navigation / scaffolding (implied by "configure/verify" exam tasks)
        if cmd in {
            "enable",
            "en",
            "disable",
            "configure",
            "conf",
            "exit",
            "end",
            "do",
        }:
            return True

        # Feature gates
        if cmd == "interface":
            # Interface config is implied by L1/L2/L3 topics.
            return any(
                cap in self.enabled_capabilities
                for cap in ("l1.interface", "l2.switching", "l3.ipv4", "security.acl", "routing.ospf", "routing.static")
            )

        if cmd == "shutdown" or (cmd == "no" and len(argv) >= 2 and argv[1].lower() == "shutdown"):
            return "l1.interface" in self.enabled_capabilities

        if cmd == "switchport":
            return "l2.switching" in self.enabled_capabilities

        if cmd == "vlan":
            return "l2.vlan" in self.enabled_capabilities

        if cmd == "channel-group" or (cmd == "no" and len(argv) >= 2 and argv[1].lower() == "channel-group"):
            return "l2.etherchannel" in self.enabled_capabilities

        if cmd == "router":
            # Currently only ospf is modeled
            return "routing.ospf" in self.enabled_capabilities

        if cmd == "network":
            return "routing.ospf" in self.enabled_capabilities

        if cmd == "ip":
            if len(argv) >= 2:
                sub = argv[1].lower()
                if sub == "address":
                    return "l3.ipv4" in self.enabled_capabilities
                if sub == "route":
                    return "routing.static" in self.enabled_capabilities
                if sub == "access-list":
                    return "security.acl" in self.enabled_capabilities
                if sub == "access-group":
                    return "security.acl" in self.enabled_capabilities
            # Any other "ip ..." is out-of-scope for now.
            return False

        if cmd in ("permit", "deny"):
            return "security.acl" in self.enabled_capabilities

        if cmd == "ping":
            return "verify.ping" in self.enabled_capabilities

        if cmd == "traceroute":
            return "verify.traceroute" in self.enabled_capabilities

        if cmd == "show":
            return self._show_in_scope(argv)

        return False

    def _show_in_scope(self, argv: List[str]) -> bool:
        # Only allow show subcommands that map to enabled capabilities.
        if len(argv) < 2:
            return False

        a1 = argv[1].lower()

        if a1 in ("run", "running-config"):
            # "show run" is a core verification tool implied by configure/verify objectives.
            return True

        if a1 == "ip":
            if len(argv) >= 3:
                a2 = argv[2].lower()
                if a2 == "route":
                    return any(cap in self.enabled_capabilities for cap in ("routing.static", "routing.ospf", "l3.ipv4"))
                if a2 == "interface" and len(argv) >= 4 and argv[3].lower() == "brief":
                    return "l3.ipv4" in self.enabled_capabilities
                if a2 == "ospf" and len(argv) >= 4 and argv[3].lower() == "neighbor":
                    return "routing.ospf" in self.enabled_capabilities
                if a2 == "protocols":
                    return any(cap in self.enabled_capabilities for cap in ("routing.static", "routing.ospf"))
            return False

        if a1 == "vlan" and len(argv) >= 3 and argv[2].lower() == "brief":
            return "l2.vlan" in self.enabled_capabilities

        if a1 == "interfaces" and len(argv) >= 3 and argv[2].lower() == "trunk":
            return "l2.trunk" in self.enabled_capabilities

        if a1 == "mac" and len(argv) >= 3 and argv[2].lower() == "address-table":
            return "l2.mac" in self.enabled_capabilities

        if a1 == "spanning-tree":
            return "l2.stp" in self.enabled_capabilities

        if a1 == "etherchannel" and len(argv) >= 3 and argv[2].lower() == "summary":
            return "l2.etherchannel" in self.enabled_capabilities

        if a1 == "access-lists":
            return "security.acl" in self.enabled_capabilities

        return False


def default_pdf_paths() -> List[str]:
    """Best-effort default locations for the CCNA/ENCOR topic list PDFs."""
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Downloads", "200-301-CCNA-v1.1.pdf"),
        os.path.join(home, "Downloads", "350-401-ENCORE-v1.1.pdf"),
    ]
    return candidates


def extract_text_from_pdfs(paths: Iterable[str]) -> str:
    # Lazy import so the simulator still runs even without the optional dependency.
    try:
        from pypdf import PdfReader  # type: ignore
    except Exception:
        return ""

    texts: List[str] = []
    for path in paths:
        if not path:
            continue
        if not os.path.exists(path):
            continue
        try:
            reader = PdfReader(path)
            for page in reader.pages:
                try:
                    texts.append(page.extract_text() or "")
                except Exception:
                    continue
        except Exception:
            continue

    return "\n".join(texts)


def _derive_capabilities(text: str) -> Set[str]:
    t = (text or "").lower()

    caps: Set[str] = set()

    # If we have no PDF text, we cannot justify any feature commands.
    if not t.strip():
        return caps

    # L1 / Interfaces
    if re.search(r"\b(interface|interfaces)\b", t):
        caps.add("l1.interface")

    # L2
    if re.search(r"\bvlan(s)?\b", t):
        caps.add("l2.vlan")
        caps.add("l2.switching")
    if re.search(r"\btrunk(s|ing)?\b|802\.1q", t):
        caps.add("l2.trunk")
        caps.add("l2.switching")
    if re.search(r"spanning[- ]tree\b|\bstp\b", t):
        caps.add("l2.stp")
        caps.add("l2.switching")
    if re.search(r"etherchannel\b|lacp\b", t):
        caps.add("l2.etherchannel")
        caps.add("l2.switching")
    if re.search(r"mac address\b|mac table\b|cam table\b", t):
        caps.add("l2.mac")
        caps.add("l2.switching")

    # L3
    if re.search(r"ipv4\b|subnet(ting)?\b|ip addressing\b", t):
        caps.add("l3.ipv4")

    # Routing
    if re.search(r"static route\b|default route\b", t):
        caps.add("routing.static")
    if re.search(r"\bospf\b|ospfv2\b", t):
        caps.add("routing.ospf")

    # Security
    if re.search(r"access control list\b|\bacl\b", t):
        caps.add("security.acl")

    # Verification
    if re.search(r"\bping\b", t):
        caps.add("verify.ping")
    # traceroute is optional but preferred; only allow if the PDF mentions it.
    if re.search(r"traceroute\b|trace route\b", t):
        caps.add("verify.traceroute")

    return caps


__all__ = [
    "AuthorityModel",
    "default_pdf_paths",
    "extract_text_from_pdfs",
    "_NOT_SUPPORTED",
]
