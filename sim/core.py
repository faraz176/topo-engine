from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Iterable, Set
import ipaddress
import re


def _norm_uid(uid: str) -> str:
    return (uid or "").strip()


def _mac_from_text(text: str) -> str:
    # Deterministic locally-administered unicast MAC.
    h = 0
    for ch in text.encode("utf-8"):
        h = (h * 131 + ch) & 0xFFFFFFFF
    b = [0x02, (h >> 24) & 0xFF, (h >> 16) & 0xFF, (h >> 8) & 0xFF, h & 0xFF, (h >> 1) & 0xFF]
    return ":".join(f"{x:02x}" for x in b)


@dataclass
class ACLRule:
    action: str  # permit|deny
    protocol: str  # ip|icmp
    src: str  # any|host x.x.x.x
    dst: str  # any|host x.x.x.x
    hits: int = 0

    def matches(self, protocol: str, src_ip: str, dst_ip: str) -> bool:
        if self.protocol not in ("ip", protocol):
            return False

        def match_endpoint(rule: str, ip: str) -> bool:
            rule = rule.strip().lower()
            if rule == "any":
                return True
            if rule.startswith("host "):
                return ip == rule.split()[1]
            return False

        return match_endpoint(self.src, src_ip) and match_endpoint(self.dst, dst_ip)


@dataclass
class OSPFConfig:
    enabled: bool = False
    process_id: str = "1"
    router_id: Optional[str] = None
    # network statements: (network_ip, wildcard, area)
    networks: List[Tuple[str, str, str]] = field(default_factory=list)


@dataclass
class Interface:
    name: str
    admin_up: bool = False

    # L2 identity
    mac: str = ""

    # L3
    ip: Optional[str] = None
    mask: Optional[str] = None

    # L2
    mode: str = "routed"  # routed|access|trunk
    access_vlan: int = 1
    trunk_vlans: Set[int] = field(default_factory=lambda: {1})

    # EtherChannel (simplified)
    channel_group: Optional[int] = None
    channel_mode: Optional[str] = None  # active|passive|on

    # ACL
    acl_in: Optional[str] = None
    acl_out: Optional[str] = None

    def has_ip(self) -> bool:
        return bool(self.ip and self.mask)

    def ip_interface(self) -> Optional[ipaddress.IPv4Interface]:
        if not self.has_ip():
            return None
        return ipaddress.IPv4Interface(f"{self.ip}/{self.mask}")


@dataclass
class Device:
    uid: str
    kind: str  # router|switch|host
    interfaces: Dict[str, Interface] = field(default_factory=dict)

    # Host-only (PC) convenience settings
    host_gateway: Optional[str] = None
    host_dns: Optional[str] = None

    # Switch state
    vlans: Dict[int, str] = field(default_factory=lambda: {1: "default"})
    mac_table: Dict[int, Dict[str, str]] = field(default_factory=dict)  # vlan -> mac -> ifname

    # Router/switch L3 state
    arp_table: Dict[int, Dict[str, str]] = field(default_factory=dict)  # vlan -> ip -> mac

    # Routing
    static_routes: List[Tuple[str, str, Optional[str]]] = field(default_factory=list)  # prefix, mask, next_hop
    ospf: OSPFConfig = field(default_factory=OSPFConfig)

    # ACLs
    acls: Dict[str, List[ACLRule]] = field(default_factory=dict)

    def ensure_vlan(self, vlan: int):
        if vlan not in self.vlans:
            self.vlans[vlan] = f"VLAN{vlan}"


@dataclass
class LinkEnd:
    device: str
    ifname: str


@dataclass
class Link:
    link_id: str
    a: LinkEnd
    b: LinkEnd


@dataclass
class Route:
    prefix: ipaddress.IPv4Network
    next_hop: Optional[str]  # ip
    out_if: str
    protocol: str  # C|S|O
    metric: int = 0


class TopologySim:
    """Deterministic topology simulator.

    Model goal: enough realism for CCNA/CCNP style labs (L2 VLANs, static + OSPF, ACL).
    """

    def __init__(self):
        self.devices: Dict[str, Device] = {}
        self.links: Dict[str, Link] = {}
        self._next_link = 1
        self._if_counters: Dict[str, int] = {}

        # Cached recompute outputs
        self._routes: Dict[str, List[Route]] = {}
        # uid -> list of (neighbor_router_id, local_if, state)
        self._ospf_neighbors: Dict[str, List[Tuple[str, str, str]]] = {}

    # ───────────────────────────── Devices / Links ─────────────────────────────

    def reset(self):
        self.__init__()

    def add_device(self, uid: str, kind: str):
        uid = _norm_uid(uid)
        kind = (kind or "router").lower()
        if kind not in ("router", "switch", "host"):
            kind = "router"
        if uid in self.devices:
            return
        self.devices[uid] = Device(uid=uid, kind=kind)
        self._if_counters[uid] = 0
        self.recompute()

    def remove_device(self, uid: str):
        uid = _norm_uid(uid)
        if uid not in self.devices:
            return
        # Remove attached links
        doomed = [lid for lid, l in self.links.items() if l.a.device == uid or l.b.device == uid]
        for lid in doomed:
            self.remove_link(lid)
        self.devices.pop(uid, None)
        self._if_counters.pop(uid, None)
        self.recompute()

    def ensure_interface(self, uid: str, ifname: str) -> Interface:
        dev = self.devices[uid]
        if ifname not in dev.interfaces:
            itf = Interface(name=ifname, mac=_mac_from_text(f"{uid}:{ifname}"))
            # PCs are "plugged in" by default.
            if dev.kind == "host" and ifname.startswith("Eth"):
                itf.admin_up = True
            dev.interfaces[ifname] = itf
            self._sync_if_counter(uid)
        # Backfill MAC for older saved configs
        if not dev.interfaces[ifname].mac:
            dev.interfaces[ifname].mac = _mac_from_text(f"{uid}:{ifname}")
        return dev.interfaces[ifname]

    def allocate_interface_name(self, uid: str) -> str:
        dev = self.devices[uid]
        self._sync_if_counter(uid)
        self._if_counters[uid] = self._if_counters.get(uid, 0) + 1
        n = self._if_counters[uid]
        if dev.kind == "switch":
            # Cisco-ish access ports start at Fa0/1
            return f"Fa0/{n}"
        if dev.kind == "host":
            return f"Eth{n-1}"
        return f"Gi0/{n-1}"

    def allocate_or_reuse_interface_name(self, uid: str) -> str:
        """Prefer a disconnected interface before minting a new one."""
        uid = _norm_uid(uid)
        dev = self.devices[uid]

        used_if: set[str] = set()
        for l in self.links.values():
            if l.a.device == uid:
                used_if.add(l.a.ifname)
            if l.b.device == uid:
                used_if.add(l.b.ifname)

        candidates = [ifn for ifn in dev.interfaces.keys() if ifn not in used_if]
        if candidates:
            def _sort_key(name: str):
                m = re.match(r"^([A-Za-z]+)(\d+)/(\d+)$", name)
                if m:
                    return (m.group(1), int(m.group(2)), int(m.group(3)))
                m = re.match(r"^([A-Za-z]+)(\d+)$", name)
                if m:
                    return (m.group(1), int(m.group(2)), -1)
                return (name, -1, -1)

            return sorted(candidates, key=_sort_key)[0]

        return self.allocate_interface_name(uid)

    def _sync_if_counter(self, uid: str):
        """Ensure future auto-allocated interface names don't collide with existing ones."""
        if uid not in self.devices:
            return
        dev = self.devices[uid]
        cur = int(self._if_counters.get(uid, 0))
        best = cur
        for ifn in dev.interfaces.keys():
            m = re.match(r"^(Gi0/)(\d+)$", ifn)
            if m:
                # allocate uses counter = index+1
                best = max(best, int(m.group(2)) + 1)
                continue
            m = re.match(r"^(Fa0/)(\d+)$", ifn)
            if m:
                best = max(best, int(m.group(2)))
            m = re.match(r"^(Eth)(\d+)$", ifn)
            if m:
                best = max(best, int(m.group(2)) + 1)
        self._if_counters[uid] = best

    def connect(self, a_uid: str, a_if: str, b_uid: str, b_if: str) -> str:
        a_uid = _norm_uid(a_uid)
        b_uid = _norm_uid(b_uid)
        if a_uid not in self.devices or b_uid not in self.devices:
            raise KeyError("Unknown device")

        self.ensure_interface(a_uid, a_if)
        self.ensure_interface(b_uid, b_if)

        link_id = f"L{self._next_link}"
        self._next_link += 1
        self.links[link_id] = Link(link_id=link_id, a=LinkEnd(a_uid, a_if), b=LinkEnd(b_uid, b_if))
        self.recompute()
        return link_id

    def remove_link(self, link_id: str):
        self.links.pop(link_id, None)
        self.recompute()

    def maybe_prune_interface(self, uid: str, ifname: str):
        """Remove an interface if it is disconnected AND still at default settings.

        This keeps the GUI experience sane: deleting/recreating links won't leave
        orphan interfaces that confuse which port maps to which cable.
        """
        uid = _norm_uid(uid)
        ifname = (ifname or "").strip()
        dev = self.devices.get(uid)
        if dev is None or not ifname:
            return

        iface = dev.interfaces.get(ifname)
        if iface is None:
            return

        # If still linked, never prune.
        if self.link_for_end(uid, ifname) is not None:
            return

        # Only prune if interface is untouched (default-ish).
        if iface.admin_up:
            return
        if iface.ip is not None or iface.mask is not None:
            return
        if iface.mode != "routed":
            return
        if iface.access_vlan != 1:
            return
        if set(iface.trunk_vlans) != {1}:
            return
        if iface.channel_group is not None or iface.channel_mode is not None:
            return
        if iface.acl_in is not None or iface.acl_out is not None:
            return

        dev.interfaces.pop(ifname, None)
        self._sync_if_counter(uid)
        self.recompute()

    def link_for_end(self, uid: str, ifname: str) -> Optional[str]:
        uid = _norm_uid(uid)
        ifname = (ifname or "").strip()
        for lid, l in self.links.items():
            if (l.a.device == uid and l.a.ifname == ifname) or (l.b.device == uid and l.b.ifname == ifname):
                return lid

        # Router-on-a-stick: subinterfaces share the parent physical link.
        parent, _vlan = self._split_subinterface(ifname)
        if parent and parent != ifname:
            for lid, l in self.links.items():
                if (l.a.device == uid and l.a.ifname == parent) or (l.b.device == uid and l.b.ifname == parent):
                    return lid
        return None

    def _split_subinterface(self, ifname: str) -> Tuple[str, Optional[int]]:
        """Return (parent_ifname, vlan) for subinterfaces like Gi0/0.10."""

        s = (ifname or "").strip()
        m = re.match(r"^([^\.]+)\.(\d+)$", s)
        if not m:
            return s, None
        return m.group(1), int(m.group(2))

    def _physical_ifname(self, uid: str, ifname: str) -> str:
        parent, _vlan = self._split_subinterface(ifname)
        dev = self.devices.get(uid)
        if dev is None:
            return ifname
        if parent and parent in dev.interfaces:
            return parent
        return ifname

    def _is_interface_up(self, uid: str, ifname: str) -> bool:
        dev = self.devices.get(uid)
        if dev is None:
            return False
        itf = dev.interfaces.get(ifname)
        if itf is None or not itf.admin_up:
            return False

        parent, _vlan = self._split_subinterface(ifname)
        if parent and parent != ifname:
            pitf = dev.interfaces.get(parent)
            if pitf is not None and not pitf.admin_up:
                return False
        return True

    def _segment_id_for_routed_link(self, uid: str, ifname: str) -> int:
        """Return a deterministic per-link segment id for routed adjacencies.

        Using a single global 'vlan 0' for all routed-to-routed links incorrectly
        merges unrelated point-to-point links into one broadcast domain, which in
        turn breaks OSPF adjacency and next-hop selection.

        The returned id is negative to avoid colliding with user VLAN numbers.
        """

        lid = self.link_for_end(uid, ifname)
        if not lid:
            return 0
        m = re.match(r"^L(\d+)$", str(lid))
        if m:
            return -int(m.group(1))
        # Fallback: stable hash
        h = 0
        for ch in str(lid).encode("utf-8"):
            h = (h * 131 + ch) & 0xFFFFFFFF
        return -int(h % 2_000_000_000)

    def other_end(self, uid: str, ifname: str) -> Optional[LinkEnd]:
        uid = _norm_uid(uid)
        ifname = (ifname or "").strip()

        for l in self.links.values():
            if l.a.device == uid and l.a.ifname == ifname:
                return l.b
            if l.b.device == uid and l.b.ifname == ifname:
                return l.a

        # Router-on-a-stick: subinterfaces share the parent physical link.
        parent, _vlan = self._split_subinterface(ifname)
        if parent and parent != ifname:
            for l in self.links.values():
                if l.a.device == uid and l.a.ifname == parent:
                    return l.b
                if l.b.device == uid and l.b.ifname == parent:
                    return l.a
        return None

    # ───────────────────────────── Serialization ─────────────────────────────

    def export_device_config(self, uid: str) -> dict:
        dev = self.devices[uid]
        return {
            "kind": dev.kind,
            "host": {
                "gateway": dev.host_gateway,
                "dns": dev.host_dns,
            },
            "interfaces": {
                ifn: {
                    "admin_up": i.admin_up,
                    "mac": i.mac,
                    "ip": i.ip,
                    "mask": i.mask,
                    "mode": i.mode,
                    "access_vlan": i.access_vlan,
                    "trunk_vlans": sorted(list(i.trunk_vlans)),
                    "channel_group": i.channel_group,
                    "channel_mode": i.channel_mode,
                    "acl_in": i.acl_in,
                    "acl_out": i.acl_out,
                }
                for ifn, i in dev.interfaces.items()
            },
            "vlans": dev.vlans,
            "static_routes": dev.static_routes,
            "ospf": {
                "enabled": dev.ospf.enabled,
                "process_id": dev.ospf.process_id,
                "router_id": dev.ospf.router_id,
                "networks": dev.ospf.networks,
            },
            "acls": {
                name: [
                    {"action": r.action, "protocol": r.protocol, "src": r.src, "dst": r.dst, "hits": r.hits}
                    for r in rules
                ]
                for name, rules in dev.acls.items()
            },
        }

    def import_device_config(self, uid: str, cfg: dict):
        if uid not in self.devices:
            return
        dev = self.devices[uid]
        if isinstance(cfg, dict):
            if cfg.get("kind") in ("router", "switch", "host"):
                dev.kind = cfg["kind"]

            host = cfg.get("host")
            if isinstance(host, dict):
                gw = host.get("gateway")
                dev.host_gateway = str(gw) if gw else None
                dns = host.get("dns")
                dev.host_dns = str(dns) if dns else None

            interfaces = cfg.get("interfaces", {})
            if isinstance(interfaces, dict):
                for ifn, icfg in interfaces.items():
                    if not isinstance(icfg, dict):
                        continue
                    itf = self.ensure_interface(uid, ifn)
                    itf.admin_up = bool(icfg.get("admin_up", itf.admin_up))
                    mac = icfg.get("mac")
                    itf.mac = str(mac) if mac else itf.mac
                    itf.ip = icfg.get("ip")
                    itf.mask = icfg.get("mask")
                    itf.mode = icfg.get("mode", itf.mode)
                    itf.access_vlan = int(icfg.get("access_vlan", itf.access_vlan))
                    tv = icfg.get("trunk_vlans")
                    if isinstance(tv, list) and tv:
                        itf.trunk_vlans = {int(v) for v in tv}
                    cg = icfg.get("channel_group")
                    itf.channel_group = int(cg) if cg is not None else None
                    cm = icfg.get("channel_mode")
                    itf.channel_mode = str(cm) if cm else None
                    itf.acl_in = icfg.get("acl_in")
                    itf.acl_out = icfg.get("acl_out")

            vlans = cfg.get("vlans")
            if isinstance(vlans, dict) and vlans:
                dev.vlans = {int(k): str(v) for k, v in vlans.items()}

            sr = cfg.get("static_routes")
            if isinstance(sr, list):
                out = []
                for item in sr:
                    if isinstance(item, (list, tuple)) and len(item) >= 2:
                        prefix, mask = str(item[0]), str(item[1])
                        nh = str(item[2]) if len(item) >= 3 and item[2] is not None else None
                        out.append((prefix, mask, nh))
                dev.static_routes = out

            ospf = cfg.get("ospf")
            if isinstance(ospf, dict):
                dev.ospf.enabled = bool(ospf.get("enabled", dev.ospf.enabled))
                dev.ospf.process_id = str(ospf.get("process_id", dev.ospf.process_id))
                rid = ospf.get("router_id")
                dev.ospf.router_id = str(rid) if rid else None
                nets = ospf.get("networks")
                if isinstance(nets, list):
                    clean = []
                    for t in nets:
                        if isinstance(t, (list, tuple)) and len(t) >= 3:
                            clean.append((str(t[0]), str(t[1]), str(t[2])))
                    dev.ospf.networks = clean

            acls = cfg.get("acls")
            if isinstance(acls, dict):
                dev.acls.clear()
                for name, rules in acls.items():
                    if not isinstance(rules, list):
                        continue
                    parsed: List[ACLRule] = []
                    for r in rules:
                        if not isinstance(r, dict):
                            continue
                        parsed.append(
                            ACLRule(
                                action=str(r.get("action", "deny")),
                                protocol=str(r.get("protocol", "ip")),
                                src=str(r.get("src", "any")),
                                dst=str(r.get("dst", "any")),
                                hits=int(r.get("hits", 0)),
                            )
                        )
                    dev.acls[str(name)] = parsed

        self.recompute()
        self._sync_if_counter(uid)

    # ───────────────────────────── Control plane computations ─────────────────────────────

    def recompute(self):
        self._compute_ospf_neighbors()
        self._compute_routes()

    def _effective_router_id(self, uid: str) -> Optional[str]:
        dev = self.devices.get(uid)
        if dev is None:
            return None

        if dev.ospf.router_id:
            return dev.ospf.router_id

        # Deterministic fallback: highest loopback IP (up), else highest active interface IP.
        loopbacks: List[ipaddress.IPv4Address] = []
        actives: List[ipaddress.IPv4Address] = []
        for ifn, itf in dev.interfaces.items():
            if not self._is_interface_up(uid, ifn) or not itf.has_ip():
                continue
            try:
                ip_addr = ipaddress.IPv4Address(itf.ip)
            except Exception:
                continue
            if ifn.lower().startswith("lo"):
                loopbacks.append(ip_addr)
            else:
                actives.append(ip_addr)

        if loopbacks:
            return str(max(loopbacks))
        if actives:
            return str(max(actives))
        return None

    def _compute_ospf_neighbors(self):
        self._ospf_neighbors = {uid: [] for uid in self.devices}

        routers = [d for d in self.devices.values() if d.kind == "router" and d.ospf.enabled]
        rid_map: Dict[str, Optional[str]] = {r.uid: self._effective_router_id(r.uid) for r in routers}

        # Determine adjacency on shared L2 segment (including direct router-router link).
        for r in routers:
            r_rid = rid_map.get(r.uid)
            if not r_rid:
                continue
            for ifn, itf in r.interfaces.items():
                if not self._is_interface_up(r.uid, ifn) or not itf.has_ip():
                    continue
                if not self._if_ospf_enabled(r.uid, itf):
                    continue
                vlan = self._interface_vlan(r.uid, ifn)
                if vlan is None:
                    continue
                peers = self._routers_on_same_vlan(r.uid, vlan)
                for p_uid, p_if in peers:
                    if p_uid == r.uid:
                        continue
                    p_rid = rid_map.get(p_uid)
                    if not p_rid or p_rid == r_rid:
                        continue
                    self._ospf_neighbors[r.uid].append((p_rid, ifn, "FULL"))

        # De-dup by (neighbor_rid, local_if)
        for uid in self._ospf_neighbors:
            seen = set()
            unique: List[Tuple[str, str, str]] = []
            for nb_rid, lif, st in self._ospf_neighbors[uid]:
                key = (nb_rid, lif)
                if key in seen:
                    continue
                seen.add(key)
                unique.append((nb_rid, lif, st))
            self._ospf_neighbors[uid] = unique

    def _wildcard_to_netmask(self, wildcard: str) -> str:
        wc = ipaddress.IPv4Address(wildcard)
        nm = ipaddress.IPv4Address((~int(wc)) & 0xFFFFFFFF)
        return str(nm)

    def _if_ospf_enabled(self, uid: str, itf: Interface) -> bool:
        dev = self.devices[uid]
        if not dev.ospf.enabled:
            return False
        if not itf.has_ip():
            return False
        ipi = itf.ip_interface()
        if ipi is None:
            return False
        ip = ipi.ip
        for net_ip, wildcard, area in dev.ospf.networks:
            try:
                nm = self._wildcard_to_netmask(wildcard)
                net = ipaddress.IPv4Network(f"{net_ip}/{nm}", strict=False)
            except Exception:
                continue
            if ip in net:
                return True
        return False

    def _compute_routes(self):
        routes: Dict[str, List[Route]] = {}
        for uid, dev in self.devices.items():
            rts: List[Route] = []

            # Connected
            for ifn, itf in dev.interfaces.items():
                if not self._is_interface_up(uid, ifn) or not itf.has_ip():
                    continue
                ipi = itf.ip_interface()
                if ipi is None:
                    continue
                rts.append(Route(prefix=ipi.network, next_hop=None, out_if=ifn, protocol="C", metric=0))

            # Static
            for prefix, mask, nh in dev.static_routes:
                try:
                    net = ipaddress.IPv4Network(f"{prefix}/{mask}", strict=False)
                except Exception:
                    continue
                out_if = self._out_if_for_next_hop(uid, nh) if nh else self._out_if_for_connected(uid, net)
                if out_if:
                    rts.append(Route(prefix=net, next_hop=nh, out_if=out_if, protocol="S", metric=1))

            routes[uid] = rts

        # OSPF: build graph of routers and advertised networks keyed by router-id
        ospf_routers = [d for d in self.devices.values() if d.kind == "router" and d.ospf.enabled]
        rid_map: Dict[str, Optional[str]] = {r.uid: self._effective_router_id(r.uid) for r in ospf_routers}
        rid_to_uid: Dict[str, str] = {rid: uid for uid, rid in rid_map.items() if rid}

        # Only consider routers with a valid router-id
        valid_rids = {uid: rid for uid, rid in rid_map.items() if rid}
        graph: Dict[str, Set[str]] = {rid: set() for rid in valid_rids.values()}

        for r in ospf_routers:
            r_rid = valid_rids.get(r.uid)
            if not r_rid:
                continue
            for nb_rid, lif, st in self._ospf_neighbors.get(r.uid, []):
                if nb_rid in graph:
                    graph[r_rid].add(nb_rid)

        # advertised networks per router-id
        adv: Dict[str, Set[ipaddress.IPv4Network]] = {rid: set() for rid in valid_rids.values()}
        for r in ospf_routers:
            r_rid = valid_rids.get(r.uid)
            if not r_rid:
                continue
            for ifn, itf in r.interfaces.items():
                if not self._is_interface_up(r.uid, ifn) or not itf.has_ip():
                    continue
                if not self._if_ospf_enabled(r.uid, itf):
                    continue
                ipi = itf.ip_interface()
                if ipi:
                    adv[r_rid].add(ipi.network)

        # For each router-id, shortest paths and install routes
        for src_rid in graph:
            src_uid = rid_to_uid.get(src_rid)
            if not src_uid:
                continue

            dist = {src_rid: 0}
            prev = {src_rid: None}
            q = [src_rid]
            while q:
                cur = q.pop(0)
                for nb in sorted(graph[cur]):
                    if nb not in dist:
                        dist[nb] = dist[cur] + 1
                        prev[nb] = cur
                        q.append(nb)

            def first_hop(dst_rid: str) -> Optional[str]:
                if dst_rid == src_rid:
                    return None
                cur = dst_rid
                while prev.get(cur) is not None and prev[cur] != src_rid:
                    cur = prev[cur]
                if prev.get(cur) == src_rid:
                    return cur
                return None

            for dst_rid, nets in adv.items():
                if dst_rid == src_rid or dst_rid not in dist:
                    continue
                hop_rid = first_hop(dst_rid)
                if hop_rid is None:
                    continue

                hop_uid = rid_to_uid.get(hop_rid)
                if not hop_uid:
                    continue

                nh_ip, out_if = self._next_hop_ip_and_out_if(src_uid, hop_uid)
                if not out_if:
                    continue

                for net in nets:
                    if any(r.prefix == net and r.protocol == "C" for r in routes[src_uid]):
                        continue
                    routes[src_uid].append(
                        Route(prefix=net, next_hop=nh_ip, out_if=out_if, protocol="O", metric=dist[dst_rid])
                    )

        # Deterministic ordering: longest prefix first, then protocol
        for uid in routes:
            routes[uid].sort(key=lambda r: (-r.prefix.prefixlen, r.protocol, str(r.prefix)))

        self._routes = routes

    def routes_for(self, uid: str) -> List[Route]:
        return list(self._routes.get(uid, []))

    def ospf_neighbors_for(self, uid: str) -> List[Tuple[str, str, str]]:
        return list(self._ospf_neighbors.get(uid, []))

    # ───────────────────────────── L2 helpers ─────────────────────────────

    def _interface_vlan(self, uid: str, ifname: str) -> Optional[int]:
        dev = self.devices[uid]
        itf = dev.interfaces.get(ifname)
        if itf is None:
            return None
        if not self._is_interface_up(uid, ifname):
            return None

        # Router-on-a-stick: subinterfaces are bound to a VLAN by their suffix.
        _parent, sub_vlan = self._split_subinterface(ifname)
        if sub_vlan is not None:
            return int(sub_vlan)

        # routed interfaces still live on some L2 (for ARP) if connected to switchport access/trunk.
        if itf.mode == "access":
            return int(itf.access_vlan)
        if itf.mode == "trunk":
            # for adjacency discovery we treat per-vlan; caller should decide which vlan.
            return 1
        # routed: if directly connected to another routed port, treat as vlan 0 domain; if connected via switch access/trunk, infer from other side.
        other = self.other_end(uid, ifname)
        if other is None:
            return None
        odev = self.devices[other.device]
        oif = odev.interfaces.get(other.ifname)
        if oif is None:
            return None
        if oif.mode == "access":
            return int(oif.access_vlan)
        if oif.mode == "trunk":
            return 1
        return self._segment_id_for_routed_link(uid, ifname)

    def _link_allows_vlan(self, lid: str, vlan: int) -> bool:
        l = self.links[lid]
        for end in (l.a, l.b):
            dev = self.devices[end.device]
            itf = dev.interfaces[end.ifname]
            if not self._is_interface_up(end.device, end.ifname):
                return False
            if itf.mode == "access" and itf.access_vlan != vlan:
                return False
            if itf.mode == "trunk" and vlan not in itf.trunk_vlans:
                return False
        return True

    def _stp_blocked_switch_ports(self, vlan: int) -> Dict[Tuple[str, str], bool]:
        # Simplified STP: compute a single spanning tree over switches for this VLAN.
        switches = sorted([d.uid for d in self.devices.values() if d.kind == "switch"])
        if not switches:
            return {}
        root = switches[0]

        # Build switch-switch adjacency edges that carry vlan.
        # If links are bundled into an EtherChannel (matching channel-group on both ends),
        # treat the bundle as a single logical edge for STP to avoid blocking member links.
        edge_members: Dict[str, Dict[str, List[str]]] = {}  # edge_id -> {sw_uid: [ifnames...]}
        edge_endpoints: Dict[str, Tuple[str, str]] = {}  # edge_id -> (sw_lo, sw_hi)

        def add_edge_member(edge_id: str, sw: str, ifname: str, sw_lo: str, sw_hi: str) -> None:
            edge_members.setdefault(edge_id, {}).setdefault(sw, []).append(ifname)
            edge_endpoints[edge_id] = (sw_lo, sw_hi)

        # First pass: gather eligible links and group by port-channel when applicable.
        po_groups: Dict[Tuple[int, str, str], List[Tuple[str, str, str, str]]] = {}
        solo_links: List[Tuple[str, str, str, str, str]] = []  # (lid, sw1, if1, sw2, if2)

        for lid, l in self.links.items():
            a, b = l.a, l.b
            da = self.devices[a.device]
            db = self.devices[b.device]
            if da.kind != "switch" or db.kind != "switch":
                continue
            if not self._link_allows_vlan(lid, vlan):
                continue

            ia = da.interfaces.get(a.ifname)
            ib = db.interfaces.get(b.ifname)
            cga = ia.channel_group if ia else None
            cgb = ib.channel_group if ib else None
            if cga is not None and cgb is not None and int(cga) == int(cgb):
                sw_lo, sw_hi = (a.device, b.device) if a.device < b.device else (b.device, a.device)
                po_groups.setdefault((int(cga), sw_lo, sw_hi), []).append((a.device, a.ifname, b.device, b.ifname))
            else:
                solo_links.append((lid, a.device, a.ifname, b.device, b.ifname))

        # Materialize port-channel edges
        for (gid, sw_lo, sw_hi), members in po_groups.items():
            edge_id = f"Po{gid}:{sw_lo}-{sw_hi}"
            for s1, if1, s2, if2 in members:
                add_edge_member(edge_id, s1, if1, sw_lo, sw_hi)
                add_edge_member(edge_id, s2, if2, sw_lo, sw_hi)

        # Materialize non-bundled edges
        for lid, s1, if1, s2, if2 in solo_links:
            sw_lo, sw_hi = (s1, s2) if s1 < s2 else (s2, s1)
            add_edge_member(lid, s1, if1, sw_lo, sw_hi)
            add_edge_member(lid, s2, if2, sw_lo, sw_hi)

        # BFS tree from root over logical edges
        adj: Dict[str, List[Tuple[str, str, str]]] = {sw: [] for sw in switches}
        for edge_id, by_sw in edge_members.items():
            sw_lo, sw_hi = edge_endpoints[edge_id]
            if sw_lo not in by_sw or sw_hi not in by_sw:
                continue
            lo_port = sorted(by_sw[sw_lo])[0]
            hi_port = sorted(by_sw[sw_hi])[0]
            adj[sw_lo].append((sw_hi, lo_port, edge_id))
            adj[sw_hi].append((sw_lo, hi_port, edge_id))

        parent: Dict[str, Optional[str]] = {root: None}
        tree_links: Set[str] = set()
        q = [root]
        while q:
            cur = q.pop(0)
            for nb, local_if, lid in sorted(adj.get(cur, []), key=lambda t: (t[0], t[2], t[1])):
                if nb not in parent:
                    parent[nb] = cur
                    tree_links.add(lid)
                    q.append(nb)

        blocked: Dict[Tuple[str, str], bool] = {}
        for edge_id, (sw_lo, sw_hi) in edge_endpoints.items():
            if edge_id in tree_links:
                continue
            # deterministically block the higher-uid side of the logical edge
            for ifn in edge_members.get(edge_id, {}).get(sw_hi, []):
                blocked[(sw_hi, ifn)] = True
        return blocked

    def _l2_reachable(self, src_uid: str, src_if: str, dst_uid: str, dst_if: str, vlan: int) -> bool:
        # Graph traversal across links that allow this VLAN, respecting STP blocks on switches.
        blocked = self._stp_blocked_switch_ports(vlan)

        start = (src_uid, self._physical_ifname(src_uid, src_if))
        goal = (dst_uid, self._physical_ifname(dst_uid, dst_if))
        seen = {start}
        q = [start]

        def can_transit(node: Tuple[str, str]) -> bool:
            duid, dif = node
            dev = self.devices[duid]
            itf = dev.interfaces.get(dif)
            if itf is None or not self._is_interface_up(duid, dif):
                return False
            if dev.kind == "switch" and blocked.get((duid, dif), False):
                return False
            if itf.mode == "access" and itf.access_vlan != vlan:
                return False
            if itf.mode == "trunk" and vlan not in itf.trunk_vlans:
                return False
            return True

        while q:
            cur = q.pop(0)
            if cur == goal:
                return True
            if not can_transit(cur):
                continue
            duid, dif = cur
            # traverse the physical link to the other end
            other = self.other_end(duid, dif)
            if other is not None:
                nxt = (other.device, other.ifname)
                if nxt not in seen:
                    # vlan allowed on that physical link?
                    lid = self.link_for_end(duid, dif)
                    if lid and self._link_allows_vlan(lid, vlan):
                        seen.add(nxt)
                        q.append(nxt)
            # if it's a switch, it can transit between its ports (bridging) within VLAN
            if self.devices[duid].kind == "switch":
                for ifn2, itf2 in self.devices[duid].interfaces.items():
                    nxt = (duid, ifn2)
                    if nxt in seen:
                        continue
                    if not can_transit(nxt):
                        continue
                    # must be same switch
                    seen.add(nxt)
                    q.append(nxt)

        return False

    def _l2_path(self, src_uid: str, src_if: str, dst_uid: str, dst_if: str, vlan: int) -> Optional[List[Tuple[str, str]]]:
        """Return a deterministic L2 path (list of (uid, ifname)) if reachable."""
        blocked = self._stp_blocked_switch_ports(vlan)
        start = (src_uid, self._physical_ifname(src_uid, src_if))
        goal = (dst_uid, self._physical_ifname(dst_uid, dst_if))

        def can_transit(node: Tuple[str, str]) -> bool:
            duid, dif = node
            dev = self.devices[duid]
            itf = dev.interfaces.get(dif)
            if itf is None or not self._is_interface_up(duid, dif):
                return False
            if dev.kind == "switch" and blocked.get((duid, dif), False):
                return False
            if itf.mode == "access" and itf.access_vlan != vlan:
                return False
            if itf.mode == "trunk" and vlan not in itf.trunk_vlans:
                return False
            return True

        prev: Dict[Tuple[str, str], Optional[Tuple[str, str]]] = {start: None}
        q = [start]
        while q:
            cur = q.pop(0)
            if cur == goal:
                # reconstruct
                out: List[Tuple[str, str]] = []
                n: Optional[Tuple[str, str]] = cur
                while n is not None:
                    out.append(n)
                    n = prev.get(n)
                out.reverse()
                return out

            if not can_transit(cur):
                continue

            duid, dif = cur
            # physical link
            other = self.other_end(duid, dif)
            if other is not None:
                nxt = (other.device, other.ifname)
                if nxt not in prev:
                    lid = self.link_for_end(duid, dif)
                    if lid and self._link_allows_vlan(lid, vlan):
                        prev[nxt] = cur
                        q.append(nxt)

            # intra-switch bridging
            if self.devices[duid].kind == "switch":
                for ifn2 in sorted(self.devices[duid].interfaces.keys()):
                    nxt = (duid, ifn2)
                    if nxt in prev:
                        continue
                    if not can_transit(nxt):
                        continue
                    prev[nxt] = cur
                    q.append(nxt)

        return None

    def _learn_mac_along_path(self, path: List[Tuple[str, str]], vlan: int, src_mac: str, dst_mac: str):
        """Update switch MAC tables deterministically based on a single exchange."""

        def learn_on_ingress(path_nodes: List[Tuple[str, str]], mac: str):
            for i in range(1, len(path_nodes)):
                prev_uid, _prev_if = path_nodes[i - 1]
                uid, ifname = path_nodes[i]
                if uid == prev_uid:
                    continue
                dev = self.devices.get(uid)
                if not dev or dev.kind != "switch":
                    continue
                dev.mac_table.setdefault(vlan, {})[mac] = ifname

        learn_on_ingress(path, src_mac)
        learn_on_ingress(list(reversed(path)), dst_mac)

    def _resolve_arp_and_learn(self, src_uid: str, out_if: str, dst_uid: str, dst_if: str, vlan: int, dst_ip: str) -> Tuple[bool, Optional[str]]:
        """Resolve next-hop MAC deterministically and update ARP+MAC tables."""
        path = self._l2_path(src_uid, out_if, dst_uid, dst_if, vlan)
        if not path:
            return False, None

        sdev = self.devices[src_uid]
        ddev = self.devices[dst_uid]
        sitf = sdev.interfaces[out_if]
        ditf = ddev.interfaces[dst_if]

        # Populate ARP on sender
        sdev.arp_table.setdefault(vlan, {})[dst_ip] = ditf.mac

        # Learn MACs on switches along the path
        self._learn_mac_along_path(path, vlan=vlan, src_mac=sitf.mac, dst_mac=ditf.mac)
        return True, ditf.mac

    def _routers_on_same_vlan(self, uid: str, vlan: int) -> List[Tuple[str, str]]:
        out = []
        for r in self.devices.values():
            if r.kind != "router" or not r.ospf.enabled:
                continue
            for ifn, itf in r.interfaces.items():
                if not self._is_interface_up(r.uid, ifn) or not itf.has_ip():
                    continue
                if not self._if_ospf_enabled(r.uid, itf):
                    continue
                rv = self._vlan_for_interface(r.uid, ifn)
                if rv == vlan:
                    out.append((r.uid, ifn))
        return out

    def _vlan_for_interface(self, uid: str, ifname: str) -> Optional[int]:
        dev = self.devices[uid]
        itf = dev.interfaces.get(ifname)
        if itf is None:
            return None

        # Router-on-a-stick: subinterfaces are bound to a VLAN by their suffix.
        _parent, sub_vlan = self._split_subinterface(ifname)
        if sub_vlan is not None:
            return int(sub_vlan)

        if itf.mode == "access":
            return int(itf.access_vlan)
        if itf.mode == "trunk":
            # Caller decides which VLAN to forward; use 1 as default.
            return 1
        # routed connected to switch access uses other side
        other = self.other_end(uid, ifname)
        if other is None:
            return 0
        odev = self.devices[other.device]
        oif = odev.interfaces.get(other.ifname)
        if oif is None:
            return 0
        if oif.mode == "access":
            return int(oif.access_vlan)
        if oif.mode == "trunk":
            return 1
        # routed-to-routed (or routed-to-host-routed): use per-link segment id
        return self._segment_id_for_routed_link(uid, ifname)

    # ───────────────────────────── Routing helpers ─────────────────────────────

    def _out_if_for_connected(self, uid: str, net: ipaddress.IPv4Network) -> Optional[str]:
        dev = self.devices[uid]
        for ifn, itf in dev.interfaces.items():
            if not self._is_interface_up(uid, ifn) or not itf.has_ip():
                continue
            ipi = itf.ip_interface()
            if ipi and ipi.network == net:
                return ifn
        return None

    def _out_if_for_next_hop(self, uid: str, next_hop: Optional[str]) -> Optional[str]:
        if not next_hop:
            return None
        nh = ipaddress.IPv4Address(next_hop)
        dev = self.devices[uid]
        for ifn, itf in dev.interfaces.items():
            if not self._is_interface_up(uid, ifn) or not itf.has_ip():
                continue
            ipi = itf.ip_interface()
            if ipi and nh in ipi.network:
                return ifn
        return None

    def lookup_route(self, uid: str, dst_ip: str) -> Optional[Route]:
        try:
            dip = ipaddress.IPv4Address(dst_ip)
        except Exception:
            return None
        best = None
        for r in self._routes.get(uid, []):
            if dip in r.prefix:
                best = r
                break
        return best

    def _next_hop_ip_and_out_if(self, src_uid: str, hop_uid: str) -> Tuple[Optional[str], Optional[str]]:
        # Find any shared VLAN segment with IPs between src and hop.
        src = self.devices[src_uid]
        hop = self.devices[hop_uid]
        for s_if, s_itf in src.interfaces.items():
            if not s_itf.admin_up or not s_itf.has_ip():
                continue
            svlan = self._vlan_for_interface(src_uid, s_if)
            for h_if, h_itf in hop.interfaces.items():
                if not h_itf.admin_up or not h_itf.has_ip():
                    continue
                hvlan = self._vlan_for_interface(hop_uid, h_if)
                if svlan == hvlan:
                    # next hop is hop's interface IP
                    if self._l2_reachable(src_uid, s_if, hop_uid, h_if, svlan):
                        return h_itf.ip, s_if
        return None, None

    # ───────────────────────────── ACL enforcement ─────────────────────────────

    def _acl_check(self, uid: str, ifname: str, direction: str, protocol: str, src_ip: str, dst_ip: str) -> Tuple[bool, Optional[str]]:
        dev = self.devices[uid]
        itf = dev.interfaces.get(ifname)
        if itf is None:
            return True, None
        acl_name = itf.acl_in if direction == "in" else itf.acl_out
        if not acl_name:
            return True, None
        rules = dev.acls.get(acl_name, [])
        for r in rules:
            if r.matches(protocol, src_ip, dst_ip):
                r.hits += 1
                return (r.action == "permit"), acl_name
        return False, acl_name

    # ───────────────────────────── Data plane: ping ─────────────────────────────

    def ping(self, src_uid: str, dst_ip: str) -> List[str]:
        src_uid = _norm_uid(src_uid)
        if src_uid not in self.devices:
            return ["% Unknown device"]
        try:
            ipaddress.IPv4Address(dst_ip)
        except Exception:
            return ["% Invalid IP address"]

        # If destination is one of our interface IPs, succeed if local can reach it.
        dst_owner = self._find_ip_owner(dst_ip)
        if dst_owner is None:
            # still route toward it; will fail with unreachable
            pass

        # choose a source interface with IP
        src_if = self._pick_source_interface(src_uid)
        if not src_if:
            return ["% No source interface with IP"]

        src_itf = self.devices[src_uid].interfaces[src_if]
        src_ip = src_itf.ip

        # hop-by-hop routing among routers
        cur_uid = src_uid
        ttl = 32
        visited = []

        while ttl > 0:
            ttl -= 1
            visited.append(cur_uid)
            # if current device owns dst
            owner = self._find_ip_owner(dst_ip)
            if owner and owner[0] == cur_uid:
                return ["!!!!!", f"Success rate is 100 percent (1/1), round-trip min/avg/max = 1/1/1 ms"]

            route = self.lookup_route(cur_uid, dst_ip)
            if route is None:
                return ["% Destination unreachable"]

            out_if = route.out_if
            out_itf = self.devices[cur_uid].interfaces.get(out_if)
            if out_itf is None or not self._is_interface_up(cur_uid, out_if):
                return ["% Interface administratively down"]

            # Outbound ACL on the egress interface (evaluated per-hop).
            ok, acl = self._acl_check(cur_uid, out_if, "out", "icmp", src_ip, dst_ip)
            if not ok:
                return ["% Administratively prohibited (ACL)"]

            # Determine next hop IP
            nh_ip = route.next_hop or dst_ip

            # Find next hop device/interface on same connected segment
            nh_owner = self._find_ip_owner(nh_ip)
            if nh_owner is None:
                return ["% Destination unreachable"]
            nh_uid, nh_if = nh_owner

            vlan = self._vlan_for_interface(cur_uid, out_if)
            if vlan is None:
                vlan = 0
            _nh_parent, nh_vlan = self._split_subinterface(nh_if)
            if nh_vlan is not None:
                vlan = int(nh_vlan)

            if not self._l2_reachable(cur_uid, out_if, nh_uid, nh_if, vlan):
                return ["% Destination unreachable"]

            # ARP/MAC learning (deterministic, simplified)
            self._resolve_arp_and_learn(cur_uid, out_if, nh_uid, nh_if, vlan, nh_ip)

            # Inbound ACL on next hop interface
            ok, acl = self._acl_check(nh_uid, nh_if, "in", "icmp", src_ip, dst_ip)
            if not ok:
                return ["% Administratively prohibited (ACL)"]

            cur_uid = nh_uid

        return ["% Time to live exceeded"]

    def traceroute(self, src_uid: str, dst_ip: str) -> List[str]:
        src_uid = _norm_uid(src_uid)
        if src_uid not in self.devices:
            return ["% Unknown device"]
        try:
            ipaddress.IPv4Address(dst_ip)
        except Exception:
            return ["% Invalid IP address"]

        src_if = self._pick_source_interface(src_uid)
        if not src_if:
            return ["% No source interface with IP"]

        src_itf = self.devices[src_uid].interfaces[src_if]
        src_ip = src_itf.ip
        ok, _acl = self._acl_check(src_uid, src_if, "out", "icmp", src_ip, dst_ip)
        if not ok:
            return ["% Administratively prohibited (ACL)"]

        lines = [f"Tracing the route to {dst_ip}", ""]
        cur_uid = src_uid
        ttl = 32
        hop = 1
        while ttl > 0:
            ttl -= 1
            owner = self._find_ip_owner(dst_ip)
            if owner and owner[0] == cur_uid:
                lines.append(f"{hop:<2} {dst_ip} 1 ms")
                return lines

            route = self.lookup_route(cur_uid, dst_ip)
            if route is None:
                lines.append(f"{hop:<2} * * *")
                return lines

            out_if = route.out_if
            out_itf = self.devices[cur_uid].interfaces.get(out_if)
            if out_itf is None or not self._is_interface_up(cur_uid, out_if):
                lines.append(f"{hop:<2} * * *")
                return lines

            nh_ip = route.next_hop or dst_ip
            nh_owner = self._find_ip_owner(nh_ip)
            if nh_owner is None:
                lines.append(f"{hop:<2} * * *")
                return lines
            nh_uid, nh_if = nh_owner

            vlan = self._vlan_for_interface(cur_uid, out_if) or 0
            _nh_parent, nh_vlan = self._split_subinterface(nh_if)
            if nh_vlan is not None:
                vlan = int(nh_vlan)
            if not self._l2_reachable(cur_uid, out_if, nh_uid, nh_if, vlan):
                lines.append(f"{hop:<2} * * *")
                return lines

            self._resolve_arp_and_learn(cur_uid, out_if, nh_uid, nh_if, vlan, nh_ip)
            lines.append(f"{hop:<2} {nh_ip} 1 ms")
            hop += 1

            ok, _acl = self._acl_check(nh_uid, nh_if, "in", "icmp", src_ip, dst_ip)
            if not ok:
                lines.append(f"{hop:<2} !H")
                return lines

            cur_uid = nh_uid

        lines.append(f"{hop:<2} * * *")
        return lines

    def _pick_source_interface(self, uid: str) -> Optional[str]:
        dev = self.devices[uid]
        for ifn in sorted(dev.interfaces.keys()):
            itf = dev.interfaces[ifn]
            if self._is_interface_up(uid, ifn) and itf.has_ip():
                return ifn
        return None

    def _find_ip_owner(self, ip: str) -> Optional[Tuple[str, str]]:
        for uid, dev in self.devices.items():
            for ifn, itf in dev.interfaces.items():
                if itf.has_ip() and itf.ip == ip and self._is_interface_up(uid, ifn):
                    return uid, ifn
        return None

    # ───────────────────────────── Show helpers ─────────────────────────────

    def show_ip_interface_brief(self, uid: str) -> str:
        dev = self.devices[uid]
        lines = ["Interface              IP-Address      OK? Method Status                Protocol"]
        for ifn in sorted(dev.interfaces.keys()):
            itf = dev.interfaces[ifn]
            ip = itf.ip if itf.ip else "unassigned"
            ok = "YES" if itf.ip else "NO"
            up = self._is_interface_up(uid, ifn)
            status = "up" if up else "administratively down"
            proto = "up" if up else "down"
            lines.append(f"{ifn:<22} {ip:<15} {ok:<3} manual {status:<20} {proto}")
        return "\n".join(lines)

    def show_ip_route(self, uid: str) -> str:
        dev = self.devices[uid]
        lines = [f"{dev.uid}# show ip route", "Codes: C - connected, S - static, O - ospf", ""]
        for r in self.routes_for(uid):
            nh = r.next_hop or "directly connected"
            lines.append(f"{r.protocol} {str(r.prefix):<18} [{r.metric}/0] via {nh}, {r.out_if}")
        return "\n".join(lines)

    def show_ospf_neighbor(self, uid: str) -> str:
        lines = ["Neighbor ID     State           Interface"]
        for nb_rid, lif, st in self.ospf_neighbors_for(uid):
            lines.append(f"{nb_rid:<15} {st:<15} {lif}")
        return "\n".join(lines)

    def show_vlan_brief(self, uid: str) -> str:
        dev = self.devices[uid]
        if dev.kind != "switch":
            return "% Command only valid on switches"
        lines = ["VLAN Name                             Status    Ports"]
        for vid in sorted(dev.vlans.keys()):
            name = dev.vlans[vid]
            ports = []
            for ifn, itf in dev.interfaces.items():
                if itf.mode == "access" and itf.access_vlan == vid:
                    ports.append(ifn)
            lines.append(f"{vid:<4} {name:<32} active    {', '.join(sorted(ports))}")
        return "\n".join(lines)

    def show_interfaces_trunk(self, uid: str) -> str:
        dev = self.devices[uid]
        if dev.kind != "switch":
            return "% Command only valid on switches"
        lines = ["Port        Mode         Encapsulation  Status        Native vlan", ""]
        for ifn in sorted(dev.interfaces.keys()):
            itf = dev.interfaces[ifn]
            if itf.mode != "trunk":
                continue
            status = "trunking" if itf.admin_up else "disabled"
            lines.append(f"{ifn:<10} on           802.1q          {status:<12} 1")
            lines.append(f"  Vlans allowed on trunk: {','.join(str(v) for v in sorted(itf.trunk_vlans))}")
        return "\n".join(lines)

    def show_mac_address_table(self, uid: str) -> str:
        dev = self.devices[uid]
        if dev.kind != "switch":
            return "% Command only valid on switches"
        lines = ["          Mac Address Table", "-------------------------------------------", "Vlan    Mac Address       Type        Ports"]
        for vlan, table in sorted(dev.mac_table.items()):
            for mac, port in sorted(table.items()):
                lines.append(f"{vlan:<7} {mac:<17} DYNAMIC     {port}")
        return "\n".join(lines)

    def show_spanning_tree(self, uid: str, vlan: int = 1) -> str:
        dev = self.devices[uid]
        if dev.kind != "switch":
            return "% Command only valid on switches"
        dev.ensure_vlan(vlan)
        blocked = self._stp_blocked_switch_ports(vlan)
        switches = sorted([d.uid for d in self.devices.values() if d.kind == "switch"])
        root = switches[0] if switches else dev.uid

        lines = [
            f"VLAN{vlan:04d}",
            "  Spanning tree enabled protocol ieee",
            f"  Root ID    Priority    32769",
            f"             Address     {_mac_from_text(root)}",
            f"             This bridge is {'the root' if dev.uid == root else 'not the root'}",
            "",
            "Interface           Role Sts Cost      Prio.Nbr Type",
        ]

        for ifn in sorted(dev.interfaces.keys()):
            itf = dev.interfaces[ifn]
            if not itf.admin_up:
                continue
            # Only consider ports that can carry the VLAN.
            if itf.mode == "access" and itf.access_vlan != vlan:
                continue
            if itf.mode == "trunk" and vlan not in itf.trunk_vlans:
                continue
            if blocked.get((uid, ifn), False):
                role = "Altn"
                sts = "BLK"
            else:
                role = "Desg"
                sts = "FWD"
            lines.append(f"{ifn:<19} {role:<4} {sts:<3} 19       128.1    P2p")

        return "\n".join(lines)

    def show_ip_protocols(self, uid: str) -> str:
        dev = self.devices[uid]
        lines = ["Routing Protocol is \"static\"" if dev.static_routes else "No static routes configured"]
        if dev.ospf.enabled:
            lines.append(f"Routing Protocol is \"ospf {dev.ospf.process_id}\"")
            rid = self._effective_router_id(uid)
            if rid:
                lines.append(f"  Router ID {rid}")
            if dev.ospf.networks:
                lines.append("  Routing for Networks:")
                for net_ip, wildcard, area in dev.ospf.networks:
                    lines.append(f"    {net_ip} {wildcard} area {area}")
        return "\n".join(lines)

    def show_etherchannel_summary(self, uid: str) -> str:
        dev = self.devices[uid]
        if dev.kind != "switch":
            return "% Command only valid on switches"
        groups: Dict[int, List[str]] = {}
        for ifn, itf in dev.interfaces.items():
            if itf.channel_group is None:
                continue
            groups.setdefault(int(itf.channel_group), []).append(ifn)
        lines = [
            "Group  Port-channel  Protocol    Ports",
        ]
        if not groups:
            lines.append("% No EtherChannels configured")
            return "\n".join(lines)
        for g in sorted(groups.keys()):
            ports = " ".join(sorted(groups[g]))
            lines.append(f"{g:<6} Po{g:<12} LACP        {ports}")
        return "\n".join(lines)

    def show_access_lists(self, uid: str) -> str:
        dev = self.devices[uid]
        lines = []
        for name, rules in dev.acls.items():
            lines.append(f"Extended IP access list {name}")
            for idx, r in enumerate(rules, start=10):
                lines.append(f" {idx} {r.action} {r.protocol} {r.src} {r.dst} (hitcnt={r.hits})")
        return "\n".join(lines) if lines else "% No access lists configured"

    def show_running_config(self, uid: str) -> str:
        dev = self.devices[uid]
        lines: List[str] = []
        lines.append(f"hostname {dev.uid}")

        # VLANs (switch)
        if dev.kind == "switch":
            for vid in sorted(dev.vlans.keys()):
                if vid == 1 and dev.vlans.get(1) == "default":
                    continue
                lines.append(f"vlan {vid}")
                lines.append(f" name {dev.vlans[vid]}")
                lines.append("!")

        # ACLs
        for name, rules in dev.acls.items():
            lines.append(f"ip access-list extended {name}")
            for r in rules:
                lines.append(f" {r.action} {r.protocol} {r.src} {r.dst}")
            lines.append("!")

        # Interfaces
        for ifn in sorted(dev.interfaces.keys()):
            itf = dev.interfaces[ifn]
            lines.append(f"interface {ifn}")
            if itf.mode in ("access", "trunk"):
                lines.append(" switchport")
                lines.append(f" switchport mode {itf.mode}")
                if itf.mode == "access":
                    lines.append(f" switchport access vlan {itf.access_vlan}")
                else:
                    lines.append(f" switchport trunk allowed vlan {','.join(str(v) for v in sorted(itf.trunk_vlans))}")
            if itf.ip and itf.mask:
                lines.append(f" ip address {itf.ip} {itf.mask}")
            if itf.acl_in:
                lines.append(f" ip access-group {itf.acl_in} in")
            if itf.acl_out:
                lines.append(f" ip access-group {itf.acl_out} out")
            lines.append(" no shutdown" if itf.admin_up else " shutdown")
            lines.append("!")

        # Static routes
        for prefix, mask, nh in dev.static_routes:
            if nh:
                lines.append(f"ip route {prefix} {mask} {nh}")

        # OSPF
        if dev.ospf.enabled:
            lines.append(f"router ospf {dev.ospf.process_id}")
            if dev.ospf.router_id:
                lines.append(f" router-id {dev.ospf.router_id}")
            for net_ip, wildcard, area in dev.ospf.networks:
                lines.append(f" network {net_ip} {wildcard} area {area}")
            lines.append("!")

        lines.append("end")
        return "\n".join(lines)
