\
"""
Optional: MCP server for topology generation/validation.

This is useful if you want "true MCP" tooling (a standardized tool server).
You can run this locally (for MCP Inspector / Claude Desktop), or deploy it
publicly and then point OpenAI "Remote MCP" tools at it.

Run (example):
  pip install mcp
  python mcp_server/topo_mcp_server.py

Then connect an MCP client to:
  http://localhost:8000/mcp
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
import json

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "Topo MCP Server",
    instructions="Tools for generating and validating network topology JSON for fast-topo-drawer.",
    stateless_http=True,
    json_response=True,
)

SUPPORTED_SCHEMA_VERSIONS = {1, 2}


def _validate_topology(data: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    if not isinstance(data, dict):
        return ["Top-level must be an object."]
    if data.get("schemaVersion") not in SUPPORTED_SCHEMA_VERSIONS:
        problems.append("schemaVersion must be 1 or 2.")
    nodes = data.get("nodes")
    links = data.get("links")
    if not isinstance(nodes, list):
        problems.append("'nodes' must be a list.")
        nodes = []
    if not isinstance(links, list):
        problems.append("'links' must be a list.")
        links = []
    ids = set()
    for i, n in enumerate(nodes):
        if not isinstance(n, dict):
            problems.append(f"nodes[{i}] must be an object.")
            continue
        nid = n.get("id")
        if not nid or not isinstance(nid, str):
            problems.append(f"nodes[{i}].id must be a string.")
            continue
        if nid in ids:
            problems.append(f"Duplicate node id: {nid}")
        ids.add(nid)
        if n.get("type") not in ("router", "switch", "host"):
            problems.append(f"nodes[{i}].type must be 'router', 'switch', or 'host'.")
        for k in ("x", "y"):
            if n.get(k) is None:
                problems.append(f"nodes[{i}].{k} missing.")
    seen = set()
    for i, e in enumerate(links):
        if not isinstance(e, dict):
            problems.append(f"links[{i}] must be an object.")
            continue
        a = e.get("a")
        b = e.get("b")
        if not a or not b:
            problems.append(f"links[{i}] must include 'a' and 'b'.")
            continue
        if a not in ids:
            problems.append(f"links[{i}].a references missing node '{a}'.")
        if b not in ids:
            problems.append(f"links[{i}].b references missing node '{b}'.")
        key = tuple(sorted((a, b)))
        if key in seen:
            problems.append(f"Duplicate link between {key[0]} and {key[1]}.")
        seen.add(key)

        # Optional link interface mappings
        ifaces = e.get("ifaces")
        if ifaces is not None and not isinstance(ifaces, list):
            problems.append(f"links[{i}].ifaces must be a list when present.")

    # Optional device configs
    cfgs = data.get("deviceConfigs")
    if cfgs is not None and not isinstance(cfgs, (dict, list)):
        problems.append("deviceConfigs must be an object or a list when present.")
    if isinstance(cfgs, list):
        for j, item in enumerate(cfgs):
            if not isinstance(item, dict):
                problems.append(f"deviceConfigs[{j}] must be an object.")
                continue
            if not isinstance(item.get("id"), str):
                problems.append(f"deviceConfigs[{j}].id must be a string.")
            if "commands" in item and not isinstance(item.get("commands"), list):
                problems.append(f"deviceConfigs[{j}].commands must be a list when present.")
    return problems


@mcp.tool()
def validate_topology_json(topology_json: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a topology JSON object; returns problems list."""
    problems = _validate_topology(topology_json)
    return {"ok": len(problems) == 0, "problems": problems}


@mcp.tool()
def generate_google_dc_stress_test() -> Dict[str, Any]:
    """Generate a complex Google-style datacenter topology to stress-test the app."""
    # This mirrors the examples/google_dc_stress.topo.json included in the repo.
    # The tool returns the JSON so the client/LLM can load it directly.
    nodes = []
    links = []

    def add_node(uid: str, typ: str, x: float, y: float):
        nodes.append({"id": uid, "type": typ, "x": x, "y": y, "seq": len(nodes)})

    def link(a: str, b: str, typ: str = "ethernet"):
        links.append({"a": a, "b": b, "type": typ})

    spine_ids = [f"SW{i}" for i in range(1, 5)]
    spine_x = [250, 450, 650, 850]
    for uid, x in zip(spine_ids, spine_x):
        add_node(uid, "switch", x, 120)

    leaf_ids = [f"SW{i}" for i in range(5, 13)]
    leaf_x = [150, 275, 400, 525, 650, 775, 900, 1025]
    for uid, x in zip(leaf_ids, leaf_x):
        add_node(uid, "switch", x, 260)

    tor_ids = [f"SW{i}" for i in range(13, 29)]
    tor_x = [100 + i * 70 for i in range(16)]
    for uid, x in zip(tor_ids, tor_x):
        add_node(uid, "switch", x, 450)

    border_ids = [f"R{i}" for i in range(1, 5)]
    border_x = [300, 500, 700, 900]
    for uid, x in zip(border_ids, border_x):
        add_node(uid, "router", x, 50)

    fw_ids = ["R5", "R6"]
    fw_x = [1050, 1130]
    for uid, x in zip(fw_ids, fw_x):
        add_node(uid, "router", x, 130)

    lb_ids = ["R7", "R8"]
    lb_x = [1050, 1130]
    for uid, x in zip(lb_ids, lb_x):
        add_node(uid, "router", x, 600)

    stor_ids = [f"SW{i}" for i in range(29, 33)]
    stor_x = [220, 420, 620, 820]
    for uid, x in zip(stor_ids, stor_x):
        add_node(uid, "switch", x, 650)

    # Links
    for leaf in leaf_ids:
        for spine in spine_ids:
            link(leaf, spine, "ethernet")

    for i, tor in enumerate(tor_ids):
        leaf_i = leaf_ids[i // 2]
        leaf_j = leaf_ids[(i // 2 + 1) % len(leaf_ids)]
        link(tor, leaf_i, "ethernet")
        link(tor, leaf_j, "ethernet")

    border_spine_pairs = {
        "R1": ["SW1", "SW2"],
        "R2": ["SW2", "SW3"],
        "R3": ["SW3", "SW4"],
        "R4": ["SW4", "SW1"],
    }
    for r, spines in border_spine_pairs.items():
        for s in spines:
            link(r, s, "uplink")

    link("R5", "R1", "firewall")
    link("R5", "R2", "firewall")
    link("R6", "R3", "firewall")
    link("R6", "R4", "firewall")

    for fw in fw_ids:
        for s in ("SW2", "SW3"):
            link(fw, s, "uplink")

    for lb, leaves in {"R7": ["SW11", "SW12"], "R8": ["SW9", "SW10"]}.items():
        for lf in leaves:
            link(lb, lf, "ethernet")

    stor_pairs = {
        "SW29": ["SW5", "SW6"],
        "SW30": ["SW7", "SW8"],
        "SW31": ["SW9", "SW10"],
        "SW32": ["SW11", "SW12"],
    }
    for st, leaves in stor_pairs.items():
        for lf in leaves:
            link(st, lf, "storage")

    # Dedup
    seen = set()
    uniq = []
    for e in links:
        k = tuple(sorted((e["a"], e["b"])))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(e)

    uniq.sort(key=lambda e: (e["a"], e["b"]))

    topo = {
        "schemaVersion": 2,
        "meta": {"name": "Google DC Stress Test (MCP)"},
        "nodes": sorted(nodes, key=lambda n: (n["type"], n["id"])),
        "links": uniq,
    }
    return topo


@mcp.tool()
def generate_simple_ospf_lab_configured() -> Dict[str, Any]:
    """Generate a small OSPF lab WITH configurations applied.

    Topology: PC1 -- R1 -- R2 -- PC2
    Includes explicit link.ifaces + deviceConfigs so the UI can load and immediately ping end-to-end.
    """

    topo = {
        "schemaVersion": 2,
        "meta": {"name": "Simple OSPF Lab (Configured)"},
        "nodes": [
            {"id": "PC1", "type": "host", "x": 150, "y": 400, "seq": 0},
            {"id": "R1", "type": "router", "x": 400, "y": 400, "seq": 1},
            {"id": "R2", "type": "router", "x": 700, "y": 400, "seq": 2},
            {"id": "PC2", "type": "host", "x": 950, "y": 400, "seq": 3},
        ],
        "links": [
            {
                "a": "PC1",
                "b": "R1",
                "type": "ethernet",
                "count": 1,
                "ifaces": [{"a_if": "Eth0", "b_if": "Gi0/0"}],
            },
            {
                "a": "R1",
                "b": "R2",
                "type": "ethernet",
                "count": 1,
                "ifaces": [{"a_if": "Gi0/1", "b_if": "Gi0/0"}],
            },
            {
                "a": "R2",
                "b": "PC2",
                "type": "ethernet",
                "count": 1,
                "ifaces": [{"a_if": "Gi0/1", "b_if": "Eth0"}],
            },
        ],
        "deviceConfigs": [
            {"id": "PC1", "cli": "pc", "commands": ["ip 10.0.1.10 255.255.255.0 10.0.1.1"]},
            {
                "id": "R1",
                "cli": "ios",
                "commands": [
                    "enable",
                    "configure terminal",
                    "interface Gi0/0",
                    "ip address 10.0.1.1 255.255.255.0",
                    "no shutdown",
                    "exit",
                    "interface Gi0/1",
                    "ip address 10.0.12.1 255.255.255.0",
                    "no shutdown",
                    "exit",
                    "router ospf 1",
                    "network 10.0.1.0 0.0.0.255 area 0",
                    "network 10.0.12.0 0.0.0.255 area 0",
                    "end",
                ],
            },
            {
                "id": "R2",
                "cli": "ios",
                "commands": [
                    "enable",
                    "configure terminal",
                    "interface Gi0/0",
                    "ip address 10.0.12.2 255.255.255.0",
                    "no shutdown",
                    "exit",
                    "interface Gi0/1",
                    "ip address 10.0.2.1 255.255.255.0",
                    "no shutdown",
                    "exit",
                    "router ospf 1",
                    "network 10.0.12.0 0.0.0.255 area 0",
                    "network 10.0.2.0 0.0.0.255 area 0",
                    "end",
                ],
            },
            {"id": "PC2", "cli": "pc", "commands": ["ip 10.0.2.10 255.255.255.0 10.0.2.1"]},
        ],
    }
    return topo


if __name__ == "__main__":
    # Streamable HTTP transport is recommended in the MCP SDK docs.
    mcp.run(transport="streamable-http")
