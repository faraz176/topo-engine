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

SCHEMA_VERSION = 1


def _validate_topology(data: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    if not isinstance(data, dict):
        return ["Top-level must be an object."]
    if data.get("schemaVersion") != SCHEMA_VERSION:
        problems.append("schemaVersion must be 1.")
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
        if n.get("type") not in ("router", "switch"):
            problems.append(f"nodes[{i}].type must be 'router' or 'switch'.")
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
        "schemaVersion": 1,
        "meta": {"name": "Google DC Stress Test (MCP)"},
        "nodes": sorted(nodes, key=lambda n: (n["type"], n["id"])),
        "links": uniq,
    }
    return topo


if __name__ == "__main__":
    # Streamable HTTP transport is recommended in the MCP SDK docs.
    mcp.run(transport="streamable-http")
