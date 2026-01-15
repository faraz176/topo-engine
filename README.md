# topo-engine  (Failed)
*A deterministic, topology-driven network simulation engine*

## Overview

**topo-engine** is a lightweight, deterministic network simulator evolved from **topo-drawer**.  
It combines an interactive topology editor with an IOS-like configuration and verification engine, enabling CCNA, CCNP, and CCIE-level study, testing, and design — without the complexity of full emulation platforms like EVE-NG or GNS3.

The focus is on **correctness, clarity, and repeatability**, not packet-level emulation.

---

## Core Capabilities

### Topology Editor
- Interactive canvas for building network topologies  
- Routers, switches, and hosts (PCs)  
- Deterministic interface naming  
- Link-based connectivity model  
- JSON-based save/load with persistent device state  

### IOS-like CLI Simulation
- Per-device CLI (routers, switches, hosts)  
- Mode-aware prompts:
  - exec (`>`)
  - privileged exec (`#`)
  - global configuration
  - interface configuration
  - routing protocol configuration  
- Cisco-style syntax and error handling  
- Real simulated state backing all commands (no hardcoded outputs)

### Implemented Networking Features (Current)

#### Layer 2
- VLANs  
- Access and trunk ports  
- MAC address learning  

#### Layer 3
- Connected routes  
- Static routing  
- OSPFv2 (single area, deterministic router-id selection)

#### Hosts / PCs
- IP addressing  
- Default gateway  
- End-to-end ping verification  

#### Verification
- `ping`  
- `show running-config`  
- `show ip route`  
- `show ip interface brief`  
- OSPF neighbor and route inspection  

#### Deterministic Behavior
- Stable ECMP selection  
- Predictable failover under link loss  
- Repeatable test outcomes  

---

## Design Philosophy

- **Simulation, not emulation**  
  No real IOS images, no virtualization, no Docker.

- **Topology-first**  
  The drawn topology defines physical and logical constraints.

- **Deterministic by default**  
  The same inputs always produce the same results.

- **Extensible architecture**  
  Protocols and features are added incrementally and tested in isolation.

- **Verification-driven**  
  Every feature must be provable via CLI commands and tests.

---

## Intended Use Cases

- CCNA / CCNP / CCIE concept validation  
- Rapid topology prototyping  
- Deterministic protocol behavior testing  
- Failure-mode exploration  
- Configuration logic rehearsal before deploying to real hardware  

---

## Current Status

⚠️ **Active development — not production-ready**

The simulator is currently stable for:
- Router-on-a-stick
- VLAN segmentation
- Multi-router OSPF topologies
- Deterministic failover scenarios

Ongoing work includes:
- Expanding CLI command coverage and autocompletion  
- Enhancing the MCP (TopoCopilot) to generate and apply full configurations  
- Improving host support and verification depth  
- Resolving cross-platform issues (macOS compatibility)  
- Stress-testing CCNP / CCIE-level edge cases  

---

## Planned Enhancements

- Advanced OSPF scenarios (multi-area, filtering)  
- ACL enforcement and verification  
- Traceroute simulation  
- Redundancy protocols (HSRP / VRRP)  
- NAT and firewall-style devices  
- Export to external lab formats (EVE-NG / real-device assist workflows)  
- Automated topology stress testing  

---

## Disclaimer

This project is **not affiliated with Cisco**.  
Cisco IOS syntax is used strictly for educational and interoperability familiarity.
