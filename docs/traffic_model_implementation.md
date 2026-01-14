# Traffic Model Implementation Instructions

**Purpose**: Precise instructions for implementing capacity-accurate link utilization visualization.

**Audience**: Senior engineer or code-generation model implementing the traffic system.

---

## PART 1 — Networking Model Validation

### Statement Under Review

> "If a PC is configured at X% throughput, and the link it is attached to has capacity C,
> then that link must carry X% × C traffic from that PC alone."

### Verdict: CORRECT — This Is a Real Networking Invariant

This statement is a fundamental property of network traffic:

1. **Conservation of data**: A PC transmitting at X% of its NIC capacity produces exactly X% × C bits per second. This traffic does not disappear, shrink, or grow as it enters the first link.

2. **No amplification in transit**: A packet transmitted by a PC is the same size when it arrives at the switch. Switches and routers do not add or remove payload data.

3. **Capacity is a hard ceiling**: A 1 Gbps link can carry at most 1 Gbps. If a PC offers 900 Mbps (90% of 1 Gbps), that link is 90% utilized by that single source.

4. **Additive aggregation**: When multiple sources share a link, their traffic sums. Two PCs each at 45% utilization produce 90% utilization on a shared uplink (assuming equal capacity).

**This invariant must hold in any physically accurate network simulation.**

---

## PART 2 — Current Modeling Flaw

### Observed Symptom

A PC→Switch link shows green (low utilization) even when the PC is conceptually "generating traffic."

### Root Cause Analysis

Examining `_flow_offered_load()` in `sim/core.py`:

```
return 0.30 * cap  # Hard-coded 30% of capacity
```

**Flaws identified:**

1. **No user-configurable throughput**: Every PC is hard-coded to offer exactly 30% of link capacity. There is no mechanism for a user to specify "this PC should generate 90% load."

2. **Traffic is then divided among peers**: The code further divides the offered load across all destination peers:
   ```
   per_flow_mbps = offered / len(peers)
   ```
   If a PC has 3 peers, its 30% becomes 10% per flow. With 4 PCs in a mesh, each access link sees only ~10% utilization per destination, not the full offered rate.

3. **Mismatch between intent and model**: The user expects "start traffic" to produce visible congestion. Instead, the mesh-traffic model distributes load thinly, and the hard-coded 30% cap ensures no single link ever exceeds 30%.

### Why the Link Stays Green

For a PC→Switch link to show 90% utilization:
- The PC must offer 90% × C Mbps
- That full amount must traverse the PC→Switch link

Currently:
- PC offers 30% × C Mbps (hard-coded)
- That 30% is split across N peers
- Each flow contributes (30% / N) to the access link
- With 3 peers: 30% / 3 = 10% per direction
- Bidirectional: ~20% total on the access link
- Result: green, not yellow/orange/red

---

## PART 3 — Missing Control: Per-PC Throughput Selector

### Concept Definition

Each PC must have a **throughput setting** that represents the percentage of its NIC capacity that the PC is actively using.

### Specification

| Property | Value |
|----------|-------|
| Name | `throughput_pct` |
| Type | Float (0.0 to 1.0) |
| UI representation | Dropdown or slider |
| Discrete values | 10%, 20%, 30%, 40%, 50%, 60%, 70%, 80%, 90% |
| Default | 0% (idle) or 30% (legacy behavior) |

### Meaning

- `throughput_pct = 0.90` means the PC is transmitting at 90% of its NIC's line rate.
- On a 1 Gbps NIC, this equals 900 Mbps of offered traffic.
- This is the **total egress rate**, not per-destination.

### How It Feeds the Traffic Model

```
offered_mbps = pc.throughput_pct × link_capacity_mbps
```

The `_flow_offered_load()` function must read this value from the PC device object instead of returning a hard-coded constant.

### Why Explicit Input Is Necessary

1. **User intent varies**: A user demonstrating congestion needs 90%. A user showing normal operation needs 30%.

2. **No inference possible**: The simulator cannot guess what traffic level the user wants to visualize.

3. **Correctness depends on it**: Without explicit input, the access link utilization is always wrong because it defaults to an arbitrary value.

---

## PART 4 — Traffic Propagation Rules

### Rule 1: Traffic Originates at PCs

Only devices of kind `host` generate traffic. Routers and switches forward traffic but do not create it.

**Implementation**: When calculating offered load, only iterate over devices where `dev.kind == "host"`.

### Rule 2: Traffic Is Conserved Hop-by-Hop

A PC transmitting 900 Mbps contributes 900 Mbps to every link on the path to its destination. The traffic does not shrink or grow in transit.

**Implementation**: When accumulating `target_mbps` for each link in a path, add the same `per_flow_mbps` value to every link traversed.

### Rule 3: Aggregation Occurs Naturally

When multiple flows traverse the same link, their contributions sum:

```
link.target_mbps += flow_1_mbps
link.target_mbps += flow_2_mbps
...
```

This is the only place where traffic values combine. A switch uplink carrying traffic from 4 PCs at 25% each shows 100% utilization (if capacities are equal).

### Rule 4: No Per-Hop Amplification

The following are **prohibited**:

- Multiplying traffic by hop count
- Scaling traffic based on device type
- Adding "overhead" that increases traffic beyond the PC's offered rate
- Any formula where downstream links carry more traffic than upstream links for the same flow

### Rule 5: Bidirectional Traffic Is Separate

If PC1→PC2 generates 100 Mbps, and PC2→PC1 generates 100 Mbps, the links carry:
- PC1→SW link: 100 Mbps out (from PC1) + 100 Mbps in (to PC1) = 200 Mbps bidirectional
- For utilization purposes, each direction is counted against the link's unidirectional capacity

**Note**: If the model uses full-duplex links, each direction has its own capacity. If half-duplex, directions share capacity.

---

## PART 5 — Link Utilization Calculation

### Formula

```
link_utilization = (sum of all traffic traversing this link) / link_capacity
```

### Step-by-Step Procedure

1. **Initialize**: For each link, set `target_mbps = 0.0`.

2. **For each PC with traffic enabled**:
   - Compute `offered_mbps = pc.throughput_pct × access_link_capacity`
   - For each destination peer, compute per-flow share (or use full offered if single destination)
   - Trace the forwarding path from PC to destination
   - For each link in the path, add `per_flow_mbps` to that link's `target_mbps`

3. **Compute utilization**: For each link:
   ```
   utilization = link.target_mbps / link.capacity_mbps
   ```

4. **Feed to visual system**: Pass `utilization` to the stress/color engine.

### What MUST Influence Link Color

- Sum of traffic from all flows traversing the link
- Link capacity
- (Optionally) Packet loss and queue depth for stress amplification

### What MUST NOT Influence Link Color

| Factor | Why It's Excluded |
|--------|-------------------|
| Routing protocol complexity | Routing determines path, not utilization |
| Device type (router vs switch) | All devices forward traffic equally |
| Number of hops in path | Each link is evaluated independently |
| Simulation wall-clock time | Utilization is instantaneous, not cumulative |
| Number of VLANs | VLANs affect path, not per-link math |
| Hardware profile | Profile affects device stress, not link stress |

---

## PART 6 — Implementation Invariants

These invariants must always hold. Use them as correctness checks during development and testing.

### Invariant 1: Single PC at 90% → Near-Red Access Link

> If one PC is configured at 90% throughput on a 1 Gbps link, the PC→Switch link must show utilization ≥ 85% and appear yellow/orange.

**Test**: Set `PC1.throughput_pct = 0.90`, start traffic, verify access link utilization.

### Invariant 2: Two PCs at 10% → ~20% Shared Uplink

> Two PCs each at 10% throughput, both routing through the same switch uplink, must produce ~20% utilization on that uplink.

**Test**: Set `PC1.throughput_pct = 0.10`, `PC2.throughput_pct = 0.10`, verify uplink shows ~20%.

### Invariant 3: Traffic Conservation Across Path

> The sum of traffic entering a link equals the sum of traffic exiting (no creation or destruction mid-path).

**Test**: For any flow, verify each link in the path receives the same `per_flow_mbps` addition.

### Invariant 4: Zero Throughput → Zero Link Utilization

> If all PCs have `throughput_pct = 0.0`, all links must show 0% utilization (idle/teal).

**Test**: Set all PCs to 0%, verify all links show baseline color.

### Invariant 5: Equal-Capacity Links Match Color

> If PC→Switch and Switch→Router have equal capacity, and all PC traffic routes through the router, both links must show identical utilization.

**Test**: Verify access link and uplink show same utilization percentage when capacities match.

### Invariant 6: Capacity Mismatch Creates Bottleneck

> If PC→Switch is 1 Gbps and Switch→Router is 100 Mbps, a PC at 50% (500 Mbps) must show 50% on access link but saturation (capped/dropped) on the uplink.

**Test**: Verify uplink shows 100%+ utilization, access link shows 50%.

### Invariant 7: Utilization Cannot Exceed Offered

> A link's utilization cannot exceed the sum of all traffic offered by all PCs in the topology.

**Test**: If total PC traffic is 2 Gbps across all sources, no link can show more than 2 Gbps load.

---

## Summary for Implementer

1. **Add `throughput_pct` field** to host devices (default 0.0 or 0.30).
2. **Replace hard-coded 30%** in `_flow_offered_load()` with `dev.throughput_pct × capacity`.
3. **Expose UI control** for users to set PC throughput (10%-90% dropdown).
4. **Verify traffic conservation**: same Mbps value added to every link in a flow's path.
5. **Test against all 7 invariants** before considering implementation complete.

The visual stress system is already calibrated correctly. Once the traffic model produces accurate utilization values, link colors will reflect reality.
