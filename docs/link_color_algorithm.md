# Link Color Determination Algorithm — Technical Specification

## Data Flow Pipeline

```
[Traffic Generation] → [Link Utilization] → [Stress Norm] → [Visible Stress] → [Color]
```

## Stage 1: Traffic Generation

- Hosts with IP addresses generate traffic to all other hosts
- Per-host offered load = `0.30 × access_link_capacity_mbps`
- Traffic distributed equally across destination peers
- `per_flow_mbps = offered_load / peer_count`

## Stage 2: Link Utilization Calculation

Location: `sim/core.py` → `compute_load_state()`

```python
for each flow traversing link:
    target_link_load[link_id]["target_mbps"] += per_flow_mbps

link_capacity = min(BASE_CAPACITY, endpoint_A.max_link_speed, endpoint_B.max_link_speed)
utilization = load_mbps / capacity_mbps  # Range: 0.0 to 1.0+
```

## Stage 3: Load Ramping

Location: `sim/core.py` → `tick()`

- Load ramps toward target using exponential smoothing
- `alpha = tick_interval / ramp_seconds` (clamped 0.2–0.6)
- `current_load += (target_load - current_load) × alpha`

## Stage 4: Stress Calculation

Location: `sim/visual_stress.py` → `_compute_stress_from_load()`

Inputs: `utilization`, `packet_loss`, `queue_depth`

```python
if util < 0.3:
    util_stress = util × 0.1
elif util < 0.6:
    util_stress = 0.03 + (util - 0.3) × 0.3
elif util < 0.85:
    util_stress = 0.12 + (util - 0.6) × 0.8
else:
    util_stress = 0.32 + (util - 0.85) × 2.5

loss_factor = 1.0 + packet_loss × 4.0
queue_stress = queue_depth × 0.15

stress_norm = clamp(util_stress × loss_factor + queue_stress, 0.0, 1.0)
```

## Stage 5: Visible Stress Evolution

Location: `sim/visual_stress.py` → `_evolve_visible_stress()`

- `visible_stress` tracks `stress_norm` with bounded rate
- Rise rate: 0.16 per second
- Decay rate: 0.04 per second
- Dead zone: ignore changes < 0.005
- Hold time: 0.5s minimum before large changes

```python
diff = stress_norm - visible_stress
rate = RISE_SPEED if diff > 0 else DECAY_SPEED
max_change = rate × dt
visible_stress += clamp(diff, -max_change, +max_change)
```

## Stage 6: Color Mapping

Location: `sim/visual_stress.py` → `_stress_to_color()`

HSL interpolation between control points:

| visible_stress | Hue   | Color Description |
|----------------|-------|-------------------|
| 0.00           | 0.40  | Teal-green (idle) |
| 0.08           | 0.35  | Green             |
| 0.20           | 0.28  | Yellow-green      |
| 0.35           | 0.22  | Lime              |
| 0.50           | 0.17  | Yellow            |
| 0.65           | 0.11  | Orange-yellow     |
| 0.78           | 0.06  | Orange            |
| 0.88           | 0.03  | Red-orange        |
| 1.00           | 0.00  | Red               |

Linear interpolation between adjacent control points in HSL space, converted to hex RGB.

## Invariants

1. **Conservation**: `traffic_on_link = Σ(flow_rates)` — packets do not multiply
2. **Uniformity**: Equal (traffic, capacity, loss) → equal color
3. **Stability**: Constant traffic → color converges, no drift
4. **Device neutrality**: Endpoint device type does not affect link color

## Queue Depth Derivation

```python
queue_depth = max(0.0, (utilization - 0.8) / 0.2) if utilization > 0.8 else 0.0
```

Queue only contributes when utilization exceeds 80%.

## Packet Loss Derivation

```python
if util < 0.85:
    drop_prob = 0.0
elif util < 1.05:
    drop_prob = (util - 0.85) / 0.2 × 0.08
else:
    drop_prob = 0.08 + (util - 1.05) / 0.5 × 0.6
```

## Summary Formula

```
color = HSL_interpolate(
    visible_stress_evolve(
        stress_from_load(
            traffic_mbps / capacity_mbps,
            packet_loss,
            queue_depth
        )
    )
)
```
