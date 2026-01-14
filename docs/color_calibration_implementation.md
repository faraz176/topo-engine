# Implementation Instructions: Link Color Calibration Fix

## Target File
`sim/visual_stress.py`

## Change 1: Replace `_compute_stress_from_load` method

**Location**: `VisualStressEngine._compute_stress_from_load()` (approximately lines 305-340)

**Current behavior**: Utilization maps aggressively to stress, allowing 100% utilization to reach stress ~0.70

**Required behavior**: Utilization alone is capped at stress 0.45. Loss and queue are additive amplifiers.

**New formula**:
```python
def _compute_stress_from_load(self, load: LoadState) -> float:
    util = load.utilization_pct
    loss = load.packet_loss_pct
    queue = load.queue_depth_pct
    
    # Base stress from utilization (flattened, capped)
    if util < 0.5:
        util_stress = util * 0.02                          # 0-50% → 0.00-0.01
    elif util < 0.7:
        util_stress = 0.01 + (util - 0.5) * 0.2            # 50-70% → 0.01-0.05
    elif util < 0.85:
        util_stress = 0.05 + (util - 0.7) * 0.67           # 70-85% → 0.05-0.15
    elif util < 0.95:
        util_stress = 0.15 + (util - 0.85) * 1.5           # 85-95% → 0.15-0.30
    elif util < 1.05:
        util_stress = 0.30 + (util - 0.95) * 1.5           # 95-105% → 0.30-0.45
    else:
        util_stress = 0.45 + (util - 1.05) * 0.5           # >105% → 0.45+ (slow growth)
    
    # Cap utilization-only stress at 0.55 (cannot reach orange alone)
    util_stress = min(util_stress, 0.55)
    
    # Loss amplifier: loss is serious, adds directly
    loss_stress = loss * 1.5                               # 10% loss → +0.15 stress
    
    # Queue amplifier: growing queues signal congestion
    queue_stress = queue * 0.4                             # 50% queue → +0.20 stress
    
    total_stress = util_stress + loss_stress + queue_stress
    return max(0.0, min(1.0, total_stress))
```

## Change 2: Update `COLOR_CONTROL_POINTS`

**Location**: Module-level constant `COLOR_CONTROL_POINTS` (approximately lines 70-85)

**Current behavior**: Orange starts at stress ~0.65, red at ~0.88

**Required behavior**: Push orange/red thresholds higher so they require loss/queue amplifiers

**New values**:
```python
COLOR_CONTROL_POINTS: List[Tuple[float, float, float, float]] = [
    # (visible_stress, hue, saturation, lightness)
    (0.00, 0.40, 0.45, 0.42),   # Teal-green (idle)
    (0.05, 0.38, 0.55, 0.45),   # Green (minimal activity)
    (0.15, 0.33, 0.65, 0.48),   # Green (active)
    (0.30, 0.25, 0.70, 0.50),   # Yellow-green (busy)
    (0.45, 0.17, 0.75, 0.52),   # Yellow (high utilization ceiling)
    (0.60, 0.12, 0.78, 0.50),   # Yellow-orange (needs loss/queue)
    (0.75, 0.07, 0.82, 0.48),   # Orange (confirmed congestion)
    (0.88, 0.03, 0.88, 0.45),   # Red-orange (severe)
    (1.00, 0.00, 0.92, 0.42),   # Red (critical)
]
```

## Change 3: Update documentation constants

**Location**: Module docstring or comments near `RISE_SPEED_PER_SEC` (approximately lines 45-55)

**Add comment**:
```python
# CALIBRATION INVARIANTS:
# - Utilization alone (no loss, no queue) cannot produce stress > 0.55
# - Stress 0.45 corresponds to 100% utilization with healthy delivery
# - Orange (stress > 0.60) requires loss > 0% OR queue > 30%
# - Red (stress > 0.85) requires loss > 5% OR queue > 70% OR util > 120%
```

## Verification Test

After implementation, run this test to confirm calibration:

```python
from sim.visual_stress import VisualStressEngine, LoadState

engine = VisualStressEngine()

# Test 1: 100% util, no loss, no queue → must be yellow, NOT orange
load = LoadState(utilization_pct=1.0, packet_loss_pct=0.0, queue_depth_pct=0.0)
stress = engine._compute_stress_from_load(load)
assert stress <= 0.45, f"100% util with no loss should be ≤0.45, got {stress}"

# Test 2: 80% util → must be green-yellow
load = LoadState(utilization_pct=0.8, packet_loss_pct=0.0, queue_depth_pct=0.0)
stress = engine._compute_stress_from_load(load)
assert stress <= 0.15, f"80% util should be ≤0.15, got {stress}"

# Test 3: 100% util + 5% loss → should reach orange
load = LoadState(utilization_pct=1.0, packet_loss_pct=0.05, queue_depth_pct=0.0)
stress = engine._compute_stress_from_load(load)
assert 0.50 <= stress <= 0.65, f"100% util + 5% loss should be 0.50-0.65, got {stress}"

# Test 4: 110% util + 10% loss + 50% queue → should reach red
load = LoadState(utilization_pct=1.1, packet_loss_pct=0.10, queue_depth_pct=0.5)
stress = engine._compute_stress_from_load(load)
assert stress >= 0.85, f"Overloaded link should reach red (≥0.85), got {stress}"

print("All calibration tests passed")
```

## Do NOT Change

- `_evolve_visible_stress()` — rate limiting is correct
- `_stress_to_color()` — HSL interpolation logic is correct
- `tick()` — evolution loop is correct
- Any code in `sim/core.py` related to traffic calculation
- The `_flow_offered_load()` function
- The `compute_load_state()` function

## Expected Outcome

| Condition | Old Stress | New Stress | Old Color | New Color |
|-----------|-----------|------------|-----------|-----------|
| 60% util, no loss | ~0.12 | ~0.03 | Green | Green |
| 80% util, no loss | ~0.28 | ~0.12 | Yellow | Green |
| 100% util, no loss | ~0.70 | ~0.45 | Orange | Yellow |
| 100% util, 5% loss | ~0.90 | ~0.53 | Red | Orange |
| 110% util, 10% loss, 50% queue | ~1.0 | ~0.87 | Red | Red |
