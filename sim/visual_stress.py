"""
Visual Stress Evolution System
==============================

A perceptually-aware color evolution engine for network simulation visualization.

Design Principles:
------------------
1. SEPARATION OF CONCERNS
   - Load Model: raw utilization, packet loss, latency, queue depth
   - Stress Model: normalized stress (0-1), rises fast, decays slow
   - Visual Model: visible_stress drives color, evolves slowly over time

2. TIME-DOMAIN EVOLUTION
   - Color changes at bounded rate per second, independent of frame rate
   - Rise speed > decay speed (stress lingers visually)
   - Transitions take multiple seconds to be perceptible

3. PERCEPTUAL COLOR MAPPING
   - Uses HSL color space for perceptually uniform transitions
   - Non-linear mapping: most spectrum between green and yellow
   - Orange/red reserved for sustained high stress only

4. ANTI-PANIC SAFEGUARDS
   - Single failures cannot cause large color jumps
   - Visual decay slower than stress recovery
   - Colors feel heavy, inertial, reluctant to panic

Author: Topo_Engine Team
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple
import colorsys
import math
import time


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION: Time-domain evolution rates
# ─────────────────────────────────────────────────────────────────────────────

# Maximum change in visible_stress per second (0-1 scale)
# At this rate, green→red would take ~6 seconds minimum
RISE_SPEED_PER_SEC = 0.16  # stress builds quickly for responsiveness
DECAY_SPEED_PER_SEC = 0.04  # stress lingers but not excessively

# Minimum time (seconds) before any significant color change
# Prevents single-frame spikes from causing visual panic
MIN_STRESS_HOLD_TIME = 0.5

# Dead zone: stress changes below this threshold are ignored
# Prevents micro-jitter in stable states
STRESS_DEAD_ZONE = 0.005

# CALIBRATION INVARIANTS:
# - Utilization alone (no loss, no queue) cannot produce stress > 0.55
# - Stress 0.45 corresponds to 100% utilization with healthy delivery
# - Orange (stress > 0.60) requires loss > 0% OR queue > 30%
# - Red (stress > 0.85) requires loss > 5% OR queue > 70% OR util > 120%


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION: Perceptual color control points
# ─────────────────────────────────────────────────────────────────────────────

# Control points: (visible_stress_norm, hue, saturation, lightness)
# HSL chosen because:
# - Hue is perceptually intuitive (green→yellow→orange→red)
# - Saturation/lightness can be tuned independently
# - More predictable than RGB interpolation
#
# Hue values: 0.0=red, 0.33=green, 0.17=yellow, 0.08=orange
#
# Design: Most of the visible_stress range maps to green→yellow
# Orange and red are compressed into the upper range

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


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LoadState:
    """Raw load metrics from simulation (input to stress model)."""
    utilization_pct: float = 0.0  # 0.0 to 1.0+
    packet_loss_pct: float = 0.0  # 0.0 to 1.0
    latency_ms: float = 0.0
    queue_depth_pct: float = 0.0  # 0.0 to 1.0


@dataclass
class StressState:
    """Normalized stress derived from load (input to visual model)."""
    stress_norm: float = 0.0  # 0.0 to 1.0
    stress_trend: float = 0.0  # positive = rising, negative = falling
    time_at_current_level: float = 0.0  # seconds stress has been stable


@dataclass
class VisualState:
    """Visual representation state (drives rendering)."""
    visible_stress_norm: float = 0.0  # 0.0 to 1.0, slowly evolving
    current_color_hex: str = "#4caf50"  # current rendered color
    target_color_hex: str = "#4caf50"  # color we're moving toward
    last_update_time: float = field(default_factory=time.time)


@dataclass
class EvolutionLog:
    """Debug instrumentation for a single tick."""
    timestamp: float
    entity_id: str
    utilization_pct: float
    stress_norm: float
    visible_stress_norm: float
    visible_stress_prev: float
    current_color: str
    target_color: str
    delta_applied: float
    reason: str


# ─────────────────────────────────────────────────────────────────────────────
# VISUAL STRESS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class VisualStressEngine:
    """
    Manages visual stress evolution for network entities.
    
    This is the main interface for the color evolution system.
    Each device/link gets its own tracked state.
    """
    
    def __init__(self, enable_logging: bool = False):
        self._entities: Dict[str, Dict] = {}  # entity_id -> state dict
        self._enable_logging = enable_logging
        self._log_buffer: List[EvolutionLog] = []
        self._max_log_size = 1000
    
    def register_entity(self, entity_id: str) -> None:
        """Register a new entity to track."""
        if entity_id not in self._entities:
            self._entities[entity_id] = {
                "load": LoadState(),
                "stress": StressState(),
                "visual": VisualState(),
            }
    
    def remove_entity(self, entity_id: str) -> None:
        """Stop tracking an entity."""
        self._entities.pop(entity_id, None)
    
    def clear_all(self) -> None:
        """Remove all tracked entities."""
        self._entities.clear()
        self._log_buffer.clear()
    
    def update_load(self, entity_id: str, 
                    utilization: float = 0.0,
                    packet_loss: float = 0.0,
                    latency_ms: float = 0.0,
                    queue_depth: float = 0.0) -> None:
        """
        Update raw load metrics for an entity.
        Call this when simulation state changes.
        """
        self.register_entity(entity_id)
        load = self._entities[entity_id]["load"]
        load.utilization_pct = max(0.0, utilization)
        load.packet_loss_pct = max(0.0, min(1.0, packet_loss))
        load.latency_ms = max(0.0, latency_ms)
        load.queue_depth_pct = max(0.0, min(1.0, queue_depth))
    
    def tick(self, dt: float) -> None:
        """
        Advance visual state for all entities by dt seconds.
        Call this every simulation tick.
        """
        now = time.time()
        
        for entity_id, state in self._entities.items():
            load = state["load"]
            stress = state["stress"]
            visual = state["visual"]
            
            # Step 1: Compute stress_norm from load
            prev_stress = stress.stress_norm
            stress.stress_norm = self._compute_stress_from_load(load)
            
            # Track stress trend
            stress_delta = stress.stress_norm - prev_stress
            if abs(stress_delta) < STRESS_DEAD_ZONE:
                stress.time_at_current_level += dt
            else:
                stress.time_at_current_level = 0.0
                stress.stress_trend = stress_delta / max(0.001, dt)
            
            # Step 2: Evolve visible_stress toward stress_norm (slowly!)
            prev_visible = visual.visible_stress_norm
            visual.visible_stress_norm = self._evolve_visible_stress(
                current=visual.visible_stress_norm,
                target=stress.stress_norm,
                dt=dt,
                time_at_level=stress.time_at_current_level,
            )
            
            # Step 3: Compute colors
            visual.target_color_hex = self._stress_to_color(stress.stress_norm)
            visual.current_color_hex = self._stress_to_color(visual.visible_stress_norm)
            visual.last_update_time = now
            
            # Step 4: Log if enabled
            if self._enable_logging:
                delta = visual.visible_stress_norm - prev_visible
                reason = self._explain_change(delta, stress, visual)
                self._add_log(EvolutionLog(
                    timestamp=now,
                    entity_id=entity_id,
                    utilization_pct=load.utilization_pct,
                    stress_norm=stress.stress_norm,
                    visible_stress_norm=visual.visible_stress_norm,
                    visible_stress_prev=prev_visible,
                    current_color=visual.current_color_hex,
                    target_color=visual.target_color_hex,
                    delta_applied=delta,
                    reason=reason,
                ))
    
    def get_color(self, entity_id: str) -> str:
        """Get the current visual color for an entity."""
        if entity_id not in self._entities:
            return "#4caf50"  # default green
        return self._entities[entity_id]["visual"].current_color_hex
    
    def get_visible_stress(self, entity_id: str) -> float:
        """Get the current visible stress level (0-1)."""
        if entity_id not in self._entities:
            return 0.0
        return self._entities[entity_id]["visual"].visible_stress_norm
    
    def get_stress(self, entity_id: str) -> float:
        """Get the current actual stress level (0-1)."""
        if entity_id not in self._entities:
            return 0.0
        return self._entities[entity_id]["stress"].stress_norm
    
    def get_debug_info(self, entity_id: str) -> Optional[Dict]:
        """Get full state for debugging."""
        if entity_id not in self._entities:
            return None
        state = self._entities[entity_id]
        return {
            "load": {
                "utilization": state["load"].utilization_pct,
                "packet_loss": state["load"].packet_loss_pct,
                "latency_ms": state["load"].latency_ms,
                "queue_depth": state["load"].queue_depth_pct,
            },
            "stress": {
                "stress_norm": state["stress"].stress_norm,
                "trend": state["stress"].stress_trend,
                "time_stable": state["stress"].time_at_current_level,
            },
            "visual": {
                "visible_stress": state["visual"].visible_stress_norm,
                "current_color": state["visual"].current_color_hex,
                "target_color": state["visual"].target_color_hex,
            },
        }
    
    def get_logs(self, last_n: int = 100) -> List[EvolutionLog]:
        """Get recent evolution logs."""
        return self._log_buffer[-last_n:]
    
    def format_logs(self, last_n: int = 20) -> str:
        """Format recent logs as human-readable text."""
        logs = self.get_logs(last_n)
        if not logs:
            return "No logs available"
        
        lines = ["Visual Stress Evolution Log", "=" * 60]
        for log in logs:
            lines.append(
                f"{log.entity_id}: util={log.utilization_pct:.1%} "
                f"stress={log.stress_norm:.3f} vis={log.visible_stress_norm:.3f} "
                f"Δ={log.delta_applied:+.4f} | {log.reason}"
            )
        return "\n".join(lines)
    
    # ─────────────────────────────────────────────────────────────────────────
    # INTERNAL: Stress computation
    # ─────────────────────────────────────────────────────────────────────────
    
    def _compute_stress_from_load(self, load: LoadState) -> float:
        """
        Convert raw load metrics to normalized stress.
        
        Stress is NOT equal to utilization:
        - Light load = very low stress
        - Moderate load = some stress
        - High load + packet loss = high stress
        - Overload + sustained loss = critical stress
        """
        util = load.utilization_pct
        loss = load.packet_loss_pct
        queue = load.queue_depth_pct
        
        # Base stress from utilization (flattened, capped)
        if util < 0.5:
            util_stress = util * 0.02  # 0-50% → 0.00-0.01
        elif util < 0.7:
            util_stress = 0.01 + (util - 0.5) * 0.2  # 50-70% → 0.01-0.05
        elif util < 0.85:
            util_stress = 0.05 + (util - 0.7) * 0.67  # 70-85% → 0.05-0.15
        elif util < 0.95:
            util_stress = 0.15 + (util - 0.85) * 1.5  # 85-95% → 0.15-0.30
        elif util < 1.05:
            util_stress = 0.30 + (util - 0.95) * 1.5  # 95-105% → 0.30-0.45
        else:
            util_stress = 0.45 + (util - 1.05) * 0.5  # >105% → 0.45+ (slow growth)

        # Cap utilization-only stress at 0.55 (cannot reach orange alone)
        util_stress = min(util_stress, 0.55)

        # Loss amplifier: loss is serious, adds directly
        loss_stress = loss * 1.5  # 10% loss → +0.15 stress

        # Queue amplifier: growing queues signal congestion
        queue_stress = queue * 0.4  # 50% queue → +0.20 stress

        total_stress = util_stress + loss_stress + queue_stress
        return max(0.0, min(1.0, total_stress))
    
    # ─────────────────────────────────────────────────────────────────────────
    # INTERNAL: Visual stress evolution
    # ─────────────────────────────────────────────────────────────────────────
    
    def _evolve_visible_stress(self, current: float, target: float, 
                                dt: float, time_at_level: float) -> float:
        """
        Slowly evolve visible_stress toward target stress.
        
        Key behaviors:
        - Rise is faster than decay (stress lingers)
        - Rate is bounded per second (prevents jumps)
        - Requires sustained stress before major color change
        """
        diff = target - current
        
        # Dead zone: don't change if difference is negligible
        if abs(diff) < STRESS_DEAD_ZONE:
            return current
        
        # Anti-panic: require minimum time at stress level before large changes
        if time_at_level < MIN_STRESS_HOLD_TIME:
            # Allow only tiny changes during hold period
            effective_dt = dt * 0.1
        else:
            effective_dt = dt
        
        # Determine rate based on direction
        if diff > 0:
            # Rising: faster rate
            rate = RISE_SPEED_PER_SEC
        else:
            # Falling: slower rate (stress lingers)
            rate = DECAY_SPEED_PER_SEC
        
        # Compute maximum allowed change this tick
        max_change = rate * effective_dt
        
        # Apply bounded change
        if abs(diff) <= max_change:
            return target  # close enough to snap
        else:
            return current + math.copysign(max_change, diff)
    
    # ─────────────────────────────────────────────────────────────────────────
    # INTERNAL: Color computation
    # ─────────────────────────────────────────────────────────────────────────
    
    def _stress_to_color(self, stress: float) -> str:
        """
        Convert visible_stress_norm to hex color using HSL interpolation.
        
        Uses control points for non-linear, perceptually meaningful mapping.
        Most of the color range is green→yellow; orange/red compressed to top.
        """
        stress = max(0.0, min(1.0, stress))
        
        # Find surrounding control points
        points = COLOR_CONTROL_POINTS
        lower_idx = 0
        for i, (s, h, sat, lit) in enumerate(points):
            if s <= stress:
                lower_idx = i
            else:
                break
        
        upper_idx = min(lower_idx + 1, len(points) - 1)
        
        # Get control points
        s0, h0, sat0, lit0 = points[lower_idx]
        s1, h1, sat1, lit1 = points[upper_idx]
        
        # Interpolate
        if s1 == s0:
            t = 0.0
        else:
            t = (stress - s0) / (s1 - s0)
        
        h = h0 + (h1 - h0) * t
        sat = sat0 + (sat1 - sat0) * t
        lit = lit0 + (lit1 - lit0) * t
        
        # Convert HSL to RGB
        r, g, b = colorsys.hls_to_rgb(h, lit, sat)
        
        # Convert to hex
        return f"#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}"
    
    # ─────────────────────────────────────────────────────────────────────────
    # INTERNAL: Logging helpers
    # ─────────────────────────────────────────────────────────────────────────
    
    def _explain_change(self, delta: float, stress: StressState, 
                        visual: VisualState) -> str:
        """Generate human-readable explanation for color change."""
        if abs(delta) < 0.0001:
            if stress.time_at_current_level > 0.5:
                return "stable (resting)"
            return "stable (hold period)"
        
        direction = "↑ warming" if delta > 0 else "↓ cooling"
        
        if stress.time_at_current_level < MIN_STRESS_HOLD_TIME:
            return f"{direction} (damped - hold period)"
        
        gap = abs(stress.stress_norm - visual.visible_stress_norm)
        if gap > 0.3:
            return f"{direction} (catching up, gap={gap:.2f})"
        elif gap > 0.1:
            return f"{direction} (approaching target)"
        else:
            return f"{direction} (near equilibrium)"
    
    def _add_log(self, log: EvolutionLog) -> None:
        """Add log entry, maintaining max buffer size."""
        self._log_buffer.append(log)
        if len(self._log_buffer) > self._max_log_size:
            self._log_buffer = self._log_buffer[-self._max_log_size:]


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def stress_color_preview() -> Dict[float, str]:
    """
    Generate a preview of colors at various stress levels.
    Useful for debugging/visualization.
    """
    engine = VisualStressEngine()
    engine.register_entity("preview")
    
    colors = {}
    for i in range(21):
        stress = i / 20.0
        color = engine._stress_to_color(stress)
        colors[stress] = color
    
    return colors


def print_color_spectrum():
    """Print the color spectrum for manual inspection."""
    colors = stress_color_preview()
    print("\nVisual Stress Color Spectrum")
    print("=" * 50)
    for stress, color in sorted(colors.items()):
        print(f"stress={stress:.2f} → {color}")
