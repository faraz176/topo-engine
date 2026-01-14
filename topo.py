import tkinter as tk
import json
import os
from tkinter import filedialog, messagebox
from typing import Optional, Dict, List

from session_log import SessionLogger

try:
    from ai.agent_panel import AgentPanel
except Exception:
    AgentPanel = None

from sim import TopologySim, CLIEngine, PCCLIEngine, AuthorityModel
from sim.core import HARDWARE_PROFILES
from sim.authority import default_pdf_paths
from sim.visual_stress import VisualStressEngine

NODE_RADIUS = 18
DRAG_THRESHOLD = 5

EDGE_COLOR = "#cccccc"
EDGE_WIDTH = 2
EDGE_HIGHLIGHT_COLOR = "#ffd54f"
EDGE_HIGHLIGHT_WIDTH = 4

EDGE_HIT_TOL = 10          # easier to click lines
PREVIEW_DASH = (6, 4)

ZOOM_MIN = 0.2
ZOOM_MAX = 4.0

SCHEMA_VERSION = 2


class TopologyTool:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Fast Network Topology Drawer")

        # Split: canvas (left) + agent panel (right)
        self.panes = tk.PanedWindow(root, orient=tk.HORIZONTAL, sashwidth=6, sashrelief=tk.RAISED)
        self.panes.pack(fill=tk.BOTH, expand=True)

        self.left = tk.Frame(self.panes, bg="#0f1115")
        self.right = tk.Frame(self.panes, bg="#14161b", width=380)

        self.panes.add(self.left, stretch="always")
        self.panes.add(self.right, minsize=320)

        # Simple top toolbar for quick actions
        self.toolbar = tk.Frame(self.left, bg="#0f1115")
        self.toolbar.pack(fill=tk.X, side=tk.TOP)

        self.traffic_btn = tk.Button(
            self.toolbar,
            text="Run Traffic (Ctrl+T)",
            command=self.simulate_traffic,
            bg="#1f222a",
            fg="#e0e0e0",
            activebackground="#2b2f38",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=8,
            pady=4,
        )
        self.traffic_btn.pack(side=tk.LEFT, padx=8, pady=6)

        self.ping_status = tk.Label(
            self.toolbar,
            text="Ping: idle",
            fg="#9e9e9e",
            bg="#0f1115",
            padx=6,
        )
        self.ping_status.pack(side=tk.LEFT, padx=(4, 10))

        # Hardware profile selectors (data-driven)
        self.router_profile_var = tk.StringVar(value="MODERN_ROUTER")
        self.switch_profile_var = tk.StringVar(value="MODERN_ACCESS_SWITCH")

        router_profiles = [p for p in sorted(HARDWARE_PROFILES.keys()) if "ROUTER" in p]
        switch_profiles = [p for p in sorted(HARDWARE_PROFILES.keys()) if "SWITCH" in p]

        tk.Label(self.toolbar, text="Router HW:", fg="#cccccc", bg="#0f1115").pack(side=tk.LEFT, padx=(4, 2))
        tk.OptionMenu(self.toolbar, self.router_profile_var, *router_profiles).pack(side=tk.LEFT, padx=(0, 8))

        tk.Label(self.toolbar, text="Switch HW:", fg="#cccccc", bg="#0f1115").pack(side=tk.LEFT, padx=(4, 2))
        tk.OptionMenu(self.toolbar, self.switch_profile_var, *switch_profiles).pack(side=tk.LEFT, padx=(0, 8))

        self.canvas = tk.Canvas(self.left, bg="#0f1115", width=1200, height=800, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        # Agent panel on the right
        self.agent_panel = None
        if AgentPanel is not None:
            self.agent_panel = AgentPanel(
                self.right,
                get_topology_cb=self.export_dict,
                apply_topology_cb=self._apply_topology_from_agent,
                log_event_cb=self.log_event,
            )
            self.agent_panel.pack(fill=tk.BOTH, expand=True)
        else:
            tk.Label(
                self.right,
                text="AgentPanel not available\n(simulation still works)",
                fg="#cccccc",
                bg="#14161b",
                justify="left",
            ).pack(anchor="nw", padx=10, pady=10)

        # Modes: neutral | router | switch | host
        self.mode = "neutral"

        # File state
        self.current_file = None

        # Data (canvas ids)
        self.nodes = {}  # node_canvas_id -> {"type": "router|switch|host", "seq": int}
        self.edges = []  # [{"line": line_id, "a": n1, "b": n2, "count": int, ...}, ...]
        self.edge_map = {}  # line_id -> edge dict (same object stored in self.edges)
        self.node_seq = 0

        # Stable IDs + labels (for JSON)
        self.node_uid = {}       # node_canvas_id -> stable uid (e.g., R1, SW1, PC1)
        self.uid_node = {}       # stable uid -> node_canvas_id
        self.node_labels = {}    # node_canvas_id -> label_canvas_id
        self.router_count = 0
        self.switch_count = 0
        self.host_count = 0

        # Simulator + CLI
        self.sim = TopologySim()
        self.sim_tick_job: Optional[str] = None
        self.ping_probe_job: Optional[str] = None

        # Visual stress engine: slow, perceptually-aware color evolution
        self.visual_engine = VisualStressEngine(enable_logging=True)

        # In-memory session log (saveable for debugging)
        self.session = SessionLogger()
        self.session.add("session_start", cwd=os.getcwd())

        # PDF-driven authority: scope gate for IOS-like CLI commands.
        # Override via env var TOPO_SIM_PDFS (semicolon-separated list of absolute paths).
        pdf_env = os.environ.get("TOPO_SIM_PDFS", "").strip()
        pdf_paths = [p.strip() for p in pdf_env.split(";") if p.strip()] if pdf_env else default_pdf_paths()
        try:
            self.authority = AuthorityModel.from_pdfs(pdf_paths)
        except Exception:
            self.authority = AuthorityModel.from_text("")

        # If PDFs are present but we couldn't extract any text, the authority model will deny
        # even valid CCNA/ENCOR commands.
        try:
            if getattr(self.authority, "topics_text", "") == "" and any(os.path.exists(p) for p in pdf_paths):
                messagebox.showwarning(
                    "Simulator authority disabled",
                    "CCNA/ENCOR PDFs were found, but text could not be extracted.\n\n"
                    "Install the optional dependency:\n"
                    "  python -m pip install pypdf\n\n"
                    "Until then, most IOS commands will be blocked by the authority model.",
                )
        except Exception:
            pass

        self.cli_engine = CLIEngine(self.sim, authority=self.authority)
        # Ungated engine for scripted provisioning (agent/MCP apply).
        # This prevents "config looked correct" but commands were blocked by authority.
        self.cli_engine_provision = CLIEngine(self.sim, authority=None)
        self.pc_cli_engine = PCCLIEngine(self.sim)
        self.cli_windows: Dict[str, "DeviceCLIWindow"] = {}

        # Node context menu
        self._ctx_node: Optional[int] = None
        self.node_menu = tk.Menu(self.root, tearoff=0)
        self.node_menu.add_command(label="Open CLI", command=self._open_cli_from_menu)

        # Edge context menu (useful for parallel links)
        self._ctx_edge: Optional[int] = None
        self.edge_menu = tk.Menu(self.root, tearoff=0)

        # Chain connect (sprout) + preview wire
        self.chain_node = None
        self.preview_line = None
        self.last_cursor = (0, 0)

        # Selection (nodes)
        self.selected_nodes = set()
        self.selection_box = None
        self.selection_start = None

        # Selection (edge)
        self.selected_edge = None

        # Ping mode (both buttons held on a device)
        self._buttons_down = set()  # {"L","R"}
        self.ping_mode = False
        self.ping_src_node: Optional[int] = None
        self.ping_src_uid: Optional[str] = None
        self._ping_src_prev_style = None  # (outline, width)

        # Right-click bookkeeping (menus open on release; also enables right-first ping mode)
        self._right_down_pos = None
        self._right_down_edge = None
        self._right_down_node = None
        self._right_moved_far = False
        self._suppress_right_menu = False

        # Dragging nodes
        self.dragging = False
        self.dragging_group = False
        self.dragging_node = None

        # Placement (router/switch/host)
        self.pending_place = False
        self.place_start = None

        # Click/drag tracking
        self.mouse_down_pos = None
        self.down_kind = None  # "node" | "edge" | "selectbox" | "place_or_select" | None
        self.down_node = None
        self.down_edge = None
        self.moved_far = False

        # For sprout-on-press safety
        self.pre_press_chain = None
        self.chain_set_on_press = False

        # Pan
        self.panning = False
        self.pan_last = None

        # Zoom
        self.zoom = 1.0

        # Navigation state
        self.nav_curr = None
        self.nav_prev = None

        self.build_menu()
        self.draw_legend()
        self.bind_events()
        self.update_title()

    def log_event(self, kind: str, **data):
        try:
            self.session.add(kind, **data)
        except Exception:
            pass

    def show_visual_stress_debug(self):
        """Print visual stress evolution logs to console (Ctrl+D)."""
        logs = self.visual_engine.format_logs(last_n=30)
        print("\n" + logs + "\n")
        # Also show current state for all entities
        print("Current Visual State:")
        print("-" * 50)
        for node_id, meta in self.nodes.items():
            uid = self.node_uid.get(node_id)
            if not uid:
                continue
            entity_id = f"device:{uid}"
            info = self.visual_engine.get_debug_info(entity_id)
            if info:
                print(f"  {uid}: vis_stress={info['visual']['visible_stress']:.3f} "
                      f"stress={info['stress']['stress_norm']:.3f} "
                      f"util={info['load']['utilization']:.1%} "
                      f"color={info['visual']['current_color']}")
        print()

    def _normalize_ios_provision_commands(self, cmds: List[str]) -> List[str]:
        # Goal: keep IOS realism (interfaces default down) while making agent-provided
        # deviceConfigs reliably usable by injecting missing "no shutdown".
        #
        # Rules:
        # - Inside each "interface X" stanza, if neither "shutdown" nor "no shutdown"
        #   is present before leaving the stanza, inject "no shutdown".
        # - If any subinterface "X.<vlan>" is configured but the parent "X" never is,
        #   inject a minimal parent stanza (interface X / no shutdown / exit) after
        #   entering global config.

        def _is_interface_cmd(s: str) -> bool:
            return s.lower().startswith("interface ")

        def _parse_ifname(s: str) -> Optional[str]:
            parts = s.split()
            if len(parts) < 2:
                return None
            return parts[1].strip()

        def _parent_of(ifname: str) -> Optional[str]:
            if "." not in ifname:
                return None
            return ifname.split(".", 1)[0]

        # Pass 1: discover subinterface parents and which physical interfaces are configured.
        subif_parents: set[str] = set()
        configured_ifaces: set[str] = set()
        for c in cmds:
            s = (c or "").strip()
            if not s or s.startswith("#"):
                continue
            if _is_interface_cmd(s):
                ifname = _parse_ifname(s)
                if ifname:
                    configured_ifaces.add(ifname)
                    parent = _parent_of(ifname)
                    if parent:
                        subif_parents.add(parent)

        missing_parents = sorted(p for p in subif_parents if p not in configured_ifaces)

        # Pass 2: inject missing parent stanzas after entering config mode (if possible).
        normalized: List[str] = []
        injected_parents = False

        def _inject_parent_blocks():
            nonlocal injected_parents
            if injected_parents or not missing_parents:
                return
            for p in missing_parents:
                normalized.extend([f"interface {p}", "no shutdown", "exit"])
            injected_parents = True

        for c in cmds:
            s = (c or "").strip()
            normalized.append(c)
            low = s.lower()
            if low in ("configure terminal", "conf t"):
                _inject_parent_blocks()

        # If we never saw config mode, inject parent blocks early (after enable if present).
        if missing_parents and not injected_parents:
            out2: List[str] = []
            inserted = False
            for c in normalized:
                out2.append(c)
                if not inserted and (c or "").strip().lower() == "enable":
                    out2.extend(["configure terminal"])
                    _inject_parent_blocks()
                    inserted = True
            if not inserted:
                out2 = ["configure terminal"]
                _inject_parent_blocks()
                out2.extend(normalized)
            normalized = out2

        # Pass 3: ensure each interface stanza has explicit admin state.
        out: List[str] = []
        in_if = False
        saw_admin = False

        for c in normalized:
            s = (c or "").strip()
            low = s.lower()

            if _is_interface_cmd(s):
                # Leaving previous interface stanza.
                if in_if and not saw_admin:
                    out.append("no shutdown")
                in_if = True
                saw_admin = False
                out.append(c)
                # Default forwarding ports/subinterfaces to UP unless explicitly shut later.
                out.append("no shutdown")
                saw_admin = True
                continue

            if in_if and low in ("exit", "end"):
                if not saw_admin:
                    out.append("no shutdown")
                out.append(c)
                in_if = False
                saw_admin = False
                continue

            if in_if and (low == "shutdown" or low == "no shutdown" or low.startswith("no shutdown ")):
                saw_admin = True

            out.append(c)

        if in_if and not saw_admin:
            out.append("no shutdown")

        # Ensure basic mode scaffolding exists: enable + conf t + closing end.
        lower_cmds = [c.strip().lower() for c in out]
        has_enable = any(c == "enable" for c in lower_cmds)
        has_conf = any(c in ("conf t", "configure terminal") for c in lower_cmds)
        has_end = any(c == "end" for c in lower_cmds)

        final: List[str] = []
        if not has_enable:
            final.append("enable")
        if not has_conf:
            final.append("configure terminal")

        final.extend(out)

        if not has_end:
            final.append("end")

        return final

    # ───────────────── Menu / JSON ─────────────────

    def build_menu(self):
        menubar = tk.Menu(self.root)

        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="New", accelerator="Ctrl+N", command=self.new_file)
        filemenu.add_command(label="Open…", accelerator="Ctrl+O", command=self.open_file_dialog)
        filemenu.add_separator()
        filemenu.add_command(label="Save", accelerator="Ctrl+S", command=self.save_file)
        filemenu.add_command(label="Save As…", accelerator="Ctrl+Shift+S", command=self.save_file_as)
        filemenu.add_separator()
        filemenu.add_command(label="Clear Canvas", command=self.clear_topology)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)

        menubar.add_cascade(label="File", menu=filemenu)

        sessionmenu = tk.Menu(menubar, tearoff=0)
        sessionmenu.add_command(label="Save Session Log…", command=self.save_session_log)
        sessionmenu.add_command(label="Clear Session Log", command=self.clear_session_log)
        sessionmenu.add_separator()
        sessionmenu.add_command(label="Simulate Traffic", command=self.simulate_traffic, accelerator="Ctrl+T")
        menubar.add_cascade(label="Session", menu=sessionmenu)

        self.root.config(menu=menubar)

    def save_session_log(self):
        # Save to the workspace root; remove previous session logs so the newest one replaces them.
        import os
        import glob
        from datetime import datetime

        base_dir = os.path.dirname(os.path.abspath(__file__))

        # Clean up existing session logs to effectively overwrite the previous one.
        try:
            for old in glob.glob(os.path.join(base_dir, "session_log_*.session.json")):
                try:
                    os.remove(old)
                except Exception:
                    pass
        except Exception:
            pass

        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        path = os.path.join(base_dir, f"session_log_{ts}.session.json")
        try:
            self.session.save_json(path)
        except Exception as e:
            messagebox.showerror("Session log", str(e))

    def clear_session_log(self):
        try:
            self.session.clear()
            self.session.add("session_cleared")
        except Exception:
            pass

    def _blend_color(self, c1: str, c2: str, t: float) -> str:
        t = max(0.0, min(1.0, t))
        c1 = c1.lstrip("#")
        c2 = c2.lstrip("#")
        r1, g1, b1 = int(c1[0:2], 16), int(c1[2:4], 16), int(c1[4:6], 16)
        r2, g2, b2 = int(c2[0:2], 16), int(c2[2:4], 16), int(c2[4:6], 16)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _color_for_stress(self, stress: float) -> str:
        # green -> yellow -> orange -> red
        stress = max(0.0, min(1.0, stress))
        if stress < 0.33:
            return self._blend_color("#4caf50", "#cddc39", stress / 0.33)
        if stress < 0.66:
            return self._blend_color("#cddc39", "#ff9800", (stress - 0.33) / 0.33)
        return self._blend_color("#ff9800", "#f44336", (stress - 0.66) / 0.34)

    def _color_for_util(self, util: float) -> str:
        util = max(0.0, util)
        if util < 0.5:
            return self._blend_color("#b0bec5", "#8bc34a", util / 0.5)
        if util < 1.0:
            return self._blend_color("#8bc34a", "#ffc107", (util - 0.5) / 0.5)
        return self._blend_color("#ffc107", "#f44336", min(1.0, util - 1.0))

    def _run_sim_tick(self):
        try:
            self.sim.tick()
        except Exception:
            self.sim_tick_job = None
            return

        # Feed simulation state into the visual stress engine
        self._sync_visual_engine()

        # Evolve visual state (slow, perceptual transitions)
        self.visual_engine.tick(self.sim.tick_interval_sec)

        # Render colors based on evolved visual state
        self.update_stress_visuals()

        # Kick ping probe to reflect current conditions.
        self._ensure_ping_probe()

        keep_running = self.sim.traffic_active
        if not keep_running:
            for l in self.sim.link_load.values():
                if l.get("utilization", 0.0) > 0.01 or l.get("load_mbps", 0.0) > 0.01:
                    keep_running = True
                    break
        if not keep_running:
            for d in self.sim.device_load.values():
                if d.get("stress_level", 0.0) > 0.01 or d.get("throughput_mbps", 0.0) > 0.01:
                    keep_running = True
                    break

        if keep_running:
            self.sim_tick_job = self.root.after(int(self.sim.tick_interval_sec * 1000), self._run_sim_tick)
        else:
            self.sim_tick_job = None

    def _ensure_sim_loop(self):
        if self.sim_tick_job is None:
            self.sim_tick_job = self.root.after(int(self.sim.tick_interval_sec * 1000), self._run_sim_tick)

    def _cancel_sim_loop(self):
        if self.sim_tick_job is not None:
            try:
                self.root.after_cancel(self.sim_tick_job)
            except Exception:
                pass
            self.sim_tick_job = None

    def _run_ping_probe(self):
        hosts = []
        for node_canvas_id, meta in self.nodes.items():
            if meta.get("type") != "host":
                continue
            uid = self.node_uid.get(node_canvas_id)
            if not uid:
                continue
            dev = self.sim.devices.get(uid)
            if not dev:
                continue
            ip_itf = next((itf for itf in dev.interfaces.values() if itf.ip), None)
            if ip_itf:
                hosts.append((uid, ip_itf.ip))

        if len(hosts) < 2:
            self.ping_status.config(text="Ping: idle", fg="#9e9e9e")
            self.ping_probe_job = None
            return

        src_uid, _ = hosts[0]
        _dst_uid, dst_ip = hosts[1]
        res = self.sim.ping(src_uid, dst_ip)
        summary = " ".join(res)
        color = "#8bc34a"
        if "Success rate is" in summary:
            try:
                rate_part = summary.split("Success rate is")[1].split("percent")[0].strip()
                pct = int(rate_part)
                if pct < 100:
                    color = "#ffc107"
                if pct < 70:
                    color = "#f44336"
            except Exception:
                pass
        self.ping_status.config(text=f"Ping {src_uid}->{dst_ip}: {summary}", fg=color)

        # Reschedule
        self.ping_probe_job = self.root.after(1000, self._run_ping_probe)

    def _ensure_ping_probe(self):
        if self.ping_probe_job is None:
            self.ping_probe_job = self.root.after(1000, self._run_ping_probe)

    def _cancel_ping_probe(self):
        if self.ping_probe_job is not None:
            try:
                self.root.after_cancel(self.ping_probe_job)
            except Exception:
                pass
            self.ping_probe_job = None

    def simulate_traffic(self):
        """Toggle continuous all-host traffic with sustained load."""
        host_uids = []
        for node_canvas_id, meta in self.nodes.items():
            if meta.get("type") == "host":
                uid = self.node_uid.get(node_canvas_id)
                if uid:
                    host_uids.append(uid)

        src_hosts = []
        for uid in host_uids:
            dev = self.sim.devices.get(uid)
            if not dev:
                continue
            ip_itf = next((itf for itf in dev.interfaces.values() if itf.ip), None)
            if ip_itf:
                src_hosts.append((uid, ip_itf.ip))

        if self.sim.traffic_active:
            self.sim.stop_traffic()
            self.log_event("simulate_traffic_stop", hosts=len(src_hosts))
            self.traffic_btn.config(text="Run Traffic (Ctrl+T)")
            self._ensure_sim_loop()  # allow cooling ticks
            self._cancel_ping_probe()
            self.ping_status.config(text="Traffic stopped. Cooling...", fg="#9e9e9e")
            return

        if len(src_hosts) < 2:
            messagebox.showwarning("Simulate Traffic", "Need at least two hosts with IP addresses to simulate traffic.")
            return

        # Start continuous traffic
        self.sim.start_traffic()
        flow_count = len(src_hosts) * (len(src_hosts) - 1)
        self.log_event("simulate_traffic_start", hosts=len(src_hosts), flows=flow_count)
        self.traffic_btn.config(text="Stop Traffic (Ctrl+T)")
        self._ensure_sim_loop()
        self._ensure_ping_probe()

        # Non-blocking indicator that persists while traffic runs
        self.ping_status.config(text="Traffic running…", fg="#8bc34a")

        sample_lines: List[str] = []
        if len(src_hosts) >= 2:
            s_uid, _ = src_hosts[0]
            _d_uid, d_ip = src_hosts[1]
            res = self.sim.ping(s_uid, d_ip)
            self.log_event("simulate_traffic_ping", src=s_uid, dst_ip=d_ip, output=res)
            sample_lines.append(f"{s_uid} -> {d_ip}: {'; '.join(res)}")

        msg = [f"Traffic running across {len(src_hosts)} hosts ({flow_count} flows)."]
        msg.append(f"Load ramps over ~{self.sim.ramp_seconds:.0f}s and cools when stopped.")
        if sample_lines:
            msg.append("\nSample ping:")
            msg.extend(sample_lines)

    def _sync_visual_engine(self):
        """Push current simulation load into the visual stress engine."""
        # Devices
        for node_id, meta in self.nodes.items():
            uid = self.node_uid.get(node_id)
            if not uid:
                continue
            dload = self.sim.device_load.get(uid, {})
            prof_name = dload.get("profile") or ""
            prof = HARDWARE_PROFILES.get(prof_name, HARDWARE_PROFILES.get("HOST_OPTIMIZED", {}))
            capacity = max(1.0, prof.get("max_forwarding_mbps", 1.0))
            util = dload.get("throughput_mbps", 0.0) / capacity
            loss = dload.get("drop_prob", 0.0)
            latency = dload.get("delay_ms", 0.0)
            # Register and update load for this device
            self.visual_engine.update_load(
                entity_id=f"device:{uid}",
                utilization=util,
                packet_loss=loss,
                latency_ms=latency,
            )

        # Links
        for edge in self.edges:
            sims = list(edge.get("sim_links", []) or [])
            if not sims:
                continue
            lid = sims[0].get("id")
            if not lid:
                continue
            lload = self.sim.link_load.get(lid, {})
            util = lload.get("utilization", 0.0)
            loss = lload.get("drop_prob", 0.0)
            # Queue depth only builds when utilization exceeds 80%
            queue = max(0.0, (util - 0.8) / 0.2) if util > 0.8 else 0.0
            self.visual_engine.update_load(
                entity_id=f"link:{lid}",
                utilization=util,
                packet_loss=loss,
                queue_depth=queue,
            )

    def update_stress_visuals(self):
        """
        Render colors using the VisualStressEngine's slowly-evolving visual state.
        Color is driven ONLY by visible_stress_norm, which changes gradually.
        """
        # Devices: color from visual engine
        for node_id, meta in self.nodes.items():
            uid = self.node_uid.get(node_id)
            if not uid:
                continue
            entity_id = f"device:{uid}"
            color = self.visual_engine.get_color(entity_id)
            self.canvas.itemconfig(node_id, fill=color)

        # Links: color from visual engine
        for edge in self.edges:
            sims = list(edge.get("sim_links", []) or [])
            if not sims:
                continue
            lid = sims[0].get("id")
            if not lid:
                continue
            entity_id = f"link:{lid}"
            color = self.visual_engine.get_color(entity_id)
            vis_stress = self.visual_engine.get_visible_stress(entity_id)
            # Width grows slowly with visible stress
            width = EDGE_WIDTH + min(4, vis_stress * 4)
            try:
                self.canvas.itemconfig(edge["line"], fill=color, width=width)
            except Exception:
                pass

    def new_file(self):
        self.clear_topology()
        self.current_file = None

    def open_file_dialog(self):
        path = filedialog.askopenfilename(
            title="Open topology JSON",
            filetypes=[("Topology JSON", "*.topo.json *.json"), ("All files", "*.*")]
        )
        if not path:
            return
        self.load_from_path(path)

    def save_file(self):
        if self.current_file:
            self.save_to_path(self.current_file)
        else:
            self.save_file_as()

    def save_file_as(self):
        path = filedialog.asksaveasfilename(
            title="Save topology JSON",
            defaultextension=".topo.json",
            filetypes=[("Topology JSON", "*.topo.json"), ("JSON", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        self.current_file = path
        self.save_to_path(path)

    def export_dict(self):
        nodes_out = []
        for node_canvas_id, meta in self.nodes.items():
            uid = self.node_uid.get(node_canvas_id)
            if not uid:
                continue
            cx, cy = self.get_center(node_canvas_id)
            hw = self.sim.devices.get(uid).hardware_profile if self.sim.devices.get(uid) else None
            nodes_out.append({
                "id": uid,
                "type": meta.get("type", "router"),
                "x": cx,
                "y": cy,
                "seq": meta.get("seq", 0),
                "hardwareProfile": hw,
            })

        nodes_out.sort(key=lambda n: (n.get("type", ""), n.get("seq", 0), n.get("id", "")))

        links_out = []
        seen = set()
        for e in self.edges:
            n1, n2 = e["a"], e["b"]
            a = self.node_uid.get(n1)
            b = self.node_uid.get(n2)
            if not a or not b:
                continue
            key = tuple(sorted((a, b)))
            if key in seen:
                continue
            seen.add(key)

            out = {"a": a, "b": b, "type": "ethernet"}
            if e.get("count", 1) > 1:
                out["count"] = e["count"]   # persisted multiplicity (still no UI numbers)
            if e.get("sim_links"):
                out["ifaces"] = [
                    {"a_if": s.get("a_if"), "b_if": s.get("b_if")}
                    for s in e.get("sim_links", [])
                ]
            links_out.append(out)

        links_out.sort(key=lambda e: (e["a"], e["b"]))

        device_cfg = {}
        for uid in sorted(self.sim.devices.keys()):
            device_cfg[uid] = self.sim.export_device_config(uid)

        return {
            "schemaVersion": SCHEMA_VERSION,
            "meta": {"name": "Topology"},
            "nodes": nodes_out,
            "links": links_out,
            "deviceConfigs": device_cfg,
        }

    def save_to_path(self, path: str):
        try:
            data = self.export_dict()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def load_from_path(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.load_from_dict(data)
            self.current_file = path
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def load_from_dict(self, data: dict):
        self.log_event(
            "load_topology",
            schemaVersion=data.get("schemaVersion"),
            nodeCount=len(data.get("nodes") or []),
            linkCount=len(data.get("links") or []),
            hasDeviceConfigs=bool(data.get("deviceConfigs")),
        )
        if not isinstance(data, dict):
            raise ValueError("Invalid JSON: expected an object at top-level")

        nodes = data.get("nodes", [])
        links = data.get("links", [])

        if not isinstance(nodes, list) or not isinstance(links, list):
            raise ValueError("Invalid JSON: 'nodes' and 'links' must be lists")

        self.clear_topology()

        # Create nodes first
        for n in nodes:
            if not isinstance(n, dict):
                continue
            uid = n.get("id")
            ntype = n.get("type", "router")
            x = n.get("x")
            y = n.get("y")
            hw = n.get("hardwareProfile") or n.get("hardware_profile")
            if not uid or x is None or y is None:
                continue
            self._create_node_of_type(str(ntype), float(x), float(y), forced_uid=str(uid), hardware_profile=hw)

        # Then links
        for e in links:
            if not isinstance(e, dict):
                continue
            a = e.get("a")
            b = e.get("b")
            if not a or not b:
                continue
            n1 = self.uid_node.get(str(a))
            n2 = self.uid_node.get(str(b))
            if not n1 or not n2 or n1 == n2:
                continue

            count = int(e.get("count", 1))
            if count < 1:
                count = 1

            ifaces = e.get("ifaces")
            if not isinstance(ifaces, list):
                ifaces = None

            for _ in range(count):
                a_if = None
                b_if = None
                if ifaces and _ < len(ifaces) and isinstance(ifaces[_], dict):
                    a_if = ifaces[_].get("a_if")
                    b_if = ifaces[_].get("b_if")
                self.connect_nodes(n1, n2, a_if=a_if, b_if=b_if)

        cfgs = data.get("deviceConfigs")

        # 1) Legacy dict form: {"R1": {...export_device_config...}}
        if isinstance(cfgs, dict):
            for uid, cfg in cfgs.items():
                uid = str(uid)
                if uid in self.sim.devices and isinstance(cfg, dict):
                    self.sim.import_device_config(uid, cfg)
                    self.log_event("apply_device_config_dict", uid=uid)

        # 2) List form (structured-output friendly):
        #    - {"id":"R1","config":{...}}  (dict config)
        #    - {"id":"R1","cli":"ios","commands":[...]} (command list)
        if isinstance(cfgs, list):
            # Apply dict-config entries first (if present)
            as_dict = {}
            cli_jobs = []
            for item in cfgs:
                if not isinstance(item, dict):
                    continue
                uid = item.get("id")
                if not isinstance(uid, str):
                    continue
                if "config" in item and isinstance(item.get("config"), dict):
                    as_dict[uid] = item.get("config")
                elif "commands" in item and isinstance(item.get("commands"), list):
                    cli_jobs.append(item)

            for uid, cfg in as_dict.items():
                if uid in self.sim.devices and isinstance(cfg, dict):
                    self.sim.import_device_config(uid, cfg)
                    self.log_event("apply_device_config_dict", uid=uid)

            # Then execute command lists via the appropriate CLI engine
            for job in cli_jobs:
                uid = str(job.get("id"))
                if uid not in self.sim.devices:
                    continue
                cli_kind = (job.get("cli") or "").lower().strip()
                cmds = [c for c in job.get("commands", []) if isinstance(c, str)]
                if not cmds:
                    continue

                self.log_event("apply_device_commands_start", uid=uid, cli=cli_kind, commandCount=len(cmds))

                executed = 0
                had_error = False

                try:
                    dev = self.sim.devices.get(uid)
                    if dev is None:
                        continue

                    if cli_kind == "pc" or dev.kind == "host":
                        ctx = self.pc_cli_engine.new_context(uid)
                        for c in cmds:
                            s = c.strip()
                            if not s or s.startswith("#"):
                                continue
                            executed += 1
                            res = self.pc_cli_engine.execute(ctx, s)
                            if getattr(res, "output", ""):
                                self.log_event("apply_device_command_output", uid=uid, cli="pc", command=s, output=res.output)
                    else:
                        # Provisioning must not be blocked by authority gating.
                        ctx = self.cli_engine_provision.new_context(uid)
                        cmds_norm = self._normalize_ios_provision_commands(cmds)
                        for c in cmds_norm:
                            s = c.strip()
                            if not s or s.startswith("#"):
                                continue
                            executed += 1
                            res = self.cli_engine_provision.execute(ctx, s)
                            if getattr(res, "output", ""):
                                self.log_event("apply_device_command_output", uid=uid, cli="ios", command=s, output=res.output)
                except Exception as e:
                    # Don't fail load because a config line was rejected.
                    had_error = True
                    self.log_event("apply_device_commands_error", uid=uid, error=str(e))
                    pass

                self.log_event("apply_device_commands_done", uid=uid, executed=executed, ok=(not had_error))

        self.update_edges()
        self.mode = "neutral"
        self.update_title()
        self.log_event("load_topology_done", nodeCount=len(self.nodes), edgeCount=len(self.edges))

    def _apply_topology_from_agent(self, topo_dict: dict):
        # Wrap so the agent panel can call it safely
        self.load_from_dict(topo_dict)

    # ───────────────── UI ─────────────────

    def draw_legend(self):
        self.canvas.create_rectangle(10, 10, 320, 205, fill="#1a1d23", outline="#444", tags="legend")
        self.canvas.create_text(165, 25, text="LEGEND / CONTROLS", fill="white",
                                font=("Arial", 11, "bold"), tags="legend")

        self.canvas.create_oval(30, 45, 60, 75, fill="#4fc3f7", outline="", tags="legend")
        self.canvas.create_text(205, 60, text="Router (R) - click to place", fill="white", tags="legend")

        self.canvas.create_rectangle(30, 80, 60, 110, fill="#81c784", outline="", tags="legend")
        self.canvas.create_text(205, 95, text="Switch (S) - click to place", fill="white", tags="legend")

        self.canvas.create_rectangle(30, 115, 60, 145, fill="#ffb74d", outline="", tags="legend")
        self.canvas.create_text(205, 130, text="Host / PC (H) - click to place", fill="white", tags="legend")

        self.canvas.create_line(30, 165, 60, 165, fill=EDGE_COLOR, width=EDGE_WIDTH, tags="legend")
        self.canvas.create_text(205, 165, text="Neutral (ESC) - pan/zoom/select", fill="white", tags="legend")

        self.canvas.create_text(165, 188, text="Delete (D / Del / Backspace)", fill="#cccccc", tags="legend")
        self.canvas.create_text(165, 203, text="Clear (C)", fill="#ff8a80", tags="legend")

    def bind_events(self):
        # ---- Canvas-focused hotkeys ----
        # NOTE: bind hotkeys to the canvas so typing in the agent panel isn't hijacked.
        self.canvas.bind("<KeyPress-r>", lambda e: self.set_mode("router"))
        self.canvas.bind("<KeyPress-R>", lambda e: self.set_mode("router"))

        # 's' is special: down-navigation when a node is focused; otherwise switch-mode.
        self.canvas.bind("<KeyPress-s>", self._on_s_key)
        self.canvas.bind("<KeyPress-S>", lambda e: self.set_mode("switch"))

        self.canvas.bind("<KeyPress-h>", lambda e: self.set_mode("host"))
        self.canvas.bind("<KeyPress-H>", lambda e: self.set_mode("host"))

        self.canvas.bind("<KeyPress-c>", lambda e: self.clear_topology())
        self.canvas.bind("<KeyPress-C>", lambda e: self.clear_topology())

        # ESC is the primary "neutral + free pan/zoom" key
        self.canvas.bind("<Escape>", self.on_escape_to_neutral)

        # Delete: use capital D + Delete/Backspace to avoid colliding with WASD navigation.
        self.canvas.bind("<KeyPress-D>", lambda e: self.delete_selected())
        self.canvas.bind("<Delete>", lambda e: self.delete_selected())
        self.canvas.bind("<BackSpace>", lambda e: self.delete_selected())

        # WASD navigation (only when a node context exists)
        self.canvas.bind("<KeyPress-w>", lambda e: self._wasd_nav_or_ignore("up"))
        self.canvas.bind("<KeyPress-a>", lambda e: self._wasd_nav_or_ignore("left"))
        self.canvas.bind("<KeyPress-d>", lambda e: self._wasd_nav_or_ignore("right"))

        # (Optional) keep arrows too (canvas-focused)
        self.canvas.bind("<Up>", lambda e: self.navigate_neighbor_dir("up"))
        self.canvas.bind("<Left>", lambda e: self.navigate_neighbor_dir("left"))
        self.canvas.bind("<Down>", lambda e: self.navigate_neighbor_dir("down"))
        self.canvas.bind("<Right>", lambda e: self.navigate_neighbor_dir("right"))

        # ---- File shortcuts (global) ----
        self.root.bind_all("<Control-n>", lambda e: self.new_file())
        self.root.bind_all("<Control-o>", lambda e: self.open_file_dialog())
        self.root.bind_all("<Control-s>", lambda e: self.save_file())
        self.root.bind_all("<Control-Shift-s>", lambda e: self.save_file_as())
        self.root.bind_all("<Control-Shift-S>", lambda e: self.save_file_as())
        self.root.bind_all("<Control-t>", lambda e: self.simulate_traffic())
        self.root.bind_all("<Control-d>", lambda e: self.show_visual_stress_debug())

        # ---- Mouse ----
        self.canvas.bind("<Button-1>", self.on_mouse_down)
        self.canvas.bind("<B1-Motion>", self.on_mouse_drag)
        self.canvas.bind("<ButtonRelease-1>", self.on_mouse_up)

        # Double-click a device to open CLI
        self.canvas.bind("<Double-Button-1>", self.on_double_click)

        # Pan (right click drag on empty space) — Button-3 (Windows/Linux), Button-2 (some mac trackpads)
        self.canvas.bind("<Button-3>", self.on_pan_down)
        self.canvas.bind("<B3-Motion>", self.on_pan_drag)
        self.canvas.bind("<ButtonRelease-3>", self.on_pan_up)
        self.canvas.bind("<Button-2>", self.on_pan_down)
        self.canvas.bind("<B2-Motion>", self.on_pan_drag)
        self.canvas.bind("<ButtonRelease-2>", self.on_pan_up)

        # Zoom
        self.canvas.bind("<MouseWheel>", self.on_mouse_wheel)  # Windows/macOS
        self.canvas.bind("<Button-4>", lambda e: self.on_linux_wheel(+1, e))  # Linux
        self.canvas.bind("<Button-5>", lambda e: self.on_linux_wheel(-1, e))  # Linux

        # Preview wire follow
        self.canvas.bind("<Motion>", self.on_mouse_move)

        # Focus canvas by default so hotkeys work immediately after a click.
        self.canvas.focus_set()

    def _has_nav_context(self) -> bool:
        """True if user is currently focused on a node (selection or chain head)."""
        if self.nav_curr is not None and self.nav_curr in self.nodes:
            return True
        if self.chain_node is not None and self.chain_node in self.nodes:
            return True
        if len(self.selected_nodes) == 1:
            n = next(iter(self.selected_nodes))
            return n in self.nodes
        return False

    def _wasd_nav_or_ignore(self, direction: str):
        """
        Use WASD for neighbor navigation only when a node is selected / focused.
        Otherwise, do nothing so keys like 'd' don't interfere with general operation.
        """
        if self._has_nav_context():
            self.navigate_neighbor_dir(direction)
            return "break"
        return None

    def _on_s_key(self, event):
        # If you have a focused node, 's' navigates DOWN.
        # Otherwise, 's' enters Switch placement mode.
        if self._has_nav_context():
            self.navigate_neighbor_dir("down")
            return "break"
        self.set_mode("switch")
        return "break"

    def update_title(self):
        base = f"Mode: {self.mode.upper()}"
        if self.current_file:
            base += f" — {self.current_file}"
        if getattr(self, "ping_mode", False) and self.ping_src_uid:
            base += f" — PING MODE: source={self.ping_src_uid} (click target)"
        self.root.title(base)

    # ───────────────── ESC => Neutral ─────────────────

    def on_escape_to_neutral(self, event=None):
        self.mode = "neutral"
        self.cancel_transients(keep_selection=False)
        self.update_title()

    def cancel_transients(self, keep_selection: bool):
        self._cancel_ping_mode()
        self.chain_node = None
        self._remove_preview()

        self.pending_place = False
        self.place_start = None

        self.dragging = False
        self.dragging_group = False
        self.dragging_node = None

        if self.selection_box:
            self.canvas.delete(self.selection_box)
            self.selection_box = None
        self.selection_start = None

        self.deselect_edge()

        self.moved_far = False
        self.mouse_down_pos = None
        self.down_kind = None
        self.down_node = None
        self.down_edge = None

        self.pre_press_chain = None
        self.chain_set_on_press = False

        self.panning = False
        self.pan_last = None

        self.nav_curr = None
        self.nav_prev = None

        if not keep_selection:
            self.clear_selection()

    # ───────────────── Ping mode ─────────────────

    def _cancel_ping_mode(self):
        if not getattr(self, "ping_mode", False):
            return
        try:
            if self.ping_src_node is not None and self._ping_src_prev_style is not None:
                outline, width = self._ping_src_prev_style
                # Restore prior visual style.
                self.canvas.itemconfigure(self.ping_src_node, outline=outline, width=width)
        except Exception:
            pass
        self.ping_mode = False
        self.ping_src_node = None
        self.ping_src_uid = None
        self._ping_src_prev_style = None
        self.update_title()
        self.log_event("ping_mode_cancel")

    def _start_ping_mode(self, node_id: int):
        if node_id not in self.nodes:
            return
        uid = self.node_uid.get(node_id)
        if not uid:
            return

        # If we're already in ping mode, restart with new source.
        self._cancel_ping_mode()
        self.ping_mode = True
        self.ping_src_node = node_id
        self.ping_src_uid = uid

        try:
            prev_outline = self.canvas.itemcget(node_id, "outline")
            prev_width = self.canvas.itemcget(node_id, "width")
            self._ping_src_prev_style = (prev_outline, prev_width)
            # Distinct highlight for ping source.
            self.canvas.itemconfigure(node_id, outline="#ab47bc", width=3)
        except Exception:
            self._ping_src_prev_style = None

        # Ping-mode should not also pan/drag/chain.
        self.deselect_edge()
        self._remove_preview()
        self.chain_node = None
        self.pending_place = False
        self.place_start = None
        self.selection_box = None
        self.selection_start = None

        self.update_title()
        self.log_event("ping_mode_start", src=self.ping_src_uid)

    def _pick_device_ip(self, uid: str) -> Optional[str]:
        dev = self.sim.devices.get(uid)
        if dev is None:
            return None
        # Hosts default to Eth0.
        if dev.kind == "host":
            itf = dev.interfaces.get("Eth0")
            if itf and itf.admin_up and itf.ip:
                return str(itf.ip)
            return None

        # Routers/switches: pick first up interface with an IP.
        for ifn in sorted(dev.interfaces.keys()):
            itf = dev.interfaces.get(ifn)
            if itf and itf.admin_up and itf.ip:
                return str(itf.ip)
        return None

    def _run_ping_mode(self, dst_node_id: int):
        if not self.ping_mode or not self.ping_src_uid:
            return
        if dst_node_id not in self.nodes:
            return

        dst_uid = self.node_uid.get(dst_node_id)
        if not dst_uid:
            return

        dst_ip = self._pick_device_ip(dst_uid)
        if not dst_ip:
            messagebox.showwarning(
                "Ping mode",
                f"Target {dst_uid} has no configured IP address to ping.\n\n"
                f"Tip: configure an interface IP first (or for PCs: 'ip <ip> <mask> [gateway]').",
            )
            self._cancel_ping_mode()
            return

        lines = self.sim.ping(self.ping_src_uid, dst_ip)
        self.log_event(
            "ping_mode_result",
            src=self.ping_src_uid,
            dst=dst_uid,
            dst_ip=dst_ip,
            output="\n".join(lines),
        )
        messagebox.showinfo(
            "Ping mode",
            f"{self.ping_src_uid} -> {dst_uid} ({dst_ip})\n\n" + "\n".join(lines),
        )
        self._cancel_ping_mode()

    def set_mode(self, mode):
        self.mode = mode
        self.cancel_transients(keep_selection=True)
        self.update_title()

    # ───────────────── Node selection ─────────────────

    def clear_selection(self):
        for n in list(self.selected_nodes):
            self.set_node_highlight(n, False)
        self.selected_nodes.clear()

    def set_node_highlight(self, node, on: bool):
        if on:
            self.canvas.itemconfigure(node, outline="#ffd54f", width=3)
        else:
            self.canvas.itemconfigure(node, outline="", width=0)

    def _apply_focus(self, node):
        if node not in self.nodes:
            return
        self.deselect_edge()
        self.clear_selection()
        self.selected_nodes.add(node)
        self.set_node_highlight(node, True)
        self.chain_node = node
        self._ensure_preview(*self.last_cursor)

    def _start_selection_box(self, x, y):
        self._remove_preview()
        self.chain_node = None
        self.deselect_edge()
        self.clear_selection()

        self.selection_start = (x, y)
        self.selection_box = self.canvas.create_rectangle(
            x, y, x, y,
            outline="#4fc3f7", dash=(4, 2),
            tags=("ui",)
        )

    # ───────────────── Selection box logic ─────────────────

    def update_group_selection(self, x1, y1, x2, y2):
        new_sel = set()
        minx, maxx = min(x1, x2), max(x1, x2)
        miny, maxy = min(y1, y2), max(y1, y2)

        for node in self.nodes:
            cx, cy = self.get_center(node)
            if minx <= cx <= maxx and miny <= cy <= maxy:
                new_sel.add(node)

        for node in list(self.selected_nodes - new_sel):
            self.set_node_highlight(node, False)
        for node in list(new_sel - self.selected_nodes):
            self.set_node_highlight(node, True)

        self.selected_nodes = new_sel

    # ───────────────── Preview wire ─────────────────

    def _ensure_preview(self, x, y):
        if self.chain_node is None:
            self._remove_preview()
            return
        if self.selection_box or self.dragging or self.panning:
            self._remove_preview()
            return

        x1, y1 = self.get_center(self.chain_node)

        if self.preview_line is None:
            self.preview_line = self.canvas.create_line(
                x1, y1, x, y,
                fill=EDGE_COLOR,
                width=EDGE_WIDTH,
                dash=PREVIEW_DASH,
                tags=("ui",)
            )
            self.canvas.tag_lower(self.preview_line)
        else:
            self.canvas.coords(self.preview_line, x1, y1, x, y)

    def _remove_preview(self):
        if self.preview_line is not None:
            self.canvas.delete(self.preview_line)
            self.preview_line = None

    def on_mouse_move(self, event):
        self.last_cursor = (event.x, event.y)
        self._ensure_preview(event.x, event.y)

    # ───────────────── Directional navigation ─────────────────

    def _nav_anchor(self) -> Optional[int]:
        """Return the current node to navigate from."""
        if self.nav_curr is not None and self.nav_curr in self.nodes:
            return self.nav_curr
        if self.chain_node is not None and self.chain_node in self.nodes:
            self.nav_curr = self.chain_node
            self.nav_prev = None
            return self.nav_curr
        if len(self.selected_nodes) == 1:
            cur = next(iter(self.selected_nodes))
            if cur in self.nodes:
                self.nav_curr = cur
                self.nav_prev = None
                return cur
        return None

    def navigate_neighbor_dir(self, direction: str):
        """Move to a connected neighbor based on direction (only among connected nodes)."""
        if self.selection_box or self.dragging or self.panning:
            return

        cur = self._nav_anchor()
        if cur is None:
            return

        adj = self.build_adjacency()
        neighbors = [n for n in adj.get(cur, []) if n in self.nodes]
        if not neighbors:
            return

        cx, cy = self.get_center(cur)

        candidates = []
        for n in neighbors:
            nx, ny = self.get_center(n)
            dx = nx - cx
            dy = ny - cy  # Tk y increases downward
            candidates.append((n, dx, dy))

        if direction == "right":
            cand = [(n, dx, dy) for (n, dx, dy) in candidates if dx > 0]
            if not cand:
                return
            nxt = max(cand, key=lambda t: (t[1], -abs(t[2])))[0]

        elif direction == "left":
            cand = [(n, dx, dy) for (n, dx, dy) in candidates if dx < 0]
            if not cand:
                return
            nxt = min(cand, key=lambda t: (t[1], abs(t[2])))[0]

        elif direction == "up":
            cand = [(n, dx, dy) for (n, dx, dy) in candidates if dy < 0]
            if not cand:
                return
            nxt = min(cand, key=lambda t: (t[2], abs(t[1])))[0]

        elif direction == "down":
            cand = [(n, dx, dy) for (n, dx, dy) in candidates if dy > 0]
            if not cand:
                return
            nxt = max(cand, key=lambda t: (t[2], -abs(t[1])))[0]

        else:
            return

        self.nav_prev = cur
        self.nav_curr = nxt
        self._apply_focus(nxt)

    def build_adjacency(self):
        adj = {n: [] for n in self.nodes}
        for e in self.edges:
            n1, n2 = e["a"], e["b"]
            if n1 in self.nodes and n2 in self.nodes:
                adj[n1].append(n2)
                adj[n2].append(n1)
        return adj

    # ───────────────── Device CLI ─────────────────

    def _open_cli_from_menu(self):
        if self._ctx_node is None:
            return
        uid = self.node_uid.get(self._ctx_node)
        if not uid:
            return
        self.open_cli(uid)

    def on_double_click(self, event):
        node = self.get_node_at(event.x, event.y)
        if node is None:
            return
        uid = self.node_uid.get(node)
        if not uid:
            return
        self.open_cli(uid)

    def open_cli(self, uid: str):
        if uid in self.cli_windows and self.cli_windows[uid].alive():
            self.cli_windows[uid].focus()
            return
        kind = "router"
        try:
            kind = self.sim.devices.get(uid).kind
        except Exception:
            kind = "router"

        if kind == "host":
            win = DeviceCLIWindow(
                self.root,
                uid,
                self.pc_cli_engine,
                banner=f"{uid} PC CLI (lightweight)",
                log_cb=self.log_event,
            )
        else:
            win = DeviceCLIWindow(
                self.root,
                uid,
                self.cli_engine,
                banner=f"{uid} IOS-like CLI (lightweight)",
                log_cb=self.log_event,
            )
        self.cli_windows[uid] = win

    # ───────────────── Edge context menu ─────────────────

    def _rebuild_edge_menu(self, line_id: int):
        self.edge_menu.delete(0, tk.END)

        edge = self.edge_map.get(line_id)
        if not edge:
            self.edge_menu.add_command(label="(No link)")
            return

        a_uid = self.node_uid.get(edge.get("a"))
        b_uid = self.node_uid.get(edge.get("b"))

        def fmt_conn(idx: int, s: dict) -> str:
            a_if = s.get("a_if")
            b_if = s.get("b_if")
            if a_uid and b_uid and a_if and b_if:
                return f"Remove {idx + 1}: {a_uid} {a_if} <-> {b_uid} {b_if}"
            return f"Remove {idx + 1}"

        self.edge_menu.add_command(label="Remove entire link", command=lambda lid=line_id: self._delete_edge(lid))

        sims = list(edge.get("sim_links", []) or [])
        if not sims:
            return

        if len(sims) == 1:
            self.edge_menu.add_command(label=fmt_conn(0, sims[0]), command=lambda lid=line_id: self._remove_edge_connection(lid, 0))
            return

        self.edge_menu.add_separator()
        for idx, s in enumerate(sims):
            self.edge_menu.add_command(
                label=fmt_conn(idx, s),
                command=lambda lid=line_id, i=idx: self._remove_edge_connection(lid, i),
            )

    def _remove_edge_connection(self, line_id: int, index: int):
        edge = self.edge_map.get(line_id)
        if not edge:
            return
        sims = list(edge.get("sim_links", []) or [])
        if index < 0 or index >= len(sims):
            return

        s = sims.pop(index)

        self.log_event(
            "remove_parallel_connection",
            a=self.node_uid.get(edge.get("a")),
            b=self.node_uid.get(edge.get("b")),
            removed={"a_if": s.get("a_if"), "b_if": s.get("b_if"), "id": s.get("id")},
            remaining=len(sims),
        )

        # Remove sim link
        try:
            self.sim.remove_link(s.get("id"))
        except Exception:
            pass

        # Prune default/disconnected interfaces to avoid confusion
        try:
            a_uid = self.node_uid.get(edge.get("a"))
            b_uid = self.node_uid.get(edge.get("b"))
            if a_uid and s.get("a_if"):
                self.sim.maybe_prune_interface(a_uid, str(s.get("a_if")))
            if b_uid and s.get("b_if"):
                self.sim.maybe_prune_interface(b_uid, str(s.get("b_if")))
        except Exception:
            pass

        edge["sim_links"] = sims
        edge["count"] = len(sims)

        # If that was the last connection, delete the visual edge as well.
        if edge["count"] <= 0:
            self._delete_edge(line_id)
            return

        self._update_edge_dots(edge)

    # ───────────────── Edge selection ─────────────────

    def select_edge(self, line_id):
        if self.selected_edge == line_id:
            return
        self.deselect_edge()
        self.selected_edge = line_id
        self.canvas.itemconfigure(self.selected_edge, fill=EDGE_HIGHLIGHT_COLOR, width=EDGE_HIGHLIGHT_WIDTH)

    def deselect_edge(self):
        if self.selected_edge is not None:
            if self.selected_edge in self.edge_map:
                self.canvas.itemconfigure(self.selected_edge, fill=EDGE_COLOR, width=EDGE_WIDTH)
            self.selected_edge = None

    # ───────────────── Delete ─────────────────

    def delete_selected(self):
        if self.selected_edge is not None:
            self._delete_edge(self.selected_edge)
            self.selected_edge = None
            return

        if self.selected_nodes:
            doomed = set(self.selected_nodes)
            self._delete_nodes(doomed)
            self.clear_selection()
            self.chain_node = None
            self._remove_preview()

            if self.nav_curr in doomed or self.nav_prev in doomed:
                self.nav_curr = None
                self.nav_prev = None
            return

    def _delete_edge(self, line_id):
        edge = self.edge_map.pop(line_id, None)
        if edge is None:
            return

        for dot in edge["dots"].values():
            self.canvas.delete(dot)

        self.canvas.delete(edge["line"])
        if edge in self.edges:
            self.edges.remove(edge)

    def _delete_nodes(self, nodes_to_delete: set):
        self.deselect_edge()

        try:
            doomed = []
            for n in nodes_to_delete:
                uid = self.node_uid.get(n)
                if uid:
                    doomed.append(uid)
            if doomed:
                self.log_event("delete_nodes", count=len(doomed), nodes=sorted(doomed))
        except Exception:
            pass

        # remove edges touching doomed nodes
        to_remove = []
        for e in self.edges:
            if e["a"] in nodes_to_delete or e["b"] in nodes_to_delete:
                to_remove.append(e["line"])
        for ln in to_remove:
            self._delete_edge(ln)

        # remove nodes + labels + uid mapping
        for n in nodes_to_delete:
            if n in self.nodes:
                lbl = self.node_labels.pop(n, None)
                if lbl is not None:
                    self.canvas.delete(lbl)

                uid = self.node_uid.pop(n, None)
                if uid is not None:
                    self.uid_node.pop(uid, None)

                self.canvas.delete(n)
                self.nodes.pop(n, None)

    # ───────────────── Clear topology ─────────────────

    def clear_topology(self):
        self.log_event(
            "clear_topology",
            nodeCount=len(self.nodes),
            edgeCount=len(self.edges),
        )
        self._cancel_sim_loop()
        self._cancel_ping_probe()
        self.traffic_btn.config(text="Run Traffic (Ctrl+T)")
        self.ping_status.config(text="Ping: idle", fg="#9e9e9e")
        self.canvas.delete("all")
        self.nodes.clear()
        self.edges.clear()
        self.edge_map.clear()
        self.node_seq = 0
        self.zoom = 1.0

        # Simulator + CLI windows
        for w in list(self.cli_windows.values()):
            try:
                w.close()
            except Exception:
                pass
        self.cli_windows.clear()
        self.sim.reset()

        # Clear visual stress engine state
        self.visual_engine.clear_all()

        self.node_uid.clear()
        self.uid_node.clear()
        self.node_labels.clear()
        self.router_count = 0
        self.switch_count = 0
        self.host_count = 0

        self.mode = "neutral"
        self.chain_node = None
        self._remove_preview()
        self.clear_selection()
        self.deselect_edge()

        self.selection_box = None
        self.selection_start = None
        self.pending_place = False
        self.place_start = None

        self.nav_curr = None
        self.nav_prev = None

        self.draw_legend()
        self.update_title()

    # ───────────────── Pan (right drag empty space) ─────────────────

    def on_pan_down(self, event):
        self.canvas.focus_set()
        self.log_event("mouse_right_down", x=event.x, y=event.y)

        # Track right button state (for ping mode).
        self._buttons_down.add("R")
        self._right_down_pos = (event.x, event.y)
        self._right_moved_far = False
        self._suppress_right_menu = False

        # If left is already held and we're on a node, enter ping mode.
        node_now = self.get_node_at(event.x, event.y)
        if node_now is not None and "L" in self._buttons_down:
            self._suppress_right_menu = True
            self._start_ping_mode(node_now)
            return

        # Defer edge/node menus until button release so right-first ping mode works.
        self._right_down_edge = self.get_edge_at(event.x, event.y)
        self._right_down_node = node_now

        # If right press began on edge/node, we do NOT start panning.
        if self._right_down_edge is not None or self._right_down_node is not None:
            return

        if self.mode != "neutral":
            return
        if self.chain_node is not None:
            return
        if self.selected_nodes or self.selected_edge is not None or self.selection_box is not None:
            return
        if self.get_node_at(event.x, event.y) is not None:
            return
        if self.get_edge_at(event.x, event.y) is not None:
            return

        self.panning = True
        self.pan_last = (event.x, event.y)

    def on_pan_drag(self, event):
        # If user moves while right button is down, treat as drag (suppress menus).
        if self._right_down_pos is not None and not self._right_moved_far:
            if abs(event.x - self._right_down_pos[0]) > DRAG_THRESHOLD or abs(event.y - self._right_down_pos[1]) > DRAG_THRESHOLD:
                self._right_moved_far = True

        if not self.panning or self.pan_last is None:
            return

        dx = event.x - self.pan_last[0]
        dy = event.y - self.pan_last[1]
        self.pan_last = (event.x, event.y)

        self.canvas.move("topo", dx, dy)
        self.last_cursor = (event.x, event.y)

    def on_pan_up(self, event):
        # Clear right button state.
        self._buttons_down.discard("R")

        # End panning if we were panning.
        if self.panning:
            self.panning = False
            self.pan_last = None
            self.last_cursor = (event.x, event.y)

        # Show deferred context menu if this was a click (not a drag) and not part of ping mode.
        if (
            not self._suppress_right_menu
            and not self._right_moved_far
            and not getattr(self, "ping_mode", False)
        ):
            if self._right_down_edge is not None:
                self._ctx_edge = self._right_down_edge
                self._rebuild_edge_menu(self._right_down_edge)
                try:
                    self.edge_menu.tk_popup(event.x_root, event.y_root)
                finally:
                    self.edge_menu.grab_release()
            elif self._right_down_node is not None:
                self._ctx_node = self._right_down_node
                try:
                    self.node_menu.tk_popup(event.x_root, event.y_root)
                finally:
                    self.node_menu.grab_release()

        self._right_down_pos = None
        self._right_down_edge = None
        self._right_down_node = None
        self._right_moved_far = False
        self._suppress_right_menu = False
        self.log_event("mouse_right_up", x=event.x, y=event.y)

    # ───────────────── Zoom ─────────────────

    def on_mouse_wheel(self, event):
        direction = 1 if event.delta > 0 else -1
        self._apply_zoom(direction, event.x, event.y)

    def on_linux_wheel(self, direction, event):
        self._apply_zoom(direction, event.x, event.y)

    def _apply_zoom(self, direction, pivot_x, pivot_y):
        factor = 1.1 if direction > 0 else 0.9

        new_zoom = self.zoom * factor
        if new_zoom < ZOOM_MIN:
            factor = ZOOM_MIN / self.zoom
            new_zoom = ZOOM_MIN
        elif new_zoom > ZOOM_MAX:
            factor = ZOOM_MAX / self.zoom
            new_zoom = ZOOM_MAX

        if abs(factor - 1.0) < 1e-6:
            return

        self.zoom = new_zoom
        self.canvas.scale("topo", pivot_x, pivot_y, factor, factor)

        self._remove_preview()
        self._ensure_preview(*self.last_cursor)

    # ───────────────── Mouse events (left) ─────────────────

    def on_mouse_down(self, event):
        self.canvas.focus_set()
        self.log_event("mouse_left_down", x=event.x, y=event.y)

        # Track left button state (for ping mode).
        self._buttons_down.add("L")

        node = self.get_node_at(event.x, event.y)

        # If we're already in ping mode, clicking a selected node or empty space cancels it; otherwise run ping.
        if getattr(self, "ping_mode", False):
            if node is None:
                self._cancel_ping_mode()
            elif node in self.selected_nodes:
                self._cancel_ping_mode()
            else:
                self._run_ping_mode(node)
                return

        self.last_cursor = (event.x, event.y)
        self.mouse_down_pos = (event.x, event.y)
        self.moved_far = False

        self.down_kind = None
        self.down_node = None
        self.down_edge = None

        self.pre_press_chain = self.chain_node
        self.chain_set_on_press = False

        # If right is currently held and user presses left on a node, enter ping mode.
        if node is not None and "R" in self._buttons_down:
            self._start_ping_mode(node)
            return
        if node:
            self.down_kind = "node"
            self.down_node = node
            self.deselect_edge()

            if node not in self.selected_nodes:
                self.clear_selection()
                self.selected_nodes.add(node)
                self.set_node_highlight(node, True)

            self.nav_curr = node
            self.nav_prev = None

            if self.chain_node is None:
                self.chain_node = node
                self.chain_set_on_press = True
                self._ensure_preview(event.x, event.y)

            self.dragging = True
            self.dragging_group = (len(self.selected_nodes) > 1)
            self.dragging_node = None if self.dragging_group else node

            try:
                moved_nodes = list(self.selected_nodes) if self.dragging_group else [node]
                moved = []
                for n in moved_nodes:
                    uid = self.node_uid.get(n)
                    if not uid:
                        continue
                    cx, cy = self.get_center(n)
                    moved.append({"id": uid, "x": cx, "y": cy})
                self.log_event(
                    "move_nodes_start",
                    count=len(moved),
                    group=bool(self.dragging_group),
                    nodes=moved,
                )
            except Exception:
                pass
            return

        edge = self.get_edge_at(event.x, event.y)
        if edge:
            self.down_kind = "edge"
            self.down_edge = edge
            self.clear_selection()
            self.chain_node = None
            self._remove_preview()
            self.select_edge(edge)

            self.nav_curr = None
            self.nav_prev = None
            return

        self.deselect_edge()

        if self.mode == "neutral":
            self.down_kind = "selectbox"
            self._start_selection_box(event.x, event.y)
            return

        self.down_kind = "place_or_select"
        self.pending_place = True
        self.place_start = (event.x, event.y)

    def _move_node(self, node, dx, dy):
        self.canvas.move(node, dx, dy)
        lbl = self.node_labels.get(node)
        if lbl is not None:
            self.canvas.move(lbl, dx, dy)

    def on_mouse_drag(self, event):
        self.last_cursor = (event.x, event.y)
        if self.mouse_down_pos is None:
            self.mouse_down_pos = (event.x, event.y)

        if not self.moved_far:
            if abs(event.x - self.mouse_down_pos[0]) > DRAG_THRESHOLD or abs(event.y - self.mouse_down_pos[1]) > DRAG_THRESHOLD:
                self.moved_far = True

        if self.down_kind == "node" and self.chain_set_on_press and self.moved_far:
            self.chain_node = self.pre_press_chain
            self.chain_set_on_press = False
            self._remove_preview()

        if self.down_kind == "place_or_select" and self.moved_far:
            self.pending_place = False
            self.down_kind = "selectbox"
            if self.selection_box is None and self.place_start is not None:
                self._start_selection_box(self.place_start[0], self.place_start[1])

        if self.down_kind == "node" and self.dragging and self.moved_far and (self.dragging_node or self.dragging_group):
            self._remove_preview()

            dx = event.x - self.mouse_down_pos[0]
            dy = event.y - self.mouse_down_pos[1]
            self.mouse_down_pos = (event.x, event.y)

            if self.dragging_group:
                for n in self.selected_nodes:
                    self._move_node(n, dx, dy)
            else:
                self._move_node(self.dragging_node, dx, dy)

            self.update_edges()
            return

        if self.down_kind == "selectbox" and self.selection_box and self.selection_start:
            x0, y0 = self.selection_start
            self.canvas.coords(self.selection_box, x0, y0, event.x, event.y)
            self.update_group_selection(x0, y0, event.x, event.y)

    def on_mouse_up(self, event):
        self.last_cursor = (event.x, event.y)
        self.log_event("mouse_left_up", x=event.x, y=event.y)

        # Clear left button state.
        self._buttons_down.discard("L")

        if self.down_kind == "place_or_select":

            if self.pending_place and self.place_start and self.mode in ("router", "switch", "host"):
                new_node = self.create_node(self.place_start[0], self.place_start[1])
                if new_node is not None:
                    # If we have a chain head, always attempt connect.
                    # Re-connecting the same pair increments interface count.
                    if self.chain_node is not None and self.chain_node in self.nodes:
                        if self.chain_node != new_node:
                            self.connect_nodes(self.chain_node, new_node)

                    # Advance the chain to the new node (continuous chaining)
                    self.chain_node = new_node
                    self._ensure_preview(event.x, event.y)

                    self.nav_curr = new_node
                    self.nav_prev = None
                    self._apply_focus(new_node)

            self.pending_place = False
            self.place_start = None


        if self.down_kind == "node":
            # Log drag end once the node(s) are dropped.
            if self.moved_far and self.down_node is not None:
                try:
                    moved_nodes = list(self.selected_nodes) if self.dragging_group else [self.down_node]
                    moved = []
                    for n in moved_nodes:
                        uid = self.node_uid.get(n)
                        if not uid:
                            continue
                        cx, cy = self.get_center(n)
                        moved.append({"id": uid, "x": cx, "y": cy})
                    self.log_event(
                        "move_nodes_done",
                        count=len(moved),
                        group=bool(self.dragging_group),
                        nodes=moved,
                    )
                except Exception:
                    pass

            if not self.moved_far and self.down_node is not None:
                clicked = self.down_node
                src = self.pre_press_chain

                if src is not None and src in self.nodes and src != clicked:
                    self.connect_nodes(src, clicked)

                    self.nav_prev = src
                    self.nav_curr = clicked
                    self._apply_focus(clicked)
                else:
                    self.nav_prev = None
                    self.nav_curr = clicked
                    self._apply_focus(clicked)

            self.dragging = False
            self.dragging_group = False
            self.dragging_node = None

        if self.down_kind == "selectbox":
            if self.selection_box and self.selection_start:
                x0, y0 = self.selection_start
                x1, y1 = event.x, event.y

                if abs(x1 - x0) <= DRAG_THRESHOLD and abs(y1 - y0) <= DRAG_THRESHOLD:
                    self.clear_selection()

                self.canvas.delete(self.selection_box)
                self.selection_box = None
                self.selection_start = None

        self.mouse_down_pos = None
        self.down_kind = None
        self.down_node = None
        self.down_edge = None
        self.moved_far = False
        self.pre_press_chain = None
        self.chain_set_on_press = False

        self._ensure_preview(event.x, event.y)

    # ───────────────── Nodes / edges ─────────────────

    def _next_uid(self, node_type: str) -> str:
        if node_type == "router":
            self.router_count += 1
            return f"R{self.router_count}"
        if node_type == "switch":
            self.switch_count += 1
            return f"SW{self.switch_count}"
        self.host_count += 1
        return f"PC{self.host_count}"

    def _bump_counters_from_uid(self, uid: str, node_type: str):
        try:
            u = uid.upper()
            if node_type == "router" and u.startswith("R") and not u.startswith("SW"):
                n = int(u[1:])
                self.router_count = max(self.router_count, n)
            elif node_type == "switch" and u.startswith("SW"):
                n = int(u[2:])
                self.switch_count = max(self.switch_count, n)
            elif node_type == "host" and u.startswith("PC"):
                n = int(u[2:])
                self.host_count = max(self.host_count, n)
        except Exception:
            pass

    def _attach_uid_and_label(self, node_canvas_id: int, node_type: str, uid: Optional[str] = None):
        if uid is None:
            uid = self._next_uid(node_type)
        else:
            if uid in self.uid_node:
                raise ValueError(f"Duplicate node id '{uid}' in imported file")
            self._bump_counters_from_uid(uid, node_type)

        self.node_uid[node_canvas_id] = uid
        self.uid_node[uid] = node_canvas_id

        cx, cy = self.get_center(node_canvas_id)
        lbl = self.canvas.create_text(
            cx, cy + NODE_RADIUS + 14,
            text=uid,
            fill="#eaeaea",
            font=("Arial", 10, "bold"),
            tags=("topo",)
        )
        self.node_labels[node_canvas_id] = lbl

    def _selected_profile_for(self, node_type: str) -> str:
        node_type = (node_type or "").lower()
        if node_type == "router":
            return self.router_profile_var.get() or "MODERN_ROUTER"
        if node_type == "switch":
            return self.switch_profile_var.get() or "MODERN_ACCESS_SWITCH"
        return "HOST_OPTIMIZED"

    def _create_node_of_type(self, node_type: str, x: float, y: float, forced_uid: Optional[str] = None, hardware_profile: Optional[str] = None):
        node_type = (node_type or "").lower()
        if node_type not in ("router", "switch", "host"):
            node_type = "router"

        if node_type == "router":
            hw = hardware_profile or self._selected_profile_for("router")
            node = self.canvas.create_oval(
                x - NODE_RADIUS, y - NODE_RADIUS,
                x + NODE_RADIUS, y + NODE_RADIUS,
                fill="#4fc3f7", outline="", width=0,
                tags=("topo",)
            )
            self.nodes[node] = {"type": "router", "seq": self.node_seq, "hardware_profile": hw}
            self.node_seq += 1
            self._attach_uid_and_label(node, "router", forced_uid)
            self._sim_on_node_created(node)
            try:
                uid = self.node_uid.get(node)
                if uid:
                    self.log_event("create_node", id=uid, type="router", x=float(x), y=float(y))
            except Exception:
                pass
            return node

        if node_type == "switch":
            hw = hardware_profile or self._selected_profile_for("switch")
            node = self.canvas.create_rectangle(
                x - NODE_RADIUS, y - NODE_RADIUS,
                x + NODE_RADIUS, y + NODE_RADIUS,
                fill="#81c784", outline="", width=0,
                tags=("topo",)
            )
            self.nodes[node] = {"type": "switch", "seq": self.node_seq, "hardware_profile": hw}
            self.node_seq += 1
            self._attach_uid_and_label(node, "switch", forced_uid)
            self._sim_on_node_created(node)
            try:
                uid = self.node_uid.get(node)
                if uid:
                    self.log_event("create_node", id=uid, type="switch", x=float(x), y=float(y))
            except Exception:
                pass
            return node

        hw = hardware_profile or "HOST_OPTIMIZED"
        node = self.canvas.create_rectangle(
            x - NODE_RADIUS, y - NODE_RADIUS,
            x + NODE_RADIUS, y + NODE_RADIUS,
            fill="#ffb74d", outline="", width=0,
            tags=("topo",)
        )
        self.nodes[node] = {"type": "host", "seq": self.node_seq, "hardware_profile": hw}
        self.node_seq += 1
        self._attach_uid_and_label(node, "host", forced_uid)
        self._sim_on_node_created(node)
        try:
            uid = self.node_uid.get(node)
            if uid:
                self.log_event("create_node", id=uid, type="host", x=float(x), y=float(y))
        except Exception:
            pass
        return node

    def _sim_on_node_created(self, node_canvas_id: int):
        uid = self.node_uid.get(node_canvas_id)
        meta = self.nodes.get(node_canvas_id, {})
        if not uid:
            return
        hw = meta.get("hardware_profile") or self._selected_profile_for(meta.get("type", "router"))
        self.sim.add_device(uid, meta.get("type", "router"), hardware_profile=hw)

    def create_node(self, x, y):
        if self.mode == "router":
            return self._create_node_of_type("router", x, y)
        if self.mode == "switch":
            return self._create_node_of_type("switch", x, y)
        if self.mode == "host":
            return self._create_node_of_type("host", x, y)
        return None

    # ───────────────── Hit testing helpers ─────────────────

    def get_center(self, node):
        x1, y1, x2, y2 = self.canvas.coords(node)
        return (x1 + x2) / 2, (y1 + y2) / 2

    def get_node_at(self, x, y):
        # Find the first node under cursor (ignores dots/labels because we test membership in self.nodes)
        for item in self.canvas.find_overlapping(x, y, x, y):
            if item in self.nodes:
                return item
        return None

    def _dist_point_to_segment(self, px, py, x1, y1, x2, y2):
        vx, vy = x2 - x1, y2 - y1
        wx, wy = px - x1, py - y1

        c1 = vx * wx + vy * wy
        if c1 <= 0:
            return ((px - x1) ** 2 + (py - y1) ** 2) ** 0.5

        c2 = vx * vx + vy * vy
        if c2 <= c1:
            return ((px - x2) ** 2 + (py - y2) ** 2) ** 0.5

        b = c1 / c2
        bx, by = x1 + b * vx, y1 + b * vy
        return ((px - bx) ** 2 + (py - by) ** 2) ** 0.5

    def get_edge_at(self, x, y):
        items = self.canvas.find_overlapping(
            x - EDGE_HIT_TOL, y - EDGE_HIT_TOL,
            x + EDGE_HIT_TOL, y + EDGE_HIT_TOL
        )
        candidates = [it for it in items if it in self.edge_map]
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]

        best = None
        best_d = float("inf")
        for line_id in candidates:
            x1, y1, x2, y2 = self.canvas.coords(line_id)
            d = self._dist_point_to_segment(x, y, x1, y1, x2, y2)
            if d < best_d:
                best_d = d
                best = line_id

        return best if best_d <= EDGE_HIT_TOL else None

    def _update_edge_dots(self, edge):
        # Back-compat for edges created before labels existed
        edge.setdefault("dots", {})
        edge.setdefault("labels", {})
        edge.setdefault("port_labels", {})

        # Keep count consistent with sim_links when available.
        sims = edge.get("sim_links", []) or []
        if sims:
            edge["count"] = len(sims)

        # Only show count indicators if more than one parallel link exists.
        if edge.get("count", 1) <= 1:
            for dot in edge["dots"].values():
                self.canvas.delete(dot)
            edge["dots"].clear()

            for lbl in edge["labels"].values():
                self.canvas.delete(lbl)
            edge["labels"].clear()

        if edge.get("count", 1) > 1:
            for node, other in ((edge["a"], edge["b"]), (edge["b"], edge["a"])):
                if node not in self.nodes or other not in self.nodes:
                    continue

                cx, cy = self.get_center(node)
                ox, oy = self.get_center(other)

                dx = ox - cx
                dy = oy - cy
                mag = (dx * dx + dy * dy) ** 0.5
                if mag == 0:
                    continue

                ux, uy = dx / mag, dy / mag

                # Use actual on-canvas node radius (works after zoom)
                x1, y1, x2, y2 = self.canvas.coords(node)
                node_rad = min(abs(x2 - x1), abs(y2 - y1)) / 2.0

                dot_r = max(2.0, node_rad * 0.12)
                dot_r = min(dot_r, node_rad * 0.25)
                dist = max(0.0, node_rad - dot_r - 2.0)

                px = cx + ux * dist
                py = cy + uy * dist

                off = max(6.0, dot_r * 2.0)
                tx = px + (-uy) * off
                ty = py + (ux) * off

                if node in edge["dots"]:
                    self.canvas.coords(edge["dots"][node], px - dot_r, py - dot_r, px + dot_r, py + dot_r)
                else:
                    dot = self.canvas.create_oval(
                        px - dot_r,
                        py - dot_r,
                        px + dot_r,
                        py + dot_r,
                        fill="#ff5252",
                        outline="",
                        tags=("topo",),
                    )
                    edge["dots"][node] = dot

                label_text = str(edge.get("count", 1))
                if node in edge["labels"]:
                    self.canvas.coords(edge["labels"][node], tx, ty)
                    self.canvas.itemconfigure(edge["labels"][node], text=label_text)
                else:
                    lbl = self.canvas.create_text(
                        tx,
                        ty,
                        text=label_text,
                        fill="#ff5252",
                        font=("Arial", 9, "bold"),
                        tags=("topo",),
                    )
                    edge["labels"][node] = lbl

        # Always show interface mapping labels near each node so it's clear which CLI port maps to which cable.
        def mappings_for(node_id: int) -> List[str]:
            a_uid = self.node_uid.get(edge.get("a"))
            b_uid = self.node_uid.get(edge.get("b"))
            out: List[str] = []
            for s in edge.get("sim_links", []) or []:
                a_if = s.get("a_if")
                b_if = s.get("b_if")
                if node_id == edge.get("a"):
                    if a_uid and b_uid and a_if and b_if:
                        out.append(f"{a_if} -> {b_uid}:{b_if}")
                    elif a_if:
                        out.append(str(a_if))
                else:
                    if a_uid and b_uid and a_if and b_if:
                        out.append(f"{b_if} -> {a_uid}:{a_if}")
                    elif b_if:
                        out.append(str(b_if))
            return out

        def format_ports(ps: List[str]) -> str:
            if not ps:
                return ""
            # Keep it readable even for many parallel links.
            if len(ps) <= 3:
                return "\n".join(ps)
            head = ps[:3]
            return "\n".join(head + [f"+{len(ps) - 3} more"]) 

        for node, other in ((edge["a"], edge["b"]), (edge["b"], edge["a"])):
            if node not in self.nodes or other not in self.nodes:
                continue

            cx, cy = self.get_center(node)
            ox, oy = self.get_center(other)
            dx = ox - cx
            dy = oy - cy
            mag = (dx * dx + dy * dy) ** 0.5
            if mag == 0:
                continue
            ux, uy = dx / mag, dy / mag

            x1, y1, x2, y2 = self.canvas.coords(node)
            node_rad = min(abs(x2 - x1), abs(y2 - y1)) / 2.0

            # Place just outside the node, slightly offset from the edge direction.
            px = cx + ux * (node_rad + 8.0)
            py = cy + uy * (node_rad + 8.0)
            off = max(10.0, node_rad * 0.35)
            tx = px + (-uy) * off
            ty = py + (ux) * off

            text = format_ports(mappings_for(node))
            if not text:
                # No ports known yet; hide any previous label.
                if node in edge["port_labels"]:
                    self.canvas.delete(edge["port_labels"][node])
                    edge["port_labels"].pop(node, None)
                continue

            if node in edge["port_labels"]:
                self.canvas.coords(edge["port_labels"][node], tx, ty)
                self.canvas.itemconfigure(edge["port_labels"][node], text=text)
            else:
                pl = self.canvas.create_text(
                    tx,
                    ty,
                    text=text,
                    fill="#9aa0a6",
                    font=("Arial", 8, "normal"),
                    tags=("topo",)
                )
                edge["port_labels"][node] = pl

    # Helper method to find an edge between two nodes
    def get_edge_between(self, a, b):
        for e in self.edges:
            if (e["a"] == a and e["b"] == b) or (e["a"] == b and e["b"] == a):
                return e
        return None

    # Check if an edge exists between two nodes
    def edge_exists(self, a, b):
        return self.get_edge_between(a, b) is not None

    # Connect two nodes, incrementing interface count if already connected
    def connect_nodes(self, n1, n2, a_if: Optional[str] = None, b_if: Optional[str] = None):
        if n1 == n2:
            return

        # If relationship already exists, increment interface count
        existing = self.get_edge_between(n1, n2)
        if existing is not None:
            existing["count"] += 1
            # Keep sim link orientation consistent with the stored edge endpoints.
            # This avoids swapping a_if/b_if when the user clicks nodes in reverse order.
            if existing.get("a") == n1 and existing.get("b") == n2:
                self._sim_on_link_added(existing, existing["a"], existing["b"], a_if=a_if, b_if=b_if)
            else:
                # n1/n2 are reversed relative to existing["a"/"b"]. Swap ifnames too.
                self._sim_on_link_added(existing, existing["a"], existing["b"], a_if=b_if, b_if=a_if)
            self._update_edge_dots(existing)
            self.log_event(
                "connect_nodes_parallel",
                a=self.node_uid.get(existing.get("a")),
                b=self.node_uid.get(existing.get("b")),
                count=existing.get("count"),
                a_if=a_if,
                b_if=b_if,
            )
            return

        x1, y1 = self.get_center(n1)
        x2, y2 = self.get_center(n2)
        line = self.canvas.create_line(
            x1, y1, x2, y2,
            fill=EDGE_COLOR, width=EDGE_WIDTH,
            tags=("topo",)
        )
        self.canvas.tag_lower(line)

        edge = {
            "line": line,
            "a": n1,
            "b": n2,
            "count": 1,     # interface count
            "dots": {},     # node_id -> dot_id
            "labels": {},   # node_id -> text_id
            "port_labels": {},  # node_id -> port label text id
            "sim_links": []
        }
        self.edges.append(edge)
        self.edge_map[line] = edge
        self._sim_on_link_added(edge, n1, n2, a_if=a_if, b_if=b_if)
        self._update_edge_dots(edge)
        self.log_event(
            "connect_nodes",
            a=self.node_uid.get(n1),
            b=self.node_uid.get(n2),
            a_if=a_if,
            b_if=b_if,
        )

    def _sim_on_link_added(self, edge: dict, n1: int, n2: int, a_if: Optional[str] = None, b_if: Optional[str] = None):
        a_uid = self.node_uid.get(n1)
        b_uid = self.node_uid.get(n2)
        if not a_uid or not b_uid:
            return

        if a_if is None:
            a_if = self.sim.allocate_or_reuse_interface_name(a_uid)
        if b_if is None:
            b_if = self.sim.allocate_or_reuse_interface_name(b_uid)

        try:
            link_id = self.sim.connect(a_uid, str(a_if), b_uid, str(b_if))
        except Exception:
            return

        edge.setdefault("sim_links", []).append({"id": link_id, "a_if": str(a_if), "b_if": str(b_if)})

    # Update all edges and their dots
    def update_edges(self):
        for e in self.edges:
            n1, n2 = e["a"], e["b"]
            if n1 not in self.nodes or n2 not in self.nodes:
                continue
            x1, y1 = self.get_center(n1)
            x2, y2 = self.get_center(n2)
            self.canvas.coords(e["line"], x1, y1, x2, y2)
            self._update_edge_dots(e)

    # Delete an edge and its associated dots
    def _delete_edge(self, line_id):
        edge = self.edge_map.pop(line_id, None)
        if edge is None:
            return

        self.log_event(
            "delete_edge",
            a=self.node_uid.get(edge.get("a")),
            b=self.node_uid.get(edge.get("b")),
            count=edge.get("count", 1),
        )

        for s in edge.get("sim_links", []) or []:
            try:
                self.sim.remove_link(s.get("id"))
            except Exception:
                pass

            # If the interface was purely auto-created and now disconnected, prune it
            # to avoid confusing leftover ports.
            try:
                a_uid = self.node_uid.get(edge.get("a"))
                b_uid = self.node_uid.get(edge.get("b"))
                if a_uid and s.get("a_if"):
                    self.sim.maybe_prune_interface(a_uid, str(s.get("a_if")))
                if b_uid and s.get("b_if"):
                    self.sim.maybe_prune_interface(b_uid, str(s.get("b_if")))
            except Exception:
                pass

        for dot in edge.get("dots", {}).values():
            self.canvas.delete(dot)

        for lbl in edge.get("labels", {}).values():
            self.canvas.delete(lbl)

        for pl in edge.get("port_labels", {}).values():
            self.canvas.delete(pl)

        self.canvas.delete(edge["line"])
        if edge in self.edges:
            self.edges.remove(edge)

    # Delete nodes and their associated edges
    def _delete_nodes(self, nodes_to_delete: set):
        self.deselect_edge()

        # remove edges touching doomed nodes
        to_remove = []
        for e in self.edges:
            if e["a"] in nodes_to_delete or e["b"] in nodes_to_delete:
                to_remove.append(e["line"])
        for ln in to_remove:
            self._delete_edge(ln)

        # remove nodes + labels + uid mapping
        for n in nodes_to_delete:
            if n in self.nodes:
                uid = self.node_uid.get(n)
                if uid:
                    try:
                        self.sim.remove_device(uid)
                    except Exception:
                        pass
                lbl = self.node_labels.pop(n, None)
                if lbl is not None:
                    self.canvas.delete(lbl)

                uid = self.node_uid.pop(n, None)
                if uid is not None:
                    self.uid_node.pop(uid, None)

                self.canvas.delete(n)
                self.nodes.pop(n, None)

    # Build adjacency list for navigation
    def build_adjacency(self):
        adj = {n: [] for n in self.nodes}
        for e in self.edges:
            n1, n2 = e["a"], e["b"]
            if n1 in self.nodes and n2 in self.nodes:
                adj[n1].append(n2)
                adj[n2].append(n1)
        return adj


class DeviceCLIWindow:
    def __init__(self, root: tk.Tk, uid: str, cli_engine, banner: Optional[str] = None, log_cb=None):
        self.root = root
        self.uid = uid
        self.cli_engine = cli_engine
        self._log_cb = log_cb
        self.ctx = cli_engine.new_context(uid)

        self.history: List[str] = []
        self.hist_idx: int = 0

        self.win = tk.Toplevel(root)
        self.win.title(f"{uid} CLI")
        self.win.geometry("760x420")
        self.win.configure(bg="#0b0d10")
        self.win.protocol("WM_DELETE_WINDOW", self.close)

        self.text = tk.Text(
            self.win,
            bg="#0b0d10",
            fg="#e6e6e6",
            insertbackground="#e6e6e6",
            font=("Consolas", 10),
            wrap="word",
            borderwidth=0,
            highlightthickness=0,
        )
        self.text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 6))

        bottom = tk.Frame(self.win, bg="#0b0d10")
        bottom.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.prompt_var = tk.StringVar(value=self.ctx.prompt())
        self.prompt_lbl = tk.Label(
            bottom,
            textvariable=self.prompt_var,
            fg="#9ccc65",
            bg="#0b0d10",
            font=("Consolas", 10, "bold"),
        )
        self.prompt_lbl.pack(side=tk.LEFT)

        self.entry = tk.Entry(
            bottom,
            bg="#0b0d10",
            fg="#e6e6e6",
            insertbackground="#e6e6e6",
            font=("Consolas", 10),
            relief=tk.FLAT,
        )
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.focus_set()

        self.entry.bind("<Return>", self._on_enter)
        self.entry.bind("<Up>", self._on_up)
        self.entry.bind("<Down>", self._on_down)
        self.entry.bind("<Tab>", self._on_tab)

        self._write_line(banner or f"{uid} IOS-like CLI (lightweight)")
        self._write_line("")

    def _log(self, kind: str, **data):
        if not self._log_cb:
            return
        try:
            self._log_cb(kind, **data)
        except Exception:
            pass

    def alive(self) -> bool:
        try:
            return bool(self.win.winfo_exists())
        except Exception:
            return False

    def focus(self):
        try:
            self.win.deiconify()
            self.win.lift()
            self.entry.focus_set()
        except Exception:
            pass

    def close(self):
        try:
            self.win.destroy()
        except Exception:
            pass

    def _write(self, s: str):
        self.text.configure(state=tk.NORMAL)
        self.text.insert(tk.END, s)
        self.text.see(tk.END)
        self.text.configure(state=tk.DISABLED)

    def _write_line(self, s: str):
        self._write(s + "\n")

    def _set_prompt(self):
        self.prompt_var.set(self.ctx.prompt())

    def _on_enter(self, event=None):
        line = self.entry.get()
        self.entry.delete(0, tk.END)

        self._write(self.ctx.prompt() + line + "\n")

        if line.strip():
            self.history.append(line)
            self.hist_idx = len(self.history)

        if line.strip():
            self._log(
                "cli_command",
                uid=self.uid,
                command=line,
                mode=getattr(self.ctx, "mode", None),
                privileged=getattr(self.ctx, "privileged", None),
            )

        res = self.cli_engine.execute(self.ctx, line)
        if res.output == "__CLOSE__":
            self._log("cli_output", uid=self.uid, command=line, output=res.output)
            self.close()
            return "break"
        if res.output:
            self._write(res.output + "\n")
            self._log("cli_output", uid=self.uid, command=line, output=res.output)
        self._set_prompt()
        return "break"

    def _on_up(self, event=None):
        if not self.history:
            return "break"
        self.hist_idx = max(0, self.hist_idx - 1)
        self.entry.delete(0, tk.END)
        self.entry.insert(0, self.history[self.hist_idx])
        return "break"

    def _on_down(self, event=None):
        if not self.history:
            return "break"
        self.hist_idx = min(len(self.history), self.hist_idx + 1)
        self.entry.delete(0, tk.END)
        if self.hist_idx < len(self.history):
            self.entry.insert(0, self.history[self.hist_idx])
        return "break"

    def _on_tab(self, event=None):
        cur = self.entry.get()
        if not cur.strip():
            return "break"

        base = cur.rstrip()

        help_res = self.cli_engine.execute(self.ctx, base + " ?")
        out = help_res.output or ""
        options = [
            ln.strip()
            for ln in out.splitlines()
            if ln.strip() and not ln.startswith("%") and ln.strip() != "<cr>"
        ]
        if not options:
            return "break"

        def lcp(strings: List[str]) -> str:
            if not strings:
                return ""
            s1 = min(strings)
            s2 = max(strings)
            i = 0
            while i < len(s1) and i < len(s2) and s1[i] == s2[i]:
                i += 1
            return s1[:i]

        if len(options) == 1:
            completed = options[0]
            if not completed.endswith(" "):
                completed += " "
            self.entry.delete(0, tk.END)
            self.entry.insert(0, completed)
            return "break"

        prefix = lcp(options)
        if prefix and len(prefix) > len(base):
            completed = prefix
            if completed in options and not completed.endswith(" "):
                completed += " "
            self.entry.delete(0, tk.END)
            self.entry.insert(0, completed)
        else:
            self._write("\n" + "\n".join(options) + "\n")
            self._set_prompt()
        return "break"


if __name__ == "__main__":
    root = tk.Tk()
    app = TopologyTool(root)
    root.mainloop()
