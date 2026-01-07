\
import tkinter as tk
import json
from tkinter import filedialog, messagebox
from typing import Optional

from ai.agent_panel import AgentPanel

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

SCHEMA_VERSION = 1


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

        self.canvas = tk.Canvas(self.left, bg="#0f1115", width=1200, height=800, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        # Agent panel on the right
        self.agent_panel = AgentPanel(
            self.right,
            get_topology_cb=self.export_dict,
            apply_topology_cb=self._apply_topology_from_agent,
        )
        self.agent_panel.pack(fill=tk.BOTH, expand=True)

        # Modes: neutral | router | switch
        self.mode = "neutral"

        # File state
        self.current_file = None

        # Data (canvas ids)
        self.nodes = {}      # node_canvas_id -> {"type": "router|switch", "seq": int}
        self.edges = []      # [(line_id, n1, n2), ...]
        self.edge_map = {}   # line_id -> (n1, n2)
        self.node_seq = 0

        # Stable IDs + labels (for JSON)
        self.node_uid = {}       # node_canvas_id -> stable uid (e.g., R1, SW1)
        self.uid_node = {}       # stable uid -> node_canvas_id
        self.node_labels = {}    # node_canvas_id -> label_canvas_id
        self.router_count = 0
        self.switch_count = 0

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

        # Dragging nodes
        self.dragging = False
        self.dragging_group = False
        self.dragging_node = None

        # Placement (router/switch)
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
        self.root.config(menu=menubar)

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
            nodes_out.append({
                "id": uid,
                "type": meta.get("type", "router"),
                "x": cx,
                "y": cy,
                "seq": meta.get("seq", 0),
            })

        nodes_out.sort(key=lambda n: (n.get("type", ""), n.get("seq", 0), n.get("id", "")))

        links_out = []
        seen = set()
        for _, n1, n2 in self.edges:
            a = self.node_uid.get(n1)
            b = self.node_uid.get(n2)
            if not a or not b:
                continue
            key = tuple(sorted((a, b)))
            if key in seen:
                continue
            seen.add(key)
            links_out.append({"a": a, "b": b, "type": "ethernet"})

        links_out.sort(key=lambda e: (e["a"], e["b"]))

        return {
            "schemaVersion": SCHEMA_VERSION,
            "meta": {"name": "Topology"},
            "nodes": nodes_out,
            "links": links_out,
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
            if not uid or x is None or y is None:
                continue
            self._create_node_of_type(str(ntype), float(x), float(y), forced_uid=str(uid))

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
            if not n1 or not n2:
                continue
            if n1 != n2 and not self.edge_exists(n1, n2):
                self.connect_nodes(n1, n2)

        self.update_edges()
        self.mode = "neutral"
        self.update_title()

    def _apply_topology_from_agent(self, topo_dict: dict):
        # Wrap so the agent panel can call it safely
        self.load_from_dict(topo_dict)

    # ───────────────── UI ─────────────────

    def draw_legend(self):
        self.canvas.create_rectangle(10, 10, 320, 180, fill="#1a1d23", outline="#444", tags="legend")
        self.canvas.create_text(165, 25, text="LEGEND / CONTROLS", fill="white",
                                font=("Arial", 11, "bold"), tags="legend")

        self.canvas.create_oval(30, 45, 60, 75, fill="#4fc3f7", outline="", tags="legend")
        self.canvas.create_text(205, 60, text="Router (R) - click to place", fill="white", tags="legend")

        self.canvas.create_rectangle(30, 80, 60, 110, fill="#81c784", outline="", tags="legend")
        self.canvas.create_text(205, 95, text="Switch (S) - click to place", fill="white", tags="legend")

        self.canvas.create_line(30, 130, 60, 130, fill=EDGE_COLOR, width=EDGE_WIDTH, tags="legend")
        self.canvas.create_text(205, 130, text="Neutral (ESC) - pan/zoom/select", fill="white", tags="legend")

        self.canvas.create_text(165, 155, text="Delete (D / Del / Backspace)", fill="#cccccc", tags="legend")
        self.canvas.create_text(165, 172, text="Clear (C)", fill="#ff8a80", tags="legend")

    def bind_events(self):
        # ---- Canvas-focused hotkeys ----
        # NOTE: bind hotkeys to the canvas so typing in the agent panel isn't hijacked.
        self.canvas.bind("<KeyPress-r>", lambda e: self.set_mode("router"))
        self.canvas.bind("<KeyPress-R>", lambda e: self.set_mode("router"))

        # 's' is special: down-navigation when a node is focused; otherwise switch-mode.
        self.canvas.bind("<KeyPress-s>", self._on_s_key)
        self.canvas.bind("<KeyPress-S>", lambda e: self.set_mode("switch"))

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

        # ---- Mouse ----
        self.canvas.bind("<Button-1>", self.on_mouse_down)
        self.canvas.bind("<B1-Motion>", self.on_mouse_drag)
        self.canvas.bind("<ButtonRelease-1>", self.on_mouse_up)

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
        self.root.title(base)

    # ───────────────── ESC => Neutral ─────────────────

    def on_escape_to_neutral(self, event=None):
        self.mode = "neutral"
        self.cancel_transients(keep_selection=False)
        self.update_title()

    def cancel_transients(self, keep_selection: bool):
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
        for _, n1, n2 in self.edges:
            if n1 in self.nodes and n2 in self.nodes:
                adj[n1].append(n2)
                adj[n2].append(n1)
        return adj

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
        self.canvas.delete(line_id)
        self.edge_map.pop(line_id, None)
        self.edges = [(ln, n1, n2) for (ln, n1, n2) in self.edges if ln != line_id]

    def _delete_nodes(self, nodes_to_delete: set):
        self.deselect_edge()

        to_remove = []
        for (ln, n1, n2) in self.edges:
            if n1 in nodes_to_delete or n2 in nodes_to_delete:
                to_remove.append(ln)
        for ln in to_remove:
            self._delete_edge(ln)

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
        self.canvas.delete("all")
        self.nodes.clear()
        self.edges.clear()
        self.edge_map.clear()
        self.node_seq = 0
        self.zoom = 1.0

        self.node_uid.clear()
        self.uid_node.clear()
        self.node_labels.clear()
        self.router_count = 0
        self.switch_count = 0

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
        if not self.panning or self.pan_last is None:
            return

        dx = event.x - self.pan_last[0]
        dy = event.y - self.pan_last[1]
        self.pan_last = (event.x, event.y)

        self.canvas.move("topo", dx, dy)
        self.last_cursor = (event.x, event.y)

    def on_pan_up(self, event):
        if not self.panning:
            return
        self.panning = False
        self.pan_last = None
        self.last_cursor = (event.x, event.y)

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

        self.last_cursor = (event.x, event.y)
        self.mouse_down_pos = (event.x, event.y)
        self.moved_far = False

        self.down_kind = None
        self.down_node = None
        self.down_edge = None

        self.pre_press_chain = self.chain_node
        self.chain_set_on_press = False

        node = self.get_node_at(event.x, event.y)
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

        if self.down_kind == "place_or_select":

            if self.pending_place and self.place_start and self.mode in ("router", "switch"):
                new_node = self.create_node(self.place_start[0], self.place_start[1])
                if new_node is not None:

        # --- AUTO-CHAIN FIX ---
                    if self.chain_node is not None and self.chain_node in self.nodes:
                        if self.chain_node != new_node and not self.edge_exists(self.chain_node, new_node):
                            self.connect_nodes(self.chain_node, new_node)

        # Advance the chain to the new node (continuous chaining)
                    self.chain_node = new_node
                    self._ensure_preview(event.x, event.y)

        # --- END FIX ---

                    self.nav_curr = new_node
                    self.nav_prev = None
                    self._apply_focus(new_node)

            self.pending_place = False
            self.place_start = None


        if self.down_kind == "node":
            if not self.moved_far and self.down_node is not None:
                clicked = self.down_node
                src = self.pre_press_chain

                if src is not None and src in self.nodes and src != clicked:
                    if not self.edge_exists(src, clicked):
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
        self.switch_count += 1
        return f"SW{self.switch_count}"

    def _bump_counters_from_uid(self, uid: str, node_type: str):
        try:
            u = uid.upper()
            if node_type == "router" and u.startswith("R") and not u.startswith("SW"):
                n = int(u[1:])
                self.router_count = max(self.router_count, n)
            elif node_type == "switch" and u.startswith("SW"):
                n = int(u[2:])
                self.switch_count = max(self.switch_count, n)
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

    def _create_node_of_type(self, node_type: str, x: float, y: float, forced_uid: Optional[str] = None):
        node_type = (node_type or "").lower()
        if node_type not in ("router", "switch"):
            node_type = "router"

        if node_type == "router":
            node = self.canvas.create_oval(
                x - NODE_RADIUS, y - NODE_RADIUS,
                x + NODE_RADIUS, y + NODE_RADIUS,
                fill="#4fc3f7", outline="", width=0,
                tags=("topo",)
            )
            self.nodes[node] = {"type": "router", "seq": self.node_seq}
            self.node_seq += 1
            self._attach_uid_and_label(node, "router", forced_uid)
            return node

        node = self.canvas.create_rectangle(
            x - NODE_RADIUS, y - NODE_RADIUS,
            x + NODE_RADIUS, y + NODE_RADIUS,
            fill="#81c784", outline="", width=0,
            tags=("topo",)
        )
        self.nodes[node] = {"type": "switch", "seq": self.node_seq}
        self.node_seq += 1
        self._attach_uid_and_label(node, "switch", forced_uid)
        return node

    def create_node(self, x, y):
        if self.mode == "router":
            return self._create_node_of_type("router", x, y)
        if self.mode == "switch":
            return self._create_node_of_type("switch", x, y)
        return None

    def connect_nodes(self, n1, n2):
        x1, y1 = self.get_center(n1)
        x2, y2 = self.get_center(n2)
        line = self.canvas.create_line(
            x1, y1, x2, y2,
            fill=EDGE_COLOR, width=EDGE_WIDTH,
            tags=("topo",)
        )
        self.edges.append((line, n1, n2))
        self.edge_map[line] = (n1, n2)
        self.canvas.tag_lower(line)

    def update_edges(self):
        for line, n1, n2 in self.edges:
            if n1 not in self.nodes or n2 not in self.nodes:
                continue
            x1, y1 = self.get_center(n1)
            x2, y2 = self.get_center(n2)
            self.canvas.coords(line, x1, y1, x2, y2)

    def edge_exists(self, a, b):
        for _, n1, n2 in self.edges:
            if (n1 == a and n2 == b) or (n1 == b and n2 == a):
                return True
        return False

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

    # ───────────────── Hit testing helpers ─────────────────

    def get_center(self, node):
        x1, y1, x2, y2 = self.canvas.coords(node)
        return (x1 + x2) / 2, (y1 + y2) / 2

    def get_node_at(self, x, y):
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
        for line in candidates:
            x1, y1, x2, y2 = self.canvas.coords(line)
            d = self._dist_point_to_segment(x, y, x1, y1, x2, y2)
            if d < best_d:
                best_d = d
                best = line

        return best if best_d <= EDGE_HIT_TOL else None


if __name__ == "__main__":
    root = tk.Tk()
    app = TopologyTool(root)
    root.mainloop()
