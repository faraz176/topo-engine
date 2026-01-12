import threading
import tkinter as tk
from tkinter import messagebox
from typing import Any, Callable, Dict, List, Optional

from .openai_agent import TopoAgent, AgentReply


class AgentPanel(tk.Frame):
    """
    Right-side panel:
      - conversation transcript
      - user input box
      - Send button

    Callbacks:
      get_topology_cb() -> dict
      apply_topology_cb(dict) -> None
    """
    def __init__(
        self,
        master,
        get_topology_cb: Callable[[], Dict[str, Any]],
        apply_topology_cb: Callable[[Dict[str, Any]], None],
        log_event_cb: Optional[Callable[..., None]] = None,
        **kwargs,
    ):
        super().__init__(master, bg="#14161b", **kwargs)

        self.get_topology_cb = get_topology_cb
        self.apply_topology_cb = apply_topology_cb
        self.log_event_cb = log_event_cb

        self.agent = TopoAgent()
        self.history: List[Dict[str, str]] = []
        self.last_reply: Optional[AgentReply] = None

        self._build_ui()

    def _log(self, kind: str, **data: Any) -> None:
        if not self.log_event_cb:
            return
        try:
            self.log_event_cb(kind, **data)
        except TypeError:
            # Back-compat: older callback signature expected only (kind)
            try:
                self.log_event_cb(kind)
            except Exception:
                pass
        except Exception:
            pass

    def _safe_json_preview(self, obj: Any, max_chars: int = 20000) -> str:
        import json

        try:
            s = json.dumps(obj, ensure_ascii=False, indent=2, default=str)
        except Exception:
            s = str(obj)

        if len(s) > max_chars:
            return s[:max_chars] + "\n... (truncated)"
        return s

    def _build_ui(self):
        header = tk.Label(
            self,
            text="TopoCopilot (MCP-style assistant)",
            bg="#14161b",
            fg="#eaeaea",
            font=("Arial", 11, "bold"),
            anchor="w",
            padx=10,
            pady=8,
        )
        header.pack(fill=tk.X)

        self.transcript = tk.Text(
            self,
            height=20,
            bg="#0f1115",
            fg="#eaeaea",
            insertbackground="#eaeaea",
            wrap="word",
            padx=10,
            pady=8,
            relief=tk.FLAT,
        )
        self.transcript.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.transcript.configure(state="disabled")

        # Input area
        self.input = tk.Text(
            self,
            height=5,
            bg="#0f1115",
            fg="#eaeaea",
            insertbackground="#eaeaea",
            wrap="word",
            padx=10,
            pady=8,
            relief=tk.FLAT,
        )
        self.input.pack(fill=tk.X, padx=10, pady=(0, 8))

        # Buttons row
        row = tk.Frame(self, bg="#14161b")
        row.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.send_btn = tk.Button(row, text="Send", command=self.on_send)
        self.send_btn.pack(side=tk.LEFT)

        self.clear_btn = tk.Button(row, text="Clear chat", command=self.on_clear_chat)
        self.clear_btn.pack(side=tk.RIGHT)

        # Enter to send, Shift+Enter newline
        self.input.bind("<Return>", self._enter_send)
        self.input.bind("<Shift-Return>", self._enter_newline)

    def _append(self, role: str, text: str):
        self.transcript.configure(state="normal")
        if role == "user":
            prefix = "You: "
            tag = "user"
        else:
            prefix = "AI: "
            tag = "assistant"

        self.transcript.insert("end", prefix + text.strip() + "\n\n", tag)
        self.transcript.configure(state="disabled")
        self.transcript.see("end")

    def _enter_send(self, event):
        self.on_send()
        return "break"

    def _enter_newline(self, event):
        self.input.insert("insert", "\n")
        return "break"

    def on_clear_chat(self):
        self.history.clear()
        self.last_reply = None

        self.transcript.configure(state="normal")
        self.transcript.delete("1.0", "end")
        self.transcript.configure(state="disabled")

    def on_send(self):
        user_text = self.input.get("1.0", "end").strip()
        if not user_text:
            return

        self._log("agent_send", text=user_text, historyLen=len(self.history))

        self.input.delete("1.0", "end")
        self._append("user", user_text)
        self.history.append({"role": "user", "text": user_text})

        topo_state = {}
        try:
            topo_state = self.get_topology_cb() or {}
        except Exception:
            topo_state = {}

        # Store a readable prompt context for debugging.
        topo_preview = self._safe_json_preview(topo_state, max_chars=20000)
        self._log(
            "agent_prompt",
            userText=user_text,
            historyLen=len(self.history),
            topoStatePreview=topo_preview,
        )

        self.send_btn.configure(state=tk.DISABLED)

        def worker():
            try:
                reply = self.agent.chat(user_text=user_text, topo_state=topo_state, history=self.history)
            except Exception as e:
                reply = AgentReply(
                    message=f"Agent error: {e}",
                    topology=None,
                    apply_hint=False,
                    warnings=[str(e)],
                )

            def done():
                self.last_reply = reply
                self._append("assistant", reply.message)
                self.history.append({"role": "assistant", "text": reply.message})

                self._log(
                    "agent_reply",
                    message=reply.message,
                    warningCount=len(reply.warnings or []),
                    hasTopology=(reply.topology is not None),
                    applyHint=bool(getattr(reply, "apply_hint", False)),
                )

                if reply.warnings:
                    self._append("assistant", "Warnings:\n- " + "\n- ".join(reply.warnings))
                    self.history.append({"role": "assistant", "text": "Warnings: " + "; ".join(reply.warnings)})

                # Auto-apply topology if present (no "Apply" button).
                if reply.topology is not None:
                    try:
                        topo_obj = reply.topology
                        topo_dict = topo_obj.model_dump() if hasattr(topo_obj, "model_dump") else topo_obj
                        self._log(
                            "agent_apply_topology_start",
                            topoPreview=self._safe_json_preview(topo_dict, max_chars=20000),
                        )
                        self.apply_topology_cb(topo_dict)
                        self._append("assistant", "Applied topology to canvas.")
                        self.history.append({"role": "assistant", "text": "Applied topology to canvas."})

                        self._log("agent_apply_topology_done")
                    except Exception as e:
                        self._append("assistant", f"Apply failed: {e}")
                        self.history.append({"role": "assistant", "text": f"Apply failed: {e}"})

                        self._log("agent_apply_failed", error=str(e))

                self.send_btn.configure(state=tk.NORMAL)

            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

