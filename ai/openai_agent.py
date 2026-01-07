import os
from typing import Any, Dict, List, Optional, Literal

from openai import OpenAI
from pydantic import BaseModel, ConfigDict, Field


# IMPORTANT:
# OpenAI Structured Outputs requires "additionalProperties": false on ALL object schemas.
# If you use Dict[str, Any] in a Pydantic model, Pydantic generates an open-ended schema
# (additionalProperties=true/unspecified), which the API rejects.
#
# Therefore we define a strict Topology schema with extra="forbid" everywhere.


class TopologyMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field("Topology", description="Human name for this topology")


class TopoNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique node id (R# or SW#)")
    type: Literal["router", "switch"] = Field(..., description="router or switch")
    x: float = Field(..., description="Canvas X coordinate")
    y: float = Field(..., description="Canvas Y coordinate")
    seq: int = Field(0, description="Sequence number")


class TopoLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    a: str = Field(..., description="Endpoint node id")
    b: str = Field(..., description="Endpoint node id")
    type: str = Field("ethernet", description="Link type")


class Topology(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: int = Field(1, description="Schema version")
    meta: TopologyMeta = Field(default_factory=TopologyMeta)
    nodes: List[TopoNode] = Field(default_factory=list)
    links: List[TopoLink] = Field(default_factory=list)


class AgentReply(BaseModel):
    model_config = ConfigDict(extra="forbid")

    """Structured reply returned by the model.

    - message: text to show in the chat panel
    - topology: optional topology JSON compatible with TopologyTool.load_from_dict()
    - apply_hint: if True, UI should enable an "Apply" button
    - warnings: optional list of warnings for the user
    """

    message: str = Field(..., description="Natural-language response to show the user.")
    topology: Optional[Topology] = Field(
        default=None,
        description="Optional topology object compatible with the app schema.",
    )
    apply_hint: bool = Field(
        default=False,
        description="If true, the UI should offer to apply the provided topology.",
    )
    warnings: List[str] = Field(default_factory=list)


SYSTEM_PROMPT = """\
You are TopoCopilot, an assistant embedded inside a network-topology drawing app.

You will receive:
- the user's request
- the app's CURRENT topology JSON (may be empty)

Your job:
1) Give helpful, specific guidance (CCNP/CCIE lab ideas, validation notes, troubleshooting).
2) When the user asks to generate or modify a topology, include a 'topology' object that matches the app schema:
   {
     "schemaVersion": 1,
     "meta": {"name": "..."},
     "nodes": [{"id":"R1","type":"router","x":123,"y":456,"seq":0}, ...],
     "links": [{"a":"R1","b":"SW1","type":"ethernet"}, ...]
   }

Constraints for topology JSON:
- node.id must be unique (use R# for routers, SW# for switches)
- node.type must be "router" or "switch"
- x,y should be within a ~1200x800 canvas (roughly 0..1200, 0..800)
- links use ids that exist in nodes
- avoid duplicate links (a-b same as b-a)

If you do NOT provide a topology, set apply_hint=false.
If you DO provide a topology, set apply_hint=true.

Always return JSON matching the AgentReply schema (no extra keys).\
"""


class TopoAgent:
    def __init__(self, model: Optional[str] = None):
        # Token / API key
        # ---------------------------------------------------------------------
        # Set your OpenAI API key as an environment variable:
        #   OPENAI_API_KEY="sk-..."   (do NOT hardcode it in code)
        # ---------------------------------------------------------------------
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = model or os.getenv("TOPO_AI_MODEL", "gpt-4o-2024-08-06")

    def chat(
        self,
        user_text: str,
        topo_state: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, str]]] = None,
    ) -> AgentReply:
        if not os.getenv("OPENAI_API_KEY"):
            return AgentReply(
                message=(
                    "OPENAI_API_KEY is not set. Set it as an environment variable and restart the app.\n"
                    "Example (PowerShell):\n"
                    "  setx OPENAI_API_KEY \"sk-...\"\n"
                    "Then reopen your terminal / rerun the app."
                ),
                topology=None,
                apply_hint=False,
                warnings=["Missing OPENAI_API_KEY"],
            )

        history = history or []

        # Provide current topology as context (fast, deterministic for the model).
        topo_json_str = "{}"
        if topo_state is not None:
            try:
                import json as _json

                topo_json_str = _json.dumps(topo_state, ensure_ascii=False)
            except Exception:
                topo_json_str = "{}"

        # Responses API with Structured Outputs (Pydantic).
        # NOTE (Responses API): content parts must use type="input_text" (not "text").
        input_messages: List[Dict[str, Any]] = [
            {"role": "system", "content": [{"type": "input_text", "text": SYSTEM_PROMPT}]},
        ]

        # Add compact history.
        # NOTE: For Responses API, assistant messages must be provided as output_text.
        for m in history[-12:]:
            role = m.get("role")
            text = (m.get("text") or "").strip()
            if not text or role not in ("user", "assistant"):
                continue

            content_type = "input_text" if role == "user" else "output_text"
            input_messages.append(
                {"role": role, "content": [{"type": content_type, "text": text}]}
            )

        # Current state + user request
        input_messages.append(
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": f"CURRENT_TOPOLOGY_JSON:\n{topo_json_str}"},
                    {"type": "input_text", "text": f"REQUEST:\n{user_text}"},
                ],
            }
        )

        resp = self.client.responses.parse(
            model=self.model,
            input=input_messages,
            text_format=AgentReply,
        )
        parsed: AgentReply = resp.output_parsed
        return parsed
