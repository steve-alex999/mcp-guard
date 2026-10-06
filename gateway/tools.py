"""The tools the gateway exposes: argument models, risk, and their MCP listing.

The read tools reuse triage's argument models and descriptions; the write tools are defined in
gateway/actions.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from mcp_types import Tool, ToolAnnotations
from pydantic import BaseModel

from gateway.actions import CloseAlertArgs, DisableAccountArgs, QuarantineHostArgs
from triage.tools import LOOKUP_TOOLS, AssetArgs, IdentityArgs, IndicatorArgs, SearchArgs

_TRIAGE = {t["function"]["name"]: t["function"] for t in LOOKUP_TOOLS}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    title: str
    description: str
    args: type[BaseModel]
    risk: Literal["low", "medium", "high"]
    writes: bool

    def input_schema(self) -> dict[str, Any]:
        """The argument model's JSON schema, plus any field descriptions triage gives the model."""
        schema = self.args.model_json_schema()
        described = _TRIAGE[self.name]["parameters"]["properties"] if self.name in _TRIAGE else {}
        for field, prop in schema["properties"].items():
            if "description" in described.get(field, {}):
                prop["description"] = described[field]["description"]
        return schema

    def mcp_tool(self) -> Tool:
        return Tool(
            name=self.name,
            title=self.title,
            description=self.description,
            input_schema=self.input_schema(),
            annotations=ToolAnnotations(
                read_only_hint=not self.writes,
                destructive_hint=self.risk == "high" if self.writes else None,
                open_world_hint=False,
            ),
        )


def _read(name: str, title: str, args: type[BaseModel]) -> ToolSpec:
    return ToolSpec(name, title, _TRIAGE[name]["description"], args, risk="low", writes=False)


TOOLS: dict[str, ToolSpec] = {spec.name: spec for spec in [
    _read("search_change_records", "Search change records", SearchArgs),
    _read("get_asset", "Get asset", AssetArgs),
    _read("get_identity", "Get identity", IdentityArgs),
    _read("check_indicator", "Check indicator", IndicatorArgs),
    ToolSpec(
        "close_alert", "Close alert",
        "Close an alert with a final verdict (benign or threat) and a short reason citing the evidence.",
        CloseAlertArgs, risk="medium", writes=True,
    ),
    ToolSpec(
        "disable_account", "Disable account",
        "Disable a user or service account, for example one that is compromised. High risk: the "
        "gateway may hold the call for human approval or refuse it for protected accounts.",
        DisableAccountArgs, risk="high", writes=True,
    ),
    ToolSpec(
        "quarantine_host", "Quarantine host",
        "Isolate a host from the network, for example one running malware. High risk: the gateway "
        "may hold the call for human approval.",
        QuarantineHostArgs, risk="high", writes=True,
    ),
]}
