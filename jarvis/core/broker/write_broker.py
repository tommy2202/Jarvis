from __future__ import annotations

from typing import Any, Dict, Optional

from jarvis.core.privacy.models import DataCategory, LawfulBasis, Sensitivity
from jarvis.core.broker.interface import ToolBroker, ToolResult
from jarvis.core.privacy.write_api import WriteDecision, write_artifact_metadata, write_memory, write_user_log
from jarvis.core.security_events import SecurityAuditLogger


class WriteBroker(ToolBroker):
    """
    Adapter that routes persistence writes through the privacy Write API.
    """

    def __init__(
        self,
        *,
        privacy_store: Any = None,
        secure_store: Any = None,
        audit_logger: Optional[SecurityAuditLogger] = None,
    ):
        self.privacy_store = privacy_store
        self.secure_store = secure_store
        self.audit_logger = audit_logger or SecurityAuditLogger()

    def write_memory(self, *, trace_id: str, user_id: str, content: str, tags: Optional[Dict[str, str]] = None) -> WriteDecision:
        return write_memory(
            privacy_store=self.privacy_store,
            secure_store=self.secure_store,
            trace_id=trace_id,
            user_id=user_id,
            content=content,
            tags=tags,
            audit_logger=self.audit_logger,
        )

    def write_transcript(self, *, trace_id: str, user_id: str, transcript: str, tags: Optional[Dict[str, str]] = None) -> WriteDecision:
        return write_user_log(
            privacy_store=self.privacy_store,
            secure_store=self.secure_store,
            trace_id=trace_id,
            user_id=user_id,
            content=transcript,
            scope="transcripts",
            data_category=DataCategory.TRANSCRIPT,
            sensitivity=Sensitivity.HIGH,
            lawful_basis=LawfulBasis.CONSENT,
            producer="runtime.transcript",
            tags=tags,
            audit_logger=self.audit_logger,
        )

    def write_artifact_metadata(self, *, record, trace_id: str) -> WriteDecision:  # noqa: ANN001
        return write_artifact_metadata(
            privacy_store=self.privacy_store,
            record=record,
            trace_id=trace_id,
            audit_logger=self.audit_logger,
        )

    def run(self, tool_name: str, args: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
        name = str(tool_name or "")
        trace_id = str((context or {}).get("trace_id") or (args or {}).get("trace_id") or "tool")
        try:
            if name == "write.memory":
                dec = self.write_memory(
                    trace_id=trace_id,
                    user_id=str((args or {}).get("user_id") or "default"),
                    content=str((args or {}).get("content") or ""),
                    tags=dict((args or {}).get("tags") or {}),
                )
                return ToolResult(allowed=bool(dec.allowed), reason_code=str(dec.reason_code), trace_id=trace_id, output={"record_id": dec.record_id})
            if name == "write.transcript":
                dec = self.write_transcript(
                    trace_id=trace_id,
                    user_id=str((args or {}).get("user_id") or "default"),
                    transcript=str((args or {}).get("content") or ""),
                    tags=dict((args or {}).get("tags") or {}),
                )
                return ToolResult(allowed=bool(dec.allowed), reason_code=str(dec.reason_code), trace_id=trace_id, output={"record_id": dec.record_id})
            if name == "write.artifact_metadata":
                dec = self.write_artifact_metadata(record=(args or {}).get("record") or {}, trace_id=trace_id)
                return ToolResult(allowed=bool(dec.allowed), reason_code=str(dec.reason_code), trace_id=trace_id, output={"record_id": dec.record_id})
            return ToolResult(allowed=False, reason_code="TOOL_UNKNOWN", trace_id=trace_id, denied_by="registry")
        except Exception as e:  # noqa: BLE001
            return ToolResult(allowed=False, reason_code="TOOL_ERROR", trace_id=trace_id, error=str(e), denied_by="registry")
