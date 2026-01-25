from __future__ import annotations

from typing import Any, Dict, Optional

from jarvis.core.privacy.models import DataCategory, LawfulBasis, Sensitivity
from jarvis.core.privacy.write_api import (
    WriteDecision,
    write_artifact_metadata,
    write_memory,
    write_user_log,
)
from jarvis.core.security_events import SecurityAuditLogger


class WriteBroker:
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
