from __future__ import annotations

"""
DSAR workflows (GDPR privacy rights).

Design constraints:
- Offline-first, Windows-safe (stdlib only).
- Do not include raw conversation content by default.
- Audit visibility via event bus events (counts/ids only).
"""

import json
import os
import time
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, Tuple

from jarvis.core.events import redact
from jarvis.core.events.models import EventSeverity
from jarvis.core.privacy.models import DataCategory
from jarvis.core.privacy.models import DSARRequest, DsarRequestType, DsarStatus
from jarvis.core.privacy.store import PrivacyStore


class ModuleDataHooks(Protocol):
    """
    Core-only hook interface for modules/subsystems that own extra user data.
    """

    def dsar_export(self, *, user_id: str, out_dir: str) -> List[Tuple[str, str]]: ...
    def dsar_delete(self, *, user_id: str) -> Dict[str, int]: ...


@dataclass
class ModuleHooksRegistry:
    _hooks: Dict[str, ModuleDataHooks]

    def __init__(self) -> None:
        self._hooks = {}

    def register(self, module_id: str, hooks: ModuleDataHooks) -> None:
        self._hooks[str(module_id)] = hooks

    def list(self) -> List[str]:
        return sorted(self._hooks.keys())

    def iter_hooks(self) -> List[Tuple[str, ModuleDataHooks]]:
        return [(k, self._hooks[k]) for k in sorted(self._hooks.keys())]


class DsarEngine:
    def __init__(self, *, store: PrivacyStore, root_path: str = ".", hooks: Optional[ModuleHooksRegistry] = None, logger: Any = None):
        self.store = store
        self.root_path = str(root_path or ".")
        self.hooks = hooks or ModuleHooksRegistry()
        self.logger = logger

    @staticmethod
    def _iso_now() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def request(self, *, user_id: str, request_type: str, payload: Optional[Dict[str, Any]] = None, trace_id: str = "privacy") -> str:
        rt = str(request_type or "").strip().lower()
        if rt in {"access", "export"}:
            kind = DsarRequestType.EXPORT
        elif rt in {"delete", "erasure"}:
            kind = DsarRequestType.DELETE
        elif rt in {"correct", "rectify"}:
            kind = DsarRequestType.CORRECT
        elif rt in {"restrict"}:
            kind = DsarRequestType.RESTRICT
        else:
            raise ValueError("unknown request_type")
        req = DSARRequest(user_id=str(user_id or "default"), request_type=kind, status=DsarStatus.OPEN, payload=dict(payload or {}))
        rid = self.store.create_dsar(req)
        # audit visibility via event bus (no content)
        self.store._emit(str(trace_id), "privacy.dsar_requested", {"request_id": rid, "user_id": req.user_id, "request_type": kind.value}, severity=EventSeverity.INFO)  # noqa: SLF001
        return rid

    def get(self, request_id: str) -> Optional[DSARRequest]:
        return self.store.get_dsar(request_id)

    def run(self, *, request_id: str, actor_is_admin: bool, trace_id: str = "privacy") -> DSARRequest:
        if not bool(actor_is_admin):
            raise PermissionError("Admin required (CAP_ADMIN_ACTION).")
        req = self.store.get_dsar(request_id)
        if req is None:
            raise KeyError("not found")
        if req.status in {DsarStatus.COMPLETED, DsarStatus.REJECTED}:
            return req
        req.status = DsarStatus.IN_PROGRESS
        self.store.update_dsar(req)
        try:
            if req.request_type == DsarRequestType.EXPORT:
                out = self._run_export(req, trace_id=trace_id)
                req.result = out.get("result") or {}
                req.export_path = out.get("export_path")
            elif req.request_type == DsarRequestType.DELETE:
                out = self._run_delete(req, trace_id=trace_id)
                req.result = out.get("result") or {}
            elif req.request_type == DsarRequestType.CORRECT:
                out = self._run_correct(req, trace_id=trace_id)
                req.result = out.get("result") or {}
            elif req.request_type == DsarRequestType.RESTRICT:
                out = self._run_restrict(req, trace_id=trace_id)
                req.result = out.get("result") or {}
            else:
                raise ValueError("unsupported request type")
            req.status = DsarStatus.COMPLETED
            req.completed_at = self._iso_now()
            self.store.update_dsar(req)
            self.store._emit(  # noqa: SLF001
                str(trace_id),
                "privacy.dsar_completed",
                {"request_id": req.request_id, "user_id": req.user_id, "request_type": req.request_type.value, "result_counts": req.result.get("counts", {})},
                severity=EventSeverity.INFO,
            )
            return req
        except Exception as e:  # noqa: BLE001
            req.status = DsarStatus.REJECTED
            req.completed_at = self._iso_now()
            req.notes = f"failed: {str(e)[:120]}"
            self.store.update_dsar(req)
            self.store._emit(str(trace_id), "privacy.dsar_failed", {"request_id": req.request_id, "user_id": req.user_id, "request_type": req.request_type.value}, severity=EventSeverity.WARN)  # noqa: SLF001
            return req

    # ---- export (Art.15/20) ----
    def _run_export(self, req: DSARRequest, *, trace_id: str) -> Dict[str, Any]:
        out_dir = os.path.join(self.root_path, "runtime", "dsar")
        os.makedirs(out_dir, exist_ok=True)
        zip_path = os.path.join(out_dir, f"{req.request_id}.zip")

        # Metadata: inventory records
        records = [r.model_dump(mode="json") for r in self.store.list_records(user_id=req.user_id, limit=5000)]
        prefs = self.store.get_preferences(user_id=req.user_id).model_dump(mode="json")
        cons = {}
        try:
            raw = self.store._privacy_cfg_raw()  # noqa: SLF001
            scopes = list((raw.get("default_consent_scopes") or {}).keys())
        except Exception:
            scopes = []
        for sc in scopes:
            c = self.store.get_consent(user_id=req.user_id, scope=sc)
            cons[str(sc)] = bool(c.granted) if c else False

        # Allowlist for copying artifacts (default: from privacy.json, overrideable by payload)
        allow_copy = set()
        try:
            cfg = self.store._privacy_cfg_raw()  # noqa: SLF001
            allow_copy = set([str(x).upper() for x in ((cfg.get("dsar") or {}).get("export") or {}).get("allow_copy_categories", []) if str(x)])
        except Exception:
            allow_copy = set()
        if req.payload.get("allow_copy_categories") is not None:
            allow_copy = set([str(x).upper() for x in (req.payload.get("allow_copy_categories") or []) if str(x)])

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("metadata/data_records.json", json.dumps(records, indent=2, ensure_ascii=False))
            z.writestr("metadata/preferences.json", json.dumps(prefs, indent=2, ensure_ascii=False))
            z.writestr("metadata/consent.json", json.dumps(cons, indent=2, ensure_ascii=False))
            z.writestr("metadata/request.json", json.dumps({"request_id": req.request_id, "user_id": req.user_id, "type": req.request_type.value, "created_at": req.created_at}, indent=2, ensure_ascii=False))

            # Redacted logs (no secrets); only include a small, known set.
            include_logs = True
            try:
                cfg = self.store._privacy_cfg_raw()  # noqa: SLF001
                include_logs = bool((((cfg.get("dsar") or {}).get("export") or {}).get("include_redacted_logs", True)))
            except Exception:
                include_logs = True
            if include_logs:
                for lp in ["logs/security.jsonl", "logs/errors.jsonl", "logs/ops.jsonl"]:
                    abs_path = os.path.join(self.root_path, lp)
                    if os.path.exists(abs_path) and os.path.isfile(abs_path):
                        z.writestr(f"logs/{os.path.basename(lp)}", self._redacted_jsonl(abs_path))

            # Copy user-owned artifacts where allowed
            copied = 0
            for r in records:
                try:
                    cat = str(r.get("data_category") or "").upper()
                    sk = str(r.get("storage_kind") or "").upper()
                    ref = str(r.get("storage_ref") or "")
                except Exception:
                    continue
                if cat not in allow_copy:
                    continue
                if sk != "FILE":
                    continue
                abs_ref = ref
                if not os.path.isabs(abs_ref):
                    abs_ref = os.path.join(self.root_path, ref)
                if not os.path.exists(abs_ref) or not os.path.isfile(abs_ref):
                    continue
                # Never include audit timeline entries by copying the audit log itself.
                if "logs/audit" in abs_ref.replace("\\", "/"):
                    continue
                try:
                    # Put under artifacts/ with a stable name.
                    arc = f"artifacts/{cat}/{os.path.basename(abs_ref)}"
                    z.write(abs_ref, arcname=arc)
                    copied += 1
                except Exception:
                    continue

            # Module hooks: allow modules to add extra export files (core-only registry)
            hook_files = 0
            for mid, h in self.hooks.iter_hooks():
                try:
                    items = h.dsar_export(user_id=req.user_id, out_dir=out_dir) or []
                    for abs_path, arcname in items:
                        if abs_path and os.path.exists(abs_path) and os.path.isfile(abs_path):
                            z.write(abs_path, arcname=str(arcname))
                            hook_files += 1
                except Exception:
                    continue

        return {"export_path": zip_path, "result": {"counts": {"data_records": len(records), "copied_files": copied}}}

    @staticmethod
    def _redacted_jsonl(path: str) -> str:
        """
        Redact common secret keys and also avoid copying large binary-ish lines.
        """
        out_lines: List[str] = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    safe = redact(obj)
                    # Avoid accidentally including raw messages if present.
                    if isinstance(safe, dict):
                        safe.pop("message", None)
                        safe.pop("messages", None)
                        safe.pop("text", None)
                    out_lines.append(json.dumps(safe, ensure_ascii=False))
        except Exception:
            return ""
        return "\n".join(out_lines) + ("\n" if out_lines else "")

    # ---- delete/erasure (Art.17) ----
    def _run_delete(self, req: DSARRequest, *, trace_id: str) -> Dict[str, Any]:
        # Configurable categories via payload or privacy.json; never delete audit.
        cats = []
        action = "delete"
        try:
            cfg = self.store._privacy_cfg_raw()  # noqa: SLF001
            blk = (cfg.get("dsar") or {}).get("delete") or {}
            cats = [str(x).upper() for x in (blk.get("categories") or []) if str(x)]
            action = str(blk.get("deletion_action") or "delete").strip().lower()
        except Exception:
            cats = [DataCategory.JOB_ARTIFACT.value]
            action = "delete"
        if req.payload.get("delete_categories") is not None:
            cats = [str(x).upper() for x in (req.payload.get("delete_categories") or []) if str(x)]
        if req.payload.get("deletion_action") is not None:
            action = str(req.payload.get("deletion_action") or "delete").strip().lower()
        if not cats:
            cats = [DataCategory.JOB_ARTIFACT.value]
        deleted = 0
        skipped = 0
        for r in self.store.list_records(user_id=req.user_id, limit=10000):
            if r.data_category.value not in cats:
                continue
            if r.data_category.value == "AUDIT":
                skipped += 1
                continue
            # best-effort: use delete
            try:
                self.store._execute_deletion_action(row=self._row_from_record(r), deletion_action=action)  # noqa: SLF001
                deleted += 1
            except Exception:
                skipped += 1

        # Hooks
        for _mid, h in self.hooks.iter_hooks():
            try:
                _ = h.dsar_delete(user_id=req.user_id)
            except Exception:
                pass

        return {"result": {"counts": {"deleted_records": deleted, "skipped": skipped}}}

    @staticmethod
    def _row_from_record(r) -> Any:  # noqa: ANN001
        # Minimal shim to reuse PrivacyStore deletion helper (expects row-like keys).
        return {
            "record_id": r.record_id,
            "storage_kind": getattr(r.storage_kind, "value", str(r.storage_kind)),
            "storage_ref": r.storage_ref,
        }

    # ---- correct/rectify (Art.16) ----
    def _run_correct(self, req: DSARRequest, *, trace_id: str) -> Dict[str, Any]:
        # Profile updates: currently only display_name supported (no raw utterances).
        updates = dict(req.payload.get("profile") or {})
        changed = 0
        if "display_name" in updates:
            name = str(updates.get("display_name") or "")[:120]
            if self.store.update_user_profile(user_id=req.user_id, display_name=name):
                changed += 1
        # Memory facts: no dedicated fact store exists in core; module hooks may handle.
        return {"result": {"counts": {"profile_fields_updated": changed}}}

    # ---- restrict processing (Art.18) ----
    def _run_restrict(self, req: DSARRequest, *, trace_id: str) -> Dict[str, Any]:
        scopes: List[str] = []
        try:
            cfg = self.store._privacy_cfg_raw()  # noqa: SLF001
            scopes = [str(x).lower() for x in (((cfg.get("dsar") or {}).get("restrict") or {}).get("default_scopes") or []) if str(x)]
        except Exception:
            scopes = ["memory"]
        if req.payload.get("scopes") is not None:
            scopes = [str(x).lower() for x in (req.payload.get("scopes") or []) if str(x)]
        if not scopes:
            scopes = ["memory"]
        applied = 0
        for sc in scopes:
            if self.store.set_scope_restricted(user_id=req.user_id, scope=sc, restricted=True, trace_id=trace_id):
                applied += 1
        return {"result": {"counts": {"scopes_restricted": applied}}}

