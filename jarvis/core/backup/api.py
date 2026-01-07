from __future__ import annotations

import json
import os
import platform
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from jarvis.core.audit.models import AuditCategory, AuditEvent, AuditOutcome, AuditSeverity, Actor, ActorSource, ActorUser
from jarvis.core.backup.archiver import write_zip
from jarvis.core.backup.collector import collect_paths, profile_from_config
from jarvis.core.backup.hasher import sha256_file, sha256_bytes
from jarvis.core.backup.models import BackupManifest, ManifestFileEntry
from jarvis.core.backup.quiesce import quiesce
from jarvis.core.backup.redaction import redact_text
from jarvis.core.backup.restorer import apply_restore, plan_restore, restore_to_staging
from jarvis.core.backup.verifier import verify_zip


def _git_commit(root: str) -> Optional[str]:
    try:
        head = os.path.join(root, ".git", "HEAD")
        if not os.path.exists(head):
            return None
        ref = open(head, "r", encoding="utf-8").read().strip()
        if ref.startswith("ref:"):
            ref_path = ref.split(":", 1)[1].strip()
            p = os.path.join(root, ".git", ref_path)
            if os.path.exists(p):
                return open(p, "r", encoding="utf-8").read().strip()
        return ref[:40]
    except Exception:
        return None


class BackupManager:
    def __init__(
        self,
        *,
        cfg: Dict[str, Any],
        root_dir: str = ".",
        config_manager: Any = None,
        secure_store: Any = None,
        runtime_state: Any = None,
        audit_timeline: Any = None,
        telemetry: Any = None,
        security_audit: Any = None,
    ):
        self.cfg = cfg or {}
        self.root_dir = root_dir
        self.config_manager = config_manager
        self.secure_store = secure_store
        self.runtime_state = runtime_state
        self.audit_timeline = audit_timeline
        self.telemetry = telemetry
        self.security_audit = security_audit

    def default_dir(self) -> str:
        return str(self.cfg.get("default_dir") or "backups")

    def list_backups(self) -> List[str]:
        d = os.path.join(self.root_dir, self.default_dir())
        if not os.path.isdir(d):
            return []
        items = [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".zip")]
        items.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return items

    def create_backup(self, *, profile: str = "standard", out_dir: Optional[str] = None, include_logs_override: Optional[bool] = None) -> str:
        if not bool(self.cfg.get("enabled", True)):
            raise ValueError("Backups disabled by config.")
        out_dir = out_dir or os.path.join(self.root_dir, self.default_dir())
        prof = profile_from_config(self.cfg, profile)
        if include_logs_override is not None:
            prof = prof.__class__(name=prof.name, include_logs=bool(include_logs_override), log_days=prof.log_days, include_telemetry=prof.include_telemetry)

        backup_id = uuid.uuid4().hex
        zip_path = os.path.join(out_dir, f"backup_{profile}_{backup_id}.zip")

        t0 = time.time()
        with quiesce(config_manager=self.config_manager, secure_store=self.secure_store, runtime_state=self.runtime_state) as qinfo:
            files, warnings = collect_paths(self.root_dir, profile=prof)

            entries: List[ManifestFileEntry] = []
            file_items: List[Tuple[str, str, bytes | None]] = []
            for abs_path in files:
                rel = os.path.relpath(abs_path, self.root_dir).replace("\\", "/")
                try:
                    st = os.stat(abs_path)
                    h = sha256_file(abs_path)
                    entries.append(ManifestFileEntry(relative_path=rel, size_bytes=int(st.st_size), sha256=h))
                    file_items.append((abs_path, rel, None))
                except Exception as e:
                    warnings.append(f"Skipped {rel}: {e}")
                    continue

            # secure store meta fingerprint
            ss_fp: Dict[str, Any] = {}
            try:
                meta_path = os.path.join(self.root_dir, "secure", "store.meta.json")
                if os.path.exists(meta_path):
                    ss_fp = json.loads(open(meta_path, "r", encoding="utf-8").read())
            except Exception:
                ss_fp = {}

            man = BackupManifest(
                backup_id=backup_id,
                profile=profile,
                python_version=sys.version.split()[0],
                os_info=f"{platform.system()} {platform.release()}",
                git_commit=_git_commit(self.root_dir),
                config_version=int(getattr(getattr(self.config_manager.get(), "app", None), "config_version", 0)) if self.config_manager is not None else None,
                runtime_state_version=int(getattr(getattr(self.runtime_state.cfg, "state_version", None), "state_version", 0)) if self.runtime_state is not None else None,
                contents=entries,
                secure_store={"included": True, "store_meta_fingerprint": ss_fp},
                warnings=list(warnings) + [f"quiesce: {qinfo}"],
                redaction_applied=False,
            ).model_dump()

            write_zip(zip_path=zip_path, root_dir=self.root_dir, files=file_items, manifest=man)

        dt_s = time.time() - t0
        if self.telemetry is not None:
            try:
                self.telemetry.record_latency("backup_create_latency_ms", dt_s * 1000.0, tags={"profile": profile})
            except Exception:
                pass
        self._audit_event(
            category=AuditCategory.lifecycle,
            action="backup.create",
            outcome=AuditOutcome.success,
            summary=f"Backup created ({profile})",
            details={"backup_id": backup_id, "path": os.path.basename(zip_path)},
            severity=AuditSeverity.INFO,
        )
        return zip_path

    def verify_backup(self, zip_path: str) -> Dict[str, Any]:
        t0 = time.time()
        res = verify_zip(zip_path)
        if self.telemetry is not None:
            try:
                self.telemetry.record_latency("backup_verify_latency_ms", (time.time() - t0) * 1000.0)
            except Exception:
                pass
        self._audit_event(
            category=AuditCategory.lifecycle,
            action="backup.verify",
            outcome=AuditOutcome.success if res.ok else AuditOutcome.failed,
            summary=f"Backup verify {'ok' if res.ok else 'failed'}",
            details={"zip": os.path.basename(zip_path), "errors": res.errors[:5]},
            severity=AuditSeverity.INFO if res.ok else AuditSeverity.WARN,
        )
        return {"ok": res.ok, "errors": res.errors, "checked_files": res.checked_files}

    def export_support_bundle(self, *, days: int, out_dir: Optional[str] = None) -> str:
        sb = (self.cfg.get("support_bundle") or {})
        redact = bool(sb.get("redact", True))
        max_total = int(sb.get("max_total_mb", 200)) * 1024 * 1024
        out_dir = out_dir or os.path.join(self.root_dir, self.default_dir())
        backup_id = uuid.uuid4().hex
        zip_path = os.path.join(out_dir, f"support_bundle_{backup_id}.zip")

        # Collect log files only (last N days)
        prof_cfg = {"profiles": {"support": {"include_logs": True, "log_days": int(days), "include_telemetry": True}}}
        prof = profile_from_config(prof_cfg, "support")
        files, warnings = collect_paths(self.root_dir, profile=prof)

        items: List[Tuple[str, str, bytes | None]] = []
        entries: List[ManifestFileEntry] = []
        total = 0
        for abs_path in files:
            rel = os.path.relpath(abs_path, self.root_dir).replace("\\", "/")
            if not rel.startswith("logs/"):
                continue
            try:
                data = open(abs_path, "r", encoding="utf-8", errors="ignore").read()
                if redact:
                    data = "\n".join(redact_text(line) for line in data.splitlines())
                b = (data + "\n").encode("utf-8")
                total += len(b)
                if total > max_total:
                    raise ValueError("support bundle exceeds max_total_mb")
                entries.append(ManifestFileEntry(relative_path=rel, size_bytes=len(b), sha256=sha256_bytes(b)))
                items.append((abs_path, rel, b))
            except ValueError:
                # Do not silently produce an oversized bundle.
                raise
            except Exception as e:
                warnings.append(f"Skipped {rel}: {e}")
        man = BackupManifest(
            backup_id=backup_id,
            profile="support",
            python_version=sys.version.split()[0],
            os_info=f"{platform.system()} {platform.release()}",
            git_commit=_git_commit(self.root_dir),
            contents=entries,
            warnings=warnings,
            redaction_applied=bool(redact),
        ).model_dump()
        write_zip(zip_path=zip_path, root_dir=self.root_dir, files=items, manifest=man)
        self._audit_event(
            category=AuditCategory.lifecycle,
            action="backup.support_bundle",
            outcome=AuditOutcome.success,
            summary="Support bundle exported",
            details={"backup_id": backup_id, "zip": os.path.basename(zip_path), "redacted": bool(redact)},
            severity=AuditSeverity.INFO,
        )
        return zip_path

    def restore(self, zip_path: str, *, mode: str, dry_run: bool = True, apply: bool = False) -> Dict[str, Any]:
        plan = plan_restore(zip_path, mode=mode)
        if dry_run and not apply:
            return {"dry_run": True, "plan": plan.__dict__}

        # Pre-restore snapshot
        pre_zip = self.create_backup(profile="minimal", out_dir=os.path.join(self.root_dir, self.default_dir()))

        staging = os.path.join(self.root_dir, "restore_staging")
        staged = restore_to_staging(zip_path, staging_dir=staging, plan=plan)
        res = apply_restore(staged, target_root=self.root_dir, plan=plan)
        res["pre_restore_zip"] = pre_zip
        self._audit_event(
            category=AuditCategory.lifecycle,
            action="backup.restore",
            outcome=AuditOutcome.success,
            summary="Restore applied",
            details={"zip": os.path.basename(zip_path), "mode": mode, "backup_id": plan.backup_id},
            severity=AuditSeverity.WARN,
        )
        return res

    # ---- helpers ----
    def _audit_event(self, *, category, action: str, outcome, summary: str, details: Dict[str, Any], severity) -> None:
        if self.audit_timeline is None:
            return
        try:
            ev = AuditEvent(
                actor=Actor(source=ActorSource.system, user=ActorUser.unknown),
                category=category,
                action=action,
                outcome=outcome,
                summary=summary,
                details=details,
                severity=severity,
            )
            self.audit_timeline._append_event(ev)  # noqa: SLF001
        except Exception:
            return

