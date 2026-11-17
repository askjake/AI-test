"""Startup guard for an unresolved reports-root switch transaction (CP45-R).  Standard library only; READ-ONLY.  Lives in the dashboard package because the dashboard may not import orchestrator*; orchestrator_cookie/switch_guard.py is a thin adapter.

Every supported way of starting the dashboard (cory-app start, cory-app init, lifecycle.start_dashboard / dashboard_environment, scripts/run_dashboard.sh and
``uvicorn dashboard.app:app``, which both import dashboard.app and run create_app() and the lifespan) calls require_resolved() BEFORE it creates or modifies any
runtime or reports directory.  When a switch performed by the package installer (install.py --switch-reports) is unresolved, unreadable or inconsistent with the
directories on disk the call raises ReportsSwitchUnresolved, prints the recovery command in its message and changes nothing.  It never recovers anything itself.

The decision uses the install backup's reports-switch.json (found through <runtime>/state/nrdp-reports-switch.pointer.json) and the device+inode identities of
the four names reports / reports.legacy-b4r11-<t> / reports.new-<t> / reports.candidate-<t>.  Without a pointer, transient artefacts of a switch (a reports.new-*
directory, or a missing reports root next to switch directories) are refused as well.  A FINAL record (COMMITTED, REVERSED, ABORTED) is accepted when the live
reports root is the directory the record says it should be, even if an operator later removed a set-aside directory.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path


POINTER_NAME = "nrdp-reports-switch.pointer.json"
RECORD_NAME = "reports-switch.json"
_STATUS = ("INTENT", "PREPARED", "ASIDE", "SWITCHED", "COMMITTED", "REVERSING", "REVERSED_SOURCE_PENDING", "REVERSED", "ABORTED")
_FINAL_LIVE = {"COMMITTED": "F", "REVERSED": "L", "ABORTED": "L"}
_EXPECT = {"INTENT": {"UNSWITCHED"}, "PREPARED": {"UNSWITCHED", "HALF_ASIDE"}, "ASIDE": {"HALF_ASIDE", "SWITCHED"}, "SWITCHED": {"SWITCHED"}, "COMMITTED": {"SWITCHED"},
           "REVERSING": {"SWITCHED", "REVERSE_HALF", "REVERSED"}, "REVERSED_SOURCE_PENDING": {"REVERSED"}, "REVERSED": {"REVERSED"}, "ABORTED": {"UNSWITCHED"}}
_KEYS = ("schema", "token", "status", "checkout", "legacy_path", "candidate_path", "fresh_path", "candidate_aside", "legacy_dev", "legacy_ino")
_TOKEN = re.compile(r"^[A-Za-z0-9_]{4,32}$")


class StartupRefused(ValueError):
    pass


class ReportsSwitchUnresolved(StartupRefused):
    pass


class AgreementRefused(StartupRefused):
    pass


IDENTITY_NAME = "BUILD_IDENTITY.json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REF = re.compile(r"^(?:[A-Za-z0-9.-]+(?::[0-9]+)?/)?[A-Za-z0-9_./-]+(?::[A-Za-z0-9_.-]+|@sha256:[a-fA-F0-9]{64})?$")
_ENGINES = ("docker", "podman")


def _label(path, legacy, fresh, *, fresh_may_be_unrecorded=False):
    try:
        st = os.lstat(str(path))
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "bad"
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return "bad"
    ident = (st.st_dev, st.st_ino)
    if ident == legacy:
        return "L"
    if fresh is not None and ident == fresh:
        return "F"
    if fresh is None and fresh_may_be_unrecorded:
        try:
            empty = os.listdir(str(path)) == []
        except OSError:
            return "other"
        if empty and st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) in (0o755, 0o700):
            return "F?"
    return "other"


def observe(rec: dict) -> dict:
    legacy = (rec["legacy_dev"], rec["legacy_ino"])
    fresh = (rec["fresh_dev"], rec["fresh_ino"]) if rec.get("fresh_ino") is not None else None
    reports, aside, new, cand = (Path(rec[k]) for k in ("candidate_path", "legacy_path", "fresh_path", "candidate_aside"))
    lab = {"reports": _label(reports, legacy, fresh), "legacy_aside": _label(aside, legacy, fresh), "fresh_new": _label(new, legacy, fresh, fresh_may_be_unrecorded=True),
           "candidate_aside": _label(cand, legacy, fresh)}
    fresh_new = lab["fresh_new"] in ("F", "F?")
    if lab["reports"] == "L" and lab["legacy_aside"] == "absent" and lab["candidate_aside"] == "absent" and (lab["fresh_new"] == "absent" or fresh_new):
        state = "UNSWITCHED"
    elif lab["reports"] == "absent" and lab["legacy_aside"] == "L" and lab["candidate_aside"] == "absent" and fresh_new:
        state = "HALF_ASIDE"
    elif lab["reports"] == "F" and lab["legacy_aside"] == "L" and lab["fresh_new"] == "absent" and lab["candidate_aside"] == "absent":
        state = "SWITCHED"
    elif lab["reports"] == "absent" and lab["legacy_aside"] == "L" and lab["candidate_aside"] == "F" and lab["fresh_new"] == "absent":
        state = "REVERSE_HALF"
    elif lab["reports"] == "L" and lab["legacy_aside"] == "absent" and lab["candidate_aside"] == "F" and lab["fresh_new"] == "absent":
        state = "REVERSED"
    else:
        state = "UNKNOWN"
    return {"state": state, "labels": lab}


def _recovery(par: Path, backup) -> str:
    checkout = str(par.parent) if par.name == ".orchestrator-cookie" else "<checkout>"
    extra = " --install-backup %s" % backup if backup else ""
    return ("Diagnose with: bash <package>/recovery/recover_reports_switch.sh --checkout %s%s (diagnosis only; add --apply to take ONE verified step). If the switch completed but the "
            "install was never committed, back it out with: bash <package>/recovery/rollback.sh --checkout %s --install-backup <backup>. Nothing was recovered automatically." % (checkout, extra, checkout))


def problems(reports_dir) -> tuple:
    """(reasons, backup) - an empty reasons list means startup may proceed.  Read-only."""
    rp = Path(os.path.abspath(str(reports_dir)))
    par, name = rp.parent, rp.name
    try:
        siblings = os.listdir(str(par))
    except FileNotFoundError:
        return [], None
    except OSError as exc:
        return ["cannot list %s: %s" % (par, exc.strerror or exc)], None
    prefixes = tuple(name + s for s in (".legacy-b4r11-", ".new-", ".candidate-"))
    artefacts = sorted(n for n in siblings if n.startswith(prefixes))
    ptr = par / "state" / POINTER_NAME
    if not os.path.lexists(str(ptr)):
        out = []
        if any(n.startswith(name + ".new-") for n in artefacts):
            out.append("a transient switch directory exists without a switch pointer: %s" % ", ".join(n for n in artefacts if n.startswith(name + ".new-")))
        if artefacts and not os.path.lexists(str(rp)):
            out.append("the reports root %s is ABSENT while switch directories exist (%s) and no switch pointer was found" % (rp, ", ".join(artefacts)))
        return out, None
    try:
        if ptr.is_symlink() or not ptr.is_file():
            return ["the switch pointer %s is not a regular file" % ptr], None
        backup = Path(str(json.loads(ptr.read_text(encoding="utf-8")).get("backup", "")))
    except (OSError, ValueError, AttributeError) as exc:
        return ["the switch pointer %s is unreadable (%s)" % (ptr, exc)], None
    if not backup.is_absolute() or not backup.name.startswith("nrdp-install-backup-") or backup.is_symlink() or not backup.is_dir():
        return ["the switch pointer names %s, which is not an install backup directory" % backup], backup
    rec_path = backup / RECORD_NAME
    try:
        if rec_path.is_symlink() or not rec_path.is_file():
            return ["the switch record %s is missing or not a regular file" % rec_path], backup
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return ["the switch record %s is unreadable (%s)" % (rec_path, exc)], backup
    if not isinstance(rec, dict) or rec.get("schema") != 2 or any(k not in rec for k in _KEYS) or rec.get("status") not in _STATUS:
        return ["the switch record %s has an unsupported shape" % rec_path], backup
    token = backup.name.rsplit("-", 1)[-1]
    real = os.path.realpath
    want = {"candidate_path": rp, "legacy_path": par / (name + ".legacy-b4r11-" + token), "fresh_path": par / (name + ".new-" + token), "candidate_aside": par / (name + ".candidate-" + token)}
    if not _TOKEN.match(token) or rec["token"] != token or any(real(str(rec[k])) != real(str(v)) for k, v in want.items()):
        return ["the switch record %s does not match this reports root or its backup name" % rec_path], backup
    obs = observe(rec)
    status, state = rec["status"], obs["state"]
    if state in _EXPECT[status]:
        if status in _FINAL_LIVE:
            return [], backup
        return ["reports-root switch %s is not final: record %s, directories %s" % (backup, status, state)], backup
    if status in _FINAL_LIVE and obs["labels"]["reports"] == _FINAL_LIVE[status] and obs["labels"]["fresh_new"] == "absent":
        return [], backup           # final record, live root is the recorded one; a set-aside directory was removed later by an operator
    return ["reports-root switch %s is inconsistent: record %s, directories %s (%s)" % (backup, status, state, json.dumps(obs["labels"], sort_keys=True))], backup


# ----------------------------------------------------------------------------------------------------------------------------------------------
# CP45-V: AGREEMENT of source identity, configured runner image, verified image identity and reports-switch state.
#
# The installed source carries src/BUILD_IDENTITY.json.  A runner image built for that source carries the label org.nrdp.build_identity_sha256 (= sha256 of that
# file) and org.nrdp.files_sha256_rollup.  runtime.json names the image (image block) and state/runner_image.json is the acquisition record (image id).  Dashboard
# startup is refused when any of these disagree.  Read-only: the only external call is `<engine> image inspect <ref>`; nothing is created, repaired or removed.
# No image block (kind unavailable / absent) = dashboard-only authoring: the image checks do not apply.  No runtime configuration reachable = not a managed
# runtime (direct development run): the image checks do not apply either; the reports-switch check still does.
def _identity_path() -> Path:
    return Path(os.path.abspath(__file__)).parent.parent / IDENTITY_NAME       # NOT resolve(): a symlinked package must keep its own checkout's file


def _config_path(reports_dir) -> Path:
    env = os.environ.get("ORCHESTRATOR_COOKIE_CONFIG") or ""
    if env and os.path.isabs(env):
        return Path(env)
    return Path(os.path.abspath(str(reports_dir))).parent / "config" / "runtime.json"


def _read_identity(path: Path):
    try:
        if path.is_symlink() or not path.is_file():
            return None, None, "the source identity file %s is missing or not a regular file" % path
        raw = path.read_bytes()
        doc = json.loads(raw.decode("utf-8"))
        if not isinstance(doc, dict):
            raise ValueError("not an object")
    except (OSError, ValueError) as exc:
        return None, None, "the source identity file %s is unreadable (%s)" % (path, exc)
    return hashlib.sha256(raw).hexdigest(), doc, None


def _load_record(reports_dir):
    """(record, backup) of the reports switch when the pointer and record are readable; None otherwise (problems() reports the unreadable cases)."""
    try:
        ptr = Path(os.path.abspath(str(reports_dir))).parent / "state" / POINTER_NAME
        if ptr.is_symlink() or not ptr.is_file():
            return None
        backup = Path(str(json.loads(ptr.read_text(encoding="utf-8")).get("backup", "")))
        rp = backup / RECORD_NAME
        if rp.is_symlink() or not rp.is_file():
            return None
        rec = json.loads(rp.read_text(encoding="utf-8"))
        return (rec, backup) if isinstance(rec, dict) else None
    except (OSError, ValueError, AttributeError):
        return None


def _inspect(engine: str, ref: str):
    exe = shutil.which(engine)
    if not exe:
        return None, "the container engine %r is not on PATH, so the image cannot be verified" % engine
    try:
        r = subprocess.run([exe, "image", "inspect", ref], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "the container engine could not be queried (%s)" % type(exc).__name__
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").strip().splitlines()
        low = (err[0] if err else "").lower()
        if "no such" in low or "not found" in low or "unable to find" in low:
            return None, "the image is not present on this host"
        return None, "the container engine did not answer the inspection (rc=%s: %s)" % (r.returncode, (err[0] if err else "no output")[:120])
    try:
        info = json.loads(r.stdout)[0]
        if not isinstance(info, dict):
            raise ValueError("not an object")
    except (ValueError, IndexError, KeyError):
        return None, "the container engine returned an unreadable inspection"
    return info, None


def _read_marker(path: Path):
    try:
        if path.is_symlink() or not path.is_file():
            return None
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def agreement_check(reports_dir, runtime_config=None, identity_path=None) -> dict:
    """{'reasons': [...], 'facts': {...}} - an empty reasons list means source, image and reports state agree (or the image checks do not apply)."""
    reasons, facts = [], {}
    ident = Path(identity_path) if identity_path else _identity_path()
    cfg_path = Path(runtime_config) if runtime_config else _config_path(reports_dir)
    sha, doc, ierr = _read_identity(ident)
    facts["source_identity_sha256"] = sha
    facts["source_version_label"] = (doc or {}).get("version_label")
    loaded = _load_record(reports_dir)
    if loaded and sha:
        rec = loaded[0]
        want = rec.get("identity_sha256_after")
        if rec.get("status") == "COMMITTED" and isinstance(want, str) and _HEX64.match(want) and want != sha:
            reasons.append("the committed reports-root switch was made for source identity %s, but the installed source identity is %s" % (want[:12], sha[:12]))
    cfg = None
    if os.path.lexists(str(cfg_path)):
        try:
            cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
            if not isinstance(cfg, dict):
                raise ValueError("not an object")
        except (OSError, ValueError) as exc:
            reasons.append("the runtime configuration %s is unreadable (%s); the configured runner image cannot be checked" % (cfg_path, exc))
            return {"reasons": reasons, "facts": facts}
    facts["runtime_config"] = str(cfg_path) if cfg is not None else None
    image = (cfg or {}).get("image")
    if cfg is None or not isinstance(image, dict) or image.get("kind") in (None, "unavailable"):
        facts["runner_image"] = "not configured (dashboard-only authoring)" if cfg is not None else "no managed runtime configuration found"
        return {"reasons": reasons, "facts": facts}
    ref = image.get("image_ref")
    facts["runner_image"] = ref
    if not isinstance(ref, str) or ref.startswith("-") or not _REF.match(ref):
        reasons.append("the configured runner image reference is missing or invalid")
        return {"reasons": reasons, "facts": facts}
    if ierr:
        reasons.append(ierr)
    engine = cfg.get("engine") or "docker"
    if engine not in _ENGINES:
        reasons.append("the configured container engine %r is not supported" % (engine,))
        return {"reasons": reasons, "facts": facts}
    info, why = _inspect(engine, ref)
    if info is None:
        reasons.append("the configured runner image %s cannot be verified: %s" % (ref, why))
        return {"reasons": reasons, "facts": facts}
    labels = (info.get("Config") or {}).get("Labels") or {}
    img_id, lab_sha, lab_roll = info.get("Id"), labels.get("org.nrdp.build_identity_sha256"), labels.get("org.nrdp.files_sha256_rollup")
    facts.update(image_id=img_id, image_identity_label=lab_sha, image_version_label=labels.get("org.nrdp.version_label"))
    if not lab_sha:
        reasons.append("the configured runner image %s carries no NRDP build-identity label, so it cannot be tied to the installed source" % ref)
    elif sha and lab_sha != sha:
        reasons.append("the configured runner image %s was built for source identity %s (%s) but the installed source identity is %s (%s)"
                       % (ref, lab_sha[:12], labels.get("org.nrdp.version_label") or "?", sha[:12], (doc or {}).get("version_label") or "?"))
    elif sha and doc is not None and lab_roll != doc.get("files_sha256_rollup"):
        reasons.append("the configured runner image %s carries the right identity label but a different image-scope rollup than the installed source" % ref)
    mk = _read_marker(cfg_path.parent.parent / "state" / "runner_image.json")
    facts["acquisition_record_image_id"] = (mk or {}).get("image_id")
    if mk is None:
        reasons.append("there is no readable image acquisition record (state/runner_image.json): the configured image has not been acquired and verified by this checkout")
    elif mk.get("image_id") != img_id:
        reasons.append("the image acquisition record names image %s but the configured image %s is %s" % (str(mk.get("image_id"))[:19], ref, str(img_id)[:19]))
    return {"reasons": reasons, "facts": facts}


def _agreement_recovery(reports_dir, backup) -> str:
    par = Path(os.path.abspath(str(reports_dir))).parent
    checkout = str(par.parent) if par.name == ".orchestrator-cookie" else "<checkout>"
    root = str(par) if par.name == ".orchestrator-cookie" else "<runtime root>"
    src = Path(os.path.abspath(__file__)).parent.parent
    return ("Diagnose (read-only; allowed during an incomplete upgrade): python3 -B %s/dashboard/switch_guard.py --runtime-root %s ; ./cory-app status ; sh install.sh doctor. "
            "To FINISH the upgrade with the dashboard stopped: bash <package>/runner_image/update_runner_image.sh --checkout %s --activate --no-restart, then repeat the diagnosis until "
            "it prints AGREEMENT=OK, then ./cory-app start. To go BACK: bash <package>/recovery/rollback.sh --checkout %s --install-backup %s --image-backup <nrdp-image-activation-backup-*> "
            "(add --dry-run first). Nothing was repaired automatically."
            % (src, root, checkout, checkout, backup if backup else "<nrdp-install-backup-*>"))


def require_resolved(reports_dir, *, check_image: bool = True) -> None:
    reasons, backup = problems(reports_dir)
    extra = agreement_check(reports_dir)["reasons"] if check_image else []
    if reasons:
        par = Path(os.path.abspath(str(reports_dir))).parent
        tail = ("; also: " + "; ".join(extra)) if extra else ""
        raise ReportsSwitchUnresolved("REPORTS_SWITCH_UNRESOLVED: " + "; ".join(reasons) + tail + ". Startup was refused BEFORE any runtime or report directory was created or modified. " + _recovery(par, backup))
    if extra:
        raise AgreementRefused("STARTUP_AGREEMENT_REFUSED: " + "; ".join(extra) + ". Dashboard startup was refused BEFORE any lifecycle state, report directory or listener was created; "
                               "nothing was changed. " + _agreement_recovery(reports_dir, backup or (_load_record(reports_dir) or (None, None))[1]))


def main(argv=None) -> int:
    """Read-only diagnosis: python3 -B <checkout>/src/dashboard/switch_guard.py --runtime-root <checkout>/.orchestrator-cookie  (exit 0 = AGREEMENT=OK, 2 = refused)."""
    import argparse
    ap = argparse.ArgumentParser(description=main.__doc__)
    ap.add_argument("--runtime-root", required=True)
    args = ap.parse_args(argv)
    root = Path(os.path.abspath(args.runtime_root))
    reports = root / "reports"
    sw, backup = problems(reports)
    ag = agreement_check(reports, runtime_config=root / "config" / "runtime.json")
    for k, v in sorted(ag["facts"].items()):
        print("  %s = %s" % (k, v))
    for r in sw + ag["reasons"]:
        print("  REASON: " + r)
    if sw or ag["reasons"]:
        print("AGREEMENT=REFUSED  (dashboard startup would be refused; nothing was changed)")
        if ag["reasons"]:
            print(_agreement_recovery(reports, backup or (_load_record(reports) or (None, None))[1]))
        if sw:
            print(_recovery(root, backup))
        return 2
    print("AGREEMENT=OK  (source identity, runner image, acquisition record and reports-switch state agree, or no runner image is configured)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
