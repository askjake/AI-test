"""CP45-N focused regressions: the read-only inspector over the real report hierarchy, and launch-time refusal (never chmod) of incompatible layouts.

Real filesystem modes are used throughout.  Ownership by the runner uid (10001) is INJECTED through an lstat wrapper: creating real 10001-owned
paths needs authority outside this stage (real foreign ownership: NOT_RUN).  A dashboard-owned-only probe does NOT cover foreign ownership; the
injected cases do, and they use the same classification code.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess

import pytest

from dashboard import project_access as PA
from orchestrator_cookie import config as CC

RUNNER = 10001
TRIG, TS = "trig_20261116T120000_cafe0001", "20261116T120000Z"


def mk(path, mode=0o755):
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)
    return path


def touch(path, mode=0o644):
    path.write_text("x")
    os.chmod(path, mode)
    return path


def full_layout(tmp_path, project="proj"):
    repo = tmp_path / "repo"
    rep = mk(CC.runtime_root(repo) / "reports")
    paths = {"root": rep, "ctrl": mk(rep / ".ctrl"), "project": mk(rep / project), "runs": mk(rep / project / ".nrdp-runs"), "pending": mk(rep / project / ".nrdp-runs" / ".pending"),
             "trigger": mk(rep / project / ".nrdp-runs" / TRIG), "control": mk(rep / project / ".nrdp-runs" / TRIG / "control"),
             "report": mk(rep / project / TS), "index": touch(rep / project / "index.html"), "top_index": touch(rep / "index.html")}
    return repo, paths


def inject(table):
    real = os.lstat
    uids = {os.path.abspath(str(p)): uid for p, uid in table.items()}

    def fake(path, *a, **k):
        st = real(path, *a, **k)
        uid = uids.get(os.path.abspath(str(path)))
        if uid is None:
            return st
        fields = list(st)
        fields[4] = uid
        return os.stat_result(fields)
    return fake


def codes(result, bucket="blocking"):
    return sorted((i["path"], i["code"]) for i in result[bucket])


def digest(root):
    out = []
    for base, dirs, files in os.walk(root):
        for n in sorted(dirs + files):
            p = os.path.join(base, n)
            st = os.lstat(p)
            out.append((os.path.relpath(p, root), stat.S_IMODE(st.st_mode), st.st_uid))
    return sorted(out)


# ------------------------------------------------------------------ inspector
def test_a_compatible_dashboard_owned_layout_has_no_findings(tmp_path):
    repo, _ = full_layout(tmp_path)
    r = CC.inspect_reports_hierarchy(repo)
    assert r["exists"] and r["blocking"] == [] and r["review"] == [] and not r["migration_blocked"] and r["inspected"] >= 9


def test_nothing_is_reported_when_reports_does_not_exist(tmp_path):
    r = CC.inspect_reports_hierarchy(tmp_path / "none")
    assert not r["exists"] and r["blocking"] == [] and not r["migration_blocked"]


def test_expected_runner_owned_run_report_and_index_paths_are_not_findings_INJECTED_OWNERSHIP(tmp_path):
    repo, p = full_layout(tmp_path)
    r = CC.inspect_reports_hierarchy(repo, _lstat=inject({p["trigger"]: RUNNER, p["report"]: RUNNER, p["index"]: RUNNER}))
    assert r["blocking"] == [] and r["review"] == [] and not r["migration_blocked"]
    assert r["expected_runner_owned_count"] == 3
    assert sorted(r["expected_runner_owned"]) == sorted(["proj/.nrdp-runs/" + TRIG, "proj/" + TS, "proj/index.html"])


@pytest.mark.parametrize("which,uid,code", [
    ("project", RUNNER, "FOREIGN_OWNER"), ("runs", RUNNER, "FOREIGN_OWNER"), ("pending", RUNNER, "FOREIGN_OWNER"), ("control", RUNNER, "FOREIGN_OWNER"),
    ("ctrl", RUNNER, "FOREIGN_OWNER"), ("root", RUNNER, "FOREIGN_OWNER"), ("project", 4242, "FOREIGN_OWNER"), ("control", 4242, "FOREIGN_OWNER")])
def test_foreign_owned_project_control_and_root_paths_BLOCK_INJECTED_OWNERSHIP(tmp_path, which, uid, code):
    repo, p = full_layout(tmp_path)
    r = CC.inspect_reports_hierarchy(repo, _lstat=inject({p[which]: uid}))
    rel = os.path.relpath(p[which], p["root"])
    assert (rel, code) in codes(r) and r["migration_blocked"]
    assert (rel, code) not in codes(r, "review")
    if uid == RUNNER:
        assert "runner uid 10001 but must be dashboard-owned" in next(i["message"] for i in r["blocking"] if i["path"] == rel)


def test_unknown_uid_on_inert_history_folders_is_review_not_blocking_INJECTED_OWNERSHIP(tmp_path):
    repo, p = full_layout(tmp_path)
    r = CC.inspect_reports_hierarchy(repo, _lstat=inject({p["trigger"]: 4242, p["report"]: 4242}))
    assert r["blocking"] == [] and r["migration_blocked"]
    assert codes(r, "review") == [("proj/.nrdp-runs/" + TRIG, "FOREIGN_OWNER"), ("proj/" + TS, "FOREIGN_OWNER")]


def test_loose_real_modes_on_project_run_control_and_root_paths_block(tmp_path):
    repo, p = full_layout(tmp_path)
    for k in ("project", "runs", "control", "pending", "ctrl"):
        os.chmod(p[k], 0o777)
    os.chmod(p["root"], 0o775)
    os.chmod(p["index"], 0o666)
    os.chmod(p["report"], 0o777)
    os.chmod(p["trigger"], 0o775)
    r = CC.inspect_reports_hierarchy(repo)
    got = set(codes(r))
    for rel in (".", "proj", "proj/.nrdp-runs", "proj/.nrdp-runs/.pending", "proj/.nrdp-runs/%s/control" % TRIG, ".ctrl", "proj/index.html"):
        assert (rel, "GROUP_WORLD_WRITABLE") in got, (rel, got)
    assert codes(r, "review") == [("proj/.nrdp-runs/" + TRIG, "GROUP_WORLD_WRITABLE"), ("proj/" + TS, "GROUP_WORLD_WRITABLE")]
    assert r["migration_blocked"]


@pytest.mark.parametrize("mode", [0o700, 0o750])
def test_a_project_directory_other_users_cannot_traverse_blocks(tmp_path, mode):
    repo, p = full_layout(tmp_path)
    os.chmod(p["project"], mode)
    assert ("proj", "NOT_TRAVERSABLE") in codes(CC.inspect_reports_hierarchy(repo))


def test_a_posix_acl_on_a_project_directory_blocks(tmp_path):
    if not shutil.which("setfacl"):
        pytest.skip("setfacl not installed")
    repo, p = full_layout(tmp_path)
    if subprocess.run(["setfacl", "-m", "u:nobody:rwx", str(p["project"])], capture_output=True).returncode != 0:
        pytest.skip("filesystem does not support ACLs")
    assert ("proj", "ACL") in codes(CC.inspect_reports_hierarchy(repo))


def test_the_inspector_changes_nothing_and_honours_its_entry_budget(tmp_path):
    repo, p = full_layout(tmp_path)
    os.chmod(p["project"], 0o777)
    before = digest(p["root"])
    r = CC.inspect_reports_hierarchy(repo)
    assert digest(p["root"]) == before and r["blocking"]
    small = CC.inspect_reports_hierarchy(repo, max_entries=3)
    assert small["truncated"] and small["migration_blocked"] and any(i["code"] == "TRUNCATED" for i in small["review"])


# ------------------------------------------------------------------ launch-time: refuse, never chmod
def _launch(rep, project="proj"):
    return PA.precreate_run_dirs(str(rep), project, TRIG, TS)


@pytest.mark.parametrize("mode", [0o777, 0o775, 0o700, 0o750])
def test_launch_refuses_an_existing_incompatible_project_dir_and_leaves_it_unchanged(tmp_path, mode):
    rep = mk(tmp_path / "reports")
    proj = mk(rep / "proj", mode)
    old = mk(proj / "20261101T000000Z", 0o777)
    before = digest(rep)
    with pytest.raises(PA.ProjectAccessError, match=r"existing report project directory .*proj .*mode %04o.*nothing was changed.*reviewed migration plan" % mode):
        _launch(rep)
    assert digest(rep) == before, "an existing directory was modified or something was created"
    assert stat.S_IMODE(os.lstat(proj).st_mode) == mode and stat.S_IMODE(os.lstat(old).st_mode) == 0o777
    assert not (proj / PA.RUNS_SUBDIR).exists()


@pytest.mark.parametrize("mode,reason", [(0o777, "group- or world-writable"), (0o775, "group- or world-writable"), (0o700, "not traversable by other users")])
def test_launch_refuses_an_incompatible_reports_root_and_changes_nothing(tmp_path, mode, reason):
    rep = mk(tmp_path / "reports", mode)
    before = digest(rep)
    with pytest.raises(PA.ProjectAccessError, match="existing reports root .*%s.*nothing was changed" % reason):
        _launch(rep)
    assert digest(rep) == before


def test_launch_accepts_a_compatible_existing_layout_without_touching_it_and_is_idempotent(tmp_path):
    rep = mk(tmp_path / "reports")
    proj = mk(rep / "proj")
    first = _launch(rep)
    again = _launch(rep)
    assert first == again and stat.S_IMODE(os.lstat(proj).st_mode) == 0o755
    for key in ("run_folder", "control", "report_folder"):
        assert stat.S_IMODE(os.lstat(first[key]).st_mode) == 0o755


def test_ensure_report_project_and_prepare_project_mounts_never_chmod_an_existing_directory(tmp_path):
    rep = mk(tmp_path / "reports")
    proj = mk(rep / "p", 0o777)
    specs = mk(tmp_path / "specs")
    mk(specs / "p")
    touch(specs / "p" / "project.yaml")
    assert PA.ensure_report_project(str(rep), "p") == str(proj)
    PA.prepare_project_mounts(str(specs), str(rep), "p")
    assert stat.S_IMODE(os.lstat(proj).st_mode) == 0o777


def test_a_NEW_project_is_created_0755_even_under_a_restrictive_umask(tmp_path):
    rep = mk(tmp_path / "reports")
    old = os.umask(0o077)
    try:
        info = _launch(rep, "fresh")
    finally:
        os.umask(old)
    for path in (info["project_dir"], os.path.dirname(info["run_folder"]), info["run_folder"], info["control"], info["report_folder"]):
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o755, path
    assert stat.S_IMODE(os.lstat(info["index"]).st_mode) == 0o644


@pytest.mark.parametrize("which", ["project", "runs", "run_folder", "control", "report_folder"])
def test_launch_refuses_foreign_owned_project_and_run_paths_without_changing_them_INJECTED_OWNERSHIP(tmp_path, monkeypatch, which):
    rep = mk(tmp_path / "reports")
    proj = mk(rep / "proj")
    runs = mk(proj / PA.RUNS_SUBDIR)
    run_folder = mk(runs / TRIG)
    control = mk(run_folder / "control")
    report = mk(proj / TS)
    paths = {"project": proj, "runs": runs, "run_folder": run_folder, "control": control, "report_folder": report}
    before = digest(rep)
    monkeypatch.setattr(PA.os, "lstat", inject({paths[which]: RUNNER}))
    with pytest.raises(PA.ProjectAccessError, match=r"owned by uid 10001, not the dashboard user.*nothing was changed"):
        _launch(rep)
    monkeypatch.undo()
    assert digest(rep) == before


def test_a_runner_owned_existing_project_index_is_expected_and_accepted_INJECTED_OWNERSHIP(tmp_path, monkeypatch):
    rep = mk(tmp_path / "reports")
    index = touch(mk(rep / "proj") / "index.html")
    monkeypatch.setattr(PA.os, "lstat", inject({index: RUNNER}))
    assert _launch(rep)["index"] == str(index)


@pytest.mark.parametrize("case", ["project_0777", "runs_0777", "control_0777", "root_0775", "project_foreign"])
def test_inspector_and_launch_agree_on_every_launch_gating_path(tmp_path, monkeypatch, case):
    repo, p = full_layout(tmp_path)
    rep = p["root"]
    # the run being launched uses NEW ids so only the pre-existing hierarchy can stop it
    target = {"project_0777": ("project", 0o777), "runs_0777": ("runs", 0o777), "root_0775": ("root", 0o775), "control_0777": ("control", 0o777)}.get(case)
    table = {}
    if target:
        os.chmod(p[target[0]], target[1])
    else:
        table = {p["project"]: RUNNER}
    r = CC.inspect_reports_hierarchy(repo, _lstat=inject(table))
    assert r["blocking"], case
    if case == "control_0777":
        # control belongs to an earlier trigger id; the inspector must flag it even though THIS launch (new ids) would not touch it
        assert any(i["path"].endswith("/control") for i in r["blocking"])
        return
    if table:
        monkeypatch.setattr(PA.os, "lstat", inject(table))
    with pytest.raises(PA.ProjectAccessError):
        PA.precreate_run_dirs(str(rep), "proj", "trig_20261116T130000_aaaa0002", "20261116T130000Z")
