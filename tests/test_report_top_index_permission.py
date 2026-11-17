"""CP45-C: the top-level reports index tolerates PermissionError (warning only); every other report write still fails visibly."""
import logging, os, sys, stat
from pathlib import Path
import pytest
from orchestrator import report

pytestmark = pytest.mark.skipif(not hasattr(os, "getuid") or os.getuid() == 0, reason="needs POSIX non-root")

def _root(tmp_path):
    root = tmp_path / "reports"; (root / "projA").mkdir(parents=True); (root / "projA" / "index.html").write_text("x")
    os.chmod(root, 0o555); return root

def test_unwritable_root_skips_top_index_with_warning(tmp_path, caplog):
    root = _root(tmp_path)
    try:
        with caplog.at_level(logging.WARNING, logger="orchestrator.report"):
            assert report.render_top_index(reports_dir=str(root)) == ""
        assert any("top-level reports index not refreshed" in r.message for r in caplog.records)
        assert not (root / "index.html").exists()
    finally: os.chmod(root, 0o755)

def test_writable_root_still_writes_index(tmp_path):
    root = _root(tmp_path); os.chmod(root, 0o755)
    assert report.render_top_index(reports_dir=str(root)) == str(root / "index.html") and (root / "index.html").is_file()

def test_project_index_and_other_errors_still_raise(tmp_path):
    root = _root(tmp_path); (root / "projA" / "index.html").unlink(); os.chmod(root / "projA", 0o555)
    try:
        with pytest.raises(PermissionError): report.render_project_index("projA", reports_dir=str(root))
    finally: os.chmod(root / "projA", 0o755)
    os.chmod(root, 0o755); (root / "index.html").mkdir()                       # IsADirectoryError is not PermissionError: must propagate
    with pytest.raises(OSError): report.render_top_index(reports_dir=str(root))
