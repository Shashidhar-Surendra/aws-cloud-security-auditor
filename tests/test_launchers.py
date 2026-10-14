from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_gui_launcher_exists():
    path = ROOT / "launcher_gui.py"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert ("class AuditorGUI" in text) or ("class AuditorApp" in text)
    assert "from auditor.runner import run_audit" in text
    assert "run_audit(" in text


def test_shell_launcher_exists_and_is_executable():
    path = ROOT / "run_audit.sh"
    assert path.exists()
    assert path.stat().st_mode & 0o111
    assert "requirements.txt" in path.read_text(encoding="utf-8")


def test_windows_launcher_exists():
    path = ROOT / "run_audit_gui.bat"
    assert path.exists()
    assert "launcher_gui.py" in path.read_text(encoding="utf-8")
