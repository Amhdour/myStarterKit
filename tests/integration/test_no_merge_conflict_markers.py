"""Integration check to ensure no unresolved merge markers are committed."""

from pathlib import Path
import subprocess


CONFLICT_START = "<<<<<<< "
CONFLICT_MID = "======="
CONFLICT_END = ">>>>>>> "


def _tracked_files() -> list[Path]:
    """Return git-tracked files when available, with a safe local fallback."""

    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z"],
            check=True,
            capture_output=True,
            text=False,
        )
        paths = [Path(item.decode("utf-8")) for item in proc.stdout.split(b"\x00") if item]
        if paths:
            return paths
    except (subprocess.SubprocessError, UnicodeDecodeError):
        pass

    return [
        path
        for path in Path(".").rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and "__pycache__" not in path.parts
        and ".venv" not in path.parts
    ]


def test_no_unresolved_merge_conflict_markers() -> None:
    tracked = _tracked_files()

    offenders: list[str] = []
    for path in tracked:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lines = text.splitlines()
        in_conflict = False
        start_line = 0
        for idx, line in enumerate(lines, start=1):
            if line.startswith(CONFLICT_START):
                in_conflict = True
                start_line = idx
                continue
            if in_conflict and line.startswith(CONFLICT_MID):
                continue
            if in_conflict and line.startswith(CONFLICT_END):
                offenders.append(f"{path}:{start_line}-{idx}")
                in_conflict = False
                start_line = 0

    assert not offenders, f"Unresolved merge markers found: {offenders}"
