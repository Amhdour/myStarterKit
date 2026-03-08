"""Integration checks that runtime code does not use registry internals for execution."""

from pathlib import Path


ALLOWED_INTERNAL_EXECUTOR_REFERENCES = {
    "tools/registry.py",
}


def test_registry_internal_executor_map_not_used_outside_registry() -> None:
    offenders: list[str] = []
    for path in Path('.').rglob('*.py'):
        rel = path.as_posix()
        if rel.startswith('.git/') or '/tests/' in f'/{rel}' or rel.startswith('tests/'):
            continue
        text = path.read_text(encoding='utf-8')
        if '._executors' in text and rel not in ALLOWED_INTERNAL_EXECUTOR_REFERENCES:
            offenders.append(rel)

    assert not offenders, f"Tool executor bypass risk: unexpected internal executor references {offenders}"
