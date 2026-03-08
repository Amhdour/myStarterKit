"""Integration checks for router-only tool execution paths."""

from pathlib import Path


ALLOWED_REGISTRY_EXECUTE_CALL_SITES = {
    "tools/router.py",
}


def test_registry_execute_called_only_by_router_in_runtime_code() -> None:
    offenders: list[str] = []
    for path in Path('.').rglob('*.py'):
        rel = path.as_posix()
        if rel.startswith('.git/') or '/tests/' in f'/{rel}' or rel.startswith('tests/'):
            continue
        text = path.read_text(encoding='utf-8')
        if 'registry.execute(' in text and rel not in ALLOWED_REGISTRY_EXECUTE_CALL_SITES:
            offenders.append(rel)

    assert not offenders, f"Tool registry execution bypass risk: unexpected call sites {offenders}"


ALLOWED_EXECUTION_GUARD_ENTRYPOINTS = {
    "tools/router.py",
    "tools/execution_guard.py",
}

ALLOWED_EXECUTION_CONTEXT_VAR_REFERENCES = {
    "tools/execution_guard.py",
}


def test_execution_guard_context_entry_only_used_by_router() -> None:
    offenders: list[str] = []
    for path in Path('.').rglob('*.py'):
        rel = path.as_posix()
        if rel.startswith('.git/') or '/tests/' in f'/{rel}' or rel.startswith('tests/'):
            continue
        text = path.read_text(encoding='utf-8')
        if 'enter_router_execution_context(' in text and rel not in ALLOWED_EXECUTION_GUARD_ENTRYPOINTS:
            offenders.append(rel)

    assert not offenders, f"Execution guard bypass risk: unexpected context-entry call sites {offenders}"


def test_execution_context_storage_not_mutated_outside_guard_module() -> None:
    offenders: list[str] = []
    for path in Path('.').rglob('*.py'):
        rel = path.as_posix()
        if rel.startswith('.git/') or '/tests/' in f'/{rel}' or rel.startswith('tests/'):
            continue
        text = path.read_text(encoding='utf-8')
        if '_ROUTER_EXECUTION_CONTEXT' in text and rel not in ALLOWED_EXECUTION_CONTEXT_VAR_REFERENCES:
            offenders.append(rel)

    assert not offenders, f"Execution context bypass risk: unexpected context-var references {offenders}"
