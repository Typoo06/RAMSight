# Alembic migration import smoke test.

import importlib.util
from pathlib import Path


def test_initial_migration_imports() -> None:
    relative_path = Path("alembic") / "versions" / "0001_initial_os_aware_schema.py"
    migration_candidates = [
        Path(__file__).resolve().parents[2] / "backend" / relative_path,
        Path("/app") / relative_path,
    ]
    migration_path = next(path for path in migration_candidates if path.exists())
    spec = importlib.util.spec_from_file_location("initial_os_aware_schema", migration_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.revision == "0001_initial_os_aware_schema"
    assert module.down_revision is None
