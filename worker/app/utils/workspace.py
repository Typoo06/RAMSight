# Temporary workspace helpers for analysis tasks.

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
import shutil
import tempfile

from app.storage.keys import normalize_object_name_part


@contextmanager
def isolated_job_workspace(job_id: object, base_dir: Path | None = None) -> Iterator[Path]:
    safe_job_id = normalize_object_name_part(job_id)
    workspace = Path(tempfile.mkdtemp(prefix=f"analysis-job-{safe_job_id}-", dir=base_dir))
    try:
        yield workspace
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

