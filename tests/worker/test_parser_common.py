# Parser common helper tests.

import pytest

from app.parsers.common import ParserError, extract_rows, parse_stdout_json


def test_extract_rows_from_columns_and_rows() -> None:
    rows = extract_rows({"columns": ["PID", "ImageFileName"], "rows": [[4, "System"]]})

    assert rows == [{"pid": 4, "image_file_name": "System"}]


def test_parse_stdout_json_rejects_invalid_json() -> None:
    with pytest.raises(ParserError):
        parse_stdout_json({"stdout": "not json"})

