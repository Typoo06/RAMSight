# Parser registry and dispatch for Volatility raw wrappers.

from app.parsers.commands import parse_command_artifacts
from app.parsers.common import ParsedArtifactBatch, ParserError, extract_rows, load_raw_wrapper, parse_stdout_json
from app.parsers.memory_regions import parse_memory_region_artifacts
from app.parsers.modules import parse_handles_as_no_artifacts, parse_module_artifacts
from app.parsers.network import parse_network_artifacts
from app.parsers.processes import parse_process_artifacts
from app.parsers.yara import parse_yara_matches

PARSER_REGISTRY = {
    "windows.pslist": parse_process_artifacts,
    "windows.psscan": parse_process_artifacts,
    "windows.pstree": parse_process_artifacts,
    "windows.cmdline": parse_command_artifacts,
    "windows.netscan": parse_network_artifacts,
    "windows.dlllist": parse_module_artifacts,
    "windows.handles": parse_handles_as_no_artifacts,
    "windows.malfind": parse_memory_region_artifacts,
    "windows.vadyarascan": parse_yara_matches,
    "yarascan": parse_yara_matches,
}


def get_parser(source_plugin: str):
    return PARSER_REGISTRY.get(source_plugin)


def parse_raw_wrapper(path) -> ParsedArtifactBatch:
    wrapper = load_raw_wrapper(path)
    source_plugin = wrapper.get("source_plugin") or wrapper.get("plugin_name")
    if wrapper.get("status") != "completed":
        return ParsedArtifactBatch("", [])
    parser = get_parser(source_plugin)
    if parser is None:
        return ParsedArtifactBatch("", [])
    rows = extract_rows(parse_stdout_json(wrapper))
    try:
        return parser(rows, source_plugin)
    except Exception as exc:  # noqa: BLE001 - caller stores a short parse error on the plugin result.
        raise ParserError(str(exc)) from exc
