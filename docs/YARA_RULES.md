# RAMSight YARA Rules

RAMSight uses YARA as a defensive memory-triage aid. In the thesis demo workflow, the `windows_memory_yara` analysis profile runs the usual Windows Volatility plugins and adds `windows.vadyarascan` so YARA rules can scan process memory.

The active demo rule file is:

```text
rules/yara/ramsight_memory_triage_demo.yar
```

In Docker development, the worker receives this path through:

```text
VOLATILITY_YARA_RULES_PATH=/rules/yara/ramsight_memory_triage_demo.yar
```

## Rule Groups

- Suspicious PowerShell/script-in-memory indicators.
- Process injection API clusters.
- Reflective-loading and PE-like memory context.
- Credential dumping context strings.
- Living-off-the-land command traces.
- Packed or obfuscated PE-like memory context.

The rules are heuristic. They require multiple related strings where possible and include `false_positive_note` metadata because legitimate admin tools, EDR, debuggers, installers, and forensic tools can expose similar strings in memory.

## Metadata

Every project YARA rule should include:

```text
description
author = "RAMSight"
category
severity
scope = "memory"
thesis_topic = "memory-only malware triage"
false_positive_note
updated
```

Additional metadata such as `confidence`, `noisy`, `requires_correlation`, and `performance` helps RAMSight explain triage confidence in findings and reports.

## Testing

Compile and statically review the YARA rules with:

```bash
docker compose -f docker-compose.dev.yml exec worker pytest /tests/worker/test_yara_rules.py
```

Or, from a Python environment with `yara-python` installed:

```bash
python - <<'PY'
import yara
yara.compile(filepath="rules/yara/ramsight_memory_triage_demo.yar")
print("YARA compile ok")
PY
```

## Reading Results

YARA matches are stored as `yara_matches`, converted into risk findings through the detection engine, and shown in the technical HTML report. A YARA hit is not a final malware verdict. It should be correlated with `malfind`, process ancestry, command line, network activity, loaded modules, and analyst notes.

## Limitations

- The rules are lab/demo heuristics, not production malware signatures.
- False positives are expected, especially for broad PE, packed-file, admin-tool, debugger, and EDR memory contexts.
- PDF export is not implemented in the current demo build; use the HTML report and IOC JSON/CSV exports.
