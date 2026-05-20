# Database Foundation

The initial schema is OS-aware while the MVP implementation remains Windows-first.

Evidence and analysis jobs store operating-system metadata including `os_family`, `os_version`, `architecture`, `kernel_version`, and `symbol_table`. Artifact tables use cross-platform names such as `module_artifacts` and `memory_region_artifacts`; plugin-specific origin is preserved in `source_plugin` values such as `windows.dlllist`, `windows.malfind`, `linux.lsmod`, or `linux.vmayarascan`.

Large evidence files, raw plugin outputs, and generated reports should be stored in MinIO/S3. PostgreSQL stores metadata, parsed artifacts, findings, IOCs, and report references only.
