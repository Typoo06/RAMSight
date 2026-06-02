import { Table } from "../ui/Table";
import type {
  CommandArtifact,
  MemoryRegionArtifact,
  ModuleArtifact,
  NetworkArtifact,
  ProcessArtifact,
  YaraMatchArtifact,
} from "../../types/domain";
import { displayValue } from "../../utils/format";

interface ArtifactDrilldownProps {
  commandArtifacts: CommandArtifact[];
  focusPid: number | null;
  memoryRegions: MemoryRegionArtifact[];
  moduleArtifacts: ModuleArtifact[];
  networkArtifacts: NetworkArtifact[];
  processArtifacts: ProcessArtifact[];
  yaraMatches: YaraMatchArtifact[];
}

interface MemoryRegionTableProps {
  caption: string;
  memoryRegions: MemoryRegionArtifact[];
  limit?: number;
}

interface YaraMatchTableProps {
  caption: string;
  yaraMatches: YaraMatchArtifact[];
  limit?: number;
}

function truncateText(value: string | null | undefined, maxLength = 180): string {
  if (!value) return "Not recorded";
  return value.length > maxLength ? `${value.slice(0, maxLength)}...` : value;
}

function addressRange(region: MemoryRegionArtifact): string {
  if (region.start_address && region.end_address) return `${region.start_address}-${region.end_address}`;
  return "Not recorded";
}

function endpoint(network: NetworkArtifact): string {
  const local = network.local_address ? `${network.local_address}:${network.local_port ?? ""}` : "local unknown";
  const remote = network.remote_address ? `${network.remote_address}:${network.remote_port ?? ""}` : "remote unknown";
  return `${local} -> ${remote}`;
}

function offsetText(offset: number | string | null): string {
  if (offset === null) return "Not recorded";
  return typeof offset === "number" ? `0x${offset.toString(16)}` : offset;
}

export function MemoryRegionTable({ caption, memoryRegions, limit = 50 }: MemoryRegionTableProps) {
  const visibleRegions = memoryRegions.slice(0, limit);

  return (
    <Table caption={caption}>
      <thead>
        <tr>
          <th>PID</th>
          <th>Process</th>
          <th>Address range</th>
          <th>Protection</th>
          <th>Executable</th>
          <th>Source plugin</th>
          <th>Excerpt</th>
        </tr>
      </thead>
      <tbody>
        {visibleRegions.map((region) => (
          <tr key={region.id}>
            <td>{displayValue(region.pid)}</td>
            <td>{displayValue(region.process_name)}</td>
            <td><code>{addressRange(region)}</code></td>
            <td>{displayValue(region.protection)}</td>
            <td>{region.is_executable ? "Yes" : "No"}</td>
            <td>{displayValue(region.source_plugin)}</td>
            <td>
              <span className="table-subtext">Hex: {truncateText(region.hexdump_excerpt)}</span>
              <span className="table-subtext">Disasm: {truncateText(region.disassembly_excerpt)}</span>
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export function YaraMatchTable({ caption, yaraMatches, limit = 50 }: YaraMatchTableProps) {
  const visibleMatches = yaraMatches.slice(0, limit);

  return (
    <Table caption={caption}>
      <thead>
        <tr>
          <th>Rule</th>
          <th>Target</th>
          <th>Offset</th>
          <th>Namespace</th>
          <th>Source plugin</th>
          <th>Matched text</th>
        </tr>
      </thead>
      <tbody>
        {visibleMatches.map((match) => (
          <tr key={match.id}>
            <td>{match.rule_name}</td>
            <td>{displayValue(match.target_identifier)}</td>
            <td><code>{offsetText(match.offset)}</code></td>
            <td>{displayValue(match.namespace)}</td>
            <td>{displayValue(match.source_plugin)}</td>
            <td>{truncateText(match.matched_text_excerpt)}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export function ArtifactDrilldown({
  commandArtifacts,
  focusPid,
  memoryRegions,
  moduleArtifacts,
  networkArtifacts,
  processArtifacts,
  yaraMatches,
}: ArtifactDrilldownProps) {
  return (
    <div className="page-stack compact-stack">
      <p className="section-note">
        {focusPid === null
          ? "Enter a PID to focus the artifact view on one process."
          : `Focused process evidence for PID ${focusPid}.`}
      </p>

      {processArtifacts.length > 0 && (
        <Table caption="Process artifacts">
          <thead>
            <tr><th>PID</th><th>PPID</th><th>Name</th><th>Image path</th><th>Source plugin</th></tr>
          </thead>
          <tbody>
            {processArtifacts.slice(0, 20).map((process) => (
              <tr key={process.id}>
                <td>{displayValue(process.pid)}</td>
                <td>{displayValue(process.ppid)}</td>
                <td>{displayValue(process.name)}</td>
                <td><code>{displayValue(process.image_path)}</code></td>
                <td>{displayValue(process.source_plugin)}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      {commandArtifacts.length > 0 && (
        <Table caption="Command artifacts">
          <thead>
            <tr><th>PID</th><th>Process</th><th>Command</th><th>Source plugin</th></tr>
          </thead>
          <tbody>
            {commandArtifacts.slice(0, 20).map((command) => (
              <tr key={command.id}>
                <td>{displayValue(command.pid)}</td>
                <td>{displayValue(command.process_name)}</td>
                <td><code>{truncateText(command.command, 260)}</code></td>
                <td>{displayValue(command.source_plugin)}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      {networkArtifacts.length > 0 && (
        <Table caption="Network artifacts">
          <thead>
            <tr><th>PID</th><th>Process</th><th>Protocol</th><th>Endpoint</th><th>State</th><th>Source plugin</th></tr>
          </thead>
          <tbody>
            {networkArtifacts.slice(0, 20).map((network) => (
              <tr key={network.id}>
                <td>{displayValue(network.pid)}</td>
                <td>{displayValue(network.process_name)}</td>
                <td>{displayValue(network.protocol)}</td>
                <td><code>{endpoint(network)}</code></td>
                <td>{displayValue(network.state)}</td>
                <td>{displayValue(network.source_plugin)}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      {moduleArtifacts.length > 0 && (
        <Table caption="Module artifacts">
          <thead>
            <tr><th>PID</th><th>Process</th><th>Module</th><th>Path</th><th>Source plugin</th></tr>
          </thead>
          <tbody>
            {moduleArtifacts.slice(0, 20).map((module) => (
              <tr key={module.id}>
                <td>{displayValue(module.pid)}</td>
                <td>{displayValue(module.process_name)}</td>
                <td>{displayValue(module.module_name)}</td>
                <td><code>{displayValue(module.module_path)}</code></td>
                <td>{displayValue(module.source_plugin)}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      {memoryRegions.length > 0 && <MemoryRegionTable caption="Focused memory region artifacts" memoryRegions={memoryRegions} limit={20} />}
      {yaraMatches.length > 0 && <YaraMatchTable caption="Focused YARA match artifacts" yaraMatches={yaraMatches} limit={20} />}
    </div>
  );
}
