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

function truncateText(value: string | null | undefined, maxLength = 420): string {
  if (!value) return "Not recorded";
  return value.length > maxLength ? `${value.slice(0, maxLength)}...` : value;
}

function copyToClipboard(value: string): void {
  if (!value || value === "Not recorded" || !navigator.clipboard) return;
  void navigator.clipboard.writeText(value);
}

function CopyButton({ value }: { value: string }) {
  if (!value || value === "Not recorded") return null;
  return <button className="copy-button" type="button" onClick={() => copyToClipboard(value)}>Copy</button>;
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

function CappedNote({ limit, total }: { limit: number; total: number }) {
  if (total <= limit) return null;
  return <p className="table-note">Showing {limit} of {total} normalized artifact rows. Use Focus PID or backend APIs for the full stored set.</p>;
}

export function MemoryRegionTable({ caption, memoryRegions, limit = 50 }: MemoryRegionTableProps) {
  const visibleRegions = memoryRegions.slice(0, limit);

  return (
    <div className="table-block">
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
              <td className="long-text readable-code-cell"><code>{addressRange(region)}</code><CopyButton value={addressRange(region)} /></td>
              <td>{displayValue(region.protection)}</td>
              <td>{region.is_executable ? "Yes" : "No"}</td>
              <td className="long-text">{displayValue(region.source_plugin)}</td>
              <td className="long-text">
                <span className="table-subtext">Hex: {truncateText(region.hexdump_excerpt)}</span>
                <span className="table-subtext">Disasm: {truncateText(region.disassembly_excerpt)}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
      <CappedNote limit={visibleRegions.length} total={memoryRegions.length} />
    </div>
  );
}

export function YaraMatchTable({ caption, yaraMatches, limit = 50 }: YaraMatchTableProps) {
  const visibleMatches = yaraMatches.slice(0, limit);

  return (
    <div className="table-block">
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
              <td className="long-text readable-code-cell"><code>{match.rule_name}</code><CopyButton value={match.rule_name} /></td>
              <td className="long-text">{displayValue(match.target_identifier)}</td>
              <td className="long-text readable-code-cell"><code>{offsetText(match.offset)}</code><CopyButton value={offsetText(match.offset)} /></td>
              <td>{displayValue(match.namespace)}</td>
              <td className="long-text">{displayValue(match.source_plugin)}</td>
              <td className="long-text">{truncateText(match.matched_text_excerpt)}</td>
            </tr>
          ))}
        </tbody>
      </Table>
      <CappedNote limit={visibleMatches.length} total={yaraMatches.length} />
    </div>
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
  const focusedLimit = 20;

  return (
    <div className="page-stack compact-stack">
      <p className="section-note">
        {focusPid === null
          ? "Enter a PID to focus the artifact view on one process. RAMSight shows normalized metadata only."
          : `Focused process evidence for PID ${focusPid}. Values are stored artifacts and require analyst review.`}
      </p>

      {processArtifacts.length > 0 && (
        <div className="table-block">
          <Table caption="Process artifacts">
            <thead>
              <tr><th>PID</th><th>PPID</th><th>Name</th><th>Image path</th><th>Source plugin</th></tr>
            </thead>
            <tbody>
              {processArtifacts.slice(0, focusedLimit).map((process) => (
                <tr key={process.id}>
                  <td>{displayValue(process.pid)}</td>
                  <td>{displayValue(process.ppid)}</td>
                  <td>{displayValue(process.name)}</td>
                  <td className="long-text readable-code-cell"><code>{displayValue(process.image_path)}</code><CopyButton value={displayValue(process.image_path)} /></td>
                  <td className="long-text">{displayValue(process.source_plugin)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
          <CappedNote limit={Math.min(processArtifacts.length, focusedLimit)} total={processArtifacts.length} />
        </div>
      )}

      {commandArtifacts.length > 0 && (
        <div className="table-block">
          <Table caption="Command artifacts">
            <thead>
              <tr><th>PID</th><th>Process</th><th>Command</th><th>Source plugin</th></tr>
            </thead>
            <tbody>
              {commandArtifacts.slice(0, focusedLimit).map((command) => (
                <tr key={command.id}>
                  <td>{displayValue(command.pid)}</td>
                  <td>{displayValue(command.process_name)}</td>
                  <td className="long-text readable-code-cell"><code>{truncateText(command.command, 520)}</code><CopyButton value={displayValue(command.command)} /></td>
                  <td className="long-text">{displayValue(command.source_plugin)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
          <CappedNote limit={Math.min(commandArtifacts.length, focusedLimit)} total={commandArtifacts.length} />
        </div>
      )}

      {networkArtifacts.length > 0 && (
        <div className="table-block">
          <Table caption="Network artifacts">
            <thead>
              <tr><th>PID</th><th>Process</th><th>Protocol</th><th>Endpoint</th><th>State</th><th>Source plugin</th></tr>
            </thead>
            <tbody>
              {networkArtifacts.slice(0, focusedLimit).map((network) => (
                <tr key={network.id}>
                  <td>{displayValue(network.pid)}</td>
                  <td>{displayValue(network.process_name)}</td>
                  <td>{displayValue(network.protocol)}</td>
                  <td className="long-text readable-code-cell"><code>{endpoint(network)}</code><CopyButton value={endpoint(network)} /></td>
                  <td>{displayValue(network.state)}</td>
                  <td className="long-text">{displayValue(network.source_plugin)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
          <CappedNote limit={Math.min(networkArtifacts.length, focusedLimit)} total={networkArtifacts.length} />
        </div>
      )}

      {moduleArtifacts.length > 0 && (
        <div className="table-block">
          <Table caption="Module artifacts">
            <thead>
              <tr><th>PID</th><th>Process</th><th>Module</th><th>Path</th><th>Source plugin</th></tr>
            </thead>
            <tbody>
              {moduleArtifacts.slice(0, focusedLimit).map((module) => (
                <tr key={module.id}>
                  <td>{displayValue(module.pid)}</td>
                  <td>{displayValue(module.process_name)}</td>
                  <td>{displayValue(module.module_name)}</td>
                  <td className="long-text readable-code-cell"><code>{displayValue(module.module_path)}</code><CopyButton value={displayValue(module.module_path)} /></td>
                  <td className="long-text">{displayValue(module.source_plugin)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
          <CappedNote limit={Math.min(moduleArtifacts.length, focusedLimit)} total={moduleArtifacts.length} />
        </div>
      )}

      {memoryRegions.length > 0 && <MemoryRegionTable caption="Focused memory region artifacts" memoryRegions={memoryRegions} limit={focusedLimit} />}
      {yaraMatches.length > 0 && <YaraMatchTable caption="Focused YARA match artifacts" yaraMatches={yaraMatches} limit={focusedLimit} />}
    </div>
  );
}
