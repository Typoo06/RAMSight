# Detection rule value objects.

from dataclasses import dataclass, field
from uuid import UUID, uuid4

VALID_OS_SCOPES = {"all", "windows", "linux"}


@dataclass(frozen=True)
class DetectionRule:
    id: str
    name: str
    description: str
    category: str
    os_scope: str
    severity: str
    score: int
    enabled: bool
    recommendation: str
    match: dict = field(default_factory=dict)


@dataclass(frozen=True)
class FindingDraft:
    analysis_job_id: UUID
    evidence_id: UUID
    plugin_result_id: UUID | None
    os_family: str
    os_scope: str
    source_plugin: str | None
    rule_id: str
    rule_name: str
    category: str
    severity: str
    score: int
    title: str
    description: str
    artifact_type: str | None = None
    artifact_id: str | None = None
    recommendation: str | None = None
    extra_data: dict | None = None
    id: UUID = field(default_factory=uuid4)


def rule_from_dict(data: dict) -> DetectionRule:
    required = [
        "id",
        "name",
        "description",
        "category",
        "os_scope",
        "severity",
        "score",
        "enabled",
        "recommendation",
    ]
    missing = [field_name for field_name in required if field_name not in data]
    if missing:
        raise ValueError(f"rule is missing required fields: {', '.join(missing)}")
    os_scope = str(data["os_scope"]).lower()
    if os_scope not in VALID_OS_SCOPES:
        raise ValueError(f"unsupported os_scope: {os_scope}")
    return DetectionRule(
        id=str(data["id"]),
        name=str(data["name"]),
        description=str(data["description"]),
        category=str(data["category"]),
        os_scope=os_scope,
        severity=str(data["severity"]).lower(),
        score=int(data["score"]),
        enabled=bool(data["enabled"]),
        recommendation=str(data["recommendation"]),
        match=data.get("match") or {},
    )


def applies_to_os(rule: DetectionRule, os_family: str | None) -> bool:
    return rule.os_scope == "all" or rule.os_scope == (os_family or "unknown").lower()
