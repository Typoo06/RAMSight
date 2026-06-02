# Report recommendation tests.

from app.reports.recommendations import generate_recommendations


def test_recommendations_are_cautious_and_contextual() -> None:
    recommendations = generate_recommendations(
        {
            "risk_findings": [{"severity": "high"}],
            "iocs": [{"ioc_type": "network_endpoint"}],
            "memory_regions": [{"pid": 123}],
            "yara_matches": [{"rule_name": "Suspicious"}],
            "command_artifacts": [{"command": "powershell.exe -enc AAAA"}],
        }
    )

    joined = " ".join(recommendations).lower()

    assert "isolate" in joined or "isolating" in joined
    assert "hunt" in joined
    assert "validate" in joined
    assert "confirmed malware" not in joined
