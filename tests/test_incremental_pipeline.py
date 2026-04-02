import json
from dataclasses import asdict
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.generation.synthetic import generate_dataset
from psdetect.pipeline.incremental import (
    IncrementalPipelineConfig,
    build_phase_specs,
    run_final_inference,
    run_incremental_training,
)


def test_build_phase_specs_creates_cumulative_unique_phases():
    specs = build_phase_specs(100, (0.1, 0.5, 1.0))

    assert [spec.row_count for spec in specs] == [10, 50, 100]
    assert specs[-1].fraction == 1.0


def test_final_artifact_can_score_unknown_data(tmp_path: Path):
    samples = generate_dataset(total=40, benign_ratio=0.5, seed=11)
    training_path = tmp_path / "train.jsonl"
    with training_path.open("w", encoding="utf-8") as handle:
        for sample in samples:
            handle.write(json.dumps(asdict(sample), ensure_ascii=True) + "\n")

    config = IncrementalPipelineConfig(
        input_path=training_path,
        output_dir=tmp_path / "run",
        phase_fractions=(0.5, 1.0),
        validation_fraction=0.25,
        log_every=0,
    )
    run_incremental_training(config)

    unknown_path = tmp_path / "unknown.jsonl"
    with unknown_path.open("w", encoding="utf-8") as handle:
        for sample in samples[:8]:
            row = {"sample_id": sample.sample_id, "text": sample.text}
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")

    summary = run_final_inference(
        artifact_path=tmp_path / "run" / "final" / "final_artifact.json",
        input_path=unknown_path,
        output_path=tmp_path / "unknown_scores.jsonl",
        summary_output=tmp_path / "unknown_summary.json",
        review_queue_output=tmp_path / "unknown_queue.jsonl",
        review_queue_summary_output=tmp_path / "unknown_queue_summary.json",
        top_k=5,
        log_every=0,
    )

    assert summary["rows"] == 8
    assert (tmp_path / "unknown_scores.jsonl").exists()
    assert (tmp_path / "unknown_summary.json").exists()
    assert (tmp_path / "unknown_queue.jsonl").exists()
    first_row = json.loads((tmp_path / "unknown_scores.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert "malicious_probability_corrected" in first_row
    assert "calibration_weights" in first_row


def test_incremental_pipeline_uses_group_split_without_overlap(tmp_path: Path):
    samples = generate_dataset(total=80, benign_ratio=0.5, seed=13)
    training_path = tmp_path / "train_group.jsonl"
    with training_path.open("w", encoding="utf-8") as handle:
        for sample in samples:
            handle.write(json.dumps(asdict(sample), ensure_ascii=True) + "\n")

    config = IncrementalPipelineConfig(
        input_path=training_path,
        output_dir=tmp_path / "group_run",
        group_column="family",
        phase_fractions=(1.0,),
        validation_fraction=0.25,
        log_every=0,
    )
    artifact = run_incremental_training(config)
    phase_summary = artifact["phases"][0]

    assert phase_summary["group_split"]["group_column"] == "family"
    assert phase_summary["group_split"]["group_overlap"] == 0
    assert phase_summary["group_split"]["unique_train_groups"] >= 1
    assert phase_summary["group_split"]["unique_validation_groups"] >= 1
    assert Path(phase_summary["validation_scores_path"]).exists()
