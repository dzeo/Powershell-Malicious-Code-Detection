from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.features.extract import build_feature_record
from psdetect.generation.synthetic import generate_dataset
from psdetect.models.baseline import HybridPowerShellDetector


def test_smoke_pipeline_trains_on_synthetic_samples():
    samples = generate_dataset(total=20, benign_ratio=0.5, seed=7)
    records = [build_feature_record(sample.sample_id, sample.text) for sample in samples]
    labels = [0 if sample.label == "benign" else 1 for sample in samples]

    model = HybridPowerShellDetector().fit(records, labels)
    probs = model.predict_proba(records)

    assert probs.shape == (20, 2)
    assert probs[:, 1].max() > probs[:, 1].min()
