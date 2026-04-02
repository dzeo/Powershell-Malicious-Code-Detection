from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.features.extract import build_feature_record
from psdetect.generation.synthetic import generate_dataset
from psdetect.models.numeric_boost import NumericBoostPowerShellDetector


def test_numeric_boost_detector_trains_with_fallback_backend():
    samples = generate_dataset(total=24, benign_ratio=0.5, seed=9)
    records = [build_feature_record(sample.sample_id, sample.text) for sample in samples]
    labels = [0 if sample.label == "benign" else 1 for sample in samples]

    model = NumericBoostPowerShellDetector(backend="auto").fit(records, labels)
    probs = model.predict_proba(records)

    assert probs.shape == (24, 2)
    assert model.backend in {"histgb", "lightgbm"}
