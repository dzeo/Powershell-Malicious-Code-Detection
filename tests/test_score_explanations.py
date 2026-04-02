from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.features.extract import build_feature_record
from psdetect.generation.synthetic import generate_dataset
from psdetect.models.baseline import HybridPowerShellDetector


def test_model_explanations_return_ranked_contributions():
    samples = generate_dataset(total=16, benign_ratio=0.5, seed=13)
    records = [build_feature_record(sample.sample_id, sample.text) for sample in samples]
    labels = [0 if sample.label == "benign" else 1 for sample in samples]
    model = HybridPowerShellDetector().fit(records, labels)

    explanations = model.explain(records[:3], top_k=5)

    assert len(explanations) == 3
    assert explanations[0]["top_model_contributions"]
    assert explanations[0]["top_numeric_signals"]
