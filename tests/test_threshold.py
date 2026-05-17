import json

import numpy as np

from detector.threshold import calibrate_threshold, load_threshold_config, save_thresholds


def test_calibration_tie_stays_near_preferred_threshold():
    y = np.array([0, 0, 1, 1])
    scores = np.array([0.1, 0.2, 0.8, 0.9])
    threshold = calibrate_threshold(y, scores, preferred=0.5)
    assert 0.21 <= threshold <= 0.8
    assert abs(threshold - 0.5) <= 0.30


def test_nested_threshold_config_round_trips(tmp_path):
    path = tmp_path / "thresholds.json"
    payload = {
        "binary_thresholds": {"regex": 0.7, "bilstm_original": 0.5},
        "calibrated_thresholds": {"regex": 0.65, "bilstm_original": 0.55},
        "risk_bands": {"benign_max_exclusive": 0.35, "suspicious_min": 0.35, "malicious_min": 0.7},
        "validation_metrics": {"regex": {"f1": 1.0}},
    }
    save_thresholds(payload, path)
    loaded = load_threshold_config(path)
    assert loaded["binary_thresholds"]["regex"] == 0.7
    assert loaded["calibrated_thresholds"]["bilstm_original"] == 0.55
    assert json.loads(path.read_text())["validation_metrics"]["regex"]["f1"] == 1.0
