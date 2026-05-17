from scripts.build_ood_stress_test import _benign_logs, _malicious_payloads


def test_ood_stress_generators_are_balanced():
    assert len(_malicious_payloads()) == len(_benign_logs())


def test_ood_stress_contains_unseen_payload_families():
    malicious_types = {obfuscation_type for _, obfuscation_type in _malicious_payloads()}
    assert "iis_percent_u_encoding" in malicious_types
    assert "unsupported_lookup_namespace" in malicious_types
    assert "date_lookup_reconstruction" in malicious_types
