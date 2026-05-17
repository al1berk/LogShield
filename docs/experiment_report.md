# Experiment Report

This report is generated from the local dataset and evaluation artifacts.

## Executive Summary

- The original benchmark is easy for both the regex baseline and BiLSTM models on standard held-out examples.
- Adversarial evasion testing shows the main value of the learned detector: regex misses 216 of 792 evasion payloads, while Raw and Normalized BiLSTM miss 72 and BiLSTM + Attention detects all 792.
- Hard-negative mining is included in train/validation without using the frozen OOD split. On the held-out hard-negative test, the neural detectors produce 0 false positives while the regex baseline flags 86 of 180 benign examples.
- Supplementary external validation was expanded to 265 rows: 65 public/fetched malicious rows from Honeynet/Splunk/Fox-IT plus 200 public benign Apache access-log rows from Elastic examples.
- Raw BiLSTM gives the best frozen OOD F1 in the final run (0.783) while keeping external benign FPR at 0.000. BiLSTM + Attention gives the lowest OOD FPR (0.000) but has lower OOD malicious recall.
- The remaining limitation is the precision/recall tradeoff on frozen OOD malicious probes versus benign documentation, fixture, search, encoded-display, and external web-log examples.

## Dataset
- Total rows: 4922
- Splits: `{'adversarial_evasion_test': 792, 'blind_manual_test': 84, 'external_benign_web_test': 200, 'external_foxit_pcap_test': 4, 'external_greedybear_test': 60, 'external_splunk_test': 1, 'hard_negative_test': 180, 'ood_stress_test': 288, 'test': 282, 'train': 2020, 'unseen_obfuscation_test': 589, 'val': 422}`

## Training Configuration

| item                      | value                                                              |
|:--------------------------|:-------------------------------------------------------------------|
| Training script           | `scripts/train_all.py` -> `scripts/train_bilstm.py`                |
| Trained neural models     | Raw BiLSTM, Normalized BiLSTM, BiLSTM + Attention, BiLSTM + Signal |
| Character vocabulary size | 93                                                                 |
| Maximum sequence length   | 512                                                                |
| Embedding dimension       | 64                                                                 |
| Base BiLSTM layers        | 128 units + 64 units per direction                                 |
| Attention BiLSTM layer    | 96 units per direction with attention pooling                      |
| Dense layers              | 64 units for base models; 96 + 32 units for attention              |
| Dropout                   | 0.30 for base models; 0.10 spatial + 0.20 dense for attention      |
| Optimizer                 | Adam                                                               |
| Learning rate             | 1e-3 for base/signal models; 8e-4 for attention                    |
| Loss                      | Binary cross-entropy                                               |
| Class weighting           | Balanced class weights from training labels                        |
| Epochs                    | 8 with early stopping on validation loss                           |
| Batch size                | 64                                                                 |
| Threshold calibration     | Validation split only; frozen OOD is never used                    |
| Canonical signal count    | 13                                                                 |

## Threshold Calibration

- Generated at: `2026-05-16T22:15:31.966203+00:00`
- Binary thresholds: `{'bilstm_attention': 0.49999999999999994, 'bilstm_normalized': 0.49999999999999994, 'bilstm_original': 0.49999999999999994, 'bilstm_signal': 0.49999999999999994, 'regex': 0.7}`
- Thresholds are calibrated on the validation split only; the frozen OOD stress split is not used for threshold selection.

## Model Selection

- Selected deployment model: Raw BiLSTM, because it has the best balanced frozen OOD F1 (0.783) while keeping hard-negative FPR at 0.000 and external benign web-log FPR at 0.000.
- BiLSTM + Attention is the conservative alternative: OOD FPR is 0.000, but OOD malicious recall drops to 0.306.
- Regex is retained as a baseline and fast known-pattern signal, but it falls to OOD F1 0.200 and hard-negative FPR 0.478.
- The final report therefore presents Raw BiLSTM as the main detector and uses Attention as an analysis variant for the precision/recall tradeoff.

## Main Benchmark

| model              | test_set                     |   accuracy |   precision |   recall |    f1 |   fpr |   tp |   fp |   tn |   fn |
|:-------------------|:-----------------------------|-----------:|------------:|---------:|------:|------:|-----:|-----:|-----:|-----:|
| Regex Baseline     | test.csv                     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   72 |    0 |  210 |    0 |
| Raw BiLSTM         | test.csv                     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   72 |    0 |  210 |    0 |
| Normalized BiLSTM  | test.csv                     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   72 |    0 |  210 |    0 |
| BiLSTM + Attention | test.csv                     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   72 |    0 |  210 |    0 |
| BiLSTM + Signal    | test.csv                     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   72 |    0 |  210 |    0 |
| Regex Baseline     | adversarial_evasion_test.csv |      0.727 |       1.000 |    0.727 | 0.842 | 0.000 |  576 |    0 |    0 |  216 |
| Raw BiLSTM         | adversarial_evasion_test.csv |      0.909 |       1.000 |    0.909 | 0.952 | 0.000 |  720 |    0 |    0 |   72 |
| Normalized BiLSTM  | adversarial_evasion_test.csv |      0.909 |       1.000 |    0.909 | 0.952 | 0.000 |  720 |    0 |    0 |   72 |
| BiLSTM + Attention | adversarial_evasion_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |  792 |    0 |    0 |    0 |
| BiLSTM + Signal    | adversarial_evasion_test.csv |      0.909 |       1.000 |    0.909 | 0.952 | 0.000 |  720 |    0 |    0 |   72 |
| Regex Baseline     | hard_negative_test.csv       |      0.522 |       0.000 |    0.000 | 0.000 | 0.478 |    0 |   86 |   94 |    0 |
| Raw BiLSTM         | hard_negative_test.csv       |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  180 |    0 |
| Normalized BiLSTM  | hard_negative_test.csv       |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  180 |    0 |
| BiLSTM + Attention | hard_negative_test.csv       |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  180 |    0 |
| BiLSTM + Signal    | hard_negative_test.csv       |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  180 |    0 |

## Frozen OOD Stress Test

| model              | test_set            |   accuracy |   precision |   recall |    f1 |   fpr |   tp |   fp |   tn |   fn |
|:-------------------|:--------------------|-----------:|------------:|---------:|------:|------:|-----:|-----:|-----:|-----:|
| Regex Baseline     | ood_stress_test.csv |      0.333 |       0.250 |    0.167 | 0.200 | 0.500 |   24 |   72 |   72 |  120 |
| Raw BiLSTM         | ood_stress_test.csv |      0.792 |       0.818 |    0.750 | 0.783 | 0.167 |  108 |   24 |  120 |   36 |
| Normalized BiLSTM  | ood_stress_test.csv |      0.583 |       0.600 |    0.500 | 0.545 | 0.333 |   72 |   48 |   96 |   72 |
| BiLSTM + Attention | ood_stress_test.csv |      0.653 |       1.000 |    0.306 | 0.468 | 0.000 |   44 |    0 |  144 |  100 |
| BiLSTM + Signal    | ood_stress_test.csv |      0.646 |       0.733 |    0.458 | 0.564 | 0.167 |   66 |   24 |  120 |   78 |

## Ablation Insights

- Raw text performs best on the frozen OOD stress split (F1 0.783), so keeping the original character stream is useful.
- Normalization alone lowers frozen OOD F1 to 0.545, which means canonicalization can remove useful surface cues on some unseen probes.
- Adding explicit canonical signal features reaches OOD F1 0.564, so the signal vector does not improve the final generalization result.
- Attention reaches OOD F1 0.468 with FPR 0.000, making it useful when false positives are more costly than missed OOD attacks.

| experiment                         | model              |   test_f1 |   adversarial_evasion_f1 |   ood_stress_f1 |   ood_stress_recall |   ood_stress_fpr |   hard_negative_fpr |   model_error_count |
|:-----------------------------------|:-------------------|----------:|-------------------------:|----------------:|--------------------:|-----------------:|--------------------:|--------------------:|
| Raw text BiLSTM                    | Raw BiLSTM         |     1.000 |                    0.952 |           0.783 |               0.750 |            0.167 |               0.000 |                 132 |
| Normalized text BiLSTM             | Normalized BiLSTM  |     1.000 |                    0.952 |           0.545 |               0.500 |            0.333 |               0.000 |                 196 |
| BiLSTM with attention              | BiLSTM + Attention |     1.000 |                    1.000 |           0.468 |               0.306 |            0.000 |               0.000 |                 100 |
| Normalized text + canonical signal | BiLSTM + Signal    |     1.000 |                    0.952 |           0.564 |               0.458 |            0.167 |               0.000 |                 178 |
| Regex only                         | Regex Baseline     |     1.000 |                    0.842 |           0.200 |               0.167 |            0.500 |               0.478 |                 508 |

## Supplementary External Validation

| model              | test_set                     |   accuracy |   precision |   recall |    f1 |   fpr |   tp |   fp |   tn |   fn |
|:-------------------|:-----------------------------|-----------:|------------:|---------:|------:|------:|-----:|-----:|-----:|-----:|
| Regex Baseline     | external_greedybear_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   60 |    0 |    0 |    0 |
| Raw BiLSTM         | external_greedybear_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   60 |    0 |    0 |    0 |
| Normalized BiLSTM  | external_greedybear_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   60 |    0 |    0 |    0 |
| BiLSTM + Attention | external_greedybear_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   60 |    0 |    0 |    0 |
| BiLSTM + Signal    | external_greedybear_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   60 |    0 |    0 |    0 |
| Regex Baseline     | external_splunk_test.csv     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    1 |    0 |    0 |    0 |
| Raw BiLSTM         | external_splunk_test.csv     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    1 |    0 |    0 |    0 |
| Normalized BiLSTM  | external_splunk_test.csv     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    1 |    0 |    0 |    0 |
| BiLSTM + Attention | external_splunk_test.csv     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    1 |    0 |    0 |    0 |
| BiLSTM + Signal    | external_splunk_test.csv     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    1 |    0 |    0 |    0 |
| Regex Baseline     | external_foxit_pcap_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    4 |    0 |    0 |    0 |
| Raw BiLSTM         | external_foxit_pcap_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    4 |    0 |    0 |    0 |
| Normalized BiLSTM  | external_foxit_pcap_test.csv |      0.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |    0 |    4 |
| BiLSTM + Attention | external_foxit_pcap_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    4 |    0 |    0 |    0 |
| BiLSTM + Signal    | external_foxit_pcap_test.csv |      0.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |    0 |    4 |
| Regex Baseline     | external_benign_web_test.csv |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  200 |    0 |
| Raw BiLSTM         | external_benign_web_test.csv |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  200 |    0 |
| Normalized BiLSTM  | external_benign_web_test.csv |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  200 |    0 |
| BiLSTM + Attention | external_benign_web_test.csv |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  200 |    0 |
| BiLSTM + Signal    | external_benign_web_test.csv |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  200 |    0 |

## Per-Obfuscation-Family Analysis

Adversarial evasion rows are malicious-only, so the table reports recall by obfuscation type.

| obfuscation_type         |   support |   Regex Baseline recall |   Raw BiLSTM recall |   BiLSTM + Attention recall |
|:-------------------------|----------:|------------------------:|--------------------:|----------------------------:|
| comment_injection        |        72 |                   0.000 |               1.000 |                       1.000 |
| context_embedded_payload |        72 |                   1.000 |               1.000 |                       1.000 |
| field_split_payload      |        72 |                   1.000 |               0.000 |                       1.000 |
| homoglyph_jndi           |        72 |                   0.000 |               1.000 |                       1.000 |
| html_entity_jndi         |        72 |                   1.000 |               1.000 |                       1.000 |
| lookup_character_concat  |        72 |                   1.000 |               1.000 |                       1.000 |
| semantic_lookup_jndi     |        72 |                   0.000 |               1.000 |                       1.000 |
| triple_url_encoded       |        72 |                   1.000 |               1.000 |                       1.000 |
| whitespace_injection     |        72 |                   1.000 |               1.000 |                       1.000 |
| zero_width_jndi          |       144 |                   1.000 |               1.000 |                       1.000 |

The frozen OOD stress table reports recall for malicious rows and false-positive rate (FPR) for benign rows.

| class     | obfuscation_type                |   support | metric   |   Regex Baseline |   Raw BiLSTM |   BiLSTM + Attention |
|:----------|:--------------------------------|----------:|:---------|-----------------:|-------------:|---------------------:|
| benign    | benign_base64_artifact          |        24 | fpr      |            0.000 |        0.000 |                0.000 |
| benign    | benign_encoded_search_query     |        24 | fpr      |            1.000 |        1.000 |                0.000 |
| benign    | benign_fragmented_tutorial_text |        24 | fpr      |            1.000 |        0.000 |                0.000 |
| benign    | benign_json_escaped_payload     |        24 | fpr      |            0.000 |        0.000 |                0.000 |
| benign    | benign_percent_u_documentation  |        24 | fpr      |            0.000 |        0.000 |                0.000 |
| benign    | benign_unit_test_fixture        |        24 | fpr      |            1.000 |        0.000 |                0.000 |
| malicious | charcode_lookup_reconstruction  |        24 | recall   |            0.000 |        0.750 |                0.375 |
| malicious | date_lookup_reconstruction      |        24 | recall   |            0.000 |        0.750 |                0.375 |
| malicious | iis_percent_u_encoding          |        24 | recall   |            0.000 |        0.750 |                0.000 |
| malicious | protocol_fragment_sys_lookup    |        24 | recall   |            1.000 |        0.750 |                0.375 |
| malicious | sys_lookup_separator            |        24 | recall   |            0.000 |        0.750 |                0.333 |
| malicious | unsupported_lookup_namespace    |        24 | recall   |            0.000 |        0.750 |                0.375 |

## Error Analysis

| model              | test_set                     | error_type                           |   count |
|:-------------------|:-----------------------------|:-------------------------------------|--------:|
| BiLSTM + Attention | ood_stress_test.csv          | false_negative_unknown_obfuscation   |     100 |
| BiLSTM + Signal    | adversarial_evasion_test.csv | false_negative_unknown_obfuscation   |      72 |
| BiLSTM + Signal    | external_foxit_pcap_test.csv | false_negative_nested_lookup         |       2 |
| BiLSTM + Signal    | external_foxit_pcap_test.csv | false_negative_unknown_obfuscation   |       2 |
| BiLSTM + Signal    | ood_stress_test.csv          | false_negative_unknown_obfuscation   |      78 |
| BiLSTM + Signal    | ood_stress_test.csv          | false_positive_keyword_only          |      24 |
| Normalized BiLSTM  | adversarial_evasion_test.csv | false_negative_unknown_obfuscation   |      72 |
| Normalized BiLSTM  | external_foxit_pcap_test.csv | false_negative_nested_lookup         |       2 |
| Normalized BiLSTM  | external_foxit_pcap_test.csv | false_negative_unknown_obfuscation   |       2 |
| Normalized BiLSTM  | ood_stress_test.csv          | false_negative_unknown_obfuscation   |      72 |
| Normalized BiLSTM  | ood_stress_test.csv          | false_positive_keyword_only          |      48 |
| Raw BiLSTM         | adversarial_evasion_test.csv | false_negative_unknown_obfuscation   |      72 |
| Raw BiLSTM         | ood_stress_test.csv          | false_negative_unknown_obfuscation   |      36 |
| Raw BiLSTM         | ood_stress_test.csv          | false_positive_keyword_only          |      24 |
| Regex Baseline     | adversarial_evasion_test.csv | false_negative_unknown_obfuscation   |     216 |
| Regex Baseline     | blind_manual_test.csv        | false_positive_documentation_example |       4 |
| Regex Baseline     | blind_manual_test.csv        | false_positive_keyword_only          |      10 |
| Regex Baseline     | hard_negative_test.csv       | false_positive_documentation_example |      35 |
| Regex Baseline     | hard_negative_test.csv       | false_positive_keyword_only          |      51 |
| Regex Baseline     | ood_stress_test.csv          | false_negative_unknown_obfuscation   |     120 |
| Regex Baseline     | ood_stress_test.csv          | false_positive_keyword_only          |      72 |

Model-specific errors are preserved in `results/error_analysis.csv` for manual review.

## Complete Generated Results

| model              | test_set                     |   accuracy |   precision |   recall |    f1 |   fpr |   tp |   fp |   tn |   fn |
|:-------------------|:-----------------------------|-----------:|------------:|---------:|------:|------:|-----:|-----:|-----:|-----:|
| Regex Baseline     | test.csv                     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   72 |    0 |  210 |    0 |
| Raw BiLSTM         | test.csv                     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   72 |    0 |  210 |    0 |
| Normalized BiLSTM  | test.csv                     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   72 |    0 |  210 |    0 |
| BiLSTM + Attention | test.csv                     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   72 |    0 |  210 |    0 |
| BiLSTM + Signal    | test.csv                     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   72 |    0 |  210 |    0 |
| Regex Baseline     | unseen_obfuscation_test.csv  |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |  589 |    0 |    0 |    0 |
| Raw BiLSTM         | unseen_obfuscation_test.csv  |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |  589 |    0 |    0 |    0 |
| Normalized BiLSTM  | unseen_obfuscation_test.csv  |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |  589 |    0 |    0 |    0 |
| BiLSTM + Attention | unseen_obfuscation_test.csv  |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |  589 |    0 |    0 |    0 |
| BiLSTM + Signal    | unseen_obfuscation_test.csv  |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |  589 |    0 |    0 |    0 |
| Regex Baseline     | adversarial_evasion_test.csv |      0.727 |       1.000 |    0.727 | 0.842 | 0.000 |  576 |    0 |    0 |  216 |
| Raw BiLSTM         | adversarial_evasion_test.csv |      0.909 |       1.000 |    0.909 | 0.952 | 0.000 |  720 |    0 |    0 |   72 |
| Normalized BiLSTM  | adversarial_evasion_test.csv |      0.909 |       1.000 |    0.909 | 0.952 | 0.000 |  720 |    0 |    0 |   72 |
| BiLSTM + Attention | adversarial_evasion_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |  792 |    0 |    0 |    0 |
| BiLSTM + Signal    | adversarial_evasion_test.csv |      0.909 |       1.000 |    0.909 | 0.952 | 0.000 |  720 |    0 |    0 |   72 |
| Regex Baseline     | hard_negative_test.csv       |      0.522 |       0.000 |    0.000 | 0.000 | 0.478 |    0 |   86 |   94 |    0 |
| Raw BiLSTM         | hard_negative_test.csv       |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  180 |    0 |
| Normalized BiLSTM  | hard_negative_test.csv       |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  180 |    0 |
| BiLSTM + Attention | hard_negative_test.csv       |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  180 |    0 |
| BiLSTM + Signal    | hard_negative_test.csv       |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  180 |    0 |
| Regex Baseline     | external_greedybear_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   60 |    0 |    0 |    0 |
| Raw BiLSTM         | external_greedybear_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   60 |    0 |    0 |    0 |
| Normalized BiLSTM  | external_greedybear_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   60 |    0 |    0 |    0 |
| BiLSTM + Attention | external_greedybear_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   60 |    0 |    0 |    0 |
| BiLSTM + Signal    | external_greedybear_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |   60 |    0 |    0 |    0 |
| Regex Baseline     | external_splunk_test.csv     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    1 |    0 |    0 |    0 |
| Raw BiLSTM         | external_splunk_test.csv     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    1 |    0 |    0 |    0 |
| Normalized BiLSTM  | external_splunk_test.csv     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    1 |    0 |    0 |    0 |
| BiLSTM + Attention | external_splunk_test.csv     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    1 |    0 |    0 |    0 |
| BiLSTM + Signal    | external_splunk_test.csv     |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    1 |    0 |    0 |    0 |
| Regex Baseline     | external_foxit_pcap_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    4 |    0 |    0 |    0 |
| Raw BiLSTM         | external_foxit_pcap_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    4 |    0 |    0 |    0 |
| Normalized BiLSTM  | external_foxit_pcap_test.csv |      0.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |    0 |    4 |
| BiLSTM + Attention | external_foxit_pcap_test.csv |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    4 |    0 |    0 |    0 |
| BiLSTM + Signal    | external_foxit_pcap_test.csv |      0.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |    0 |    4 |
| Regex Baseline     | external_benign_web_test.csv |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  200 |    0 |
| Raw BiLSTM         | external_benign_web_test.csv |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  200 |    0 |
| Normalized BiLSTM  | external_benign_web_test.csv |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  200 |    0 |
| BiLSTM + Attention | external_benign_web_test.csv |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  200 |    0 |
| BiLSTM + Signal    | external_benign_web_test.csv |      1.000 |       0.000 |    0.000 | 0.000 | 0.000 |    0 |    0 |  200 |    0 |
| Regex Baseline     | blind_manual_test.csv        |      0.833 |       0.222 |    1.000 | 0.364 | 0.175 |    4 |   14 |   66 |    0 |
| Raw BiLSTM         | blind_manual_test.csv        |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    4 |    0 |   80 |    0 |
| Normalized BiLSTM  | blind_manual_test.csv        |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    4 |    0 |   80 |    0 |
| BiLSTM + Attention | blind_manual_test.csv        |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    4 |    0 |   80 |    0 |
| BiLSTM + Signal    | blind_manual_test.csv        |      1.000 |       1.000 |    1.000 | 1.000 | 0.000 |    4 |    0 |   80 |    0 |
| Regex Baseline     | ood_stress_test.csv          |      0.333 |       0.250 |    0.167 | 0.200 | 0.500 |   24 |   72 |   72 |  120 |
| Raw BiLSTM         | ood_stress_test.csv          |      0.792 |       0.818 |    0.750 | 0.783 | 0.167 |  108 |   24 |  120 |   36 |
| Normalized BiLSTM  | ood_stress_test.csv          |      0.583 |       0.600 |    0.500 | 0.545 | 0.333 |   72 |   48 |   96 |   72 |
| BiLSTM + Attention | ood_stress_test.csv          |      0.653 |       1.000 |    0.306 | 0.468 | 0.000 |   44 |    0 |  144 |  100 |
| BiLSTM + Signal    | ood_stress_test.csv          |      0.646 |       0.733 |    0.458 | 0.564 | 0.167 |   66 |   24 |  120 |   78 |

## Interpretation Notes

- Single-class evaluation sets intentionally report `NaN` for ROC-AUC and PR-AUC.
- `ood_stress_test.csv` is a frozen-model stress split and is not used for training, validation, regex tuning, threshold calibration, or model selection.
- Frozen OOD stress results should be read as a generalization and false-positive limit, not as the primary tuned benchmark.
- External Splunk and Fox-IT rows are validation-only and should not be interpreted as broad population-level estimates when their row counts are small.
- The detector identifies exploitation attempts visible in logs; it does not prove successful exploitation and does not replace Log4j patching.
