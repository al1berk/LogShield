# Limitations

The dataset is mixed-source and partially synthetic.

Real-world labeled HTTP Log4Shell datasets are limited.

The detector may miss unknown obfuscation strategies.

Some external validation files are single-class malicious or single-class benign datasets, making metrics such as Receiver Operating Characteristic Area Under the Curve (ROC-AUC) undefined on those individual files.

External Splunk and Fox-IT validation row counts depend on source availability, Git Large File Storage access, and local `tshark` availability. The expanded external validation should be treated as supplementary evidence rather than population-level performance evidence.

Evaluation uses validation-calibrated binary thresholds for model comparison. The live API reports risk bands from the selected neural model score, with regex fallback only when model artifacts are unavailable.

The detector should support, not replace, patch management, dependency inventory, egress filtering, and runtime monitoring.

The Docker lab is intentionally defensive and does not include a weaponized LDAP/RMI exploit server.
