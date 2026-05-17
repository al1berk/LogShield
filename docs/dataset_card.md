# Dataset Card

## Sources

The dataset combines controlled synthetic payloads, generated benign logs, Apache-format benign logs, hard-negative benign examples, and external validation adapters for Honeynet/Log4Pot-style feeds, Splunk attack data, Fox-IT packet captures, public Elastic Apache access logs, PayloadsAllTheThings payload examples, and CuratedIntel indicators.

## Schema

All processed files use:

```text
id,timestamp,source,raw_log,normalized_log,label,attack_family,obfuscation_type,field,split,risk_level
```

## Labeling Strategy

Synthetic malicious examples are labeled `1` when they contain Log4Shell JNDI lookup intent. Benign and hard-negative examples are labeled `0`. External honeypot, attack-data, packet-capture, and public Apache access-log rows are used as external validation and are not used for model training.

PayloadsAllTheThings examples are used for unseen-obfuscation expansion and taxonomy coverage. CuratedIntel indicators are used as callback-host and threat-intelligence context, not as labeled HTTP access-log rows.

## Splits

Training includes plain JNDI, LDAP/RMI/DNS/LDAPS, simple URL encoding, case manipulation, and a limited set of adversarial evasion variants. The unseen obfuscation test includes nested lookup, environment fallback, fragmented tokens, double URL encoding, Unicode escape, and mixed separator variants. The dedicated `adversarial_evasion_test.csv` split holds out stronger signature-bypass probes such as zero-width character insertion, Unicode homoglyphs, HTML entities, triple URL encoding, lookup-character concatenation, semantic lookup reconstruction, context embedding, whitespace/comment injection, and simulated field splitting.

## Hard Negatives

Hard negatives include benign documentation, search, scanner-report, Java Naming and Directory Interface (JNDI), Lightweight Directory Access Protocol (LDAP), and escaped payload examples. Apache-format benign training rows are generated synthetically so the model can learn normal access-log structure without seeing the public Elastic external benign test rows.

## Limitations

The dataset is mixed-source and partially synthetic. Public real-world labeled HTTP Log4Shell datasets are limited. Adversarial evasion rows represent attacker-intent probes visible in request logs and should be evaluated as detection coverage, not proof that a target runtime would execute the lookup. Some external validation and adversarial evasion files are single-class, so Receiver Operating Characteristic Area Under the Curve (ROC-AUC) can be undefined for those sets.

Fox-IT packet-capture-derived rows require `tshark`; if `tshark` is not available, the builder records a fallback source in dataset metadata rather than mislabeling fallback examples as extracted packet-capture rows.

## Privacy

Generated examples avoid real user data. External importers preserve raw payload strings for reproducibility; defenders should review external logs for sensitive data before publication.
