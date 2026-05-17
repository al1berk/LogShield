# Threat Model

## What The System Detects

LogShield AI detects Log4Shell exploitation attempts visible in HTTP/request-derived logs, including JNDI lookup payloads hidden with URL encoding, nested lookup expressions, environment fallbacks, Unicode escapes, mixed case, and fragmented tokens.

## What The System Does Not Detect

The system does not prove that exploitation succeeded. It does not inspect memory, Java bytecode, process execution, network callbacks, or vulnerable dependency inventories.

## Assumptions

- The attempted payload appears in an access log, request log, or application log.
- The defender can monitor log lines near real time.
- The detector runs after log collection and before or during analyst triage.

## Attacker Capabilities

The attacker can control request paths, query strings, headers, and body fields. The attacker may use common Log4j lookup obfuscation techniques.

## Defender Capabilities

The defender can collect logs, run detection, review alerts, inspect outbound LDAP/RMI/DNS traffic, and patch vulnerable Apache Log4j versions.

## Limitations

This system detects exploitation attempts visible in logs. It does not prove successful exploitation and does not replace patching vulnerable Log4j versions.
