# yara-l-detection-rules

Example YARA-L 2.0 detection rules for Google SecOps (Chronicle), mapped to MITRE ATT&CK.

| Rule | Technique |
|---|---|
| `suspicious_powershell_encoded.yaral` | T1059.001 |
| `brute_force_then_success.yaral` | T1110 |
| `persistence_registry_run_key.yaral` | T1547.001 |
| `lateral_movement_many_hosts.yaral` | T1021 |
| `exfiltration_large_outbound.yaral` | T1041 |

Tune thresholds and test with retrohunt before enabling alerting. Rules are generic examples, not tied to any environment.

License: MIT

## Disclaimer
Provided for educational and defensive purposes only, as-is and without warranty. Use only on systems and accounts you own or are explicitly authorized to manage. Review and test in a non-production environment before use.

