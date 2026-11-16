# Offline rule search

Use `tools/search_rules.py` to search the collected corpus without network access or tenant credentials.

```bash
# Search rule names, descriptions, paths and provenance fields.
python3 tools/search_rules.py service_account

# Search only GCP rules.
python3 tools/search_rules.py IAM --gcp

# Search the local rule bodies as well as the index.
python3 tools/search_rules.py metadata.event_type --content --gcp

# Require every term and filter by license/repository.
python3 tools/search_rules.py login privileged --all-terms \
  --license Apache-2.0 --repo chronicle

# Use a case-insensitive regular expression and JSON output.
python3 tools/search_rules.py --regex 'gcp|cloud.?audit' --gcp --json

# Show collection statistics.
python3 tools/search_rules.py --stats
python3 tools/search_rules.py --stats --gcp
```

The default search is case-insensitive **OR** matching across index metadata. `--content` adds the local file body. `--gcp` switches from `RULE_INDEX.csv` to `GCP_RULE_INDEX.csv`; it does not change or validate rule status. The tool is a corpus search utility, not a YARA-L compiler or Google SecOps validator.
