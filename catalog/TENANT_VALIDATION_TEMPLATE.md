# Google SecOps tenant validation intake (optional, ngoài phạm vi collection)

> Corpus collection không yêu cầu template này. Chỉ dùng nếu sau này muốn bổ sung validation riêng; không phải điều kiện để snapshot, index hoặc học tập từ rule.

Template này dành cho người dùng có **quyền được ủy quyền** trên Google SecOps tenant. Chỉ gửi kết quả đã sanitize; không đưa credentials, service-account key, raw customer logs, token, secret, email thật, hostname thật, IP thật hoặc tenant identifier nhạy cảm vào repository.

## Cách sanitize bắt buộc

- IPv4/IPv6 → RFC 5737/test values, ví dụ `192.0.2.10`, `198.51.100.10`, `203.0.113.10`.
- Email/UPN → `analyst@example.com`.
- Hostname/project/org/customer ID → `host-example`, `project-example`, `tenant-example`.
- GUID/request ID → `00000000-0000-0000-0000-000000000001`.
- Token, key, cookie, secret → xóa hoàn toàn hoặc thay bằng `<REDACTED>`.

## Manifest validation batch

Copy block này một lần cho mỗi rule hoặc một nhóm rule có cùng kết quả. Không đánh dấu `verified` chỉ dựa trên static lint.

```yaml
validation_batch:
  reviewer: "<team-or-role>"
  authorization_confirmed: true
  tenant_context: "<sanitized-tenant-context>"
  region: "<region-or-redacted>"
  validation_date: "YYYY-MM-DD"
  method: "Rules Editor Verify Rule | authorized API | other"
  raw_customer_data_included: false

rules:
  - local_path: "rules/gcp/collected/<path>.yaral"
    rule_name: "<rule name>"
    sha256: "<copy from catalog/GCP_RULE_INDEX.csv>"
    upstream_commit: "<catalog commit>"
    compiler_result: "PASS | FAIL | NOT_RUN"
    compiler_message: "<sanitized exact message or empty>"
    rule_revision_or_id: "<sanitized revision/id>"
    test_window: "<sanitized time range>"
    udm_mapping_result: "CONFIRMED | PARTIAL | NOT_CONFIRMED"
    event_types_observed:
      - "<actual metadata.event_type>"
    log_types_observed:
      - "<actual metadata.log_type>"
    vendor_product_observed:
      - vendor_name: "<sanitized vendor>"
        product_name: "<sanitized product>"
    fields_confirmed:
      - "metadata.event_type"
      - "<UDM path>"
    fields_missing_or_different:
      - "<UDM path or empty>"
    positive_test: "PASS | FAIL | NOT_RUN"
    negative_test: "PASS | FAIL | NOT_RUN"
    boundary_or_delayed_test: "PASS | FAIL | NOT_RUN"
    benign_automation_test: "PASS | FAIL | NOT_RUN"
    notes: "<parser/event semantics, sanitized>"
```

## Result interpretation

- `compiler_result=PASS` is evidence of compilation in the stated tenant/method only; it is not proof of correct detection coverage.
- `udm_mapping_result=CONFIRMED` requires observed tenant events and field/value evidence, not only documentation.
- Positive/negative tests must identify the expected behavior without exposing customer data.
- A rule may remain `PARTIAL` or `NOT_CONFIRMED` when the parser does not populate a required field.

## Repository update protocol

After review, update only the corresponding rows in `catalog/GCP_RULE_INDEX.csv` and preserve the original provenance/hash. Add the sanitized batch artifact or a link to an approved internal record; never replace upstream content or remove the original `NOT_RUN`/`NOT_VERIFIED` history without a dated audit note.

Until this template is completed from an authorized tenant, all 80 GCP entries must remain:

```text
syntax_validation_status = NOT_RUN_REQUIRES_GOOGLE_SECOPS_TENANT
udm_mapping_status       = NOT_VERIFIED_AGAINST_TENANT_EVENTS
```
