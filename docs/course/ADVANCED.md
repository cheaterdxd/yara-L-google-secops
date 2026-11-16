# Giáo trình nâng cao YARA-L 2.0 — Google SecOps

> Tài liệu bổ sung cho [khóa học chính](README.md) và [lab](LABS.md). Snippets là ví dụ học tập, không production-ready. Event type, product name, field population và UDM mapping phải xác minh trong tenant.

## 1. Detection engineering bắt đầu từ evidence

Đừng bắt đầu bằng cách chọn UDM field ngẫu nhiên. Hãy viết hypothesis có thể bác bỏ, ví dụ: “Một identity được cấp role nhạy cảm, sau đó dùng identity đó truy cập resource; chuỗi hành vi này cần analyst review.” Tách hypothesis thành các câu hỏi:

1. Log source nào quan sát hành động? Cloud Audit Logs Admin Activity, Data Access, VPC Flow, DNS hay product-specific audit?
2. Parser map hành động vào `metadata.event_type`, `metadata.product_event_type`, `metadata.product_name` và `metadata.log_type` nào?
3. Actor là user, service account, delegated identity hay impersonated principal? Có canonical key chung giữa log sources không?
4. Role/resource/action được map vào field nào và có repeated-field semantics không?
5. Thành công/thất bại nằm ở `security_result.action`, status, hay custom field?
6. Thời gian hành vi và độ trễ ingest là bao lâu? Có out-of-order events?
7. Automation hợp lệ nào có thể match: Terraform, CI/CD, break-glass, platform operations?

Tạo evidence table từ event mẫu đã sanitize:

| Thuộc tính | Positive sample | Benign sample | UDM field đã xác minh? | Nguồn/parser |
|---|---|---|---|---|
| Event type | enum thực tế | enum thực tế | Yes/No | log type |
| Actor | normalized principal | service identity | Yes/No | parser |
| Target | resource/identity | project/resource | Yes/No | parser |
| Outcome | action/status | expected result | Yes/No | parser |
| Timestamp | event time | ingest time | Yes/No | parser |

Thiếu positive và negative samples thì chỉ nên gọi rule là `draft/hypothesis`, không phải validated detection.

## 2. Cấu trúc rule: sections và vai trò

```yaral
rule example_single_event {
  meta:
    author = "SOC Detection Engineering"
    description = "Example only; replace with a tenant-verified hypothesis"
    severity = "Medium"
    priority = "Medium"
    type = "hunt"
    data_source = "Replace with verified parser/log source"
    assumption = "Enums and UDM paths remain placeholders until verified"

  events:
    $event.metadata.event_type = "CONFIRMED_EVENT_TYPE"
    $event.metadata.log_type = "CONFIRMED_LOG_TYPE"

  condition:
    $event
}
```

- `meta`: ownership, intent, severity, ATT&CK and triage context; does not filter events.
- `events`: selects telemetry, constrains records and binds variables. Prefer selective equality filters before regex/reference lookups when the logic permits.
- `match`: defines grouping keys and time boundaries for correlation/aggregation. An empty/common key can cause bad correlation or cardinality issues.
- `outcome`: adds aggregate/context values; it is not automatically the trigger.
- `condition`: expresses when the hypothesis is considered met.
- `options`: behavior flags; use only after checking the current engine semantics.

Use readable event-variable names (`$iam_change`, `$gcs_read`) and placeholders (`$actor_email`, `$project_id`) rather than generic `$e1`/`$x`. Names help reviewers; they do not change behavior.

## 3. Convert search logic to a rule

Search can omit rule-specific structure. A rule needs named event variables and explicit correlation/trigger logic.

### Stage 1: discover candidate events

Conceptual filter-search shape:

```text
metadata.log_type = "GCP_CLOUDAUDIT"
metadata.product_event_type = "SetIamPolicy"
```

This is not a universal schema assertion. Confirm actual values using tenant data, parser docs and UDM field references.

### Stage 2: name the event and verify fields

```yaral
events:
  $iam.metadata.log_type = "CONFIRMED_LOG_TYPE"
  $iam.metadata.product_event_type = "CONFIRMED_METHOD_NAME"
  $iam.security_result.action = "CONFIRMED_SUCCESS_ACTION"
```

Only add predicates that represent the hypothesis. A wrong enum may compile but never match. A broad `NETWORK_*` predicate may be expensive or noisy.

### Stage 3: bind stable correlation keys

```yaral
  $actor = $iam.principal.user.userid
  $resource = $iam.target.resource.name
```

Verify the field is populated and normalized consistently across all correlated sources. Prefer stable identifiers over display names. Consider service-account impersonation, aliases, project scope and empty values.

### Stage 4: add time and trigger logic

Add `match` only when correlation/aggregation needs it. Do not choose threshold/window by habit; derive them from behavior timing, ingestion latency, event volume and benign baseline.

## 4. Co-occurrence is not necessarily sequence

```yaral
events:
  $login.metadata.event_type = "CONFIRMED_LOGIN_EVENT"
  $login.principal.user.userid = $actor

  $change.metadata.event_type = "CONFIRMED_CHANGE_EVENT"
  $change.principal.user.userid = $actor

match:
  $actor over 30m

condition:
  $login and $change
```

This expresses both event variables within the chosen grouping/window semantics; variable names do not establish order. If the detection requires “login before change”, use a documented temporal construct or timestamp comparison supported by the rule engine and test it. Explicitly decide which timestamp is authoritative and how late-arriving records affect results.

| Login | Change | Same actor | Required order | Expected result |
|---:|---:|---:|---:|---|
| absent | present | — | — | no match |
| present | absent | — | — | no match |
| present | present | no | — | no match |
| present | present | yes | no | no match if order is part of hypothesis |
| present | present | yes | yes | candidate match; review context/false positives |

## 5. Thresholds, counts and grouping

Do not confuse event count with distinct placeholder count. Confirm the exact `#event`/`#placeholder` semantics in the current YARA-L documentation and the relevant rule mode.

Threshold calibration workflow:

1. Choose the population key: user, service account, IP, resource, project or a justified composite.
2. Include enough time to capture weekday/weekend, maintenance and scheduled-job patterns.
3. Measure raw count and distinct count distributions (for example median/95th/99th percentile).
4. Separate expected automation from human activity using owned, expiring allowlists.
5. Compare threshold/window pairs against a false-positive budget.
6. Start non-alerting/hunt where possible; measure detections per day before alerting.

Example shape only:

```yaral
match:
  $actor over VERIFIED_WINDOW

condition:
  #event_variable >= VERIFIED_THRESHOLD
```

Replace placeholders with valid variable names and evidence-derived values. Do not copy this as a ready-to-run rule.

## 6. Zero values, nulls and joins

UDM scalar fields can be absent and assume zero/default values. If two missing strings are equated, both may appear as `""`, creating an unintended join. Before joining:

- Compare positive/negative events and field coverage from each parser.
- Ensure every join key is populated on both event paths.
- Apply supported non-empty checks only where necessary; know the engine's implicit zero-value handling for match variables.
- Do not infer null semantics from SQL, SPL or another SIEM.
- Review repeated-field/cardinality behavior; multi-valued fields can produce unexpected combinations.

Review identity canonicalization, email normalization, service account impersonation, resource scope, cross-project joins and repeated arrays.

## 7. Regex, CIDR, reference lists and data tables

Regex is for stable patterns, not a replacement for exact enum matching. Prefer narrow/anchored expressions; verify escaping, case and supported RE2 syntax. An exact event enum equality often gives a smaller candidate set than regex.

For reference lists/data tables:

- Match data type to list type (STRING, REGEX, CIDR) and field type.
- Store source URL, owner, reviewer, refresh time, expiry and approval.
- Separate allowlists from threat-indicator lists.
- Test empty fields, case sensitivity, negation and table-column behavior.
- Avoid embedding large static indicator collections in the rule body.
- Check table/list scope and ensure dependencies exist before rule validation.

An empty or stale threat-intel list can make a rule silent or noisy. Document feed freshness and failure behavior.

## 8. Outcomes and risk scoring

Use outcomes for analyst context: actor, resource, project, distinct resource count, source IPs, detection count or risk score. They do not necessarily gate a detection; use a condition on an outcome only if supported and intended.

- Output only context needed for triage; avoid unnecessary sensitive data.
- Understand `array_distinct`, `count_distinct`, and aggregation constraints for the rule mode.
- A numeric risk score is prioritization, not a probability of compromise.
- Explain score weights and keep them aligned with severity policy.
- Avoid excessive arrays/output cardinality.

## 9. GCP worked-design: sensitive IAM permission grant

**Hypothesis:** a principal receives a sensitive role on an organization/project/resource outside an approved workflow.

**Telemetry dependencies:** Cloud Audit Logs Admin Activity enabled and ingested; verify actual method-to-UDM mapping for IAM policy changes. Data Access logs are needed only if the hypothesis also includes data access. Confirm organization/folder/project scope.

| Field group | Verify before implementation |
|---|---|
| Event type/method | Actual `metadata.event_type` and `metadata.product_event_type` from parser output |
| Actor | `principal.user` identity, service account, delegation/impersonation behavior |
| Granted identity | Target principal or binding delta field actually populated |
| Role | Exact role path, custom roles, removal vs addition semantics |
| Result | Successful/denied action mapping |
| Resource | Organization, folder, project, service account or bucket scope |
| Exceptions | Narrow CI/CD/admin identities with owner and expiry |
| Tests | Positive grant, normal admin change, denied change, empty actor, unrelated role, late/duplicate event |

Do not assume fields such as `target.user.attribute.roles.name` exist in every parser. Inspect representative, sanitized UDM events and confirm against the parser's mapping. Only then write the predicates and run Rules Editor/API verification.

### Safe tuning loop

1. Confirm ingestion and normalization through allowed UDM search.
2. Save a sanitized evidence sample and field-coverage notes.
3. Verify syntax/fields in the SecOps Rules Editor or `verifyRuleText` API.
4. Run positive, negative, boundary, benign-automation, late/duplicate and missing-field cases.
5. Test/retrohunt on an approved historical range; record volume and false positives.
6. Peer-review changes, use non-alerting first where practical, then deploy with owner and rollback plan.

## 10. Performance and maintainability

Reduce candidate events early with selective event-type, log-type, product, method and action filters. Keep windows as short as behavior allows. Avoid overly broad match keys and repeated-field cross products. Profile regex/reference-list usage on representative volume.

Rule hygiene:

- One `.yaral` file per rule, stable name and required metadata.
- Retain upstream copyright/license header and provenance when adapting content.
- Document owner, rule ID, source, version, data dependencies, assumptions, ATT&CK and runbook.
- Distinguish `draft`, `hunt`, `alert-candidate`, `validated` and `deprecated` states.
- Keep edits reviewed and reversible; never commit tenant secrets or raw customer logs.

## 11. Validation levels

| Level | Check | Proves | Does not prove |
|---|---|---|---|
| 0 | Design review | Intent and assumptions are understandable | Syntax correctness |
| 1 | Local lint/parser | Selected structural/style issues | Google engine compatibility unless explicitly supported |
| 2 | SecOps `verifyRuleText`/Rules Editor | The engine accepts rule syntax and supported field references | Detection quality |
| 3 | Sanitized positive/negative fixtures | Logic against those cases | Live parser behavior or real false-positive rate |
| 4 | Test Rule/retrohunt | Behavior on selected tenant/time range | Future coverage or universal portability |
| 5 | Non-alerting live run | Ingestion delay and operational behavior | Zero false negatives |

For each validation, record sanitized tenant/environment identifier, date, rule revision/hash, method, compiler result, test window, field evidence and reviewer. Never claim syntax/UDM validation if no tenant request was run.

## 12. Review exercises

### Exercise A — Key creation

Design a single-event hypothesis for a new service-account key. State the audit-log prerequisite, exact method/event mapping to verify, actor/target fields, expected admin automation, and positive/negative cases. Do not invent enums.

### Exercise B — IAM change followed by GCS access

Draw the event sequence and choose the correlation key. Specify the window, order constraint, timestamp field and tests for reversed order, different actor, missing identity and late ingestion. Confirm that the selected temporal construct is supported before coding.

### Exercise C — Permission-denied burst

Separate per-principal event count from distinct services/resources. Define a baseline method, possible benign causes, exclusions with owner/expiry, and an alert-volume target.

### Exercise D — Source intake review

For any public rule source, capture repository URL, immutable commit, file path, exact license, source log, UDM assumptions, SHA-256, test status, and whether the logic is a production detection, hunting query, saved search or fixture. If license is unclear, record a link-only pointer rather than redistributing.

## 13. Risk Analytics và `metrics.*`

`metrics.*` là nhóm hàm của Google SecOps Risk Analytics dùng dữ liệu lịch sử đã được aggregate để so sánh hành vi hiện tại với baseline. Đây không phải một cách thay thế cho UDM mapping: rule vẫn cần event hiện tại, placeholder dimension đúng và telemetry tương ứng.

### 13.1 Các invariant cần nhớ

1. Metric function chỉ được gọi trong `outcome:`.
2. Rule dùng metric được xử lý như **multi-event rule**, kể cả khi chỉ khai báo một event variable; điều này ảnh hưởng quota, scheduling và latency.
3. `period` và `window` phải là cặp được tài liệu hỗ trợ. Ví dụ thường gặp là `period: 1d, window: 30d`; metric theo giờ có giới hạn riêng.
4. Metric phải dùng đúng dimension mà function hỗ trợ. Placeholder trong `events:` phải đại diện cho cùng UDM path được truyền vào metric.
5. Không diễn giải giá trị `0` một cách máy móc: không có metric data và metric có giá trị bằng 0 có thể có ý nghĩa khác nhau. Dùng `num_metric_periods` khi cần biết có dữ liệu lịch sử hay không.
6. Các ngưỡng như `z_score >= 3` chỉ là điểm khởi đầu. Cần baseline, minimum volume, allowlist và kiểm tra false positive trong tenant.

### 13.2 Mẫu học tập: outbound bytes vượt baseline

Snippet dưới đây minh họa hình dạng logic, **chưa được compile hoặc Verify trong tenant của dự án**. Tên metric, dimension và field phải đối chiếu tài liệu/tenant hiện tại.

```yaral
rule anomalous_outbound_bytes_template {
  meta:
    author = "Detection Engineering"
    description = "Template: outbound bytes vượt baseline lịch sử của asset"
    severity = "Medium"
    assumption = "Xác nhận metrics.network_bytes_outbound và principal.asset.ip trong tenant"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $ip = $e.principal.asset.ip
    $e.network.sent_bytes > 0

  match:
    $ip over 24h

  outcome:
    $actual = sum($e.network.sent_bytes)
    $baseline = max(metrics.network_bytes_outbound(
      period: 1d,
      window: 30d,
      metric: value_sum,
      agg: avg,
      principal.asset.ip: $ip
    ))
    $risk_score = max(if($actual > $baseline, 65, 20))

  condition:
    $e and $actual > $baseline
}
```

### 13.3 Quy trình kiểm thử metrics rule

1. Xác minh metric function, allowed `period/window`, dimensions và field type bằng documentation hiện hành.
2. Tạo positive case vượt baseline và negative case dưới baseline; thêm case không có lịch sử, baseline bằng zero, nhiều IP và entity đổi namespace.
3. Kiểm tra `outcome` aggregation: khi có `match:`, event-derived values phải dùng aggregate phù hợp.
4. Chạy offline structural lint nếu có, sau đó dùng `Verify Rule`/compiler của tenant được ủy quyền.
5. Đo detection latency, volume, baseline drift và false positives trước khi bật alerting.

Nguồn tham khảo chính: [Google SecOps metrics functions](https://docs.cloud.google.com/chronicle/docs/detection/metrics-functions). Tài liệu này không biến snippet thành rule đã xác minh.

## 14. GCP capstone portfolio

Select one rule each for identity/IAM, logging defense, network/perimeter, data access and workload/security posture from `catalog/GCP_RULE_INDEX.csv`. For each deliverable, include:

1. Detection brief and evidence-backed hypothesis.
2. Required Cloud Audit/Data Access/VPC/DNS telemetry and scope.
3. UDM mapping table based on sanitized representative events.
4. Syntax verification result and rule revision hash.
5. Positive, negative, boundary, delayed/duplicate and benign automation cases.
6. False-positive categories and suppression design.
7. Severity/risk rationale, owner, triage runbook, rollout and rollback plan.

Until these artifacts exist, preserve `NOT_RUN_REQUIRES_GOOGLE_SECOPS_TENANT` and `NOT_VERIFIED_AGAINST_TENANT_EVENTS` status rather than claiming production readiness.
