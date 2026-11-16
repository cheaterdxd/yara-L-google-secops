# Bộ rule GCP — starter collection

Các rule dưới là template phòng thủ, **chưa compile/run trong tenant**. Thay mọi `CONFIRMED_*` bằng event type thực sự đã quan sát, xác nhận UDM fields/vendor, rồi Verify trong Rule Editor. Cần audit log tương ứng được bật và ingest.

## Rule GCP sưu tầm từ nguồn public

Kho GCP có **80 nội dung rule khác nhau** đã khử trùng lặp theo SHA-256:

- `collected/` — 13 rule từ GoogleCloudPlatform Community Security Analytics, Apache-2.0.
- `collected/community/` — 67 rule GCP từ community sources, gồm rule canonical, rule GCP Cloud Audit từ Sofecta, variants từ forks, một draft AI workload rule, một SCC sample và hai Graft examples. Bản sao byte-identical của Dandye/gocloudwave/rowham/sreed/radkawar được ghi ở alternate provenance nhưng không nhân bản trong bộ GCP.

> **Caveat về hai Graft rules:** `lopes_gcp_service_account_key_created.yaml` và `lopes_gcp_storage_bucket_public_access_granted.yaml` được giữ nguyên từ Apache-2.0 upstream wrapper, nhưng upstream đánh dấu `EXPERIMENTAL - NOT WORKING`. Chúng là ví dụ/draft trong corpus, **không dùng trực tiếp**; cần kiểm thử/điều chỉnh và Verify trong tenant trước khi dùng. License/provenance/checksum ở [`GCP_RULE_INDEX.csv`](../../catalog/GCP_RULE_INDEX.csv).

Mỗi rule giữ header bản quyền/notice có sẵn; license ở các thư mục collection. Xem [`catalog/GCP_RULE_INDEX.csv`](../../catalog/GCP_RULE_INDEX.csv) để tra path, rule name, commit, license, upstream URL, SHA-256 và alternate provenance; [`catalog/RULE_INDEX.csv`](../../catalog/RULE_INDEX.csv) lập chỉ mục toàn corpus. Đây là nội dung cộng đồng, không phải detection pack chính thức. Chưa được compile/run trong tenant.

Để hỗ trợ bước kiểm định có tenant, [`catalog/GCP_FIELD_INVENTORY.csv`](../../catalog/GCP_FIELD_INVENTORY.csv) liệt kê UDM paths và literal values trích xuất tĩnh từ 80 file rule. Inventory này chỉ là review checklist: nó không chứng minh field tồn tại trong parser hay event values match dữ liệu tenant.

| File | Use case (theo tên upstream) | Ghi chú |
|---|---|---|
| `1_01_login_highly_privileged_account.yaral` | Login tài khoản đặc quyền cao | Workspace/Cloud Identity telemetry; xem use-case doc upstream. |
| `1_02_suspicious_login_attempt.yaral` | Login bị gắn suspicious | Cần login audit. |
| `1_03_excessive_login_failures.yaral` | Nhiều lần login thất bại | Threshold 3 / 15m trong bản upstream; cần baseline. |
| `1_20_access_attempts_blocked_by_IAP.yaral` | IAP chặn access | HTTP(S) LB/IAP logs. |
| `2_10_org_admin_permissions_granted.yaral` | Cấp org admin privilege | Cloud Audit/IAM; xác minh role mapping. |
| `2_20_permissions_granted_over_SA.yaral` | Cấp quyền trên service account | Admin Activity; xem binding semantics. |
| `3_12_firewall_rules_modified_or_deleted.yaral` | Firewall rule modify/delete | Audit log Admin Activity. |
| `3_14_dns_zones_modified_or_deleted.yaral` | DNS zone modify/delete | Cloud DNS audit. |
| `5_01_users_who_most_frequently_accessed_data.yaral` | Thống kê user truy cập dữ liệu | Analytics/hunting, không nhất thiết alert. |
| `6_01_hosts_reaching_to_many_other_hosts_or_ports.yaral` | Nhiều host/port trong mạng | VPC Flow Logs; xem window và cardinality. |
| `6_21_log4j_exploit_attempts.yaral` | Log4j exploit attempt | Detect pattern trong ingress logs; không phải exploit guide. |
| `6_22_log4j_exploit_attempts_remote_IP_address_list.yaral` | Log4j attempts theo IP | Cần reference list/ingress logs. |
| `6_23_spring4shell_exploit_attempts.yaral` | Spring4Shell attempt | Ingress logs; validate parser and FP. |
| `lopes_gcp_service_account_key_created.yaml` | Tạo/upload service account key | Graft upstream đánh dấu `EXPERIMENTAL - NOT WORKING`; chỉ xem như draft, không triển khai. |
| `lopes_gcp_storage_bucket_public_access_granted.yaml` | Cấp binding public cho GCS bucket | Graft upstream đánh dấu `EXPERIMENTAL - NOT WORKING`; chỉ xem như draft, không triển khai. |

67 community rules khác nằm trong `collected/community/`; danh sách đầy đủ và upstream provenance có trong [`GCP_RULE_INDEX.csv`](../../catalog/GCP_RULE_INDEX.csv).

### Draft GCP AI workload rule

`collected/community/gcp_autonomous_ai_agent_escape.yaral` is a licensed public example for an AI workload / metadata-token access scenario. The upstream repository presents it as a lab detection, not tenant-validated content. Before use, check whether the workload audit source populates the referenced container labels, URL path, principals and product names; confirm correlation/join semantics and counts in Verify Rule; then test benign agent workloads. It remains **unverified** and must not be enabled directly in production.

Phân loại, log source và ATT&CK mapping của upstream có thể đổi; đọc `.md` use-case cùng phiên bản upstream nếu cần thiết. Rule “top/frequency” là analytics chứ không tự động là alert.

## GCP-01 — IAM policy change
```yaral
rule gcp_iam_policy_change_template {
  meta:
    author = "Detection Engineering"
    description = "Template: review thay đổi IAM policy trên Google Cloud"
    severity = "Medium"
    data_source = "Google Cloud Audit Logs; verify UDM mapping"
    assumption = "Thay CONFIRMED_IAM_POLICY_EVENT bằng event type đã xác nhận"
  events:
    $e.metadata.event_type = "CONFIRMED_IAM_POLICY_EVENT"
    $e.metadata.vendor_name = "Google Cloud"
    $e.target.resource.name = $resource
  condition:
    $e
}
```

## GCP-02 — IAM change burst theo principal
```yaral
rule gcp_iam_change_burst_template {
  meta:
    author = "Detection Engineering"
    description = "Template: nhiều IAM change events bởi cùng principal"
    severity = "High"
    data_source = "Google Cloud Audit Logs; verify actor mapping"
    assumption = "Ngưỡng minh họa; xác lập baseline trước triển khai"
  events:
    $e.metadata.event_type = "CONFIRMED_IAM_POLICY_EVENT"
    $e.metadata.vendor_name = "Google Cloud"
    $e.principal.user.userid = $actor
    $actor != ""
  match:
    $actor over 10m
  condition:
    #e >= 5
}
```

## GCP-03 — Tạo service account key
```yaral
rule gcp_service_account_key_creation_template {
  meta:
    author = "Detection Engineering"
    description = "Template: phát hiện tạo service account key cần review"
    severity = "High"
    data_source = "Google Cloud Audit Logs; verify method-to-UDM mapping"
    assumption = "Event type/target field phải được xác minh"
  events:
    $e.metadata.event_type = "CONFIRMED_SERVICE_ACCOUNT_KEY_CREATE_EVENT"
    $e.metadata.vendor_name = "Google Cloud"
    $e.principal.user.userid = $actor
    $e.target.resource.name = $resource
  condition:
    $e
}
```

## Điều chỉnh bắt buộc
- Placeholder `CONFIRMED_*` chưa thay thì rule cố ý chưa dùng được.
- Xác nhận vendor, actor (user/service account/impersonation), target và deduplication.
- Xác nhận `#e` + `match` semantics/threshold bằng docs và Rule Editor hiện tại.
- Kiểm tra Data Access audit config khi use case yêu cầu; thiếu log không đồng nghĩa không có hành vi.
- Chỉ thêm exclusion có owner/expiry; bổ sung outcome/runbook/ATT&CK sau khi xác nhận use case.
- Chạy positive, negative, boundary tests; không bật production nếu chưa review.
