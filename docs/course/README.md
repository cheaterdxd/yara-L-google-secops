# Khóa học YARA-L 2.0 cho Google SecOps

**Đối tượng:** analyst/detection engineer đã biết log và SIEM. **Mục tiêu:** đọc, viết, kiểm thử, tinh chỉnh và quản lý rule phòng thủ. Tên field/operator giữ English để khớp sản phẩm. Học theo thứ tự; từng bài có mục tiêu và bài tập.

Phần đào sâu về evidence-first detection engineering, rule lifecycle, correlation semantics, zero values, thresholds, list/table tuning, outcomes, performance và validation rubric nằm trong [ADVANCED.md](ADVANCED.md).

Để thực hành từng bước, xem [LABS.md](LABS.md) (8 lab, test matrix, rubric và peer-review checklist).

## Lộ trình
1. [Nền tảng, UDM và tư duy detection](#bài-1--nền-tảng-udm-và-tư-duy-detection)
2. [Cấu trúc rule và meta](#bài-2--cấu-trúc-rule-và-meta)
3. [Events, filters và placeholder](#bài-3--events-filters-và-placeholder)
4. [Condition, single-event và threshold](#bài-4--condition-single-event-và-threshold)
5. [Match, window và correlation](#bài-5--match-window-và-correlation)
6. [Multi-event và absence](#bài-6--multi-event-và-absence)
7. [Outcome](#bài-7--outcome)
8. [Regex, lists, tables](#bài-8--regex-lists-tables)
9. [GCP Cloud Audit Logs](#bài-9--gcp-cloud-audit-logs)
10. [FP, hiệu năng, testing](#bài-10--fp-hiệu-năng-testing)
11. [Detection-as-Code](#bài-11--detection-as-code)
12. [Capstone](#bài-12--capstone)

## Bài 1 — Nền tảng, UDM và tư duy detection
YARA-L 2.0 là ngôn ngữ tương quan/detection trên event đã chuẩn hóa của Google SecOps; khác YARA dùng quét file. Luồng tư duy: **hành vi → telemetry → UDM field → predicate → ngưỡng/thời gian → điều tra**. Rule chỉ thấy dữ liệu đã ingest/parse. UDM có các nhóm `metadata`, `principal`, `target`, `network`, `security_result`; không đoán field từ raw log. `metadata.event_type` thường là enum viết hoa; xác nhận parser/tenant.

**Bài tập:** chọn “thay đổi cấu hình nhạy cảm”; xác định audit log, event mẫu, actor/resource/project và câu hỏi analyst. **Checklist:** coverage, latency, retention, parser, field rỗng, automation hợp lệ.

## Bài 2 — Cấu trúc rule và meta
Các section thường gặp: `meta`, `events`, `match`, `outcome`, `condition`, `options`; `meta`, `events`, `condition` là phần cốt lõi của rule thông thường. Ví dụ skeleton (event type chỉ là token cần thay):

```yaral
rule example_rule {
  meta:
    author = "Detection Engineering"
    description = "Mô tả hành vi và phạm vi"
    severity = "Medium"
  events:
    $e.metadata.event_type = "CONFIRMED_EVENT_TYPE"
  condition:
    $e
}
```

Meta hỗ trợ quản trị, không làm logic đúng hơn. Thống nhất author/owner, description, severity, data source, assumption, reference và ATT&CK mapping nếu có. **Bài tập:** viết meta cho IAM change, nêu log bắt buộc và hướng triage.

## Bài 3 — Events, filters và placeholder
`$e` là event variable; filters thu hẹp event. Placeholder như `$actor`, `$resource` gán giá trị field để tái sử dụng/liên kết.

```yaral
events:
  $e.metadata.event_type = "CONFIRMED_EVENT_TYPE"
  $e.principal.user.userid = $actor
  $e.target.resource.name = $resource
```

Field cần được xác minh. Nhiều filter trên cùng event variable áp dụng cùng event. Dùng event variables khác nhau cho các event/hành vi khác nhau. Xử lý empty/null có chủ đích. **Bài tập:** xác nhận actor/resource/project qua các event mẫu, bao gồm benign.

## Bài 4 — Condition, single-event và threshold
`condition` quyết định detection. `$e` thường kiểm tra có event phù hợp; `#e` đếm event trong ngữ cảnh hỗ trợ; `#placeholder` đếm giá trị phân biệt theo semantics sản phẩm. Xác nhận docs/Rule Editor hiện hành. Dùng ngoặc để rõ `and`/`or`, viết điều kiện analyst giải thích được.

```yaral
events:
  $e.metadata.event_type = "CONFIRMED_EVENT_TYPE"
condition:
  $e
```

Threshold cần grouping/window phù hợp, không suy rộng semantics giữa các mode. Chọn ngưỡng từ baseline và impact, không đoán. **Bài tập:** đề xuất 3 threshold, ghi FP dự kiến và cách đo.

## Bài 5 — Match, window và correlation
`match` nhóm event theo placeholder trong khoảng thời gian, ví dụ `$actor over 10m`. Chọn key ổn định, tránh empty/common key (join sai/cardinality lớn). Window dài tăng nhiễu/độ trễ; ngắn có thể bỏ hành vi chậm. Xác minh windowing/late-event semantics theo tài liệu hiện hành.

```yaral
match:
  $actor over 10m
```

Không cần `match` cho mọi single-event rule. Kiểm tra ingestion delay và timestamp. **Bài tập:** so sánh window 5m/30m trên dữ liệu đại diện.

## Bài 6 — Multi-event và absence
Dùng `$e1`, `$e2` cùng placeholder để nối theo actor/resource. `condition: $e1 and $e2` yêu cầu cả hai; tên biến không tự tạo thứ tự thời gian. Sequence cần logic thời gian được hỗ trợ và kiểm chứng. Absence/negative detection rất nhạy với log trễ hoặc thiếu: “không thấy” không chứng minh “không xảy ra”.

**Bài tập:** mô hình “đăng nhập rồi IAM change”; xác định correlation key, timeframe, telemetry và giới hạn suy luận.

## Bài 7 — Outcome
`outcome` thêm context/aggregation cho detection bằng các hàm được hỗ trợ. Khả năng dùng hàm phụ thuộc mode và aggregation constraints. Chỉ xuất dữ liệu cần cho triage; risk score không phải xác suất compromise. Ghi rõ quy ước tính điểm.

**Bài tập:** chọn actor/resource/count tối thiểu, mô tả cách analyst sử dụng.

## Bài 8 — Regex, lists, tables
Regex cho pattern ổn định; tránh quá rộng/đắt. Reference lists/data tables phù hợp IOC/exception có provenance, owner, expiry và cadence review; không hard-code list dài. Xác nhận loại STRING/REGEX/CIDR, toán tử và giới hạn hiện hành. IOC không đồng nghĩa kết luận compromise.

**Bài tập:** thiết kế allowlist service account có người duyệt và hạn dùng; tránh whitelist rộng.

## Bài 9 — GCP Cloud Audit Logs
Phân biệt Admin Activity, Data Access, System Event và Policy Denied. Không phải log nào cũng được bật/giữ/ingest mặc định. Xác nhận scope project/folder/org, parser, latency và UDM mapping. Use case: IAM changes, tạo service account/key, sửa audit policy, firewall/network changes, truy cập dữ liệu nhạy cảm bất thường. Xem [starter rules GCP](../../rules/gcp/README.md), không mặc định event type/field giống mọi tenant.

Principal có thể là user/service account; hiểu impersonation/delegation, automation, resource scope, caller IP và status. ATT&CK mapping chỉ sau khi xác định hành vi; mapping không thay evidence.

## Bài 10 — FP, hiệu năng, testing
Đánh giá precision/recall qua dữ liệu đại diện: expected changes, service identities, pipeline. Bắt đầu non-alerting nếu khả thi; tune exclusion có kiểm soát. Đo alert volume, unique actor/resource, triage time và missed cases. Xem cardinality, event variables, window, regex/list lookup.

Test positive, negative, boundary, empty fields, duplicate, delayed event, benign admin/service account, multi-project. Cú pháp hợp lệ không chứng minh efficacy. Ghi expected outcome và evidence; không tuyên bố test nếu chưa thực hiện.

## Bài 11 — Detection-as-Code
Lưu `.yaral` trong Git, review, lint, kiểm tra license/provenance, peer review, verify bằng Rule Editor/API, deploy theo môi trường và rollback có phê duyệt. Quản lý ID/version/owner/status/suppression/runbook/expiry. Không lưu secrets; không deploy production tự động thiếu approval/test.

## Bài 12 — Capstone
Nộp detection brief, telemetry checklist, UDM evidence, rule draft, positive/negative tests, FP analysis, metadata/ATT&CK, analyst runbook, rollout plan, owner/expiry và review. Chấm: logic 30%, assumptions 20%, tests 20%, triage/tuning 15%, governance/provenance 15%. Production-ready chỉ sau tenant verification và approval.

## Tham khảo
- [Getting started](https://docs.cloud.google.com/chronicle/docs/yara-l/getting-started)
- [Examples](https://docs.cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples)
- [Functions](https://docs.cloud.google.com/chronicle/docs/yara-l/functions)
- [Reference lists](https://docs.cloud.google.com/chronicle/docs/yara-l/reference-list-syntax)
- [Community rules/style guide](https://github.com/chronicle/detection-rules)
- [GCP Security Analytics](https://github.com/GoogleCloudPlatform/security-analytics)
