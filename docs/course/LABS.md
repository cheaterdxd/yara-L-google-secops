# Thực hành có hướng dẫn — YARA-L / Google SecOps

Các lab dùng dữ liệu giả lập/sanitized hoặc dữ liệu tenant được phép. Không cần truy vấn hệ thống để hoàn thành lab; chỉ dùng UDM events mẫu được cấp/đã phê duyệt. Kết quả cuối phải được verify trong phiên bản Google SecOps của tổ chức.

## Lab 1 — Từ detection hypothesis đến UDM

**Tình huống:** phát hiện quyền IAM nhạy cảm được cấp ngoài quy trình.

1. Viết hypothesis: “Một principal cấp role nhạy cảm lên resource; analyst cần biết actor, resource, project, thời điểm và kết quả.”
2. Liệt kê telemetry tối thiểu: Cloud Audit Logs Admin Activity; xác nhận phạm vi organization/folder/project và routing/retention.
3. Từ event mẫu đã parse, ghi `metadata.vendor_name`, `metadata.product_name`, `metadata.product_event_type`, `principal`, `target`, `security_result` và giá trị thật. Ghi schema/type; không suy luận field nếu chưa thấy.
4. So sánh event thành công/thất bại, identity user/service account, impersonation, policy change và role binding.
5. Tạo mapping table: raw source key → UDM field → sample value → confidence → missing cases.

**Exit criteria:** có ít nhất một positive event và các benign/negative examples; xác nhận log coverage với owner.

## Lab 2 — Đọc rule GCP upstream

Mở `rules/gcp/collected/2_10_org_admin_permissions_granted.yaral` và `rules/gcp/collected/3_12_firewall_rules_modified_or_deleted.yaral`.

- Xác định event variable (`$gcp`) và từng field filter.
- Nêu sự khác nhau giữa `metadata.event_type` và `metadata.product_event_type` trong cách rule upstream lọc.
- Đánh giá predicate role `roles/resourcemanager.organizationAdmin`: có bao phủ mọi biến thể/API hay chỉ một biểu diễn cụ thể?
- Đọc `not ... = /gserviceaccount.com/`: ngoại lệ này giảm nhiễu gì, và có thể bỏ sót actor nào?
- Đọc `match` 24h: rule grouping theo resource/project ra sao? Liệu đây là alert hay chỉ kiểm tra/change monitoring? Xem metadata và upstream use case.
- Không sửa nguồn gốc trực tiếp. Tạo bản fork trong nhánh nội bộ, ghi link, commit, license và lý do mỗi thay đổi.

**Bàn luận:** cú pháp có thể hợp lệ nhưng logic vẫn không đúng nghiệp vụ. Event mapping, completeness và exception là phần phải xác minh.

## Lab 3 — Viết single-event rule theo tenant

Không điền sẵn enum giả. Thay `CONFIRMED_IAM_POLICY_EVENT` trong template bằng enum quan sát được; chỉ lọc `product_event_type` sau khi xác nhận value. Thêm điều kiện role/resource dựa trên UDM evidence, không copy field path mù quáng.

Test matrix:

| Case | Kỳ vọng |
|---|---|
| Role nhạy cảm được cấp thành công | Match |
| Role thường được cấp | Không match (nếu use case chỉ role nhạy cảm) |
| IAM change thất bại/denied | Theo hypothesis; ghi rõ lựa chọn |
| Actor là service account automation đã duyệt | Match/non-match theo exception có provenance |
| Target/actor field rỗng | Không join sai; xác định xử lý rõ |

Lưu rule revision, test evidence đã sanitize, mọi assumption và reviewer. Syntax verification không thay test matrix.

## Lab 4 — Threshold, grouping và false-positive budget

1. Dùng `gcp_iam_change_burst_template` làm cấu trúc tham khảo, không giữ ngưỡng 5/10m mặc định.
2. Xác định grouping key: actor, project, resource hay kết hợp; đánh giá field rỗng/cardinality.
3. Lấy baseline đã phê duyệt (hoặc synthetic data) để so ngưỡng 3/5/10 events và các cửa sổ 10m/1h.
4. Đếm detections theo actor/service account và khoảng thời gian, phân loại benign vs suspicious.
5. Chọn threshold theo yêu cầu triage; thêm allowlist hẹp, owner và expiry nếu cần.

**Deliverable:** bảng trade-off recall/noise, không chỉ một con số threshold.

## Lab 5 — Multi-event correlation

Giả thuyết: cùng actor thực hiện authentication event, rồi IAM change trong khoảng ngắn. Trước khi viết, xác định hai event types đã parse, correlation key có cùng chuẩn hóa không, thứ tự temporal cần thiết không, và event late/duplicate xử lý thế nào. Đọc tài liệu YARA-L về multi-event/sequence; `condition: $e1 and $e2` tự nó không chứng minh thứ tự. Tạo cases: same actor/same project, different actors, events đảo thứ tự, event ngoài window, actor trống.

**Deliverable:** diagram event→join key→window→condition, cùng test outcomes. Nếu semantics cần thiết không được tenant hỗ trợ, đổi detection design thay vì giả lập.

## Lab 6 — Outcome và analyst experience

Thiết kế outcome tối thiểu phục vụ triage: actor, resource, project, count/summary. Kiểm tra aggregate function có được hỗ trợ trong rule mode không. Tránh array lớn, PII dư thừa và score không giải thích được.

Viết analyst runbook theo dạng: xác minh change ticket; đối chiếu actor/service ownership; kiểm tra scope/role; xem source IP/session/context sẵn có; xác định containment/escalation theo quy trình tổ chức. Đây là hướng dẫn phân tích phòng thủ, không phải hành động tự động.

## Lab 7 — Rule QA / peer review

Peer reviewer lần lượt trả lời:

- Có data source/coverage evidence? UDM fields đã xác nhận?
- Logic có thể kích hoạt vì benign behavior? Exception có quá rộng/stale?
- Threshold/window có giải thích được? Match key có thể rỗng?
- Rule alert hay informational/hunting? Severity phù hợp không?
- Outcome có hữu ích và tối thiểu? Runbook có đủ evidence cần thu thập qua quy trình được phép?
- Provenance/license/ATT&CK/source link/test evidence/owner/expiry đầy đủ?
- Có verify trên Rule Editor/API version phù hợp và approval/rollback plan?

Nếu chưa có tenant access, trạng thái bắt buộc là `UNVERIFIED`, không ghi “validated”.

## Lab 8 — Portfolio triage từ corpus

Mở `catalog/RULE_INDEX.csv`, lọc theo repository, platform, rule name/description. Chọn 5 rule; cho từng rule ghi detection type (alert/analytics/building block), data source, prerequisites, license, UDM assumptions, MITRE (nếu có), test status và tune backlog. Không import hàng loạt vào tenant. Chọn mẫu phù hợp rồi review từng rule.

## Thang đánh giá

| Hạng mục | Trọng số | Đạt khi |
|---|---:|---|
| Detection hypothesis | 15% | Có hành vi, scope, impact và analyst question |
| UDM/telemetry evidence | 20% | Field/event type có chứng cứ, giới hạn coverage nêu rõ |
| Logic/correlation | 20% | Condition, key, window và threshold đúng ý định |
| Testing/tuning | 20% | Positive/negative/boundary, FP trade-off và kết quả có lưu |
| Analyst context | 10% | Severity, outcome và runbook dùng được |
| Governance | 15% | Provenance/license, peer review, version, owner, approval, rollback |
