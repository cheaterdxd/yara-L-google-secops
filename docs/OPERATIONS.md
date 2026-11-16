# Thẩm định và vận hành rule

## Trước khi viết
1. Nêu detection hypothesis, câu hỏi điều tra, impact của miss/false alert.
2. Xác nhận log source, audit configuration, retention/latency, parser và UDM event mẫu.
3. Xác nhận field/type/event enum trong docs và tenant; ghi mọi giả định.

## Trước khi bật
- Verify cú pháp trong Rule Editor/API phù hợp; lưu kết quả và rule revision.
- Test positive, negative, boundary, missing/empty, benign automation, delayed/duplicate events.
- Historical/non-alerting review nếu có thể; đo volume, FP và chi phí.
- Peer review logic, provenance/license, metadata, severity, owner, suppression và runbook.
- Có phê duyệt, rollout/rollback plan và monitoring.

## Sau triển khai
Theo dõi alert volume, độ chính xác, drift log/parser, analyst feedback và expiry của exception. Ghi quyết định tune trong Git. Rollback theo quy trình khi sai lệch nghiêm trọng; giữ audit trail.

## An toàn
Chỉ phục vụ phát hiện/điều tra phòng thủ. Không đưa secrets/dữ liệu tổ chức vào ví dụ hoặc commit. Kho này không cung cấp khai thác, payload, mã độc hay hướng dẫn thu thập/truy xuất dữ liệu.
