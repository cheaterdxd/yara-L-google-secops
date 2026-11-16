# Trạng thái goal YARA-L / Google SecOps

Ngày cập nhật: 2026-11-16

Quyết định phạm vi hiện tại: **tập trung vào thu thập corpus/tri thức public**, không thực hiện tenant validation. Không chờ credentials hoặc tenant artifact; mọi GCP rule được giữ provenance/license và ghi chú trạng thái nguồn, còn Verify Rule/UDM chỉ là thông tin tùy chọn ngoài phạm vi collection.

## Deliverables hiện có

| Deliverable | Trạng thái | Evidence |
|---|---|---|
| Khóa học tiếng Việt | Hoàn thành bản nền: 12 bài, 8 lab, tài liệu nâng cao | `docs/course/README.md`, `docs/course/LABS.md`, `docs/course/ADVANCED.md` |
| Corpus rule public | Snapshot có provenance/license cho các nguồn đủ điều kiện | `catalog/RULE_INDEX.csv` |
| Bộ rule GCP | 80 nội dung byte-unique và manifest provenance/license | `catalog/GCP_RULE_INDEX.csv`, `rules/gcp/README.md` |
| UDM field inventory GCP | Static extraction/review checklist | `catalog/GCP_FIELD_INVENTORY.csv` |
| Discovery/exclusion log | Có commit, license status và quyết định | `catalog/CODEHOST_REVIEW.csv`, `catalog/EXCLUDED_SOURCES.csv`, `catalog/LINK_ONLY_RULES.csv` |
| Corpus summary | Phân bố license/content type/repository và GCP source | `catalog/COLLECTION_SUMMARY.csv` |

## Số liệu kiểm tra gần nhất

```text
RULE_INDEX.csv: 4,341 entries, 36 repository snapshots, 2,732 byte-distinct contents
GCP_RULE_INDEX.csv: 80 entries, 80 unique SHA-256 values
GCP_FIELD_INVENTORY.csv: 830 static field-reference rows
COLLECTION_SUMMARY.csv: license/content-type/source inventory derived from the manifests
```

Các số liệu trên được kiểm tra bằng Python `csv.DictReader`; mọi local path trong `RULE_INDEX.csv` tồn tại và mọi SHA-256 trong GCP manifest khớp file tương ứng ở lần kiểm tra gần nhất.

## Giới hạn không được che giấu

1. Đây là snapshot của các host/repository đã discovery và review, **không phải toàn bộ internet**. Không thể chứng minh mọi public repository đã được tìm thấy.
2. Search engine/API có thể bỏ sót fork, mirror, host ít được index, repo mới, repo bị rate-limit hoặc nội dung không khai báo license.
3. Nguồn không có license rõ được giữ link-only/exclusion; không suy đoán quyền tái phân phối.
4. Static lint, fixture review và field inventory không thay thế Google SecOps compiler hoặc parser behavior.
5. GCP entries giữ trạng thái nguồn/collection hiện có; các trường tenant-validation chỉ là metadata minh bạch, không phải điều kiện để thu thập hoặc sử dụng corpus cho mục đích học tập/review.

## Next actions có thể tiếp tục

### Public discovery

- Chạy các query discovery mới, đối chiếu với `catalog/CODEHOST_REVIEW.csv` trước khi review.
- Với mỗi ứng viên: pin commit, xác nhận tree/file rule, xác nhận license, hash, kiểm tra trùng byte, rồi snapshot hoặc ghi exclusion.
- Không chạy application/tooling từ repo không cần thiết; không lấy telemetry, secrets, private data hoặc dữ liệu hệ thống.

### Tenant validation — ngoài phạm vi collection

Phần này **không thuộc mục tiêu hiện tại** và không được dùng làm blocker. Nếu sau này cần mở rộng sang validation, có thể dùng tenant được ủy quyền hoặc artifact Verify Rule/UDM đã sanitize, tối thiểu gồm:

- rule identifier/revision hoặc SHA-256;
- kết quả `Verify Rule`/compiler (thành công hoặc lỗi cụ thể);
- event type, `metadata.log_type`, vendor/product và các UDM fields thực tế;
- positive/negative/boundary test result;
- parser/tenant context đã loại bỏ IP, email, hostname, ID và secret nhạy cảm.

Không cần và không được cung cấp credentials, service-account keys, raw customer logs hoặc private telemetry trong repository này.

## Quy tắc báo cáo

- Gọi là `snapshot`, không gọi là `complete internet corpus`.
- Gọi là `static/unverified`, không gọi là `validated` nếu chưa có compiler/tenant evidence.
- Giữ nguyên provenance upstream; không nhân bản rule byte-identical chỉ để tăng số lượng.
