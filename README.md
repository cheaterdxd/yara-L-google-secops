# YARA-L cho Google SecOps — học liệu & detection knowledge base

> Mục đích: học tập và detection phòng thủ. Không chứa mã khai thác, malware hay thu thập/truy xuất dữ liệu hệ thống.

## Nội dung
- [Khóa học YARA-L 2.0 bằng tiếng Việt](docs/course/README.md)
- [Catalog nguồn public và phạm vi](catalog/SOURCES.md)
- [Trạng thái freshness của upstream chính](catalog/UPSTREAM_FRESHNESS.csv)
- [Nguồn rule/snippets chỉ dẫn link do license chưa rõ](catalog/LINK_ONLY_RULES.csv)
- [Chỉ mục 4.329 file rule public đã snapshot](catalog/RULE_INDEX.csv)
- [Rule mẫu GCP](rules/gcp/README.md)
- [Chỉ mục 78 rule GCP đã khử trùng lặp](catalog/GCP_RULE_INDEX.csv)
- [UDM field inventory tĩnh cho 78 rule GCP](catalog/GCP_FIELD_INVENTORY.csv)
- [Lab thực hành chuyên sâu](docs/course/LABS.md)
- [Giáo trình nâng cao và validation rubric](docs/course/ADVANCED.md)
- [Thẩm định và vận hành](docs/OPERATIONS.md)

## Tính đầy đủ
Không thể đảm bảo thu thập “mọi rule trên mọi repo public”: repo có thể riêng tư, bị xóa, không được lập chỉ mục, đổi nhánh hoặc có license hạn chế. Catalog ghi nguồn tiêu biểu, provenance và cách cập nhật, không tuyên bố toàn diện. Rule ở đây là ví dụ giáo dục, chưa được xác thực trong tenant Google SecOps. Verify cú pháp, UDM mapping, nguồn log và false positive trước khi triển khai; không bật tự động trên production.
