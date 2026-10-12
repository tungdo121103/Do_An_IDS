# Kết quả huấn luyện model SSH Brute Force v1

## Dữ liệu và cách chia

- Nguồn: `dataset/ssh/processed/ssh_train_ready.csv` từ CICIDS2017 Tuesday-WorkingHours.
- 45 feature số, nhãn `BENIGN` (0) và `SSH-Patator` (1).
- File đã làm sạch có 375.042 BENIGN và 3.219 SSH-Patator.
- Mẫu huấn luyện lấy ngẫu nhiên 15.000 BENIGN (`random_state=42`) và toàn bộ 3.219 SSH-Patator.
- Chia 80/20 bằng `train_test_split(..., stratify=y, random_state=42)`.

| Tập | BENIGN | SSH-Patator | Tổng |
|---|---:|---:|---:|
| Train | 12.000 | 2.575 | 14.575 |
| Test | 3.000 | 644 | 3.644 |

## Thuật toán

Cả hai model được train và đánh giá trên cùng một tập:

- Random Forest: 200 cây, `class_weight="balanced_subsample"`, `random_state=42`.
- LightGBM: 200 cây, `class_weight="balanced"`, `random_state=42`.

## Kết quả offline

| Model | Accuracy | Precision SSH | Recall SSH | F1 SSH | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Random Forest | 0,998628 | 1,000000 | 0,992236 | 0,996103 | 3000 | 0 | 5 | 639 |
| LightGBM | 0,999177 | 0,998445 | 0,996894 | 0,997669 | 2999 | 1 | 2 | 642 |

LightGBM có Recall và F1 cao hơn trên tập test đã lấy mẫu; Random Forest có 0 false positive trong 3.000 mẫu BENIGN test. Dashboard cho phép chọn một trong hai thuật toán; lựa chọn này áp dụng cho cả nhánh DDoS và nhánh SSH.

## Artifacts

Thư mục `models/ssh_v1_artifacts/` chứa:

- `ssh_random_forest_v1.joblib`
- `ssh_lightgbm_v1.joblib`
- `ssh_feature_manifest_v1.json`
- hai ảnh confusion matrix
- `ssh_model_comparison_v1.csv`
- báo cáo JSON của từng model

Manifest xác định đúng tên và thứ tự 45 feature. `src/live_sensor.py` tạo bộ 46 feature chung; nhánh SSH chọn 45 feature theo manifest của nó.

## Giới hạn của phép đánh giá

Các chỉ số trên được tính từ tập test lấy ngẫu nhiên trong cùng nguồn CICIDS2017, với BENIGN đã được lấy mẫu xuống 15.000 dòng. Chúng không đo trực tiếp tỷ lệ báo nhầm trong lưu lượng mạng tự nhiên và chưa xác nhận hiệu quả trên traffic SSH tạo trong VM. Cần chạy kiểm thử realtime trên IDS VM trước khi kết luận hiệu quả demo.
