# Kết quả huấn luyện model SSH Brute Force v1

> Đây là báo cáo **train/test offline** của nhánh SSH trong IDS kết hợp. Hướng dẫn chạy hệ thống ở [runbook](COMBINED_IDS_RUNBOOK.md); phần giải thích cho buổi bảo vệ ở [tài liệu demo](DEMO_DO_AN_2026-10-19.md).

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

Các chỉ số trên được tính từ tập test lấy ngẫu nhiên trong cùng nguồn CICIDS2017, với BENIGN đã được lấy mẫu xuống 15.000 dòng. Chúng không đo trực tiếp tỷ lệ báo nhầm trong lưu lượng mạng tự nhiên. Model không nhìn thấy mật khẩu hay số lần đăng nhập thất bại; đầu vào là đặc trưng flow của traffic SSH mã hóa.

Trong lần kiểm tra live đã lưu ở `reports/ssh_live_flows_50_attempts.csv`, bài script 50 lần thử password tạo 12 TCP/22 flows. Trên cùng 12 flow này, Random Forest dự đoán **1 SSH + 11 BENIGN**, LightGBM dự đoán **0 SSH + 12 BENIGN**. Đây là một phép thử lab nhỏ, không đủ để ước lượng recall live; nó cho thấy kết quả offline không tự bảo đảm khả năng nhận diện traffic VM. Nguyên nhân cần khảo sát tiếp gồm cách gom flow, khác biệt phân bố/ý nghĩa feature so với CICIDS2017 và phiên bản thư viện khi nạp model. Không quy hết sự khác biệt cho một nguyên nhân khi chưa kiểm chứng.

Đối chiếu thêm model v1 với `reports/ssh_benign_lab.csv` (14 flow từ các phiên SSH hợp lệ trong lab) trên máy Windows ngày 02/11/2026: Random Forest đánh dấu **0/14** flow bình thường là tấn công, còn LightGBM đánh dấu **11/14**. Cùng lần tính này, kết quả 12 flow Hydra vẫn là **1/12** và **0/12** tương ứng. Đây là kiểm tra chẩn đoán trên hai file nhỏ đã có, không phải tập test độc lập mới. Random Forest cho xác suất lớp tấn công của flow Hydra khoảng **0,135–0,55**, của flow bình thường khoảng **0–0,425**; hai khoảng chồng lấn. Vì vậy chỉ hạ ngưỡng dự đoán để tăng số cảnh báo sẽ làm tăng nguy cơ báo nhầm, không chứng minh model ổn định. LightGBM trên bộ này còn đánh dấu nhiều flow bình thường hơn flow Hydra, nên không nên chọn nó cho demo SSH chỉ vì điểm offline cao. Khi nạp model trên máy kiểm tra, scikit-learn cảnh báo artifact được tạo bằng phiên bản 1.6.1 còn môi trường hiện tại dùng 1.9.1; cần kiểm tra với môi trường khớp phiên bản trước khi quy kết hoàn toàn cho dữ liệu hoặc sensor.

## Kiểm tra lại nhánh SSH ngày 2026-10-26

Model v1 học từ 15.000 flow `BENIGN` lấy trong dữ liệu Tuesday của nhiều dịch vụ, nhưng khi chạy thật nhánh SSH chỉ nhận TCP/22. Trong dữ liệu gốc có 2.136 flow `BENIGN` và 5.897 flow `SSH-Patator` ở **cổng đích 22**. File CICIDS2017 này không có cột `Protocol`, nên không thể lọc TCP trực tiếp trong nguồn gốc; runtime vẫn định tuyến bằng cả TCP và cổng 22. `src/prepare_ssh_port22_dataset.py` tạo tập ứng viên theo cổng đích; sau làm sạch và loại trùng còn 1.485 `BENIGN` và 3.219 `SSH-Patator`, với cùng 45 feature như model v1. Tập ứng viên nằm ở `dataset/ssh/processed/ssh_port22_train_ready.csv` (được `.gitignore` bỏ qua).

`src/train_ssh_port22_candidate.py` chỉ tạo model **ứng viên** trong `models/ssh_port22_candidate/`; nó không thay model đang chạy trên IDS. Khi có môi trường Python với pandas, NumPy, scikit-learn, LightGBM và joblib, chạy từ thư mục project:

```bash
python src/train_ssh_port22_candidate.py \
  --lab-attack reports/ssh_live_flows_50_attempts.csv \
  --lab-benign reports/ssh_benign_lab.csv
```

`reports/ssh_benign_lab.csv` đã được thu từ các lượt đăng nhập SSH bình thường trong lab, nhưng mới là một lượt thu nhỏ. **Không gán nhãn toàn bộ `live_flows.csv` là benign** vì file có thể chứa flow Hydra. Chỉ số test ngẫu nhiên trong cùng capture CICIDS2017 và một lần Hydra lab không đủ chứng minh khả năng tổng quát. Cần thêm nhiều phiên tấn công và bình thường độc lập, đo cả bỏ sót lẫn báo nhầm trước khi thay model v1. Cảnh báo số lần nhập sai mật khẩu từ log Victim là tín hiệu riêng, không phải dự đoán của model.

Để thu mẫu SSH bình thường mà không xóa lưu lượng DDoS, chép `tools/capture_ssh_lab_flows.py` sang IDS, giữ sensor chạy và mở một terminal IDS mới:

```bash
cd ~/DoAn_IDS_DDoS
.venv/bin/python tools/capture_ssh_lab_flows.py --output reports/ssh_benign_lab.csv
```

Sau khi lệnh báo đã ghi nhận vị trí bắt đầu, thực hiện một số phiên **đăng nhập SSH thành công** từ Kali tới Victim, không chạy Hydra đồng thời. Thoát các phiên SSH, chờ ít nhất 12 giây để sensor xuất flow, rồi nhấn Enter ở terminal thu mẫu. Công cụ chỉ sao chép các flow TCP/22 mới từ Kali đến Victim; nó không sửa `data/live_flows.csv`. Nên lặp lại thành nhiều phiên độc lập và giữ riêng file của từng phiên khi đánh giá nghiêm túc.

### Kết quả đối chiếu trên VM ngày 2026-10-27

Ứng viên chỉ huấn luyện với dữ liệu cổng đích 22 có điểm test ngẫu nhiên trên CICIDS2017 rất cao, nhưng trên VM nó đánh dấu **12/12 flow Hydra là tấn công và đồng thời đánh dấu 14/14 flow đăng nhập SSH bình thường là tấn công**. Vì tỷ lệ báo nhầm trên mẫu bình thường này là 100%, **không triển khai ứng viên**. File `reports/ssh_benign_lab.csv` là một lượt thu 14 flow từ khoảng 10 phiên đăng nhập thành công; file `reports/ssh_live_flows_50_attempts.csv` chứa 12 flow của bài Hydra. Hai mẫu nhỏ này không đại diện cho mọi lưu lượng SSH, nhưng đủ bác bỏ ứng viên hiện tại trong bài lab.

So sánh trực tiếp cho thấy 12 flow Hydra có `Total Length of Fwd Packets` khoảng 1.227–1.727 byte và `Total Length of Bwd Packets` khoảng 1.670–2.006 byte; đa số flow đăng nhập thành công trong lượt thu có khoảng 5.853–6.725 byte chiều đi và 7.558–8.242 byte chiều về. Điều này gợi ý sự khác biệt giữa phiên xác thực không thành công và phiên mở shell thành công, nhưng **chưa chứng minh được** khả năng phân biệt Hydra với người dùng chỉ gõ sai mật khẩu một hoặc hai lần. Cần thu riêng các phiên sai ít lần nhưng không đăng nhập thành công và giữ một số phiên tấn công/bình thường độc lập làm tập kiểm tra trước khi huấn luyện model từ dữ liệu VM. Không chọn feature hay ngưỡng chỉ để khớp hai file này rồi coi là kết quả tổng quát.
