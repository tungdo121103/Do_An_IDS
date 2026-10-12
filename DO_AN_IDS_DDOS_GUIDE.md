# Đồ án IDS phát hiện tấn công DDoS theo thời gian thực bằng học máy

## 1. Tên đề tài đề xuất

**Nghiên cứu hệ thống phát hiện xâm nhập IDS ứng dụng học máy trong phát hiện tấn công DDoS theo thời gian thực trong môi trường mạng**

Tên tiếng Anh tham khảo:

**Research on a Machine Learning-Based Intrusion Detection System for Real-Time DDoS Attack Detection in Network Environments**

## 2. Mục tiêu đồ án

Đồ án tập trung nghiên cứu và triển khai một hệ thống IDS có khả năng phát hiện tấn công DDoS theo thời gian thực bằng học máy.

Mục tiêu chính:

- Nghiên cứu bài toán phát hiện tấn công DDoS trong môi trường mạng.
- Phân tích và xử lý dữ liệu từ bộ CIC-DDoS2019.
- Huấn luyện và so sánh một số mô hình học máy.
- Lựa chọn mô hình phù hợp để tích hợp vào hệ thống IDS.
- Xây dựng pipeline phát hiện theo thời gian thực.
- Lưu log phát hiện vào cơ sở dữ liệu.
- Hiển thị cảnh báo và thống kê trên dashboard.
- Thử nghiệm trong môi trường mạng mô phỏng gồm attacker, victim, IDS và máy giám sát.

Trọng tâm của đề tài không chỉ là huấn luyện mô hình, mà là **tích hợp mô hình học máy vào hệ thống IDS realtime hoàn chỉnh**.

## 3. Kiến trúc tổng thể

Mô hình demo đề xuất gồm 4 máy:

```text
Attacker VM  --->  IDS VM / Gateway  --->  Victim VM
                         |
                         v
                SQLite database + Dashboard
                         ^
                         |
                  Máy thật xem dashboard
```

Vai trò từng thành phần:

| Thành phần | Vai trò |
|---|---|
| Attacker VM | Tạo lưu lượng tấn công DDoS vào victim |
| Victim VM | Chạy dịch vụ bị tấn công, ví dụ web server |
| IDS VM | Bắt lưu lượng, trích xuất flow, dự đoán bằng mô hình ML và ghi log |
| Máy thật | Mở trình duyệt để xem dashboard realtime |

Địa chỉ IP tham khảo:

```text
Attacker VM: 192.168.56.10
Victim VM:   192.168.56.20
IDS VM:      192.168.56.30
Host thật:   192.168.56.1
```

Nên cấu hình IDS VM làm gateway/router để chắc chắn nhìn thấy lưu lượng:

```text
Attacker -> IDS VM -> Victim
```

## 4. Cấu trúc project

```text
D:\DoAn_IDS_DDoS\
├── dashboard\
│   ├── app.py
│   ├── static\
│   │   ├── app.js
│   │   └── style.css
│   └── templates\
│       └── index.html
├── data\
│   └── ids_logs.db
├── dataset\
│   └── CSV-01-12\
│       └── 01-12\
│           ├── UDPLag.csv
│           ├── DrDoS_UDP.csv
│           ├── DrDoS_DNS.csv
│           └── ...
├── models\
│   ├── ddos_v2\
│   │   ├── ddos_random_forest_v2.joblib
│   │   ├── ddos_lightgbm_v2.joblib
│   │   └── ddos_feature_manifest_v2.json
├── notebooks\
└── src\
    ├── check_dataset.py
    ├── check_database.py
    ├── test_model.py
    └── train_model.py
```

## 5. Dataset sử dụng

Dataset chính: **CIC-DDoS2019**.

Dataset gồm các file CSV chứa flow traffic, mỗi file tương ứng với một loại tấn công DDoS/DrDoS hoặc biến thể liên quan.

Các file đã upload lên Kaggle:

```text
DrDoS_DNS.csv
DrDoS_LDAP.csv
DrDoS_MSSQL.csv
DrDoS_NTP.csv
DrDoS_NetBIOS.csv
DrDoS_SNMP.csv
DrDoS_SSDP.csv
DrDoS_UDP.csv
LDAP.csv
MSSQL.csv
NetBIOS.csv
Portmap.csv
Portmap2.csv
Syn.csv
Syn2.csv
TFTP.csv
UDP.csv
UDPLag.csv
UDPLag2.csv
```

Đường dẫn dataset trên Kaggle:

```python
DATASET_DIR = Path("/kaggle/input/datasets/dqt123/model-ids")
```

Cột nhãn của dataset:

```text
Label
```

Trong dataset CIC, một số tên cột có dấu cách ở đầu, vì vậy khi đọc dữ liệu cần chuẩn hóa tên cột:

```python
df.columns = df.columns.str.strip()
```

## 6. Vấn đề mất cân bằng dữ liệu

Dữ liệu CIC-DDoS2019 bị lệch mạnh về lớp tấn công. Lưu lượng BENIGN rất ít so với lưu lượng DDoS.

Ví dụ một số file:

| File | BENIGN | TOTAL | DDoS suy ra |
|---|---:|---:|---:|
| DrDoS_DNS.csv | 3,402 | 5,074,413 | 5,071,011 |
| DrDoS_LDAP.csv | 1,612 | 2,181,542 | 2,179,930 |
| DrDoS_MSSQL.csv | 2,006 | 4,524,498 | 4,522,492 |
| DrDoS_NTP.csv | 14,365 | 1,217,007 | 1,202,642 |

Công thức suy ra số dòng tấn công:

```text
DDoS = TOTAL - BENIGN
```

Nếu train trực tiếp toàn bộ dữ liệu, mô hình dễ bị thiên về lớp DDoS. Vì vậy cần lấy mẫu lại để cân bằng tương đối.

Tập train/test được xây dựng lại từ cả 19 file với số lượng cố định:

```text
BENIGN: 150,000 mẫu
DDoS:    50,000 mẫu
Tổng:   200,000 flow
```

Tỉ lệ:

```text
BENIGN : DDoS = 3 : 1
```

Các mẫu DDoS được phân bổ giữa nhiều nhóm tấn công. Khi chia dữ liệu bằng `stratify=y`, tập train có 160.000 flow và tập test có 40.000 flow.

## 7. Các cột cần loại bỏ trước khi train

Không nên đưa toàn bộ cột vào mô hình. Cần loại bỏ các cột định danh, thời gian hoặc dữ liệu dạng text vì có thể làm mô hình học thuộc hoặc khó dùng khi chạy realtime.

Danh sách cột loại bỏ:

```python
DROP_COLUMNS = [
    "Unnamed: 0",
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Timestamp",
    "SimillarHTTP",
]
```

Lý do:

| Cột | Lý do loại bỏ |
|---|---|
| Unnamed: 0 | Cột index thừa |
| Flow ID | Định danh flow, dễ làm mô hình học thuộc |
| Source IP | IP trong dataset khác IP trong môi trường lab |
| Destination IP | IP trong dataset khác IP trong môi trường lab |
| Source Port | Dễ thay đổi, có thể gây nhiễu |
| Destination Port | Bản đầu loại bỏ để mô hình tổng quát hơn |
| Timestamp | Không ổn định khi chạy realtime |
| SimillarHTTP | Có thể là text/object, dễ gây lỗi khi train |

Sau khi loại bỏ các cột định danh, dữ liệu còn 79 feature số của CIC-DDoS2019. Đây là bộ feature ứng viên, chưa phải toàn bộ đầu vào triển khai realtime.

Trong phiên bản v2, nhóm tiếp tục lựa chọn 46 feature mà `live_sensor.py` có thể tính thống nhất. Model và sensor đều đọc thứ tự feature từ `models/ddos_v2/ddos_feature_manifest_v2.json`.

## 8. Quy trình tiền xử lý dữ liệu

Quy trình tiền xử lý:

```text
Đọc CSV
-> chuẩn hóa tên cột
-> loại bỏ cột không cần thiết
-> tách cột Label
-> đổi BENIGN thành 0, attack thành 1
-> ép feature về dạng số
-> xử lý Infinity thành NaN
-> thay NaN bằng 0
-> lựa chọn 46 feature tương thích với live sensor
-> shuffle dữ liệu
-> chia train/test
```

Mapping label:

```text
BENIGN -> 0
Tất cả nhãn còn lại -> 1
```

Bài toán của đồ án là binary classification:

```text
0 = lưu lượng bình thường
1 = lưu lượng tấn công DDoS
```

## 9. Thuật toán học máy được sử dụng

Phiên bản v2 huấn luyện và so sánh hai mô hình:

| Mô hình | Vai trò |
|---|---|
| Random Forest | Mô hình chính, ổn định với dữ liệu dạng bảng |
| LightGBM | Mô hình so sánh, tốc độ huấn luyện nhanh |

Nếu muốn nhẹ hơn có thể thay XGBoost bằng Logistic Regression.

Các chỉ số đánh giá:

```text
Accuracy
Precision
Recall
F1-score
Confusion matrix
Training time
Prediction time
```

Trong hệ thống IDS, cần chú ý đặc biệt tới:

- Recall của lớp DDoS: tránh bỏ sót tấn công.
- False Positive của lớp BENIGN: tránh cảnh báo nhầm quá nhiều.

## 10. Kết quả train phiên bản v2

Phiên bản v2 sử dụng dữ liệu lấy mẫu từ đủ 19 file CSV trong dataset Kaggle. Sau tiền xử lý, dữ liệu có 200.000 flow và 46 feature.

```text
Data shape: (200000, 46)
BENIGN: 150,000
DDoS:    50,000
Train: 160,000
Test:   40,000
```

Kết quả trên tập test:

| Model | Accuracy | Precision DDoS | Recall DDoS | F1-score DDoS | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Random Forest v2 | 0.999450 | 0.999800 | 0.998000 | 0.998899 | 2 | 20 |
| LightGBM v2 | 0.999625 | 0.999500 | 0.999000 | 0.999250 | 5 | 10 |

LightGBM v2 có Recall và F1-score cao hơn trên tập test; Random Forest v2 có ít false positive hơn. Cả hai model đều được lưu để lựa chọn trong dashboard.

## 11. File output sau khi train

Sau khi train trên Kaggle, tải thư mục output gồm:

```text
ddos_random_forest_v2.joblib
ddos_lightgbm_v2.joblib
ddos_feature_manifest_v2.json
ddos_model_comparison_v2.csv
```

Copy vào local:

```text
D:\DoAn_IDS_DDoS\models\ddos_v2\
```

Vai trò:

| File | Vai trò |
|---|---|
| ddos_random_forest_v2.joblib | Mô hình Random Forest với 46 feature |
| ddos_lightgbm_v2.joblib | Mô hình LightGBM với 46 feature |
| ddos_feature_manifest_v2.json | Danh sách 46 feature và thứ tự đầu vào |

Khi predict realtime, sensor và detector phải dùng đúng thứ tự trong `ddos_feature_manifest_v2.json`.

## 12. Kiểm tra model local

Chạy:

```powershell
python src\test_model.py
```

Kết quả mong đợi:

```text
Features: 46
Sample shape: (20, 46)
Predictions: DDoS
```

Nếu test bằng `UDPLag.csv`, kết quả ra DDoS là hợp lý vì đây là file tấn công.

## 13. Dashboard hiện tại

Dashboard dùng Flask:

```text
dashboard/app.py
```

Chạy dashboard:

```powershell
python dashboard\app.py
```

Mở trình duyệt:

```text
http://127.0.0.1:5000
```

Nếu xem từ máy khác cùng mạng:

```text
http://IP_MAY_CHAY_DASHBOARD:5000
```

Các tab hiện có:

| Tab | Nội dung |
|---|---|
| Overview | Tổng flow, DDoS flow, BENIGN flow, attack rate, biểu đồ |
| Alerts | Timeline cảnh báo |
| Traffic | Biểu đồ traffic theo batch |
| Model | Thông tin mô hình và pipeline |

## 14. Database

Hệ thống dùng SQLite:

```text
D:\DoAn_IDS_DDoS\data\ids_logs.db
```

Bảng chính:

```text
flow_logs
```

Các trường quan trọng:

```text
created_at
batch_total
attack_count
benign_count
attack_rate
status
level
source_ip
destination_ip
message
```

Flow hiện tại:

```text
CSV demo -> model predict -> ghi SQLite -> dashboard đọc SQLite -> hiển thị realtime
```

Kiểm tra database:

```powershell
python src\check_database.py
```

## 15. Realtime demo hiện tại

Bản hiện tại là realtime simulation bằng CSV:

```text
UDPLag.csv
-> đọc từng batch 250 dòng
-> predict bằng model
-> lưu database
-> dashboard cập nhật mỗi 2 giây
```

Ý nghĩa:

- Kiểm tra pipeline realtime.
- Kiểm tra model load và predict được.
- Kiểm tra dashboard cập nhật theo thời gian thực.
- Chưa phải traffic thật từ VM.

Sau này sẽ thay nguồn CSV bằng flow thật từ IDS VM.

## 16. Realtime thật trong môi trường VM

Pipeline hoàn chỉnh:

```text
Attacker VM tạo traffic
-> Victim VM nhận traffic
-> IDS VM bắt traffic
-> trích xuất flow feature
-> preprocess giống lúc train
-> model predict
-> ghi SQLite/API
-> dashboard cảnh báo
```

Điểm quan trọng nhất:

```text
Feature realtime phải khớp feature lúc train.
```

Nếu train bằng feature CICFlowMeter, realtime cũng nên trích xuất bằng CICFlowMeter hoặc công cụ tạo feature tương đương.

## 17. Công cụ dự kiến sử dụng

| Mục đích | Công cụ |
|---|---|
| Train model | Kaggle Notebook |
| Xử lý dữ liệu | pandas, numpy |
| Học máy | scikit-learn, xgboost nếu dùng |
| Lưu model | joblib |
| Dashboard | Flask, HTML, CSS, JavaScript |
| Database | SQLite |
| Bắt gói/flow | CICFlowMeter, tshark, tcpdump hoặc Zeek |
| Tạo attack | hping3, nping, slowloris hoặc công cụ tương đương trong lab kín |
| Victim service | Apache, Nginx hoặc Flask app |

## 18. Quy trình train trên Kaggle

1. Upload dataset lên Kaggle.
2. Tạo Kaggle Notebook.
3. Add Input dataset `model_IDS`.
4. Kiểm tra đường dẫn CSV:

```python
import os

for root, dirs, files in os.walk("/kaggle/input"):
    for file in files:
        if file.endswith(".csv"):
            print(os.path.join(root, file))
```

5. Đặt đường dẫn dataset:

```python
DATASET_DIR = Path("/kaggle/input/datasets/dqt123/model-ids")
```

6. Tạo tập 200.000 flow từ 19 file, lọc 46 feature và chia train/test 80/20.
7. Train Random Forest và LightGBM.
8. Lưu output:

```python
import json

joblib.dump(model, "/kaggle/working/ddos_v2/ddos_random_forest_v2.joblib")
with open("/kaggle/working/ddos_v2/ddos_feature_manifest_v2.json", "w") as file:
    json.dump(manifest, file, ensure_ascii=False, indent=2)
```

9. Tải thư mục output về local và copy vào `models/ddos_v2`.

## 19. Quy trình train v2 đã thực hiện

Phiên bản v2 đã thực hiện theo quy trình:

```text
Lấy mẫu 150,000 BENIGN và 50,000 DDoS từ đủ 19 file
Lựa chọn 46 feature có thể tính trong live sensor
Tổng 200,000 flow
Shuffle
Train/test split 80/20 với stratify
Train Random Forest và LightGBM
So sánh kết quả
Tích hợp hai model vào dashboard
```

Tỉ lệ đề xuất:

```text
BENIGN : DDoS = 3 : 1
```

Đây là tỉ lệ hợp lý hơn so với việc train gần như toàn DDoS.

## 20. Hướng viết báo cáo

Các chương có thể triển khai:

```text
Chương 1: Tổng quan về IDS, DDoS và học máy
Chương 2: Cơ sở lý thuyết và các thuật toán sử dụng
Chương 3: Phân tích dataset và tiền xử lý dữ liệu
Chương 4: Thiết kế hệ thống IDS realtime
Chương 5: Cài đặt, huấn luyện mô hình và đánh giá
Chương 6: Triển khai demo, dashboard và kết quả thực nghiệm
Chương 7: Kết luận và hướng phát triển
```

Câu mô tả ngắn gọn:

> Đồ án nghiên cứu và triển khai hệ thống IDS ứng dụng học máy để phát hiện tấn công DDoS theo thời gian thực trong môi trường mạng mô phỏng. Hệ thống sử dụng mô hình học máy được huấn luyện từ dataset CIC-DDoS2019, tích hợp vào pipeline giám sát gồm thu thập flow, tiền xử lý, dự đoán, lưu log và hiển thị cảnh báo trên dashboard.

## 21. Hạn chế hiện tại

- Dashboard hiện tại mới chạy realtime simulation bằng CSV.
- Chưa nối với traffic thật từ IDS VM.
- Model v2 đã cân bằng dữ liệu theo tỷ lệ 150.000 BENIGN và 50.000 DDoS.
- Cần thống nhất version scikit-learn giữa Kaggle và local để tránh warning.
- Cần trích xuất feature realtime đúng format với feature lúc train.

## 22. Hướng phát triển

- Đánh giá thêm trên traffic SYN/UDP trong môi trường VM.
- So sánh kết quả offline và realtime trên cùng feature manifest.
- Thêm Start/Pause/Reset cho dashboard.
- Tách module detection riêng khỏi dashboard.
- Nối IDS VM với CICFlowMeter/tshark/Zeek để lấy flow realtime.
- Thêm cảnh báo theo IP nguồn, IP đích, loại tấn công và mức độ nguy hiểm.
- Thêm export báo cáo CSV/PDF từ dashboard.
- Thêm cơ chế gửi cảnh báo qua email/Telegram nếu cần.

## 23. Kết luận tạm thời

Đồ án hiện tại đã có các thành phần nền tảng:

```text
Dataset CIC-DDoS2019
Model Random Forest và LightGBM v2 train trên Kaggle
Hai file model .joblib và manifest 46 feature
Script test model local
Dashboard Flask
SQLite log database
Realtime simulation pipeline
```

Bước tiếp theo là kiểm thử model v2 với traffic thật trong môi trường VM và ghi nhận kết quả trên `live_flows.csv`.
