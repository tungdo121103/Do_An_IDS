# Tài liệu tiền xử lý dữ liệu IDS

Tài liệu này ghi lại các bước tiền xử lý đã thực hiện cho hai bài toán của project:

1. Phát hiện DDoS.
2. Phát hiện SSH Brute Force.

Mục tiêu của tiền xử lý là tạo ra dữ liệu số, sạch, có nhãn rõ ràng và đặc biệt là bảo đảm **bộ feature khi train giống bộ feature do sensor realtime tạo ra**.

## 1. Nguyên tắc chung

Dataset ban đầu là các file CSV dạng flow. Mỗi dòng không phải một packet riêng lẻ mà là một network flow đã được tổng hợp từ nhiều packet.

Các cột định danh như IP, port, Flow ID và timestamp không được đưa trực tiếp vào model vì:

- không mô tả ổn định hành vi tấn công;
- có thể làm model học thuộc môi trường thu thập dữ liệu;
- không phù hợp để sử dụng khi chạy sensor realtime;
- có thể làm model dự đoán sai khi IP hoặc port thay đổi.

Sau khi loại bỏ các cột không phù hợp, các feature còn lại được ép sang dạng số, xử lý giá trị thiếu/vô cực và sắp xếp theo manifest cố định.

## 2. Tiền xử lý dữ liệu DDoS

### 2.1. Dữ liệu đầu vào

Dữ liệu DDoS được lấy từ đủ 19 file CSV của bộ CIC-DDoS2019. Các file chứa nhiều nhóm tấn công như DNS, LDAP, MSSQL, NTP, NetBIOS, SNMP, SSDP, UDP, SYN, TFTP, Portmap và UDPLag.

Tổng dữ liệu gốc rất lớn, hơn 30 GB. Không đọc toàn bộ dữ liệu vào model cùng một lúc; thay vào đó, notebook Kaggle quét từng file, đếm nhãn và lấy mẫu phân tầng.

### 2.2. Chuẩn hóa cột

Tên cột được loại bỏ khoảng trắng thừa ở đầu/cuối:

```python
df.columns = df.columns.astype(str).str.strip()
```

Việc này tránh lỗi khi tên cột trong các file có khoảng trắng không nhìn thấy hoặc khác nhau về cách ghi.

### 2.3. Chuẩn hóa nhãn

Nhãn `BENIGN` được giữ là lưu lượng hợp lệ. Tất cả nhãn tấn công DDoS được gom về một lớp nhị phân:

```text
BENIGN → 0
mọi nhãn tấn công → 1
```

Model DDoS v2 vì vậy giải quyết bài toán nhị phân `BENIGN/DDoS`, không phân loại riêng DNS, SYN, UDP hay HTTP.

### 2.4. Lấy mẫu cân bằng

Dữ liệu gốc có số lượng flow tấn công rất lớn nhưng số flow BENIGN ít hơn nhiều. Để tránh việc các nhãn tấn công lớn lấn át các nhãn khác, dữ liệu được lấy mẫu như sau:

```text
BENIGN: 150.000 dòng
DDoS:   50.000 dòng
Tổng:  200.000 dòng
```

50.000 dòng DDoS được lấy gần như đều theo từng nhóm nhãn tấn công, khoảng 2.980 dòng cho mỗi nhóm trong mẫu cuối. Cách lấy mẫu này giúp mẫu train vẫn có nhiều loại DDoS thay vì chỉ đại diện cho một file lớn nhất.

### 2.5. Loại bỏ cột không dùng

Các cột định danh hoặc không thể tái tạo nhất quán trong sensor được loại bỏ, gồm:

```text
Unnamed: 0
Flow ID
Source IP
Source Port
Destination IP
Destination Port
Timestamp
Label
```

`Label` chỉ được loại bỏ khỏi `X`; nó vẫn được giữ riêng trong `y` để làm mục tiêu train.

Các cột dạng text như `SimillarHTTP` cũng không được đưa vào model nếu không thể chuyển đổi số an toàn.

### 2.6. Chọn 46 feature triển khai

Sau khi loại bỏ cột định danh và cột text, nhóm chọn đúng 46 feature mà `src/live_sensor.py` có thể tính được trong thời gian thực. Đây là bước quan trọng nhất để tránh lỗi lệch cột giữa train và demo.

Thứ tự 46 feature được lưu tại:

```text
models/ddos_v2/ddos_feature_manifest_v2.json
```

Model và sensor đều đọc cùng manifest này. Không được tự ý đổi thứ tự feature khi chạy predict.

### 2.7. Ép kiểu và xử lý dữ liệu lỗi

Các giá trị không chuyển được sang số được chuyển thành `NaN`:

```python
X = X.apply(pd.to_numeric, errors="coerce")
```

Các giá trị vô cực thường phát sinh ở feature tốc độ được xử lý:

```python
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)
```

Sau bước này, notebook kiểm tra lại:

```text
Số giá trị NaN còn lại: 0
Số giá trị vô cực còn lại: 0
```

### 2.8. Chia train/test

Mẫu 200.000 dòng được chia theo tỷ lệ 80/20 và stratify theo nhãn:

```text
Train: 160.000 dòng
Test:   40.000 dòng
```

Phân bố:

```text
Train: 120.000 BENIGN, 40.000 DDoS
Test:   30.000 BENIGN, 10.000 DDoS
```

Kết quả sau tiền xử lý DDoS:

```text
X: (200000, 46)
y: (200000,)
```

## 3. Tiền xử lý dữ liệu SSH Brute Force

### 3.1. Dữ liệu đầu vào

SSH sử dụng file:

```text
dataset/Tuesday-WorkingHours.pcap_ISCX.csv
```

File này nhỏ hơn nhiều so với bộ 19 file DDoS. Nó chứa khoảng 412 nghìn flow BENIGN và 3.219 flow `SSH-Patator`.

### 3.2. Lọc nhãn cần thiết

Chỉ giữ hai nhãn phục vụ bài toán nhị phân:

```text
BENIGN
SSH-Patator
```

Sau đó ánh xạ:

```text
BENIGN     → 0
SSH-Patator → 1
```

Các loại tấn công khác trong file Tuesday không được đưa vào model SSH vì không thuộc mục tiêu SSH Brute Force.

### 3.3. Loại bỏ cột định danh

Script `src/prepare_ssh_train_ready.py` loại bỏ các cột:

```text
Unnamed: 0
Flow ID
Source IP
Source Port
Destination IP
Destination Port
Timestamp
```

Các cột này vẫn có thể dùng để định tuyến hoặc hiển thị cảnh báo, nhưng không đưa vào vector feature của model.

### 3.4. Chọn feature tương thích realtime

SSH sử dụng danh sách feature riêng được định nghĩa trong:

```text
src/prepare_ssh_train_ready.py
```

Kết quả hiện tại có:

```text
45 feature + 1 cột Label
```

Thứ tự feature được lưu tại:

```text
dataset/ssh/processed/ssh_feature_manifest.json
```

File CSV sau khi chuẩn bị:

```text
dataset/ssh/processed/ssh_train_ready.csv
```

### 3.5. Làm sạch số liệu

Các feature được ép về số bằng `errors="coerce"`. Sau đó:

```python
replace([np.inf, -np.inf], np.nan)
```

Các dòng có giá trị không hợp lệ bị loại khỏi tập train-ready. Các dòng trùng hoàn toàn cũng được loại bỏ để tránh một flow xuất hiện đồng thời ở train và test.

Kết quả đã chuẩn bị:

```text
Tổng dòng: 378.261
BENIGN:    375.042
SSH-Patator: 3.219
Feature:   45
NaN/Inf:    0
```

### 3.6. Mất cân bằng nhãn SSH

SSH-Patator ít hơn BENIGN rất nhiều. Đây là đặc điểm của dữ liệu CICIDS2017, không phải do thiếu file tải xuống. Khi train cần:

- giữ toàn bộ 3.219 mẫu SSH-Patator;
- lấy mẫu bớt BENIGN khi cần để giảm tỷ lệ lệch;
- dùng `class_weight="balanced_subsample"` trong Random Forest;
- đánh giá riêng Precision, Recall và F1 của lớp SSH.

Không tự tạo bản sao dữ liệu SSH để làm tăng số lượng, vì việc đó có thể làm kết quả đánh giá không đáng tin cậy.

## 4. Kiểm tra trước khi train

Trước khi train phải kiểm tra:

```text
- Số cột feature đúng với manifest.
- Tên và thứ tự feature ổn định.
- Label chỉ chứa các lớp đã định nghĩa.
- Không còn NaN hoặc Infinity.
- Không còn dòng trùng ngoài ý muốn.
- Tỷ lệ train/test và phân bố nhãn đã được ghi lại.
```

Khi chạy realtime, `realtime_detect.py` phải đọc cùng manifest và không được tự động bổ sung các cột thiếu bằng giá trị tùy ý. Nếu feature live không khớp manifest, hệ thống phải báo lỗi để tránh dự đoán sai âm thầm.

## 5. Tệp kết quả và khả năng tái lập

Các tệp quan trọng của DDoS v2:

```text
models/ddos_v2/ddos_random_forest_v2.joblib
models/ddos_v2/ddos_lightgbm_v2.joblib
models/ddos_v2/ddos_feature_manifest_v2.json
```

Các tệp đầu vào SSH sau tiền xử lý:

```text
dataset/ssh/processed/ssh_train_ready.csv
dataset/ssh/processed/ssh_feature_manifest.json
```

Các script thực hiện tiền xử lý SSH:

```text
src/prepare_ssh_dataset.py
src/prepare_ssh_train_ready.py
```

Việc lưu manifest cùng model/dataset giúp sensor realtime, script test offline và model sử dụng đúng cùng một schema feature.

## 6. Tóm tắt dùng trong báo cáo

Tiền xử lý không chỉ là xóa một vài cột. Quy trình gồm lọc nhãn, chuẩn hóa tên cột, loại bỏ định danh, chọn feature có thể triển khai realtime, chuyển dữ liệu về dạng số, xử lý NaN/Infinity, loại bỏ dòng trùng, lấy mẫu để giảm mất cân bằng và chia train/test có stratify. DDoS v2 sử dụng 200.000 flow với 46 feature; SSH sử dụng 378.261 flow đã làm sạch với 45 feature. Cả hai pipeline đều lưu thứ tự feature trong manifest để bảo đảm dữ liệu train và dữ liệu realtime tương thích.
