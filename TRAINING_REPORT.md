# Báo cáo huấn luyện mô hình IDS phát hiện DDoS

## 1. Mục tiêu

Mục tiêu của giai đoạn này là xây dựng và đánh giá các mô hình học máy để phân loại flow mạng thành hai nhóm:

- `BENIGN`: lưu lượng mạng bình thường
- `DDoS`: lưu lượng có dấu hiệu tấn công từ chối dịch vụ phân tán

Mô hình sau khi huấn luyện sẽ được xuất ra file `.joblib` và tích hợp vào dashboard IDS realtime của project.

## 2. Bộ dữ liệu sử dụng

Project sử dụng bộ dữ liệu **CIC-DDoS2019**, gồm nhiều file CSV tương ứng với các kiểu tấn công DDoS khác nhau, ví dụ:

- `DrDoS_DNS.csv`
- `DrDoS_LDAP.csv`
- `DrDoS_MSSQL.csv`
- `DrDoS_NTP.csv`
- `DrDoS_NetBIOS.csv`
- `DrDoS_SNMP.csv`
- `DrDoS_SSDP.csv`
- `DrDoS_UDP.csv`
- `Syn.csv`
- `TFTP.csv`
- `UDP.csv`
- `UDPLag.csv`
- `Portmap.csv`

Mỗi dòng trong file CSV tương ứng với **một network flow**. Một flow là một luồng giao tiếp mạng được tổng hợp từ nhiều packet, thường được xác định bởi:

- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol

Mỗi flow có nhiều đặc trưng thống kê như thời gian flow, số packet, tốc độ byte/giây, cờ TCP, độ dài packet trung bình, v.v.

## 3. Lấy mẫu dữ liệu

Do dữ liệu gốc có kích thước lớn và phân bố nhãn không cân bằng, project không huấn luyện trực tiếp trên toàn bộ dataset. Thay vào đó, dữ liệu được lấy mẫu theo hướng gần với môi trường mạng thực tế, trong đó traffic bình thường chiếm đa số.

Tập dữ liệu huấn luyện sau khi lấy mẫu gồm:

| Nhãn | Số mẫu |
|---|---:|
| BENIGN | 150,000 |
| DDoS | 50,000 |
| Tổng | 200,000 |

Tỷ lệ này tương đương:

```text
BENIGN : DDoS = 3 : 1
```

Với lớp DDoS, dữ liệu không được lấy ngẫu nhiên toàn bộ một lần. Thay vào đó, các mẫu DDoS được lấy theo từng nhóm tấn công để tránh việc mô hình bị lệch về một loại tấn công có số lượng lớn.

Phân bố sau khi lấy mẫu:

| Label | Số mẫu |
|---|---:|
| BENIGN | 150,000 |
| DrDoS_MSSQL | 2,981 |
| LDAP | 2,981 |
| DrDoS_SSDP | 2,981 |
| MSSQL | 2,981 |
| DrDoS_SNMP | 2,981 |
| DrDoS_NTP | 2,981 |
| DrDoS_LDAP | 2,981 |
| DrDoS_UDP | 2,981 |
| DrDoS_NetBIOS | 2,981 |
| DrDoS_DNS | 2,981 |
| TFTP | 2,980 |
| Portmap | 2,980 |
| NetBIOS | 2,980 |
| Syn | 2,980 |
| UDP-lag | 2,979 |
| UDP | 2,979 |
| UDPLag | 1,873 |
| WebDDoS | 439 |

Tổng số mẫu DDoS là 50,000. Các nhãn được lấy từ đủ 19 file và phân bổ theo khả năng lấy mẫu của từng nhóm.

## 4. Tiền xử lý dữ liệu

Sau khi lấy mẫu, dữ liệu vẫn còn các cột định danh và các cột không phù hợp để đưa vào mô hình học máy. Các cột này được loại bỏ trước khi huấn luyện.

Danh sách cột bị loại bỏ:

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

Lý do loại bỏ:

- `Unnamed: 0`: cột index dư thừa từ file CSV.
- `Flow ID`: định danh flow, không phải đặc trưng tổng quát.
- `Source IP`, `Destination IP`: có thể làm mô hình học lệch theo địa chỉ IP trong dataset.
- `Source Port`, `Destination Port`: có thể làm mô hình phụ thuộc vào port cụ thể thay vì hành vi traffic.
- `Timestamp`: mang tính thời điểm thu thập, không nên dùng làm đặc trưng chính.
- `SimillarHTTP`: cột dạng chuỗi/text, không phù hợp nếu chưa mã hóa.

Cột `Label` được dùng để tạo nhãn đầu ra:

```text
BENIGN -> 0
Khác BENIGN -> 1
```

Sau khi tiền xử lý:

| Dữ liệu | Kích thước |
|---|---:|
| Dữ liệu ban đầu | 200,000 dòng, 88 cột |
| Sau khi loại cột định danh | 200,000 dòng, 79 feature ứng viên |
| Sau khi lựa chọn feature triển khai | 200,000 dòng, 46 feature |

Các giá trị không hợp lệ được xử lý như sau:

- Chuyển các cột feature về dạng số bằng `pd.to_numeric`
- Thay `inf`, `-inf` bằng `NaN`
- Điền `NaN` bằng `0`


## 4.1. Quy trình tiền xử lý trước khi train/test

Sau khi tạo file sample `ddos_sample_200k_150k_50k_stratified.csv`, dữ liệu được tiền xử lý theo cùng một quy trình trước khi đưa vào các thuật toán học máy. Việc này giúp các mô hình được huấn luyện và đánh giá trên cùng một bộ feature, đảm bảo kết quả so sánh công bằng.

Quy trình gồm các bước chính:

### Bước 1: Chuẩn hóa tên cột

Tên cột trong các file CIC-DDoS2019 có thể chứa khoảng trắng ở đầu hoặc cuối, ví dụ ` Source IP`, ` Destination IP`. Vì vậy, trước khi xử lý, toàn bộ tên cột được chuẩn hóa bằng cách loại bỏ khoảng trắng thừa:

```python
df.columns = df.columns.str.strip()
```

Bước này giúp tránh lỗi khi truy cập cột, đặc biệt là cột `Label` và các cột cần loại bỏ.

### Bước 2: Tạo nhãn đầu ra `y`

Bài toán trong project được xây dựng theo hướng phân loại nhị phân:

```text
0 = BENIGN
1 = DDoS
```

Do đó, cột `Label` được chuyển thành vector nhãn `y` như sau:

```python
y = df["Label"].astype(str).str.upper().str.strip().ne("BENIGN").astype(int)
```

Trong đó:

- Nếu `Label` là `BENIGN` thì gán `0`
- Nếu `Label` khác `BENIGN` thì gán `1`

Các nhãn như `DrDoS_DNS`, `DrDoS_LDAP`, `Syn`, `TFTP`, `UDP-lag`, `WebDDoS` đều được gom vào lớp `DDoS`.

### Bước 3: Tạo tập đặc trưng đầu vào `X`

Sau khi tạo nhãn `y`, dữ liệu đầu vào `X` được tạo bằng cách loại bỏ các cột định danh, cột thời gian, cột dạng text và cột nhãn:

```python
X = df.drop(columns=DROP_COLUMNS + ["Label"], errors="ignore")
```

Sau bước này, `X` chỉ còn các feature số mô tả hành vi của flow mạng, ví dụ:

- `Flow Duration`
- `Total Fwd Packets`
- `Total Backward Packets`
- `Flow Bytes/s`
- `Flow Packets/s`
- `Packet Length Mean`
- `SYN Flag Count`
- `ACK Flag Count`
Đây là bộ feature ứng viên sau khi bỏ các cột định danh. Trong phiên bản v2, nhóm tiếp tục chọn 46 feature mà `live_sensor.py` có thể tính thống nhất với dữ liệu huấn luyện:

```python
X = df[DDOS_FEATURES].copy()
```

Danh sách và thứ tự 46 feature được lưu trong `ddos_feature_manifest_v2.json`.

### Bước 4: Chuyển dữ liệu feature về dạng số

Một số cột trong CSV có thể được đọc dưới dạng chuỗi hoặc có giá trị không hợp lệ. Vì các thuật toán học máy yêu cầu feature dạng số, toàn bộ `X` được chuyển sang numeric:

```python
X = X.apply(pd.to_numeric, errors="coerce")
```

Tham số `errors="coerce"` sẽ chuyển các giá trị không chuyển được sang số thành `NaN`.

### Bước 5: Xử lý giá trị vô cực và thiếu

Trong dữ liệu flow mạng có thể xuất hiện các giá trị `inf` hoặc `-inf`, thường do các phép tính tốc độ như byte/giây hoặc packet/giây khi thời gian flow rất nhỏ. Các giá trị này được thay bằng `NaN`, sau đó điền bằng `0`:

```python
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)
```

Cách xử lý này giúp tránh lỗi khi train model và đảm bảo toàn bộ ma trận feature có giá trị hữu hạn.

### Bước 6: Chia dữ liệu thành train/test

Sau khi có `X` và `y`, dữ liệu được chia thành tập train và test:

```python
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)
```

Trong đó:

- `X_train`, `y_train`: dùng để huấn luyện mô hình
- `X_test`, `y_test`: dùng để đánh giá mô hình trên dữ liệu chưa từng được học
- `test_size=0.2`: 20% dữ liệu dùng làm tập test
- `random_state=42`: cố định kết quả chia dữ liệu để có thể tái lập
- `stratify=y`: giữ nguyên tỷ lệ BENIGN/DDoS ở cả tập train và test

Nhờ `stratify=y`, tỷ lệ 3:1 giữa BENIGN và DDoS được giữ ổn định:

| Tập dữ liệu | BENIGN | DDoS | Tổng |
|---|---:|---:|---:|
| Train | 120,000 | 40,000 | 160,000 |
| Test | 30,000 | 10,000 | 40,000 |

Như vậy, Random Forest và LightGBM v2 được train và test trên cùng một bộ dữ liệu 46 feature, giúp kết quả đánh giá có tính so sánh trực tiếp.

## 5. Chia train/test

Dữ liệu được chia theo tỷ lệ:

```text
80% train
20% test
```

Sử dụng `stratify=y` để giữ nguyên tỷ lệ BENIGN/DDoS trong cả tập train và test.

Kết quả chia dữ liệu:

| Tập dữ liệu | BENIGN | DDoS | Tổng |
|---|---:|---:|---:|
| Train | 120,000 | 40,000 | 160,000 |
| Test | 30,000 | 10,000 | 40,000 |

## 6. Các thuật toán huấn luyện

Phiên bản v2 tiến hành huấn luyện và so sánh 2 thuật toán:

### 6.1. Random Forest

Random Forest là mô hình ensemble gồm nhiều Decision Tree. Mô hình này giúp giảm overfitting và tăng độ ổn định so với một cây quyết định đơn lẻ.

Lý do phù hợp:

- Hoạt động tốt với dữ liệu dạng bảng
- Không cần scale dữ liệu phức tạp
- Dễ lưu bằng `joblib`
- Dễ tích hợp vào Flask dashboard
- Cho kết quả ổn định trên bài toán IDS

### 6.2. LightGBM

LightGBM là thuật toán gradient boosting tối ưu cho dữ liệu dạng bảng và dữ liệu lớn. Mô hình này thường có tốc độ huấn luyện nhanh và độ chính xác cao.

Lý do phù hợp:

- Hiệu quả với dữ liệu nhiều feature
- Tốc độ huấn luyện nhanh
- Phù hợp bài toán classification
- Có thể dùng cho hệ thống gần realtime

## 7. Kết quả thực nghiệm

Tập test gồm 40,000 mẫu, trong đó:

```text
BENIGN: 30,000
DDoS: 10,000
```

### 7.1. Random Forest v2

| Chỉ số | Giá trị |
|---|---:|
| Train time | 17.8713 s |
| Accuracy | 0.999450 |
| Precision DDoS | 0.999800 |
| Recall DDoS | 0.998000 |
| F1-score DDoS | 0.998899 |

Confusion matrix:

```text
[[29998     2]
 [   20  9980]]
```

Diễn giải:

- 29,998 mẫu BENIGN được dự đoán đúng
- 2 mẫu BENIGN bị báo nhầm thành DDoS
- 20 mẫu DDoS bị bỏ sót
- 9,980 mẫu DDoS được phát hiện đúng

### 7.2. LightGBM v2

| Chỉ số | Giá trị |
|---|---:|
| Train time | 5.1420 s |
| Accuracy | 0.999625 |
| Precision DDoS | 0.999500 |
| Recall DDoS | 0.999000 |
| F1-score DDoS | 0.999250 |

Confusion matrix:

```text
[[29995     5]
 [   10  9990]]
```

Diễn giải:

- 29,995 mẫu BENIGN được dự đoán đúng
- 5 mẫu BENIGN bị báo nhầm thành DDoS
- 10 mẫu DDoS bị bỏ sót
- 9,990 mẫu DDoS được phát hiện đúng

## 8. Bảng so sánh tổng hợp

| Model | Accuracy | Precision DDoS | Recall DDoS | F1-score DDoS | False Positive | False Negative | Train time | Prediction time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Random Forest v2 | 0.999450 | 0.999800 | 0.998000 | 0.998899 | 2 | 20 | 17.8713 s | — |
| LightGBM v2 | 0.999625 | 0.999500 | 0.999000 | 0.999250 | 5 | 10 | 5.1420 s | — |

Trong bài toán IDS, các chỉ số cần quan tâm gồm:

- `False Negative`: số mẫu DDoS bị bỏ sót
- `False Positive`: số mẫu BENIGN bị báo nhầm thành DDoS
- `Recall` của lớp DDoS
- `F1-score` của lớp DDoS
- Thời gian dự đoán

## 9. Nhận xét

Cả hai mô hình v2 đều đạt độ chính xác rất cao trên tập test. LightGBM v2 có Accuracy, Recall và F1-score cao hơn Random Forest v2.

Random Forest v2 có số false positive thấp hơn LightGBM v2:

```text
False Positive của Random Forest v2 = 2
False Positive của LightGBM v2 = 5
```

LightGBM có số mẫu DDoS bị bỏ sót ít hơn Random Forest:

```text
False Negative của LightGBM v2 = 10
False Negative của Random Forest v2 = 20
```

LightGBM v2 được ưu tiên khi cần giảm số DDoS bị bỏ sót; Random Forest v2 được giữ làm lựa chọn thay thế khi cần giảm false positive.

## 10. Lựa chọn mô hình cho dashboard

Theo kết quả offline, **LightGBM v2** được ưu tiên khi cần giảm số DDoS bị bỏ sót. Runtime hiện đặt Random Forest v2 làm model mặc định và vẫn cho phép chọn LightGBM từ dashboard.

Lý do:

- Recall DDoS cao hơn: `0.999000`
- F1-score DDoS cao hơn: `0.999250`
- Thời gian huấn luyện ngắn hơn trong lần thực nghiệm này
- Đã được lưu cùng manifest 46 feature

Random Forest v2 vẫn được giữ trong dashboard để so sánh và là lựa chọn mặc định hiện tại khi cần giảm false positive.

## 11. Kết luận

Qua quá trình tiền xử lý và huấn luyện, project đã tạo được tập dữ liệu 200,000 flow theo tỷ lệ 3:1 giữa BENIGN và DDoS. Lớp DDoS được lấy mẫu phân tầng theo từng nhóm tấn công để hạn chế lệch mẫu.

Hai thuật toán Random Forest và LightGBM v2 đã được huấn luyện và đánh giá trên cùng một tập train/test gồm 46 feature. LightGBM v2 có kết quả tốt hơn về Recall và F1-score; Random Forest v2 vẫn được giữ làm model mặc định và cả hai có thể chọn trong dashboard.



