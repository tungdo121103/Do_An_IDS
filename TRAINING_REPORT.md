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
| DrDoS_LDAP | 4,167 |
| DrDoS_SSDP | 4,167 |
| DrDoS_UDP | 4,167 |
| DrDoS_NetBIOS | 4,167 |
| DrDoS_MSSQL | 4,167 |
| DrDoS_SNMP | 4,167 |
| DrDoS_NTP | 4,167 |
| DrDoS_DNS | 4,167 |
| Syn | 4,166 |
| TFTP | 4,166 |
| Portmap | 4,166 |
| UDP-lag | 4,155 |
| WebDDoS | 11 |

Tổng số mẫu DDoS là 50,000. Nhãn `WebDDoS` xuất hiện trong nhóm `UDPLag`, nên tổng nhóm này vẫn đạt 4,166 mẫu.

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
| Dữ liệu sau khi loại cột thừa | 200,000 dòng, 79 feature |

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
- `Idle Mean`
- `Active Mean`

Đây là các đặc trưng được dùng để mô hình học sự khác biệt giữa traffic bình thường và traffic DDoS.

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

Như vậy, toàn bộ các mô hình Decision Tree, Random Forest và LightGBM đều được train và test trên cùng một bộ dữ liệu đã tiền xử lý, giúp kết quả đánh giá có tính so sánh trực tiếp.

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

Project tiến hành huấn luyện và so sánh 3 thuật toán:

### 6.1. Decision Tree

Decision Tree được sử dụng làm mô hình cơ sở. Mô hình này dễ hiểu, dễ giải thích và có tốc độ huấn luyện nhanh. Tuy nhiên, Decision Tree đơn lẻ có nguy cơ overfitting nếu cây quá sâu.

Vai trò trong đồ án:

```text
Làm baseline để so sánh với các mô hình ensemble mạnh hơn.
```

### 6.2. Random Forest

Random Forest là mô hình ensemble gồm nhiều Decision Tree. Mô hình này giúp giảm overfitting và tăng độ ổn định so với một cây quyết định đơn lẻ.

Lý do phù hợp:

- Hoạt động tốt với dữ liệu dạng bảng
- Không cần scale dữ liệu phức tạp
- Dễ lưu bằng `joblib`
- Dễ tích hợp vào Flask dashboard
- Cho kết quả ổn định trên bài toán IDS

### 6.3. LightGBM

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

### 7.1. Decision Tree

| Chỉ số | Giá trị |
|---|---:|
| Train time | 4.5483 s |
| Prediction time | 0.0167 s |
| Accuracy | 0.999600 |
| Precision DDoS | 0.999400 |
| Recall DDoS | 0.999000 |
| F1-score DDoS | 0.999200 |

Confusion matrix:

```text
[[29994     6]
 [   10  9990]]
```

Diễn giải:

- 29,994 mẫu BENIGN được dự đoán đúng
- 6 mẫu BENIGN bị báo nhầm thành DDoS
- 10 mẫu DDoS bị bỏ sót
- 9,990 mẫu DDoS được phát hiện đúng

### 7.2. Random Forest

| Chỉ số | Giá trị |
|---|---:|
| Train time | 10.8622 s |
| Prediction time | 0.1630 s |
| Accuracy | 0.999675 |
| Precision DDoS | 1.000000 |
| Recall DDoS | 0.998700 |
| F1-score DDoS | 0.999350 |

Confusion matrix:

```text
[[30000     0]
 [   13  9987]]
```

Diễn giải:

- 30,000 mẫu BENIGN được dự đoán đúng
- 0 mẫu BENIGN bị báo nhầm thành DDoS
- 13 mẫu DDoS bị bỏ sót
- 9,987 mẫu DDoS được phát hiện đúng

### 7.3. LightGBM

| Chỉ số | Giá trị |
|---|---:|
| Train time | 7.3616 s |
| Prediction time | 0.1830 s |
| Accuracy | 0.999675 |
| Precision DDoS | 0.999800 |
| Recall DDoS | 0.998900 |
| F1-score DDoS | 0.999350 |

Confusion matrix:

```text
[[29998     2]
 [   11  9989]]
```

Diễn giải:

- 29,998 mẫu BENIGN được dự đoán đúng
- 2 mẫu BENIGN bị báo nhầm thành DDoS
- 11 mẫu DDoS bị bỏ sót
- 9,989 mẫu DDoS được phát hiện đúng

## 8. Bảng so sánh tổng hợp

| Model | Accuracy | Precision DDoS | Recall DDoS | F1-score DDoS | False Positive | False Negative | Train time | Prediction time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Decision Tree | 0.999600 | 0.999400 | 0.999000 | 0.999200 | 6 | 10 | 4.5483 s | 0.0167 s |
| Random Forest | 0.999675 | 1.000000 | 0.998700 | 0.999350 | 0 | 13 | 10.8622 s | 0.1630 s |
| LightGBM | 0.999675 | 0.999800 | 0.998900 | 0.999350 | 2 | 11 | 7.3616 s | 0.1830 s |

Trong bài toán IDS, các chỉ số cần quan tâm gồm:

- `False Negative`: số mẫu DDoS bị bỏ sót
- `False Positive`: số mẫu BENIGN bị báo nhầm thành DDoS
- `Recall` của lớp DDoS
- `F1-score` của lớp DDoS
- Thời gian dự đoán

## 9. Nhận xét

Cả ba mô hình đều đạt độ chính xác rất cao trên tập test. Random Forest và LightGBM có cùng accuracy là `0.999675`, cao hơn Decision Tree.

Random Forest có ưu điểm là không báo nhầm mẫu BENIGN nào thành DDoS trong tập test:

```text
False Positive = 0
```

LightGBM có số mẫu DDoS bị bỏ sót ít hơn Random Forest:

```text
False Negative của LightGBM = 11
False Negative của Random Forest = 13
```

Decision Tree có tốc độ dự đoán nhanh nhất, nhưng do là mô hình đơn lẻ nên khả năng tổng quát hóa kém ổn định hơn các mô hình ensemble.

## 10. Lựa chọn mô hình cho dashboard

Trong phạm vi project, **Random Forest** được đề xuất làm mô hình chính để tích hợp vào dashboard IDS realtime.

Lý do:

- Accuracy cao: `0.999675`
- Không có false positive trên tập test
- Dễ giải thích hơn LightGBM
- Dễ lưu và nạp bằng `joblib`
- Phù hợp với kiến trúc dashboard hiện tại của project

LightGBM được giữ làm mô hình so sánh vì có hiệu năng tốt và thời gian huấn luyện nhanh hơn Random Forest.

## 11. Kết luận

Qua quá trình tiền xử lý và huấn luyện, project đã tạo được tập dữ liệu 200,000 flow theo tỷ lệ 3:1 giữa BENIGN và DDoS. Lớp DDoS được lấy mẫu phân tầng theo từng nhóm tấn công để hạn chế lệch mẫu.

Ba thuật toán Decision Tree, Random Forest và LightGBM đã được huấn luyện và đánh giá trên cùng một tập train/test. Kết quả cho thấy Random Forest và LightGBM đạt hiệu năng cao nhất, trong đó Random Forest được chọn làm mô hình chính cho hệ thống IDS realtime do tính ổn định, dễ tích hợp và kết quả false positive bằng 0 trên tập test.



