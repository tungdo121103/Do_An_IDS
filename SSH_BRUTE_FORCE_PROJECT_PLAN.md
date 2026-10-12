# ĐỀ CƯƠNG ĐỀ TÀI SSH BRUTE FORCE IDS

## 1. Tên đề tài



## 2. Lý do chọn đề tài

SSH là dịch vụ quản trị từ xa phổ biến trên máy chủ Linux. Nếu tài khoản sử dụng mật khẩu yếu, mật khẩu mặc định hoặc mật khẩu đã bị lộ, kẻ tấn công có thể tự động thử nhiều cặp tên đăng nhập và mật khẩu để tìm thông tin xác thực hợp lệ.

Khác với DDoS, mục tiêu của SSH Brute Force không phải làm quá tải dịch vụ mà là chiếm quyền truy cập máy chủ. Hai đề tài có thể dùng chung hướng tiếp cận IDS và học máy, nhưng phát hiện hai nhóm hành vi tấn công khác nhau.

## 3. Mục tiêu

- Nghiên cứu đặc điểm của tấn công SSH Brute Force và các biến thể liên quan.
- Thu thập và tiền xử lý dữ liệu lưu lượng SSH.
- Xây dựng mô hình học máy phân loại lưu lượng `Benign` và `SSH Brute Force`.
- So sánh một số thuật toán như Decision Tree, Random Forest và LightGBM/XGBoost.
- Triển khai mô hình trong mạng máy ảo và phát hiện gần thời gian thực.
- Hiển thị kết quả, địa chỉ nguồn, máy đích, thời gian và mức cảnh báo trên dashboard.
- Đánh giá mô hình bằng Precision, Recall, F1-score, confusion matrix và thời gian dự đoán.

## 4. Phạm vi

Đề tài chỉ được triển khai trong mạng lab máy ảo được phép kiểm thử. Tài khoản, danh sách mật khẩu và máy chủ thử nghiệm đều do nhóm tự tạo.

Phiên bản đầu tập trung vào:

- Giao thức SSH trên TCP port 22.
- Phát hiện dựa trên thông tin flow và tần suất kết nối.
- Phân loại nhị phân: `Benign` và `SSH Brute Force`.

Hướng mở rộng:

- Thêm dữ liệu `/var/log/auth.log` để xác nhận số lần đăng nhập thất bại.
- Phân biệt Brute Force, Dictionary Attack và Password Spraying.
- Tự động cảnh báo hoặc đề xuất chặn IP bằng Fail2ban/firewall.

## 5. Kiến trúc hệ thống đề xuất

| Máy ảo | IP dự kiến | Vai trò |
|---|---:|---|
| Kali Linux | `192.168.247.10` | Tạo lưu lượng SSH bình thường và kịch bản kiểm thử Brute Force |
| Ubuntu Server | `192.168.247.21` | Victim chạy OpenSSH Server và tài khoản thử nghiệm |
| Ubuntu Desktop IDS | `192.168.247.30` | Bắt gói tin, trích xuất flow, chạy model và dashboard |

Tất cả máy ảo đặt trong cùng mạng lab, ví dụ `VMnet1 - Host-only`, để traffic không đi ra mạng ngoài.

Luồng xử lý tổng quát:

```text
Kali Attacker
      |
      | Kết nối và thử xác thực SSH trong mạng lab
      v
Ubuntu SSH Victim
      |
      | Traffic/flow được IDS quan sát
      v
IDS Sensor -> Feature Extraction -> ML Model -> Alert -> Dashboard
```

## 6. Dữ liệu và đặc trưng

### 6.1. Dataset ban đầu

Có thể sử dụng **CICIDS2017**, trong đó có các nhãn phù hợp:

- `BENIGN`
- `SSH-Patator`
- `FTP-Patator` (chỉ dùng nếu mở rộng sang FTP)

Cần kiểm tra và xử lý:

- Giá trị thiếu, `NaN` và vô cực.
- Bản ghi trùng lặp.
- Mất cân bằng giữa hai lớp.
- Chuẩn hóa tên cột và kiểu dữ liệu.
- Loại bỏ các cột gây rò rỉ nhãn nếu có.

### 6.2. Đặc trưng flow dự kiến

- Source IP, destination IP, source port và destination port.
- Flow duration.
- Tổng số packet theo hai chiều.
- Tổng số byte theo hai chiều.
- Packet length mean/max/min.
- Flow packets per second và flow bytes per second.
- Khoảng thời gian giữa các packet.
- Số lượng cờ TCP như SYN, RST và FIN.
- Số kết nối ngắn lặp lại từ cùng một địa chỉ nguồn.

Do nội dung SSH được mã hóa, sensor mạng không đọc trực tiếp được mật khẩu. Hệ thống sẽ nhận biết mẫu hành vi qua metadata và tần suất kết nối. Nếu kết hợp `auth.log`, kết quả đăng nhập thất bại có thể được dùng như nguồn dữ liệu bổ sung.

## 7. Mô hình học máy

Nên xây dựng ít nhất một baseline và hai mô hình so sánh:

| Mô hình | Mục đích |
|---|---|
| Logistic Regression hoặc Decision Tree | Baseline để đối chiếu |
| Random Forest | Mô hình chính, dễ giải thích và phù hợp dữ liệu dạng bảng |
| LightGBM hoặc XGBoost | So sánh hiệu năng và khả năng nhận biết mẫu phức tạp |

Quy trình huấn luyện:

1. Làm sạch và chuẩn hóa dữ liệu.
2. Chọn các feature có thể trích xuất được trong sensor realtime.
3. Chia train/validation/test theo phiên hoặc theo thời gian.
4. Huấn luyện và điều chỉnh tham số.
5. Đánh giá từng lớp bằng Precision, Recall và F1-score.
6. Lưu model, danh sách feature và bộ tiền xử lý.
7. Tích hợp model vào sensor realtime.

Không nên chỉ dựa vào Accuracy vì dữ liệu tấn công có thể ít hơn nhiều so với dữ liệu bình thường. Recall của lớp tấn công và tỷ lệ False Positive cần được ưu tiên khi đánh giá.

## 8. Các module cần xây dựng

```text
ssh-bruteforce-ids/
|-- data/                 # Dữ liệu mẫu và dữ liệu flow realtime
|-- models/               # Model và preprocessor đã huấn luyện
|-- notebooks/            # Khảo sát dữ liệu và thử nghiệm
|-- src/
|   |-- preprocess.py     # Làm sạch và chuẩn hóa dataset
|   |-- train.py          # Huấn luyện và đánh giá model
|   |-- live_sensor.py    # Bắt traffic SSH và tạo flow
|   `-- detector.py       # Nạp model và phân loại
|-- dashboard/            # API, giao diện và cảnh báo
|-- tools/                # Script tạo traffic lab
`-- README.md             # Hướng dẫn cài đặt và demo
```

Có thể tái sử dụng cấu trúc sensor và dashboard của đề tài DDoS, nhưng model, feature, nhãn và kịch bản kiểm thử SSH phải được tách riêng để thể hiện đóng góp của đề tài mới.

## 9. Kịch bản demo dự kiến

### Giai đoạn 1 - Lưu lượng bình thường

1. Khởi động Victim và đảm bảo dịch vụ SSH đang hoạt động.
2. Khởi động sensor và dashboard trên IDS.
3. Đăng nhập SSH bình thường từ Kali bằng tài khoản hợp lệ.
4. Xác nhận dashboard ghi nhận flow là `Benign`.

### Giai đoạn 2 - Kiểm thử SSH Brute Force

1. Sử dụng tài khoản thử nghiệm và danh sách mật khẩu nhỏ trong mạng lab.
2. Tạo nhiều lần xác thực thất bại từ Kali đến Victim.
3. IDS trích xuất đặc trưng và chuyển cho model.
4. Dashboard hiện cảnh báo `SSH Brute Force`.
5. Kiểm tra IP nguồn, IP đích, thời gian, số flow nghi vấn và độ tin cậy.

### Giai đoạn 3 - Đánh giá

1. Dừng kịch bản kiểm thử và quan sát dashboard trở về trạng thái bình thường.
2. Đối chiếu cảnh báo với log xác thực trên Victim.
3. Ghi lại false positive, false negative và thời gian phát hiện.

## 10. Kết quả mong đợi

- Một model có khả năng phân biệt SSH bình thường và hành vi Brute Force.
- Sensor realtime tạo đúng tập feature mà model đã học.
- Dashboard hiển thị cảnh báo rõ ràng, không chỉ hiển thị nhãn dự đoán.
- Báo cáo có bảng so sánh mô hình và giải thích lý do chọn model cuối cùng.
- Demo lặp lại được trong mạng VM mà không phụ thuộc Internet.

## 11. Kế hoạch thực hiện đề xuất

| Giai đoạn | Nội dung | Sản phẩm bàn giao |
|---|---|---|
| 1 | Nghiên cứu SSH Brute Force, dataset và kiến trúc | Đề cương, sơ đồ hệ thống |
| 2 | Xử lý CICIDS2017 và khảo sát feature | Dataset sạch, notebook phân tích |
| 3 | Huấn luyện và so sánh model | Model, metrics, confusion matrix |
| 4 | Dựng ba máy ảo và tạo traffic lab | Mạng VM hoạt động, log và PCAP mẫu |
| 5 | Viết sensor realtime và tích hợp model | File flow realtime, kết quả dự đoán |
| 6 | Xây dashboard và cảnh báo | Giao diện demo |
| 7 | Kiểm thử, viết báo cáo và luyện trình bày | Báo cáo, kịch bản demo, slide |

## 12. Nội dung trình bày ngắn với giảng viên

> Đề tài nghiên cứu phương pháp phát hiện tấn công dò mật khẩu SSH bằng học máy. Hệ thống thu thập metadata của các phiên SSH trong mạng máy ảo, trích xuất các đặc trưng flow và sử dụng model để phân biệt truy cập bình thường với hành vi thử xác thực lặp lại bất thường. Kết quả được cảnh báo trên dashboard và có thể đối chiếu với log đăng nhập của máy chủ. Đề tài bổ sung cho module DDoS để hướng tới một IDS có khả năng phát hiện nhiều nhóm tấn công.

## 13. Lưu ý quan trọng

- Chỉ kiểm thử trên các máy ảo và tài khoản do nhóm quản lý.
- Không thử mật khẩu trên IP, tài khoản hoặc dịch vụ bên ngoài phòng lab.
- Tách tập train và test hợp lý để tránh data leakage.
- Báo cáo cả false positive, không chỉ đưa ra điểm Accuracy cao.
- Đảm bảo feature khi chạy realtime trùng thứ tự và ý nghĩa với feature lúc huấn luyện.
- Sao lưu snapshot VM trước khi thay đổi cấu hình quan trọng.

