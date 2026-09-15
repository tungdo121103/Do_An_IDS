# Báo cáo setup và demo hệ thống IDS realtime phát hiện DDoS

## 1. Mục tiêu demo

Mục tiêu của demo là kiểm chứng hệ thống IDS phát hiện DDoS theo thời gian thực trong môi trường mạng mô phỏng bằng máy ảo.

Phiên bản demo hiện tại đã chuyển từ mô hình một nguồn tấn công sang mô hình nhiều nguồn tấn công:

```text
Kali attacker + Bot Ubuntu Server
-> cùng tạo HTTP flood traffic thật
-> Victim Ubuntu Server chạy Apache2 nhận request
-> IDS Ubuntu Desktop bắt traffic trên ens33
-> trích xuất flow feature realtime
-> đưa vào mô hình học máy để dự đoán
-> lưu log vào SQLite
-> dashboard hiển thị cảnh báo realtime
```

Điểm quan trọng: demo không dùng lại CSV dataset train/test để giả lập. File `live_flows.csv` được sinh từ packet thật mà IDS bắt được trong môi trường VM lab.

## 2. Mô hình mạng máy ảo

Demo sử dụng 4 máy ảo và 1 máy thật:

| Thành phần | Hệ điều hành | IP | Vai trò |
|---|---|---|---|
| Kali-Attacker | Kali Linux | `192.168.247.10` | Attacker/controller, chạy script local và điều khiển bot qua SSH |
| Bot-Ubuntu-Server | Ubuntu Server | `192.168.247.11` | Bot giả lập, nhận lệnh từ Kali và cùng gửi traffic tới victim |
| Victim-Ubuntu-Server | Ubuntu Server | `192.168.247.20` | Máy chủ bị tấn công, chạy Apache2 |
| IDS-Ubuntu-Desktop | Ubuntu Desktop | `192.168.247.30` | Bắt traffic, chạy sensor, model, SQLite và dashboard |
| Windows host | Windows | `192.168.247.1` | Mở trình duyệt xem dashboard |

Sơ đồ tổng quát:

```text
                    Windows host browser
                            |
                            v
        IDS Ubuntu Desktop: sensor + model + dashboard
                            |
                            | sniff on ens33
                            v
Kali attacker  --------------------------\
192.168.247.10                            \
                                           >  Victim Apache
Bot Ubuntu Server -----------------------/   192.168.247.20
192.168.247.11
```

Mô hình này mô phỏng DDoS vì victim nhận HTTP traffic từ nhiều IP nguồn khác nhau. Bot không phải mã độc thật; đây là bot giả lập được Kali điều khiển hợp pháp qua SSH trong môi trường lab.

## 3. Cấu hình tài nguyên máy ảo

Do máy thật có 8GB RAM, các VM được cấu hình tiết kiệm tài nguyên:

| VM | RAM | CPU |
|---|---:|---:|
| Kali attacker/controller | 1536 MB | 1 core |
| Bot Ubuntu Server | 768 MB | 1 core |
| Victim Ubuntu Server | 768 MB | 1 core |
| IDS Ubuntu Desktop | 2560 MB | 2 cores |

Lý do:

- Kali chỉ cần terminal, SSH và ApacheBench.
- Bot là Ubuntu Server không GUI, chỉ cần SSH và `ab`.
- Victim là Ubuntu Server không GUI, chỉ chạy Apache2.
- IDS nặng nhất vì chạy Ubuntu Desktop, Scapy sensor, Pandas/joblib model, SQLite và Flask dashboard.

## 4. Setup Victim Ubuntu Server

Victim chạy Apache2 và được cấu hình tự khởi động khi bật VM.

Cài và bật Apache2 một lần:

```bash
sudo apt update
sudo apt install -y apache2
sudo systemctl enable --now apache2
```

Kiểm tra khi demo:

```bash
hostname -I
systemctl is-active apache2
```

Kết quả mong muốn:

```text
192.168.247.20
active
```

Từ Kali hoặc Bot kiểm tra Apache:

```bash
curl http://192.168.247.20/
```

## 5. Setup Bot Ubuntu Server

Bot được clone/tạo từ Ubuntu Server và đổi thành:

```text
Hostname: bot-ubuntu
User dùng demo: bot
IP: 192.168.247.11
```

Kiểm tra trên Bot:

```bash
hostname
hostname -I
systemctl is-active ssh
systemctl is-enabled ssh
which ab
```

Kết quả mong muốn:

```text
bot-ubuntu
192.168.247.11
active
enabled
/usr/bin/ab
```

Bot cần cài sẵn:

```bash
sudo apt install -y openssh-server apache2-utils
sudo systemctl enable --now ssh
```

Từ Kali kiểm tra SSH sang Bot:

```bash
ssh bot@192.168.247.11 "hostname"
```

Để demo chạy một lệnh không cần nhập password, Kali đã cấu hình SSH key:

```bash
ssh-keygen
ssh-copy-id bot@192.168.247.11
```

Sau khi cấu hình xong, lệnh sau không hỏi password nữa:

```bash
ssh bot@192.168.247.11 "hostname"
```

## 6. Script tạo HTTP flood traffic

File script dùng cho cả Kali và Bot:

```text
tools/attack_http_flood.sh
```

Cấu hình demo hiện tại:

```bash
DURATION_SECONDS=180
REQUESTS_PER_ROUND=2000
CONCURRENCY=50
SLEEP_SECONDS=2
```

Ý nghĩa:

| Tham số | Ý nghĩa |
|---|---|
| `DURATION_SECONDS=180` | Chạy khoảng 3 phút |
| `REQUESTS_PER_ROUND=2000` | Mỗi vòng gửi tổng cộng 2000 HTTP request |
| `CONCURRENCY=50` | Tối đa 50 request đồng thời |
| `SLEEP_SECONDS=2` | Nghỉ 2 giây giữa các vòng |

Script không tạo dữ liệu giả. Nó gọi ApacheBench `ab` để gửi HTTP request thật tới Victim Apache.

Copy script sang Bot một lần từ Kali:

```bash
scp ~/attack_http_flood.sh bot@192.168.247.11:/home/bot/
ssh bot@192.168.247.11 "chmod +x /home/bot/attack_http_flood.sh"
```

Chạy local trên Kali:

```bash
./attack_http_flood.sh
```

Chạy từ xa trên Bot:

```bash
ssh bot@192.168.247.11 "/home/bot/attack_http_flood.sh"
```

Chạy demo nhiều nguồn bằng một lệnh trên Kali:

```bash
ssh bot@192.168.247.11 "/home/bot/attack_http_flood.sh" & ./attack_http_flood.sh
```

Lệnh trên kích hoạt Bot tấn công Victim ở background, đồng thời Kali cũng chạy script local.

## 7. Setup IDS Ubuntu Desktop

IDS chứa project, model và dashboard.

Di chuyển vào project và kích hoạt venv:

```bash
cd ~/DoAn_IDS_DDoS
source .venv/bin/activate
```

### 7.1. Chạy live sensor

Sensor đã được sửa để nhận nhiều attacker IP bằng tham số `--attacker-ips`.

Chạy sensor trên IDS terminal 1:

```bash
sudo .venv/bin/python src/live_sensor.py --interface ens33 --victim-ip 192.168.247.20 --attacker-ips 192.168.247.10,192.168.247.11 --reset
```

Khi chạy đúng sẽ hiển thị:

```text
Listening on ens33 for victim 192.168.247.20 and attackers 192.168.247.10, 192.168.247.11
Writing realtime flows to /home/tungdo/DoAn_IDS_DDoS/data/live_flows.csv
Press Ctrl+C to stop.
```

Khi traffic chạy, sensor ghi log dạng:

```text
[10:25:18] wrote 250 flows to /home/tungdo/DoAn_IDS_DDoS/data/live_flows.csv
```

Có thể kiểm tra IDS nhìn thấy traffic bằng tcpdump:

```bash
sudo tcpdump -i ens33 host 192.168.247.20
```

Trong thử nghiệm, tcpdump xác nhận IDS thấy cả hai nguồn:

```text
192.168.247.10 -> 192.168.247.20
192.168.247.11 -> 192.168.247.20
```

### 7.2. Chạy dashboard

Chạy dashboard trên IDS terminal 2:

```bash
cd ~/DoAn_IDS_DDoS
source .venv/bin/activate
python dashboard/app.py
```

Máy Windows host mở:

```text
http://192.168.247.30:5000/
```

Dashboard gọi `/api/stats` mỗi 2 giây để lấy dữ liệu mới.

## 8. Quy trình chạy demo chuẩn

Thứ tự khi quay video/demo:

1. Bật Victim VM. Apache2 tự chạy.
2. Bật Bot VM. SSH tự chạy.
3. Bật Kali VM.
4. Bật IDS VM.
5. Show nhanh IP/topology:
   ```bash
   hostname -I
   ```
6. Trên Victim show Apache active:
   ```bash
   systemctl is-active apache2
   ```
7. Trên Bot show SSH/ab sẵn sàng:
   ```bash
   hostname -I
   systemctl is-active ssh
   which ab
   ```
8. Trên IDS chạy sensor multi-attacker.
9. Trên IDS chạy dashboard.
10. Trên dashboard chọn `Random Forest`, bấm `Reset`, sau đó bấm `Start`.
11. Trên Kali chạy lệnh attack nhiều nguồn:
    ```bash
    ssh bot@192.168.247.11 "/home/bot/attack_http_flood.sh" & ./attack_http_flood.sh
    ```
12. Quan sát dashboard hiển thị `DDoS Detected`, flow tăng và Recent Alerts có cả `.10` và `.11`.

Luồng xử lý trong demo:

```text
Kali script + Bot script
-> HTTP request tới Apache victim
-> IDS bắt packet trên ens33
-> live_sensor.py gom packet thành flow
-> ghi flow feature vào data/live_flows.csv
-> dashboard gọi /api/stats mỗi 2 giây
-> FlowDetector đọc tối đa 250 flow mới mỗi lần
-> Random Forest dự đoán BENIGN/DDoS
-> ghi SQLite
-> dashboard hiển thị realtime
```

## 9. Cơ chế flow và feature

Model không phân loại trực tiếp từng HTTP request hoặc packet thô. Model nhận đầu vào là vector đặc trưng số của flow.

Dataset CIC-DDoS2019 dùng để train có dạng:

```text
1 dòng CSV = 1 flow + feature thống kê + Label
```

Trong demo realtime:

```text
request thật -> packet thật -> flow realtime -> 79 feature -> ML prediction
```

`live_sensor.py` load danh sách feature từ:

```text
models/feature_columns.joblib
```

Số feature model sử dụng:

```text
79 feature
```

File `live_flows.csv` có cấu trúc:

```text
Source IP, Source Port, Destination IP, Destination Port, 79 feature, Label
```

Khi predict, các cột định danh như IP/port và `Label` không được đưa vào model. Model chỉ nhận đúng 79 feature đã dùng khi train.

## 10. Cấu hình dashboard realtime

Dashboard cập nhật mỗi 2 giây:

```javascript
setInterval(refreshStats, 2000)
```

Detector đọc tối đa 250 flow mới mỗi lần:

```python
BATCH_SIZE = 250
```

Nghĩa là:

```text
Mỗi 2 giây dashboard xử lý tối đa 250 flow mới
```

Nếu Kali/Bot tạo traffic nhanh hơn tốc độ dashboard đọc, `live_flows.csv` sẽ có backlog. Khi dừng attack, dashboard có thể tiếp tục cập nhật thêm một lúc để đọc nốt flow đã ghi trong file.

## 11. Kết quả demo Random Forest nhiều nguồn

Kết quả chạy thử sau khi thêm Bot:

```text
Model: Random Forest
Status: DDoS Detected
Total Flows: 2,507
DDoS Flows: 45
Benign Flows: 2,462
Last Attack Rate: 1.2%
```

Recent Alerts ghi nhận cả hai nguồn:

```text
192.168.247.11 -> 192.168.247.20
192.168.247.10 -> 192.168.247.20
```

Nhận xét:

- IDS đã bắt được traffic thật từ nhiều source IP.
- Dashboard sinh cảnh báo `DDoS Detected`.
- Random Forest cho tỷ lệ cảnh báo thấp-vừa phải, ổn định hơn cho demo chính.
- Đây là mô phỏng DDoS ở tầng ứng dụng bằng HTTP flood từ nhiều nguồn.

## 12. Kết quả chạy thử LightGBM

Khi chuyển sang LightGBM, dashboard từng ghi nhận tỷ lệ DDoS cao hơn nhiều, ví dụ:

```text
Total Flows: 13,500
DDoS Flows: 10,390
Last Attack Rate: 84.4%
```

Nhận xét:

- LightGBM nhạy hơn trên dữ liệu realtime.
- Kết quả offline giữa Random Forest và LightGBM gần nhau, nhưng realtime feature được trích bằng Scapy có phân phối khác CICFlowMeter.
- Vì vậy demo chính chọn Random Forest, còn LightGBM dùng để so sánh.

## 13. Đánh giá kết quả demo

| Yêu cầu | Trạng thái |
|---|---|
| Có môi trường mạng mô phỏng nhiều máy | Đạt |
| Có nhiều nguồn tấn công vào cùng victim | Đạt |
| Kali điều khiển Bot qua SSH | Đạt |
| Bot và Kali cùng tạo HTTP traffic thật | Đạt |
| Victim chạy Apache2 | Đạt |
| IDS bắt traffic thật trên interface mạng | Đạt |
| Sensor sinh flow realtime | Đạt |
| Model nhận đúng 79 feature | Đạt |
| Dashboard cập nhật realtime | Đạt |
| Có cảnh báo DDoS và IP nguồn/đích | Đạt |
| Có thể chọn Random Forest hoặc LightGBM | Đạt |

Kết luận demo:

```text
Hệ thống đã thử nghiệm thành công pipeline IDS realtime trong môi trường mạng VM lab. Kali attacker và Bot Ubuntu Server đồng thời tạo HTTP flood traffic thật tới Ubuntu Server victim chạy Apache2. IDS Ubuntu Desktop bắt traffic trên interface ens33, tổng hợp packet thành flow, trích xuất 79 đặc trưng tương thích với bộ feature huấn luyện, đưa vào mô hình Random Forest và hiển thị cảnh báo DDoS trên dashboard theo thời gian thực.
```

## 14. Hạn chế và hướng phát triển

Hạn chế hiện tại:

- Botnet trong demo là bot giả lập điều khiển qua SSH, không triển khai mã độc thật.
- Số lượng nguồn tấn công hiện tại là 2 nguồn: Kali và 1 Bot.
- Feature realtime được trích bằng Scapy, chưa hoàn toàn giống CICFlowMeter.
- Một số feature phức tạp của CICFlowMeter có thể được xấp xỉ hoặc gán giá trị mặc định.
- LightGBM cho tỷ lệ DDoS rất cao trên realtime traffic, cho thấy có hiện tượng lệch phân phối giữa dữ liệu train/test và dữ liệu realtime.
- Dashboard đọc tối đa 250 flow mỗi 2 giây, nên khi traffic sinh quá nhanh có thể xuất hiện backlog.

Hướng phát triển:

- Tăng số bot hoặc dùng thêm VM/container có IP riêng để mô phỏng DDoS nhiều nguồn hơn.
- Tích hợp CICFlowMeter, Zeek hoặc tshark để trích xuất feature chuẩn hơn.
- Bổ sung đánh giá cùng một `live_flows.csv` trên nhiều model để so sánh công bằng.
- Thêm thống kê realtime về throughput, số request, số flow mỗi giây và số source IP.
- Thêm chức năng export log demo ra CSV/PDF.
- Tối ưu dashboard để hiển thị rõ topology, attacker IP, bot IP, victim IP và interface IDS.

## 15. Câu thuyết minh ngắn khi demo

Có thể trình bày như sau:

```text
Trong demo này, hệ thống sử dụng nhiều nguồn tấn công gồm Kali attacker và một máy Bot Ubuntu Server. Bot không phải mã độc thật mà là máy giả lập botnet được Kali điều khiển qua SSH trong môi trường lab. Cả Kali và Bot đồng thời gửi HTTP request thật tới Ubuntu Server victim chạy Apache2. IDS Ubuntu Desktop bắt lưu lượng trên interface ens33, gom packet thành flow và trích xuất 79 đặc trưng thống kê tương thích với bộ feature đã huấn luyện từ CIC-DDoS2019. Các flow realtime được đưa vào mô hình Random Forest để phân loại BENIGN hoặc DDoS. Kết quả được lưu vào SQLite và hiển thị trên dashboard theo thời gian thực. Khi traffic bất thường xuất hiện, dashboard sinh cảnh báo DDoS Detected với địa chỉ nguồn 192.168.247.10 hoặc 192.168.247.11 và đích 192.168.247.20.
```