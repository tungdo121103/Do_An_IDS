# Chạy hệ thống IDS kết hợp DDoS và SSH

## Kiến trúc

`live_sensor.py` trên IDS VM bắt packet giữa attacker và Victim, xuất một file flow chung `data/live_flows.csv` với 46 feature. `realtime_detect.py` dùng `Protocol` và `Destination Port` để định tuyến:

- TCP tới cổng 22 → model SSH Brute Force với 45 feature.
- Các flow khác → model DDoS với 46 feature.

Sensor giữ TCP/22 theo **cả kết nối** và ghi flow khi thấy RST, hai phía đã FIN, hoặc 10 giây không có packet; các flow khác vẫn ghi theo cửa sổ 2 giây. Vì vậy một lượt thử SSH có thể xuất hiện trên dashboard trễ vài giây, và số flow không bằng số lần thử mật khẩu.

Với TCP/22, các feature độ dài gói/byte được tính từ TCP payload (gói không có payload có độ dài 0) để gần với dữ liệu SSH dùng train. Các flow khác, bao gồm HTTP/UDP cho DDoS, vẫn dùng độ dài gói cũ; model và cách gom flow DDoS không đổi. Điều này chỉ xử lý một phần sai lệch feature, không bảo đảm model SSH sẽ cảnh báo traffic lab.

Dropdown trên dashboard chọn Random Forest hoặc LightGBM cho cả hai nhánh. Dashboard thống kê DDoS, SSH Brute Force và BENIGN riêng.

## Triển khai từ Windows sang IDS VM

Chỉ đồng bộ các thành phần **chạy trên IDS**: sensor, detector, dashboard và hai bộ model. Không chép đè cả project vì `data/live_flows.csv`, `data/ids_logs.db`, `.venv` và các dữ liệu/runtime trên VM phải được giữ nguyên. Các script tạo lưu lượng SSH sẽ chép sang Kali ở bước kiểm thử riêng.

Chạy trong PowerShell từ `D:\DoAn_IDS_DDoS` khi IDS VM đã bật và SSH tới `192.168.247.30` hoạt động:

```powershell
scp -r .\models\ddos_v2 tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/models/
scp -r .\models\ssh_v1_artifacts tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/models/
scp .\src\live_sensor.py tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/src/
scp .\src\realtime_detect.py tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/src/
scp .\dashboard\app.py tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/dashboard/
scp .\dashboard\templates\index.html tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/dashboard/templates/
scp .\dashboard\static\app.js tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/dashboard/static/
scp .\dashboard\static\style.css tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/dashboard/static/
```

Sensor local đã dùng manifest DDoS v2 để xuất đủ 46 feature và giữ `Destination Port`, nên khi cập nhật một IDS VM có bản code cũ phải chép cả `live_sensor.py` cùng model DDoS v2. Trên IDS VM kiểm tra hai bộ model và cú pháp Python:

```bash
ls -lh ~/DoAn_IDS_DDoS/models/ssh_v1_artifacts/
ls -lh ~/DoAn_IDS_DDoS/models/ddos_v2/
cd ~/DoAn_IDS_DDoS
.venv/bin/python -m py_compile src/live_sensor.py src/realtime_detect.py dashboard/app.py
```

## Chạy IDS

Terminal 1 trên IDS:

```bash
cd ~/DoAn_IDS_DDoS
sudo .venv/bin/python src/live_sensor.py --interface ens33 --victim-ip 192.168.247.20 --attacker-ips 192.168.247.10,192.168.247.11 --reset
```

Terminal 2 trên IDS:

```bash
cd ~/DoAn_IDS_DDoS
.venv/bin/python dashboard/app.py
```

Mở `http://192.168.247.30:5000/` từ Windows và bấm `Start`. Nút `Reset` xóa các dòng `flow_logs` trong SQLite **và** làm trống `data/live_flows.csv`; chỉ dùng nếu chủ ý xóa kết quả demo cũ. Khi chạy lại sensor với `--reset`, hãy khởi động lại dashboard để đưa offset đọc CSV về 0, thay vì bấm `Reset` nếu muốn giữ log cũ.

## Chuẩn bị SSH trên Victim

Trên Victim kiểm tra SSH lắng nghe cổng 22:

```bash
systemctl is-active ssh
sudo ss -ltnp | grep ':22'
```

Từ Kali kiểm tra một kết nối SSH hợp lệ tới `192.168.247.20`. Sau đó mới chạy kịch bản SSH Brute Force có giới hạn trong mạng lab. Bot không bắt buộc cho bài SSH; Bot dùng cho HTTP Flood nhiều nguồn.

Để chạy HTTP Flood hai nguồn có thể dừng đồng thời, cập nhật **một file** `tools/attack_http_flood.sh` trên cả Kali và Bot. Trên Windows PowerShell trong `D:\DoAn_IDS_DDoS`:

```powershell
scp .\tools\attack_http_flood.sh kali@192.168.247.10:/home/kali/
```

Sau đó trên **terminal Kali** (`kali@kali`), không phải Bot hoặc Victim:

```bash
scp /home/kali/attack_http_flood.sh bot@192.168.247.11:/home/bot/
bash /home/kali/attack_http_flood.sh --with-bot
```

Lệnh thứ nhất cập nhật Bot; lệnh thứ hai khởi động cả Kali và Bot. Script mặc định chạy 180 giây; `Ctrl+C` trong terminal Kali sẽ dừng cả hai phía. Cần SSH key từ Kali sang Bot. Không dùng lệnh `ssh bot ... & bash ...` cũ vì tiến trình Bot có thể tiếp tục chạy nền.

## Kiểm tra kết quả

1. Lưu lượng bình thường: `Benign Flows` tăng, hai bộ đếm tấn công không tăng.
2. HTTP Flood: `DDoS Flows` và cảnh báo DDoS tăng.
3. SSH tới TCP/22: flow được đưa tới model SSH; nếu model dự đoán lớp 1 thì `SSH Brute Force Flows` và cảnh báo SSH tăng.
4. Chuyển thuật toán trên dropdown và lặp lại bài test nếu cần so sánh Random Forest/LightGBM.

Kết quả train/test offline cao không bảo đảm traffic VM được nhận diện tương tự. Nếu SSH live không có cảnh báo, lưu ảnh/số liệu thực tế và kiểm tra `data/live_flows.csv`, đặc biệt cột `Destination Port` và các feature 45 cột theo manifest; không tự sửa nhãn dự đoán để ép demo.
