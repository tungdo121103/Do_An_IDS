# Chạy hệ thống IDS kết hợp DDoS và SSH

> Runbook vận hành lab hiện tại. Để hiểu mục tiêu, phần chung/riêng và cách trả lời khi demo, xem [tài liệu demo ngày 19/10/2026](DEMO_DO_AN_2026-10-19.md). Kết quả model offline nằm trong [báo cáo DDoS](TRAINING_REPORT_DDOS.md) và [báo cáo SSH](SSH_TRAINING_REPORT.md).

## Điều kiện trước khi chạy

| Máy | IP lab | Cần có |
| --- | --- | --- |
| Kali | `192.168.247.10` | `hydra`, `ab` (gói `apache2-utils`), script SSH/HTTP flood |
| Bot giả lập | `192.168.247.11` | SSH server, `ab`, cùng bản `attack_http_flood.sh` với Kali |
| Victim | `192.168.247.20` | Apache2 cổng 80, OpenSSH cổng 22, Python 3 để chạy agent đọc log SSH |
| IDS | `192.168.247.30` | Project, `.venv` với Scapy/Flask/pandas/joblib/scikit-learn/LightGBM, hai cặp model và manifest |

Các IP, user `tungdo`/`victim`/`bot` và card `ens33` dưới đây là **giá trị của lab hiện tại**, không tự đúng trên máy mới. Xác nhận bằng `ip -br addr`; dùng `curl -I http://192.168.247.20/` từ Kali và kiểm tra `systemctl is-active apache2`, `systemctl is-active ssh` trên Victim. IDS quan sát thụ động trên mạng lab; **không cần** làm gateway/router. Chỉ thực hiện kịch bản traffic với các VM/tài khoản được phép.

Nếu cài lại VM: trên Victim cần `apache2` và `openssh-server`; trên Bot cần `openssh-server` và `apache2-utils`; Kali cần Hydra, `apache2-utils` và SSH client. Kali phải SSH sang Bot bằng key không hỏi mật khẩu để chế độ `--with-bot` chạy được. Không có file dependency Python đã khóa phiên bản trong repo, nên khi dựng IDS mới phải tự kiểm tra/cài đúng các thư viện và tương thích phiên bản model; không copy `.venv` giữa hai máy rồi mặc định sẽ hoạt động.

Ví dụ setup **trên các VM lab mới** (bỏ qua phần đã cài; không ghi đè SSH key đang dùng):

```bash
# Victim
sudo apt install -y apache2 openssh-server
sudo systemctl enable --now apache2 ssh

# Bot
sudo apt install -y openssh-server apache2-utils
sudo systemctl enable --now ssh

# Kali: chỉ chạy nếu chưa có SSH key để vào Bot
ssh-keygen
ssh-copy-id bot@192.168.247.11
ssh -o BatchMode=yes bot@192.168.247.11 hostname
```

Các đoạn trên chạy trên **máy được ghi ở dòng chú thích**, không copy cả block vào một terminal. Khi clone repo sang máy khác, đường dẫn dataset lớn và `.venv` sẽ không có; demo chỉ cần model artifact đã commit, môi trường Python tương thích và script traffic trên đúng VM.

Cấu hình VM đã từng dùng trên host 8 GB RAM (tham khảo, không phải yêu cầu tối thiểu đã đo): Kali 1.536 MB/1 core; Bot 768 MB/1 core; Victim 768 MB/1 core; IDS Desktop 2.560 MB/2 cores. Các bài SYN/UDP flood trong `tools/` chỉ là thử nghiệm mở rộng: sensor có thể thấy packet, nhưng model DDoS v2 chưa được chứng minh nhận diện ổn định các flow live này. Kịch bản chính là HTTP flood.

## Kiến trúc

`live_sensor.py` trên IDS VM bắt packet giữa attacker và Victim, xuất một file flow chung `data/live_flows.csv` với 46 feature. `realtime_detect.py` dùng `Protocol` và `Destination Port` để định tuyến:

- TCP tới cổng 22 → model SSH Brute Force với 45 feature.
- Các flow khác → model DDoS với 46 feature.

Sensor giữ TCP/22 theo **cả kết nối** và ghi flow khi thấy RST, hai phía đã FIN, hoặc 10 giây không có packet; các flow khác vẫn ghi theo cửa sổ 2 giây. Vì vậy một lượt thử SSH có thể xuất hiện trên dashboard trễ vài giây, và số flow không bằng số lần thử mật khẩu.

Với TCP/22, các feature độ dài gói/byte được tính từ TCP payload (gói không có payload có độ dài 0) để gần với dữ liệu SSH dùng train. Các flow khác, bao gồm HTTP/UDP cho DDoS, vẫn dùng độ dài gói cũ; model và cách gom flow DDoS không đổi. Điều này chỉ xử lý một phần sai lệch feature, không bảo đảm model SSH sẽ cảnh báo traffic lab.

Dashboard có hai trang thật: `/ddos` chỉ hiển thị flow và cảnh báo DDoS; `/ssh` chỉ hiển thị dữ liệu đăng nhập SSH và kết quả model SSH. Mỗi trang chọn Random Forest hoặc LightGBM riêng. Bộ chọn trên trang này không đổi model của trang kia. Nút Start IDS/Pause IDS điều khiển chung tiến trình đọc flow của IDS; nút Reset chỉ xóa kết quả model đang chọn trên trang hiện tại. Reset SSH còn xóa các sự kiện log SSH; Reset DDoS không xóa log SSH. Reset theo trang không làm trống `data/live_flows.csv`. Trước mỗi lượt demo của cùng model, bấm Reset trên đúng trang nếu muốn bộ đếm bắt đầu từ 0.

Trang **SSH** hiển thị số dòng `Failed password` lấy trực tiếp từ journal trên Victim, biểu đồ theo các khoảng 10 giây, nguồn IP và số lần thất bại, số SSH flow được model đánh dấu trên tổng SSH flow. Agent `tools/ssh_auth_agent.py` chạy trên Victim và gửi IP/cổng nguồn tới dashboard IDS; agent không gửi mật khẩu hoặc username. Dashboard cảnh báo **Repeated SSH password failures in Victim log** khi cùng một IP có ít nhất 10 lần thất bại trong 60 giây. Đây là tín hiệu từ log, khác với cảnh báo của model. Tỷ lệ flow được đánh dấu không phải độ chính xác của model. SSH mã hóa nên IDS không thể tự đếm chính xác mật khẩu chỉ từ packet. Nếu agent chưa chạy, bộ đếm log sẽ không có dữ liệu; mô hình flow vẫn hoạt động như trước.

## Triển khai từ Windows sang IDS và Victim VM

Chỉ đồng bộ sensor, detector, dashboard và hai bộ model sang **IDS**; chép thêm `ssh_auth_agent.py` sang **Victim** để đọc log SSH. Không chép đè cả project vì `data/live_flows.csv`, `data/ids_logs.db`, `.venv` và các dữ liệu/runtime trên VM phải được giữ nguyên. Các script tạo lưu lượng SSH sẽ chép sang Kali ở bước kiểm thử riêng.

Chạy trong PowerShell từ `D:\DoAn_IDS_DDoS` khi IDS/Victim đã bật và SSH tới `192.168.247.30`/`192.168.247.20` hoạt động:

```powershell
scp -r .\models\ddos_v2 tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/models/
scp -r .\models\ssh_v1_artifacts tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/models/
scp .\src\live_sensor.py tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/src/
scp .\src\realtime_detect.py tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/src/
scp .\dashboard\app.py tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/dashboard/
scp .\dashboard\static\style.css tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/dashboard/static/
scp .\dashboard\templates\detector.html tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/dashboard/templates/
scp .\dashboard\static\detector.js tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/dashboard/static/
scp .\tools\ssh_auth_agent.py victim@192.168.247.20:/home/victim/
```

Sensor local đã dùng manifest DDoS v2 để xuất đủ 46 feature và giữ `Destination Port`, nên khi cập nhật một IDS VM có bản code cũ phải chép cả `live_sensor.py` cùng model DDoS v2. Trên IDS VM kiểm tra hai bộ model và cú pháp Python:

```bash
ls -lh ~/DoAn_IDS_DDoS/models/ssh_v1_artifacts/
ls -lh ~/DoAn_IDS_DDoS/models/ddos_v2/
cd ~/DoAn_IDS_DDoS
.venv/bin/python -m py_compile src/live_sensor.py src/realtime_detect.py dashboard/app.py
```

## Chạy IDS và nguồn log SSH

Tạo một token ngẫu nhiên **một lần** bằng `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`. Dùng **cùng một giá trị** trong terminal dashboard IDS và terminal agent Victim; không ghi token vào repo/Git. Khi dán lệnh, thay `TOKEN_CUA_BAN` bằng giá trị vừa tạo.

Terminal 1 trên IDS:

```bash
cd ~/DoAn_IDS_DDoS
sudo .venv/bin/python src/live_sensor.py --interface ens33 --victim-ip 192.168.247.20 --attacker-ips 192.168.247.10,192.168.247.11 --reset
```

Terminal 2 trên IDS:

```bash
cd ~/DoAn_IDS_DDoS
export IDS_SSH_AUTH_TOKEN='TOKEN_CUA_BAN'
.venv/bin/python dashboard/app.py
```

Terminal trên **Victim**, chạy trước khi bắt đầu thử SSH trên Kali:

```bash
export IDS_SSH_AUTH_TOKEN='TOKEN_CUA_BAN'
sudo --preserve-env=IDS_SSH_AUTH_TOKEN python3 /home/victim/ssh_auth_agent.py --ids-url http://192.168.247.30:5000/api/ssh-auth-event
```

Giữ cả ba terminal trên IDS/Victim mở. Agent chỉ theo dõi **dòng log mới** sau khi khởi động, vì vậy hãy chạy nó trước script Hydra. `Ctrl+C` dừng agent. Nếu token hai bên không khớp, agent báo HTTP 401; nếu dashboard chưa chạy, agent sẽ đợi và thử gửi lại sự kiện hiện tại.

Mở `http://192.168.247.30:5000/ddos` để xem DDoS hoặc `http://192.168.247.30:5000/ssh` để xem SSH, rồi bấm `Start`. URL `/` chuyển sang trang DDoS. Trang SSH cho biết số lần nhập sai trong log Victim, số kết nối SSH sensor ghi được và số flow được ML đánh dấu. Cảnh báo log gần nhất được giữ trên màn hình sau khi bài thử kết thúc. Reset trên trang chỉ xóa kết quả của nhánh và model đang chọn; nếu Reset SSH thì các sự kiện log SSH cũng được xóa. Khi chạy lại sensor với `--reset`, hãy khởi động lại dashboard để đưa offset đọc CSV về 0.

## Chuẩn bị SSH trên Victim

Trên Victim kiểm tra SSH lắng nghe cổng 22:

```bash
systemctl is-active ssh
sudo ss -ltnp | grep ':22'
```

Từ Kali kiểm tra một kết nối SSH hợp lệ tới `192.168.247.20`. Sau đó mới chạy kịch bản SSH Brute Force có giới hạn trong mạng lab. Bot không bắt buộc cho bài SSH; Bot dùng cho HTTP Flood nhiều nguồn.

Nếu Kali chưa có script và danh sách password, từ Windows PowerShell trong `D:\DoAn_IDS_DDoS` chép hai file:

```powershell
scp .\tools\ssh_bruteforce_lab.sh .\tools\ssh_lab_passwords.txt kali@192.168.247.10:/home/kali/
```

Trên **Kali** chạy (chỉ trong lab được phép):

```bash
bash /home/kali/ssh_bruteforce_lab.sh 192.168.247.20 victim /home/kali/ssh_lab_passwords.txt --rounds 1
```

Demo chính dùng `--rounds 1`, tối đa 50 password và 2 tác vụ song song. Script vẫn hỗ trợ `--rounds 1` đến `--rounds 5` cho thử nghiệm có kiểm soát, nhưng tăng số vòng không bảo đảm model đánh dấu nhiều flow hơn. `Ctrl+C` dừng sớm. Không tìm được password đúng là kết quả bình thường của danh sách thử sai. Sensor ghi **flow mạng**, không ghi từng lần thử password; có thể cần chờ FIN/RST hoặc idle timeout 10 giây mới thấy flow trên dashboard.

## Chạy HTTP flood hai nguồn

Để chạy HTTP Flood hai nguồn có thể dừng đồng thời, cập nhật **một file** `tools/attack_http_flood.sh` trên cả Kali và Bot. Victim cần Apache2 đang chạy; Kali/Bot cần `ab`. Trên Windows PowerShell trong `D:\DoAn_IDS_DDoS`:

```powershell
scp .\tools\attack_http_flood.sh kali@192.168.247.10:/home/kali/
```

Sau đó trên **terminal Kali** (`kali@kali`), không phải Bot hoặc Victim:

```bash
scp /home/kali/attack_http_flood.sh bot@192.168.247.11:/home/bot/
DURATION_SECONDS=60 bash /home/kali/attack_http_flood.sh --with-bot
```

Lệnh thứ nhất cập nhật Bot; lệnh thứ hai khởi động cả Kali và Bot. Script mặc định chạy tối đa 60 giây, mỗi vòng 2.000 request, concurrency 50, nghỉ 2 giây; giới hạn cứng sẽ dừng lượt `ab` đang chạy khi hết giờ và `Ctrl+C` trong terminal Kali có thể dừng sớm cả hai phía. Cần SSH key từ Kali sang Bot. Không dùng lệnh `ssh bot ... & bash ...` cũ vì tiến trình Bot có thể tiếp tục chạy nền.

## Kiểm tra kết quả

1. Lưu lượng bình thường: kỳ vọng `Benign Flows` tăng; đây là dự đoán, vẫn có thể có false positive.
2. HTTP Flood: quan sát `DDoS Flows` và cảnh báo DDoS; tổng flow có thể tăng nhanh và không đồng nghĩa tổng request.
3. SSH tới TCP/22: flow được đưa tới model SSH; nếu model dự đoán lớp 1 thì `SSH Brute Force Flows` và cảnh báo ML tăng. Một lần thử 50 password có thể chỉ sinh ít flow. Tab SSH đồng thời đếm `Failed password` từ Victim và hiển thị tín hiệu lặp lại 10 lần/60 giây nếu agent đang chạy. Nếu log báo nhiều thất bại mà ML vẫn báo 0, hãy trình bày đó là lần mô hình bỏ sót; không gọi tín hiệu log là dự đoán của mô hình.
4. Chuyển thuật toán trên dropdown và lặp lại bài test nếu cần so sánh Random Forest/LightGBM.

Kết quả train/test offline cao không bảo đảm traffic VM được nhận diện tương tự. Lần thử live SSH đã lưu tại `reports/ssh_live_flows_50_attempts.csv` cho 12 flow: Random Forest dự đoán 1 SSH/11 BENIGN, LightGBM 0 SSH/12 BENIGN. Vì vậy chọn Random Forest cho bài SSH demo chính và nói rõ giới hạn LightGBM live. Nếu SSH live không có cảnh báo, lưu ảnh/số liệu thực tế và kiểm tra `data/live_flows.csv`, đặc biệt cột `Destination Port` và các feature 45 cột theo manifest; không tự sửa nhãn dự đoán để ép demo. Dashboard hỏi dữ liệu mỗi 2 giây và đọc tối đa 250 flow mới mỗi lần; sau khi dừng script, số liệu vẫn có thể tăng do backlog. `Last batch DDoS rate` là tỷ lệ của lô DDoS mới nhất; `ML flagged / SSH flows` là tỷ lệ cộng dồn cho model SSH đang chọn, không phải độ chính xác.
