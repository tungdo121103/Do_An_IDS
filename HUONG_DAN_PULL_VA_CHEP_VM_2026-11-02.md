# Hướng dẫn pull GitHub và chép project lên các VM — 02/11/2026

Tài liệu này dành cho thành viên đã dựng bốn VM trong mạng lab và chỉ cần lấy bản project mới nhất để chạy demo. Repo không chứa VM, `.venv` hoặc dataset lớn. Không chép file token, mật khẩu hoặc `VM_CREDENTIALS.md` lên GitHub.

## 1. Sơ đồ lab mẫu

| Máy | Tài khoản/IP mẫu | Vai trò |
| --- | --- | --- |
| Kali | `kali@192.168.247.10` | Tạo lưu lượng SSH và HTTP flood |
| Bot | `bot@192.168.247.11` | Nguồn HTTP flood thứ hai |
| Victim | `victim@192.168.247.20` | OpenSSH cổng 22 và Apache2 cổng 80 |
| IDS | `tungdo@192.168.247.30` | Sensor, hai model và dashboard |

Bốn VM phải nằm trong cùng mạng lab, ví dụ `192.168.247.0/24`, không trùng IP. Nếu máy mới dùng subnet hoặc tên card khác, thay toàn bộ IP và `ens33` trong các lệnh dưới bằng giá trị thực tế. Kiểm tra bằng:

```bash
ip -br addr
```

## 2. Clone hoặc pull repo trên Windows

Repo đang để private nên tài khoản GitHub của thành viên phải chấp nhận lời mời cộng tác trước.

Clone lần đầu trong PowerShell:

```powershell
cd D:\
git clone https://github.com/tungdo121103/Do_An_IDS.git DoAn_IDS_DDoS
cd D:\DoAn_IDS_DDoS
git status
```

Nếu đã clone rồi:

```powershell
cd D:\DoAn_IDS_DDoS
git pull origin main
```

Kiểm tra phải có các thư mục `src`, `dashboard`, `tools`, `models/ddos_v2` và `models/ssh_v1_artifacts`.

## 3. Cài công cụ một lần trên các VM

Victim:

```bash
sudo apt update
sudo apt install -y apache2 openssh-server python3
sudo systemctl enable --now apache2 ssh
```

Kali:

```bash
sudo apt update
sudo apt install -y hydra apache2-utils openssh-client openssh-server curl netcat-openbsd
sudo systemctl enable --now ssh
```

Bot:

```bash
sudo apt update
sudo apt install -y apache2-utils openssh-server
sudo systemctl enable --now ssh
```

IDS:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip openssh-server tcpdump
sudo systemctl enable --now ssh
mkdir -p ~/DoAn_IDS_DDoS/{src,dashboard/templates,dashboard/static,models,data}
cd ~/DoAn_IDS_DDoS
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install flask scapy pandas numpy joblib 'scikit-learn==1.6.1' lightgbm
```

## 4. Chép đúng file từ Windows sang từng VM

Chạy toàn bộ lệnh trong mục này bằng PowerShell tại `D:\DoAn_IDS_DDoS`.

### IDS

```powershell
cd D:\DoAn_IDS_DDoS
ssh tungdo@192.168.247.30 "mkdir -p /home/tungdo/DoAn_IDS_DDoS/src /home/tungdo/DoAn_IDS_DDoS/dashboard/templates /home/tungdo/DoAn_IDS_DDoS/dashboard/static /home/tungdo/DoAn_IDS_DDoS/models /home/tungdo/DoAn_IDS_DDoS/data"
scp .\src\live_sensor.py .\src\realtime_detect.py tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/src/
scp .\dashboard\app.py tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/dashboard/
scp .\dashboard\templates\detector.html tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/dashboard/templates/
scp .\dashboard\static\detector.js .\dashboard\static\style.css tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/dashboard/static/
scp -r .\models\ddos_v2 .\models\ssh_v1_artifacts tungdo@192.168.247.30:/home/tungdo/DoAn_IDS_DDoS/models/
```

### Kali

```powershell
scp .\tools\attack_http_flood.sh .\tools\ssh_bruteforce_lab.sh .\tools\ssh_lab_passwords.txt kali@192.168.247.10:/home/kali/
```

### Bot

```powershell
scp .\tools\attack_http_flood.sh bot@192.168.247.11:/home/bot/
```

### Victim

```powershell
scp .\tools\ssh_auth_agent.py victim@192.168.247.20:/home/victim/
```

Không chép `data/live_flows.csv` hoặc `data/ids_logs.db` từ máy khác. Đây là dữ liệu runtime và sẽ được tạo trên IDS.

## 5. Chạy IDS

Terminal 1 trên IDS, dùng đúng tên card mạng lab:

```bash
cd ~/DoAn_IDS_DDoS
sudo .venv/bin/python src/live_sensor.py --interface ens33 --victim-ip 192.168.247.20 --attacker-ips 192.168.247.10,192.168.247.11 --reset
```

Terminal 2 trên IDS. Token có thể tự đặt trong lab nhưng phải giống hệt token trên Victim:

```bash
cd ~/DoAn_IDS_DDoS
export IDS_SSH_AUTH_TOKEN=idsdemo123
.venv/bin/python dashboard/app.py
```

Mở:

- DDoS: `http://192.168.247.30:5000/ddos`
- SSH: `http://192.168.247.30:5000/ssh`

## 6. Chạy nguồn log SSH trên Victim

Chạy trước bài SSH trên Kali và giữ terminal mở:

```bash
export IDS_SSH_AUTH_TOKEN=idsdemo123
sudo --preserve-env=IDS_SSH_AUTH_TOKEN python3 /home/victim/ssh_auth_agent.py --ids-url http://192.168.247.30:5000/api/ssh-auth-event
```

Nếu báo HTTP 401 thì token trên IDS và Victim không giống nhau. Agent hoạt động đúng sẽ hiện `Watching new SSH password failures...` và in nguồn IP khi có lần đăng nhập sai mới.

## 7. Demo SSH — tối đa 50 mật khẩu

Trên trang SSH chọn model, bấm Reset rồi Start IDS. Trên Kali chạy một vòng:

```bash
bash /home/kali/ssh_bruteforce_lab.sh 192.168.247.20 victim /home/kali/ssh_lab_passwords.txt --rounds 1
```

Chờ thêm khoảng 15–20 giây để sensor kết thúc các flow. Biểu đồ trên lấy số lần sai mật khẩu từ log Victim; biểu đồ dưới là phân loại flow TCP/22 của model. Tỷ lệ flow bị đánh dấu không phải độ chính xác của model.

## 8. Demo HTTP flood hai nguồn

Thiết lập SSH key từ Kali sang Bot một lần:

```bash
ssh-keygen -t ed25519
ssh-copy-id bot@192.168.247.11
ssh -o BatchMode=yes bot@192.168.247.11 hostname
```

Trên trang DDoS chọn model, bấm Reset rồi Start IDS. Trên Kali chạy:

```bash
bash /home/kali/attack_http_flood.sh --with-bot
```

`Ctrl+C` trên Kali sẽ yêu cầu dừng cả tiến trình Kali và Bot. Chỉ chạy trong mạng lab được phép.

## 9. Kiểm tra nhanh khi không có dữ liệu

```bash
# Victim
systemctl is-active ssh apache2
sudo ss -ltnp | grep -E ':22|:80'

# Kali
nc -vz 192.168.247.20 22
curl -I http://192.168.247.20/

# IDS
ip -br addr
sudo tcpdump -ni ens33 host 192.168.247.20
```

Nếu đổi IP/subnet, phải thay IP trong lệnh sensor, URL dashboard, URL agent, lệnh SSH và script HTTP flood. IDS không cần làm gateway; nó chỉ cần quan sát được traffic của mạng lab.
