# Biên bản demo IDS cuối trước giai đoạn viết báo cáo — DDoS 27/10, SSH đến 04/11/2026

> Trạng thái: đã ghi hai ảnh DDoS ngày 27/10, các ảnh SSH ngày 02/11 và hai ảnh xác nhận SSH Random Forest/LightGBM ngày 04/11/2026. Đường gửi log từ Victim đã hoạt động trong phiên 04/11. Các số dưới đây là số hiển thị trên dashboard, không phải nhãn đúng của từng flow.

## 1. Mục đích và phạm vi

Buổi này là lần chạy demo cuối của hệ thống IDS trong mạng máy ảo trước khi chuyển trọng tâm sang viết báo cáo đồ án. Hai kịch bản cần ghi nhận riêng là **HTTP flood từ Kali và Bot** và **thử mật khẩu SSH từ Kali**. Mục đích là xác nhận chương trình chạy với lưu lượng thật trong lab, ghi lại số liệu và cảnh báo thực tế, đồng thời nêu các giới hạn còn tồn tại. Không coi một buổi demo là phép đo khả năng hoạt động trên Internet hoặc tỷ lệ phát hiện tổng quát.

## 2. Sơ đồ và cách hệ thống hoạt động

| Máy | Địa chỉ trong lab | Vai trò |
| --- | --- | --- |
| Kali | `192.168.247.10` | Tạo HTTP flood; riêng bài SSH dùng Hydra |
| Bot | `192.168.247.11` | Nguồn HTTP flood thứ hai do Kali điều khiển |
| Victim | `192.168.247.20` | Apache2 cổng 80 và SSH cổng 22 |
| IDS | `192.168.247.30` | Sensor `ens33`, suy luận model, lưu log và dashboard |

Sensor `src/live_sensor.py` bắt gói giữa các nguồn đã khai báo và Victim, gom thành flow rồi ghi `data/live_flows.csv`. Detector `src/realtime_detect.py` đưa TCP đích cổng 22 sang model SSH; các flow còn lại sang model DDoS. Dropdown trên dashboard chọn Random Forest hoặc LightGBM cho cả hai nhánh, nhưng mỗi nhánh dùng model đã huấn luyện riêng. Dashboard đọc các kết quả đã lưu và hiển thị tổng flow, số flow được phân loại, lịch sử và cảnh báo.

## 3. Kịch bản HTTP flood/DDoS

Trên Kali chạy `bash /home/kali/attack_http_flood.sh --with-bot`. Script điều khiển cả Kali và Bot gửi HTTP request tới Apache2 trên Victim. Cấu hình hiện tại của mỗi máy là tối đa **60 giây**, **2.000 request mỗi vòng**, **50 kết nối đồng thời** và nghỉ **2 giây** giữa các vòng. `Ctrl+C` ở Kali dừng phiên trên cả hai máy; cơ chế timeout cũng dừng tiến trình khi đủ thời lượng. Đây là bài **HTTP flood hai nguồn trong lab**; nó minh họa đặc điểm nhiều nguồn của DDoS, không phải botnet thật hoặc phép thử khả năng chịu tải Internet của Victim.

Model DDoS dự đoán từng **flow** dựa trên 46 đặc trưng. IP nguồn và cổng đích được dùng để định tuyến/hiển thị, không phải số lượng máy tham gia được đưa trực tiếp vào dự đoán. Vì vậy tăng số nguồn không tự bảo đảm tỷ lệ phát hiện tăng hoặc giống lần demo này. Nếu model đánh dấu ít nhất một flow DDoS trong một lô, dashboard ghi cảnh báo cho lô đó; mức `HIGH` khi ít nhất 70% flow trong lô/nhánh đó bị đánh dấu, còn có dương tính nhưng dưới ngưỡng này là `MEDIUM`. Đây là mức cảnh báo theo **tỷ lệ dự đoán trong lô**, không phải đánh giá chắc chắn rằng Victim đã mất khả năng phục vụ.

`DDoS Flows` là số flow được model dự đoán là DDoS. `Benign Flows` là số flow được dự đoán bình thường. `Last Attack Rate` = số flow được dự đoán tấn công chia cho tổng flow **của lô/nhánh xử lý mới nhất**; nó không phải tỷ lệ HTTP request độc hại, cũng không phải tỷ lệ cả buổi. Sau khi flood dừng, `Last Attack Rate` có thể về 0% trong khi tổng `DDoS Flows` vẫn giữ nguyên.

### Kết quả thực tế của phiên cuối

Hai ảnh đều chụp dashboard ở trạng thái `Paused`. Ảnh không cho biết số request Apache nhận thành công, thời điểm bắt đầu/dừng script, hoặc các flow có được gán nhãn đúng độc lập hay không. Số tổng trên dashboard có thể là cộng dồn trong từng phiên kể từ lần reset tương ứng; ảnh không đủ để xác nhận hai model được chạy trên cùng một tập flow.

| Chỉ số trên dashboard | Random Forest | LightGBM |
| --- | ---: | ---: |
| Tổng flow | 45.927 | 45.000 |
| Flow **được model dự đoán** DDoS | 867 | 5.665 |
| Flow **được model dự đoán** benign | 45.060 | 39.335 |
| Flow **được model dự đoán** SSH Brute Force | 0 | 0 |
| Tỷ lệ flow dự đoán DDoS trên toàn bộ flow đang hiển thị, tự tính | 1,89% | 12,59% |
| `Last Attack Rate` **của lô gần nhất** | 2,4% | 11,2% |
| Cảnh báo nhìn thấy | `MEDIUM`, ví dụ lô #184 lúc 14:40:03: 6 flow | `MEDIUM`, ví dụ lô #180 lúc 14:53:45: 28 flow |

![Dashboard Random Forest sau demo HTTP flood](reports/demo_2026-10-27/ddos_random_forest.png)

![Dashboard LightGBM sau demo HTTP flood](reports/demo_2026-10-27/ddos_lightgbm.png)

Danh sách cảnh báo trong cả hai ảnh có nguồn `192.168.247.10` **và** `192.168.247.11` đi tới `192.168.247.20`, phù hợp với kịch bản Kali và Bot. Nhãn `250 flows` ở đầu ô `Recent Alerts` là **số flow của lô xử lý mới nhất**, không phải 250 cảnh báo. Số `#184` hoặc `#180` là mã thứ tự lô, không phải số lần cảnh báo. `Last Attack Rate` không bằng tỷ lệ 867/45.927 hay 5.665/45.000 vì nó chỉ tính cho lô gần nhất.

### Đánh giá hiệu quả và so sánh hai model

**Trên demo live:** cả hai model đều làm pipeline sinh cảnh báo DDoS và hiển thị hai nguồn. LightGBM đánh dấu **5.665 flow**, nhiều hơn Random Forest (**867 flow**) trong hai ảnh, và tỷ lệ flow bị đánh dấu cao hơn khoảng **6,7 lần** (12,59% so với 1,89%). Đây là mức **nhạy hơn trong hai lần chạy quan sát được**; không được diễn giải là LightGBM chính xác hơn 6,7 lần. Việc Random Forest chỉ đánh dấu khoảng 1,89% flow trong bài HTTP flood là tín hiệu cần nêu trung thực khi bảo vệ, vì phần lớn flow từ kịch bản này được model xếp benign. Chưa thể kết luận những flow đó là báo sót thật nếu thiếu nhãn đúng theo từng flow và lưu lượng nền được kiểm soát.

**Trên tập test offline có nhãn của project:** `models/ddos_v2/ddos_model_comparison_v2.csv` và `TRAINING_REPORT_DDOS.md` ghi cả hai model được đánh giá trên cùng 40.000 mẫu (30.000 BENIGN, 10.000 DDoS). Các số sau thuộc tập test offline, **không phải độ chính xác của buổi demo live**.

| Chỉ số offline | Random Forest v2 | LightGBM v2 |
| --- | ---: | ---: |
| Accuracy | 0,999450 | 0,999625 |
| Precision DDoS | 0,999800 | 0,999500 |
| Recall DDoS | 0,998000 | 0,999000 |
| F1 DDoS | 0,998899 | 0,999250 |
| BENIGN báo nhầm DDoS (FP) | 2 | 5 |
| DDoS bị bỏ sót (FN) | 20 | 10 |

Trên tập test này, LightGBM có recall và F1 nhỉnh hơn, giảm số mẫu DDoS bị bỏ sót từ 20 xuống 10; Random Forest có ít báo nhầm hơn (2 so với 5). Đây là chênh lệch nhỏ trên tập offline. Tập test được tách ngẫu nhiên từ cùng bộ dữ liệu lấy mẫu của project, chưa phải một môi trường triển khai độc lập. Hai lần demo live dùng tổng flow khác nhau và không có nhãn chuẩn, nên không thể dùng 867 và 5.665 để tính precision/recall live hoặc xếp hạng độ chính xác. Dù điểm offline rất cao, kết quả live khác biệt rõ cho thấy cần thận trọng khi suy rộng sang HTTP flood thật ngoài lab.

## 4. Kịch bản SSH brute force

Kali chạy `bash /home/kali/ssh_bruteforce_lab.sh 192.168.247.20 victim /home/kali/ssh_lab_passwords.txt`. Script dùng Hydra thử tối đa 50 mật khẩu với 2 tác vụ song song vào SSH cổng 22 của Victim. Một lần thử mật khẩu không đồng nghĩa một flow; nhiều lần thử có thể thuộc một kết nối. Sensor gom TCP/22 theo phiên rồi model SSH v1 phân loại flow thành BENIGN hoặc SSH Brute Force.

Sau các ảnh ngày 02/11, script Kali được cập nhật để chạy **3 vòng mặc định** hoặc chọn `--rounds 1` đến `--rounds 5`; mỗi vòng vẫn giới hạn 50 mật khẩu và 2 tác vụ, cách nhau 12 giây. Ảnh 12 flow Random Forest và 11 flow LightGBM ở dưới là kết quả **trước thay đổi này**. Các vòng mới chỉ tạo thêm lượt quan sát, không thay model hoặc bảo đảm có thêm cảnh báo. Kết quả chạy lại phải được ghi riêng khi có ảnh mới.

Tab SSH có hai tín hiệu **riêng**: kết quả model trên flow, và số dòng `Failed password` từ log Victim nếu agent log được cấu hình đúng token. Cảnh báo từ log không được gọi là kết quả dự đoán của model. Model ứng viên huấn luyện lại theo cổng 22 đã được thử trên 12 flow Hydra và 14 flow đăng nhập bình thường: nó đánh dấu **cả 12/12 flow Hydra lẫn 14/14 flow bình thường là tấn công**, nên **đã bị loại, không triển khai**. Model SSH v1 vẫn là model đang chạy trên dashboard; các lần thử trước có hiện tượng bỏ sót SSH live.

### Kết quả thực tế của phiên cuối

Ảnh người thực hiện gửi ngày **02/11/2026** cho thấy:

| Chỉ số | Random Forest v1 | LightGBM v1 |
| --- | ---: | ---: |
| Tổng flow trên Overview | 12 | 11 |
| Flow được model đánh dấu SSH Brute Force | 1 | 0 |
| Flow được model đánh dấu BENIGN | 11 | 11 |
| Cảnh báo ML quan sát được | `SSH Brute Force Detected`, lô #12 lúc 11:39:09 | Không thấy cảnh báo trong ảnh |
| `Last Attack Rate` trong ảnh | 100% | 0% |

![Random Forest trên Overview](reports/demo_2026-11-02/ssh_random_forest_overview.png)

![Random Forest trên tab SSH](reports/demo_2026-11-02/ssh_random_forest_tab.png)

![LightGBM trên Overview](reports/demo_2026-11-02/ssh_lightgbm_overview.png)

`100%` và mức `HIGH` của Random Forest áp dụng cho **lô cuối chỉ có 1 flow, và flow đó bị đánh dấu**. Chúng không có nghĩa model nhận diện đúng 100% của 12 flow trong toàn phiên; thực tế tab SSH ghi rõ `1 of 12 SSH flows`. `2 flows` trong ô Recent Alerts của ảnh LightGBM là kích thước lô gần nhất, không phải 2 cảnh báo. Hai ảnh của hai model có tổng flow khác nhau nên đây là hai ảnh quan sát, không phải phép so sánh độ chính xác trên cùng một tập flow có nhãn chuẩn.

Trong ảnh ngày 02/11, tab SSH Random Forest còn hiển thị `Failed passwords (Victim log) = 0`, nên riêng phiên cũ đó chưa có bằng chứng log agent gửi thành công sự kiện từ Victim. Đường log đã được sửa và xác nhận hoạt động trong phiên ngày 04/11 ở phần cập nhật bên dưới; nhận định “log Victim chưa hoạt động” không còn áp dụng cho phiên cuối mới nhất.

**Đánh giá cho buổi bảo vệ:** mô hình Random Forest đã tạo **một cảnh báo ML thật** trên lưu lượng SSH live, nên có thể trình bày chức năng định tuyến, phân loại và hiển thị cảnh báo. Mức phát hiện quan sát được chỉ là **1/12 flow bị gắn nhãn tấn công**; LightGBM không đánh dấu flow nào trong lượt tương ứng. Kết quả này chưa đủ để nói model SSH hoạt động ổn định hoặc đạt tỷ lệ phát hiện cao trong lab. Trang SSH hiện đã hiển thị riêng số lần sai mật khẩu từ log Victim, biểu đồ theo cửa sổ 10 giây, kết quả phân loại flow và cảnh báo model, giúp phân biệt bằng chứng hành vi với dự đoán ML.

Kiểm tra chẩn đoán model v1 trên hai file lab đã lưu (`12` flow Hydra và `14` flow đăng nhập bình thường) cho thấy Random Forest đánh dấu tấn công **1/12** flow Hydra và **0/14** flow bình thường; LightGBM đánh dấu **0/12** Hydra nhưng **11/14** flow bình thường. Đây không phải đánh giá ổn định vì chỉ có một lượt thu cho mỗi nhóm. Đặc biệt, không thể tăng tỷ lệ cảnh báo bằng cách hạ ngưỡng rồi gọi đó là cải thiện model: xác suất của hai nhóm chồng lấn và nguy cơ báo nhầm tăng. Cần các phiên tấn công và phiên bình thường **độc lập**, có nhãn theo từng phiên, rồi mới so sánh tỷ lệ phát hiện và báo nhầm trên dữ liệu chưa dùng để chỉnh model.

Lý do quan trọng về thiết kế: model SSH hiện tại phân loại **từng kết nối/flow** bằng đặc trưng packet. Hành vi vét cạn lại thể hiện mạnh ở **nhiều lần thất bại từ cùng một nguồn trong một khoảng thời gian**; model flow không nhận trực tiếp số lần sai mật khẩu trong cửa sổ 60 giây. Chạy Hydra nhiều lần có thể làm tăng số flow và số cảnh báo tuyệt đối, nhưng không tự làm tỷ lệ phát hiện hoặc độ ổn định của model tốt hơn. Để chứng minh model SSH mới có khả năng dự đoán hành vi lặp lại, cần thu nhiều kịch bản lab có nhãn, gồm Hydra, đăng nhập đúng và người dùng gõ sai ít lần; xây dựng đặc trưng theo cửa sổ thời gian và đánh giá trên các phiên độc lập chưa dùng huấn luyện. Tín hiệu ngưỡng từ log Victim hiện có chỉ là cảnh báo theo quy tắc, phải ghi riêng với dự đoán ML.

Khi thuyết trình, cần phân biệt **tỷ lệ flow bị đánh dấu** với **tỷ lệ phiên tấn công được phát hiện**. Mười hai flow của một lượt Hydra chỉ thuộc **một** phiên tấn công; một cảnh báo ML có thể đủ để báo rằng phiên đó đáng nghi, dù chỉ 1/12 flow bị gắn nhãn. Để kiểm tra tính lặp lại, chạy nhiều phiên Hydra độc lập và nhiều phiên đăng nhập bình thường độc lập, lưu kết quả mỗi phiên trước khi reset. Tính `số phiên Hydra có ít nhất một cảnh báo ML / số phiên Hydra thử` và `số phiên bình thường bị cảnh báo ML / số phiên bình thường thử`. Đồng thời ghi tỷ lệ flow được đánh dấu của từng phiên. Một lượt Hydra có cảnh báo như ảnh chỉ là **1/1 phiên quan sát được**, chưa chứng minh độ ổn định; không đưa ra một ngưỡng phần trăm tùy ý rồi gọi là độ chính xác model.

### Kiểm tra lại sau khi script Kali có 3 vòng (02/11/2026)

Ảnh Overview sau khi dùng bản script có nhiều vòng cho thấy **29 tổng flow, 0 flow dự đoán SSH Brute Force, 29 flow dự đoán BENIGN, không có cảnh báo ML**; lô gần nhất có 4 flow và `Last Attack Rate = 0%`. Ảnh chụp khi dashboard còn `Running`; chưa có ảnh terminal Kali để xác nhận cả 3 vòng đã kết thúc. Kết quả này cho thấy tăng số lượt kết nối không tự làm model v1 phát hiện tốt hơn. Cần đối chiếu `live_flows.csv` của chính lượt chạy này với model và dữ liệu huấn luyện trước khi chỉnh ngưỡng hoặc thay model.

![Random Forest sau khi thử script nhiều vòng](reports/demo_2026-11-02/ssh_random_forest_three_rounds_overview.png)

### Cập nhật xác nhận cuối — hai model SSH ngày 04/11/2026

Hai phiên mới nhất sử dụng trang SSH riêng, sensor bắt TCP/22 trên IDS và agent đọc `Failed password` trên Victim. Mỗi model được chọn trước khi tạo một lượt traffic mới bằng script giới hạn `--rounds 1`. Kết quả quan sát được:

| Chỉ số trên trang SSH | Random Forest | LightGBM |
| --- | ---: | ---: |
| Failed passwords từ log Victim | 59 | 58 |
| SSH TCP flows do IDS thu được | 12 | 11 |
| Flow được model đánh dấu SSH Brute Force | 1 | 0 |
| Flow được model xếp benign | 11 | 11 |
| Tỷ lệ flow bị model gắn cờ | 8,3% | 0% |
| Cảnh báo model | Lô #519, `HIGH`, lúc 15:07:24; phát hiện 1 flow | Không có cảnh báo ML |
| Cảnh báo log | Ít nhất 10 lần thất bại từ `192.168.247.10` trong 60 giây | Ít nhất 10 lần thất bại từ `192.168.247.10` trong 60 giây |

![Kết quả SSH Random Forest cuối ngày 04/11/2026](reports/demo_2026-11-04/ssh_random_forest_final.png)

![Kết quả SSH LightGBM cuối ngày 04/11/2026](reports/demo_2026-11-04/ssh_lightgbm_final.png)

Hai tín hiệu trong ảnh phải được diễn giải riêng: `59` và `58` là số lần xác thực thất bại lấy từ journal của Victim; `1/12 (8,3%)` và `0/11 (0%)` là kết quả phân loại flow của từng model. Cảnh báo log chứng minh hành vi thử mật khẩu lặp lại đã xảy ra ở cả hai phiên. Random Forest tạo được một cảnh báo ML, trong khi LightGBM không gắn cờ flow nào trong lượt quan sát mới nhất. Tỷ lệ 8,3% và 0% là tỷ lệ flow bị gắn cờ trong từng phiên, không phải accuracy, precision hoặc recall của model. Hai phiên có số flow khác nhau và không có nhãn đúng độc lập cho từng flow, vì vậy chỉ có thể kết luận Random Forest nhạy hơn trong hai lượt demo này, không thể dùng chúng để xếp hạng độ chính xác tổng quát.

Kết quả được lưu riêng theo tên model trong SQLite. Khi chuyển dropdown từ Random Forest sang LightGBM, dữ liệu Random Forest không bị sửa hoặc dùng để cập nhật trọng số LightGBM; model chỉ thực hiện suy luận, không tự huấn luyện lại trong lúc demo. Trang LightGBM chỉ hiển thị các bản ghi mang tên LightGBM, còn kết quả Random Forest vẫn được giữ để xem lại khi chọn lại model. Tuy nhiên detector chỉ xử lý **flow mới chưa đọc** bằng model đang được chọn; đổi sang LightGBM không làm các flow Random Forest cũ được dự đoán lại. Để so sánh công bằng, cần chọn LightGBM, reset riêng trang/model đó, làm sạch file runtime bằng sensor `--reset`, rồi tạo một lượt traffic SSH mới với cùng cấu hình script.

## 5. Khả năng áp dụng ngoài lab và kết luận

Buổi demo chứng minh pipeline có thể bắt traffic VM, tạo flow, chạy model và đưa kết quả lên dashboard trong cấu hình đã thử. Nó **không chứng minh** hệ thống phát hiện mọi HTTP flood hoặc SSH brute force ngoài thực tế, cũng không xác nhận một tỷ lệ cảnh báo cố định khi nhiều máy cùng truy cập Victim. Các nguồn truy cập thật có thể gồm người dùng bình thường, bot, công cụ và mạng với đặc điểm rất khác. Model có thể báo nhầm hoặc bỏ sót; cần dữ liệu kiểm thử độc lập có nhãn đúng, nhiều kịch bản và đo precision/recall live để kết luận định lượng.

**Kết luận phần DDoS của demo cuối:** pipeline bắt flow và đưa cảnh báo từ cả Kali lẫn Bot lên dashboard bằng cả Random Forest và LightGBM. LightGBM gắn nhãn DDoS cho tỷ lệ flow cao hơn trong hai ảnh; chưa có phép đo độ chính xác live. **Phần SSH cập nhật đến 04/11:** đường log Victim đã hoạt động ở cả hai lượt. Random Forest ghi 59 lần sai mật khẩu, thu 12 flow và gắn cờ 1 flow (8,3%); LightGBM ghi 58 lần sai mật khẩu, thu 11 flow và gắn cờ 0 flow. Kết quả xác nhận pipeline hoạt động trong lab và cho thấy Random Forest tạo được cảnh báo ML trong lượt demo cuối, nhưng vẫn cần nhiều phiên tấn công và bình thường độc lập để đánh giá độ ổn định; không chỉnh nhãn hoặc ngưỡng chỉ để có nhiều cảnh báo trong demo.
