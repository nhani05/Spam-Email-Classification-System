# Hướng Dẫn Demo Dự Án MailGuard AI

Tài liệu này dùng để demo dự án trước giảng viên hoặc hội đồng. Mục tiêu là trình bày dự án không chỉ là một spam/ham classifier, mà là một hệ thống phân tích an toàn email: risk score, threat taxonomy, URL phishing, QR/quishing, campaign detection, dashboard, feedback loop và model lab.

## 1. Thông Điệp Chính Khi Giới Thiệu

Nên mở đầu ngắn gọn:

```text
Dự án ban đầu là Spam Email Classification System.
Em đã nâng cấp thành MailGuard AI - Adaptive Email Threat Intelligence Platform.

Hệ thống không chỉ hỏi "email này là spam hay ham",
mà trả lời:
- Email có nguy hiểm không?
- Nguy hiểm theo loại nào: phishing, credential theft, quishing, malware risk?
- Vì sao hệ thống đánh giá như vậy?
- Những email nguy hiểm có thuộc cùng một chiến dịch tấn công không?
- Người dùng có thể feedback để cải thiện model không?
```

## 2. Chuẩn Bị Trước Khi Demo

### 2.1 Kích Hoạt Môi Trường

```bash
venv\Scripts\activate
```

Nếu chưa cài thư viện:

```bash
pip install -r requirements.txt
```

### 2.2 Kiểm Tra Model Path

Ứng dụng đọc model trong `src/config/config.py`:

```python
model_path = "outputs/2026-06-08_09-08-52/models/SVM_model.pkl"
feature_path = "outputs/2026-06-08_09-08-52/models/vectorizer.pkl"
```

Nếu thư mục `outputs/...` không có, đổi về model có sẵn:

```python
model_path = "data/models/v1/model.pkl"
feature_path = "data/models/v1/feature.pkl"
```

Trong workspace hiện tại đã có model spam/ham theo path `outputs/2026-06-08_09-08-52/...`, nên không cần đổi nếu file vẫn tồn tại.

Để demo risk analysis bằng AI threat model, cập nhật thêm:

```python
ai_threat_model_path = "outputs/2026-06-17_10-46-06_ai-threat/models/email_threat_model.pkl"
ai_url_model_path = "outputs/2026-06-17_10-46-06_ai-threat/models/url_phishing_model.pkl"
```

Nếu để hai path này rỗng, app vẫn chạy nhưng phần risk analysis sẽ hiển thị `model_unavailable` và không chấm điểm bằng rule.

### 2.3 Kiểm Tra Nhanh Trước Giờ Demo

Chạy:

```bash
python -m compileall src app.py scripts
python scripts\smoke_adaptive_threat_intelligence.py
```

Kết quả mong đợi:

```text
adaptive threat intelligence smoke passed
```

### 2.4 Cấu Hình Database Nếu Muốn Demo Đăng Nhập/Dashboard/History

Tạo database:

```bash
mysql -u root -p < database/schema.sql
```

Tạo file `.env`:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=spam_detection
```

Nếu MySQL không sẵn sàng, vẫn demo được chế độ khách: single email, URL phishing và QR image. Các phần cần đăng nhập như dashboard, MBOX, history, feedback sẽ không hoạt động đầy đủ.

### 2.5 Chạy Ứng Dụng

```bash
streamlit run app.py
```

Mở:

```text
http://localhost:8501
```

### 2.6 Input Chuẩn Bị Sẵn Trước Khi Demo

Mở sẵn file này và copy theo từng khối khi demo. Bộ input dưới đây được chọn để tạo đủ tín hiệu: email an toàn, phishing, credential theft, BEC/payment scam, URL rủi ro, QR/quishing và MBOX campaign.

#### Tài Khoản Demo

Nếu đã chạy `mysql -u root -p < database/schema.sql`, database có sẵn user mẫu:

```text
alice / pass123
bob / qwerty12
charlie / charlie99
```

Nếu đăng nhập bằng user mẫu không được do môi trường hash mật khẩu khác, dùng form `Đăng ký` ở sidebar để tạo user mới, sau đó đăng nhập bằng user vừa tạo.

#### Email Safe - Copy Vào `Email đơn`

```text
Subject: Project report review

Hi team,

Please review the project report before our meeting tomorrow morning.
I updated the dashboard screenshots and added the latest notes from the model evaluation run.

Thanks,
Minh
```

#### Email Phishing/Credential Theft - Copy Vào `Email đơn`

```text
Subject: URGENT: Your PayPal account has been suspended

We detected unusual login activity on your PayPal account.
Verify your password immediately at:
http://paypa1-login.xyz/reset

If you do not verify within 24 hours, your account will be permanently locked.
```

#### Email Malware Risk - Copy Vào `Email đơn`

```text
Subject: Invoice payment overdue

Please open the attached invoice_update.exe and enable macros to view the full payment details.
Your account will be charged a late fee today if this invoice is not confirmed.

Download mirror:
http://invoice-secure-update.ru/download
```

#### Email Business Email Compromise / Payment Scam - Copy Vào `Email đơn`

```text
Subject: Urgent supplier payment change

Hi Finance team,

I am in a meeting and cannot call. Please update the supplier bank account and send the pending payment today.
Use this new account for the wire transfer and keep this request confidential until I return.

Regards,
CEO Office
```

#### URL Demo - Copy Vào `Phân tích URL phishing`

```text
https://google.com
https://mail.google.com
http://paypa1-login.xyz/verify?account=locked
https://bit.ly/free-gift-login
http://192.168.1.10/login
http://invoice-secure-update.ru/download
https://secure-microsoft-login.example.com/verify-password
```

#### QR/Quishing Payload

Tạo trước một ảnh QR chứa payload này:

```text
http://paypa1-login.xyz/verify?source=qr
```

Nếu cần tạo nhanh QR bằng Python:

```bash
python -m pip install qrcode[pil]
python -c "import qrcode; qrcode.make('http://paypa1-login.xyz/verify?source=qr').save('demo_quishing_qr.png')"
```

Upload `demo_quishing_qr.png` vào mục `Phân tích QR / Quishing`.

#### MBOX Demo Campaign - Nội Dung File Mẫu

Tạo file `demo_campaign.mbox` ở máy demo với nội dung sau, sau đó upload vào tab `File MBOX`. Các email dùng chung domain/link và ngôn ngữ khẩn cấp để tăng khả năng gom thành một campaign.

```text
From attacker1@paypa1-login.xyz Sat Jan 20 10:00:00 2026
Date: Sat, 20 Jan 2026 10:00:00 +0700
From: PayPal Security <attacker1@paypa1-login.xyz>
To: victim@example.com
Subject: URGENT: PayPal account verification required

Your PayPal account has been limited. Verify your login immediately:
http://paypa1-login.xyz/verify

From attacker2@paypa1-login.xyz Sat Jan 20 10:04:00 2026
Date: Sat, 20 Jan 2026 10:04:00 +0700
From: PayPal Support <attacker2@paypa1-login.xyz>
To: victim2@example.com
Subject: PayPal password reset required

We detected suspicious activity. Reset your password now:
http://paypa1-login.xyz/reset

From attacker3@paypa1-login.xyz Sat Jan 20 10:08:00 2026
Date: Sat, 20 Jan 2026 10:08:00 +0700
From: PayPal Alert <attacker3@paypa1-login.xyz>
To: victim3@example.com
Subject: Final warning: PayPal wallet locked

Your wallet will be locked within 24 hours. Confirm your account:
http://paypa1-login.xyz/confirm

From colleague@example.com Sat Jan 20 10:12:00 2026
Date: Sat, 20 Jan 2026 10:12:00 +0700
From: Project Team <colleague@example.com>
To: victim4@example.com
Subject: Meeting notes

Hi, attached are the discussion points for tomorrow's project meeting.
No action is required before the meeting.
```

## 3. Luồng Demo Tổng Thể

Nên demo theo thứ tự:

```text
1. Giới thiệu dashboard và mục tiêu hệ thống
2. Demo safe email
3. Demo spam/phishing email
4. Demo URL phishing detection
5. Demo QR/quishing detection
6. Demo MBOX batch + campaign detection
7. Demo history/dashboard sau khi có dữ liệu
8. Demo feedback loop
9. Demo model lab và tài liệu kỹ thuật
```

Nếu thời gian chỉ có 5-7 phút, bỏ qua training live và chỉ nói model lab qua docs/output.

## 4. Demo 1 - Email Bình Thường

### Input Mẫu

Dán vào tab `Email Đơn`:

```text
Hi team,

Please review the project report before our meeting tomorrow morning.
I updated the dashboard screenshots and attached the latest notes.

Thanks.
```

### Kết Quả Mong Đợi

- Prediction: `Ham`.
- Risk score thấp.
- Risk level: `Low`.
- Threat label: `Safe` hoặc risk thấp.
- Reasons nói không có dấu hiệu phishing/link/malware mạnh.

### Nội Dung Nên Nói Khi Demo

```text
Với email công việc bình thường, model phân loại là Ham.
Spam/ham model vẫn chạy riêng; threat-risk layer chỉ kết luận khi AI threat model đã được cấu hình.
Hệ thống không chỉ hiện Ham/Spam mà còn hiện risk score, threat label và lý do.
```

## 5. Demo 2 - Email Phishing/Credential Theft

### Input Mẫu

```text
URGENT: Your PayPal account has been suspended.

We detected unusual login activity. Verify your password immediately at:
http://paypa1-login.xyz/reset

If you do not verify within 24 hours, your account will be permanently locked.
```

### Kết Quả Mong Đợi

- Prediction thường là `Spam`.
- Risk score cao.
- Risk level: `High` hoặc `Critical`.
- Threat label có thể là `Spam`, `Phishing` hoặc `Credential Theft` tùy score.
- URL analyzer hiển thị domain `paypa1-login.xyz`.
- Reasons có các dấu hiệu:
  - urgency/pressure language.
  - password/login/verify.
  - URL không dùng HTTPS.
  - domain/TLD đáng nghi.

### Nội Dung Nên Nói Khi Demo

```text
Email này có nhiều dấu hiệu tấn công: yêu cầu xác minh mật khẩu, tạo áp lực thời gian và chứa link đáng nghi.
Hệ thống dùng ML để dự đoán spam/ham, sau đó dùng AI threat model riêng để chấm phishing, fake link, malware-risk và các nhãn threat khác.
Risk aggregator hợp nhất các tín hiệu này thành final verdict và recommended actions.
```

## 6. Demo 3 - Phishing URL Detection

Mở mục `Phishing URL Detection`, dán nhiều URL, mỗi dòng một URL:

```text
https://google.com
http://paypa1-login.xyz/verify?account=locked
https://bit.ly/free-gift-login
http://192.168.1.10/login
```

### Kết Quả Mong Đợi

- URL an toàn có score thấp.
- URL giả mạo/shortener/IP có score cao hơn.
- Mỗi URL có:
  - final destination.
  - domain.
  - extracted features.
  - reasons.

### Nội Dung Nên Nói Khi Demo

```text
Phần này không mở link thật, chỉ phân tích cú pháp và đặc trưng URL.
Hệ thống phát hiện short link, raw IP, từ khóa login/verify, TLD rủi ro và domain giả mạo thương hiệu.
```

## 7. Demo 4 - QR / Quishing Detection

Mở mục `Quishing Detection`, upload ảnh có QR code.

### Mẫu QR Nên Chuẩn Bị

Chuẩn bị trước 1 ảnh QR chứa link:

```text
http://paypa1-login.xyz/verify
```

Hoặc QR thanh toán nếu muốn demo payment QR review.

### Kết Quả Mong Đợi

- Hệ thống đọc QR payload.
- Nếu QR chứa URL đáng nghi, hiển thị URL analysis.
- Nếu QR là payment payload, verdict có thể là `PAYMENT_QR_REVIEW`.

### Nội Dung Nên Nói Khi Demo

```text
Quishing là phishing qua QR code.
Người dùng thường không thấy URL thật trước khi quét, nên hệ thống giải mã QR và chấm điểm rủi ro trước khi người dùng mở link.
```

## 8. Demo 5 - MBOX Batch Và Campaign Detection

Phần này cần đăng nhập và database hoạt động.

### Cách Demo

1. Đăng nhập bằng tài khoản có sẵn hoặc đăng ký tài khoản mới.
2. Mở tab `File MBOX`.
3. Upload file MBOX.
4. Bấm xử lý.

### Kết Quả Mong Đợi

Bảng kết quả có các cột:

- `Prediction`
- `Threat Label`
- `Risk Score`
- `Risk Level`
- `Verdict`
- `Campaign ID`

Nếu có nhiều email nguy hiểm liên quan, hệ thống hiển thị `Threat Campaigns`:

- `campaign_id`
- `primary_threat_label`
- `risk_level`
- `risk_score`
- `email_count`
- `top_domains`

Có nút tải:

- Campaign summaries JSON.
- First campaign report Markdown.

### Nội Dung Nên Nói Khi Demo

```text
Đây là điểm nâng cấp lớn nhất của dự án.
Hệ thống không chỉ phân loại từng email riêng lẻ, mà còn gom các email có chung domain, URL, subject/body, brand hoặc thời gian thành một phishing campaign.
Nó giống một mini SOC investigation platform.
```

## 9. Demo 6 - Dashboard Bảo Mật

Sau khi đã phân tích một số email, mở tab `Dashboard`.

### Nội Dung Cần Chỉ Ra

- Total emails.
- Spam/Ham ratio.
- High risk count.
- Campaign count.
- Threat taxonomy distribution.
- High-risk trend.
- Adaptive learning review queue nếu có.
- Model lab runs nếu đã train model mới.

### Nội Dung Nên Nói Khi Demo

```text
Dashboard không chỉ thống kê spam/ham.
Nó được nâng cấp thành security dashboard: risk trend, threat taxonomy, campaign count và review queue.
```

## 10. Demo 7 - Feedback Loop Và Active Learning

Phần này cần đăng nhập.

### Cách Demo

1. Phân tích một email.
2. Sau khi kết quả được lưu, mở `Prediction feedback`.
3. Chọn:
   - `correct` nếu kết quả đúng.
   - `incorrect` nếu kết quả sai.
4. Nếu sai, chọn corrected threat label, ví dụ `Phishing`.
5. Nhập analyst note.
6. Bấm `Save feedback`.

### Kết Quả Mong Đợi

- Feedback được lưu nếu DB migration đã chạy.
- Case sai được đưa vào review queue.
- Dashboard có thể hiển thị review queue.

### Nội Dung Nên Nói Khi Demo

```text
Hệ thống không retrain trực tiếp từ feedback vì có nguy cơ feedback sai hoặc độc.
Thay vào đó, feedback đi vào review queue. Chỉ những item được duyệt mới được export thành retraining data.
```

## 11. Demo 8 - Model Evaluation Lab

Không nên train live nếu thời gian demo ngắn, vì GridSearchCV có thể lâu.

### Nói Về Pipeline

Training pipeline:

```bash
python -m src.pipeline.training_pipeline
```

Sau khi train, hệ thống sinh:

```text
outputs/<timestamp>/models/
outputs/<timestamp>/observations/model_metadata.csv
outputs/<timestamp>/observations/model_comparison_summary.csv
outputs/<timestamp>/observations/threshold_analysis.csv
outputs/<timestamp>/observations/error_analysis.json
outputs/<timestamp>/observations/model_lab_metadata.json
```

### Điểm Cần Nhấn Mạnh

```text
Model lab không chỉ báo accuracy.
Nó báo per-class precision/recall/F1, macro F1, weighted F1, confusion matrix, threshold analysis và error analysis.
Điều này phù hợp hơn với bài toán spam/phishing vì dữ liệu bị lệch lớp.
```

## 12. Các Câu Hỏi Hội Đồng Có Thể Hỏi

### Câu Hỏi: Dự án khác gì spam classifier cơ bản?

Trả lời:

```text
Spam classifier cơ bản chỉ trả về Spam/Ham.
Dự án này có thêm risk score, threat taxonomy, URL/QR analysis, campaign detection, graph-ready investigation, feedback loop và model lab.
Nó phân tích email như một security event.
```

### Câu Hỏi: Vì sao không dùng Transformer?

Trả lời:

```text
Transformer có thể là hướng mở rộng, nhưng với đồ án này em ưu tiên hybrid sklearn pipeline vì nhẹ, giải thích được, chạy local tốt và phù hợp demo.
Hệ thống đã thiết kế model lab nên sau này có thể thêm Transformer như một benchmark mới.
```

### Câu Hỏi: Nếu model báo Ham nhưng URL nguy hiểm thì sao?

Trả lời:

```text
Nếu thiếu artifact AI threat model, hệ thống trả `model_unavailable` để tránh dùng rule làm verdict thay thế.
Nếu ML báo Ham nhưng URL/QR/malware signal cao, risk score vẫn được đẩy lên và case có thể vào review queue.
```

### Câu Hỏi: Campaign detection dựa vào gì?

Trả lời:

```text
Hệ thống tính similarity dựa trên text similarity, domain overlap, URL overlap, sender-domain, brand, QR payload, threat label và time window.
Nếu nhiều email có score vượt threshold, chúng được gom vào một campaign.
```

### Câu Hỏi: Feedback có làm model học sai không?

Trả lời:

```text
Không retrain trực tiếp từ feedback.
Feedback vào review queue. Chỉ item được approve mới được export thành retraining data.
Đây là cách giảm nguy cơ poisoning.
```

## 13. Lỗi Thường Gặp Khi Demo

### Lỗi Không Load Được Model

Kiểm tra `src/config/config.py`. Nếu path trong `outputs/...` không tồn tại, đổi về:

```python
model_path = "data/models/v1/model.pkl"
feature_path = "data/models/v1/feature.pkl"
```

### Lỗi Không Đăng Nhập Được

Kiểm tra:

- MySQL đang chạy.
- `.env` đúng user/password/database.
- Đã chạy `mysql -u root -p < database/schema.sql`.

### QR Không Đọc Được

Thử:

- Ảnh rõ nét hơn.
- QR lớn hơn.
- Định dạng `png` hoặc `jpg`.
- QR không bị nghiêng/cắt góc.

### MBOX Không Có Campaign

Không phải lỗi. Nếu file chỉ có email riêng lẻ, hệ thống sẽ không ép tạo campaign. Muốn demo campaign, cần file có nhiều email cùng domain/link/subject phishing.

## 14. Checklist Ngay Trước Khi Bảo Vệ

- [ ] Chạy `python -m compileall src app.py scripts`.
- [ ] Chạy `python scripts\smoke_adaptive_threat_intelligence.py`.
- [ ] Kiểm tra model path trong `src/config/config.py`.
- [ ] Chạy Streamlit và mở `http://localhost:8501`.
- [ ] Chuẩn bị sẵn input safe email.
- [ ] Chuẩn bị sẵn input phishing email.
- [ ] Chuẩn bị sẵn danh sách URL demo.
- [ ] Chuẩn bị sẵn ảnh QR nếu demo quishing.
- [ ] Chuẩn bị sẵn file MBOX nếu demo campaign.
- [ ] Đăng nhập thử trước nếu demo dashboard/history/feedback.

## 15. Kết Luận Nên Nói

```text
Kết quả cuối cùng là MailGuard AI - một hệ thống phân tích an toàn email tổng hợp.
Dự án vẫn có nền tảng ML spam classification, nhưng được nâng cấp thêm risk scoring, explainability, URL/QR phishing detection, campaign intelligence, dashboard và adaptive feedback learning.
Hướng phát triển tiếp theo là bổ sung dữ liệu phishing thật, thêm header authentication SPF/DKIM/DMARC và benchmark Transformer trong Model Lab.
```

## AI Risk Model Demo Note

Neu muon demo risk analysis la AI/ML that, chay:

```bash
python scripts\train_ai_threat_models.py
python scripts\smoke_ai_threat_models.py
```

Sau khi train, copy hai path artifact in ra terminal vao `src/config/config.py`:

```python
ai_threat_model_path = "outputs/<timestamp>_ai-threat/models/email_threat_model.pkl"
ai_url_model_path = "outputs/<timestamp>_ai-threat/models/url_phishing_model.pkl"
```

Khi duoc hoi, giai thich ngan gon: spam/ham model van duoc giu, nhung threat/risk layer dung supervised AI model rieng. Neu artifact AI chua duoc cau hinh, he thong hien `model_unavailable` va khong fallback sang rule-based scoring.
