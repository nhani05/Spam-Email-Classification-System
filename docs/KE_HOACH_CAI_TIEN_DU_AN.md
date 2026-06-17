# Kế Hoạch Cải Tiến Dự Án

Tài liệu này mô tả hướng nâng cấp dự án từ hệ thống phân loại spam/ham thành hệ thống phân tích an toàn email tổng hợp. Định hướng đề xuất:

```text
MailGuard AI: Intelligent Email Threat Detection System
```

Mục tiêu không chỉ trả lời:

```text
Email này là spam hay ham?
```

mà trả lời đầy đủ hơn:

```text
Email này có nguy hiểm không?
Nguy hiểm ở điểm nào?
Vì sao hệ thống đánh giá như vậy?
Người dùng nên làm gì tiếp theo?
```

## Mục Tiêu Nâng Cấp

- Biến dự án thành hệ thống Email Threat Detection thay vì chỉ Spam Classification.
- Kết hợp Machine Learning với rule-based security analysis.
- Tăng tính giải thích của kết quả dự đoán.
- Bổ sung dashboard, feedback loop và khả năng mở rộng thành sản phẩm thực tế.
- Tạo thêm các điểm demo thuyết phục: risk score, explainable reasons, QR phishing, URL analysis, admin/security dashboard.

## Kiến Trúc Mục Tiêu

```text
Email input / MBOX / QR image
        |
        v
Text preprocessing + email parsing
        |
        +--> ML Spam/Ham model
        |
        +--> URL risk analyzer
        |
        +--> QR phishing analyzer
        |
        +--> Attachment/header/brand impersonation rules
        |
        v
Risk Aggregator
        |
        v
Final verdict + reasons + recommended actions
        |
        v
Streamlit UI + history + dashboard + feedback
```

## Roadmap Tổng Quan

| Giai đoạn | Mục tiêu | Độ khó | Giá trị khi demo |
| --- | --- | --- | --- |
| Phase 1 | Risk score tổng hợp và explainable reasons | Trung bình | Rất cao |
| Phase 2 | URL phishing và QR phishing nâng cao | Trung bình/cao | Rất cao |
| Phase 3 | Security dashboard và history nâng cấp | Trung bình | Cao |
| Phase 4 | Feedback loop và model evaluation | Trung bình | Cao |
| Phase 5 | Admin mode, blacklist/whitelist, report export | Cao | Rất cao |
| Phase 6 | FastAPI/Docker nếu còn thời gian | Cao | Cộng điểm kỹ thuật |

## Phase 1: Risk Score Tổng Hợp

### Mục Tiêu

Thay vì chỉ hiển thị `Spam` hoặc `Ham`, hệ thống cần hiển thị:

- Spam prediction.
- Spam confidence.
- Phishing score.
- Fake link score.
- Malware/file risk score.
- QR risk score nếu có ảnh QR.
- Overall risk score từ `0-100`.
- Risk level: `Low`, `Medium`, `High`, `Critical`.
- Final verdict: `Safe`, `Suspicious`, `Spam`, `Phishing`, `Malware Risk`, `High Risk`.

### Đề Xuất Xử Lý

Tạo module:

```text
src/security/risk_aggregator.py
```

Module này nhận kết quả từ ML model và các analyzer hiện có, sau đó tính điểm tổng hợp.

Ví dụ công thức ban đầu:

```text
overall_risk = max(
    spam_score * 0.35,
    phishing_score * 0.30,
    fake_link_score * 0.20,
    malware_score * 0.15,
    qr_score
)
```

### Tiêu Chí Hoàn Thành

- Mỗi lần phân tích email có risk score `0-100`.
- UI hiển thị risk level và final verdict.
- Kết quả có danh sách lý do rõ ràng.
- Lịch sử lưu thêm risk score và risk level.

## Phase 2: Phishing URL Và QR Phishing

### Mục Tiêu

Nâng cấp phân tích link trong email và link giải mã từ QR code.

### URL Features Nên Bổ Sung

- URL dùng IP thay vì domain.
- URL quá dài.
- Nhiều subdomain bất thường.
- Có ký tự `@`, `%`, nhiều dấu `-`.
- Dùng `http` thay vì `https`.
- Domain giống thương hiệu lớn nhưng không phải domain chính thức.
- URL shortener: `bit.ly`, `tinyurl`, `t.co`, `goo.gl`.
- Từ khóa nhạy cảm: `login`, `verify`, `secure`, `bank`, `wallet`, `otp`, `password`.

### QR Phishing

Tên tính năng:

```text
Quishing Detection
```

Quy trình:

1. Người dùng upload ảnh.
2. Hệ thống decode QR.
3. Phân tích URL trong QR.
4. Hiển thị URL thật và domain.
5. Cảnh báo nếu QR ẩn link đáng nghi.

## Phase 3: Security Dashboard

Dashboard không chỉ thống kê spam/ham, mà trở thành dashboard an toàn email.

Chỉ số nên có:

- Tổng email đã phân tích.
- Số email theo nhãn `Spam`/`Ham`.
- Số email theo risk level.
- Tỉ lệ email high risk.
- Top risky domains.
- Top suspicious keywords.
- Số QR nguy hiểm đã phát hiện.
- Biểu đồ risk theo thời gian.
- Danh sách email nguy hiểm gần đây.

## Phase 4: Feedback Loop Và Model Evaluation

### Feedback Loop

Sau khi hệ thống dự đoán, cho người dùng phản hồi:

```text
Kết quả đúng
Kết quả sai
```

Dữ liệu feedback được lưu vào DB để phục vụ retraining.

### Model Evaluation

Thêm phần `Model Evaluation` để hiển thị:

- Accuracy.
- Precision.
- Recall.
- F1-score.
- Confusion matrix.
- Bảng so sánh model.
- Best model.

## Phase 5: Admin Mode Và Rule Management

Mục tiêu là thêm vai trò admin để dự án giống sản phẩm thật hơn.

Chức năng admin:

- Xem thống kê toàn hệ thống.
- Xem danh sách email high risk.
- Quản lý blacklist domain.
- Quản lý whitelist domain.
- Quản lý keyword đáng nghi.
- Xem feedback của người dùng.

## Phase 6: FastAPI Và Docker

Nếu còn thời gian, bổ sung khả năng triển khai và tích hợp.

Endpoint FastAPI đề xuất:

```text
POST /predict-email
POST /analyze-url
POST /analyze-qr
GET /history
GET /dashboard
```

Docker service đề xuất:

- `app`: Streamlit/FastAPI.
- `mysql`: MySQL database.

## Thứ Tự Ưu Tiên Để Đạt Điểm Cao

1. Risk score tổng hợp.
2. Explainable reasons.
3. URL phishing detection nâng cao.
4. QR phishing/quishing detection.
5. Security dashboard.
6. Feedback loop.
7. Model evaluation.
8. Admin mode.
9. Report export.
10. FastAPI/Docker.

## Bản Demo Đề Xuất

Khi bảo vệ, nên demo theo kịch bản:

1. Mở dashboard giới thiệu hệ thống MailGuard AI.
2. Nhập một email bình thường và cho thấy verdict `Safe`.
3. Nhập một email lừa đảo có link đáng nghi và cho thấy risk score cao.
4. Mở phần `Why this result?` để giải thích các lý do.
5. Upload ảnh QR chứa link đáng nghi và demo Quishing Detection.
6. Đăng nhập tài khoản và xem lịch sử.
7. Xử lý một file MBOX và tải kết quả CSV.
8. Xem dashboard security sau khi có dữ liệu.
9. Gửi feedback đúng/sai để cho thấy hệ thống có khả năng cải thiện.

## Hướng Nâng Cấp Mới: Adaptive Threat Intelligence Platform

Để biến đề tài khó hơn nữa, roadmap mới nâng cấp hệ thống thành:

```text
MailGuard AI: Adaptive Email Threat Intelligence Platform
```

Khác với spam classifier thông thường, hệ thống này phân tích email như một security event:

- Trích xuất IoC: sender, domain, URL, QR payload, risky file, brand impersonation, keyword.
- Phân loại threat taxonomy: Safe, Spam, Phishing, Malware Risk, Business Email Compromise, Quishing, Credential Theft, Payment Scam.
- Model Lab: so sánh model, threshold tuning, calibration metadata, error analysis.
- Campaign Intelligence: gom các email liên quan thành phishing/scam campaign.
- Threat Graph: tạo node/edge giữa campaign, email, sender, URL, domain, brand.
- Adaptive Learning: feedback người dùng, review queue, export dữ liệu retraining.

Demo nâng cao nên gồm:

1. Chạy email safe và email phishing để thấy threat label khác spam/ham.
2. Xử lý batch có nhiều email cùng domain phishing để hiển thị campaign.
3. Tải campaign report Markdown/JSON.
4. Mở dashboard thấy threat taxonomy, high-risk trend, review queue và model lab.
5. Gửi feedback sai nhãn và xuất approved retraining data.

## Rủi Ro Và Cách Giảm Thiểu

| Rủi ro | Cách giảm thiểu |
| --- | --- |
| Thiếu dataset phishing/malware | Kết hợp ML spam/ham với rule-based analyzer |
| Model path không khớp | Chuẩn hóa `Config` và README |
| DB schema thay đổi gây lỗi app | Viết migration SQL riêng và cập nhật `auth.py` |
| UI quá nhiều tab | Gom theo nhóm: Analyze, Batch, Dashboard, History, Admin |
| Chậm khi xử lý MBOX lớn | Giới hạn preview, cache model, xử lý theo batch |

## Kết Quả Mong Đợi

Sau khi hoàn thành các phase ưu tiên, dự án có thể được trình bày như một hệ thống:

```text
MailGuard AI phân tích email bằng cách kết hợp machine learning,
phishing URL detection, QR threat analysis, explainable risk scoring,
dashboard bảo mật và feedback loop để cải thiện model.
```
