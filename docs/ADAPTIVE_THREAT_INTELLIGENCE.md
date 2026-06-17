# Nền Tảng Adaptive Threat Intelligence

## Tổng Quan

Bản nâng cấp này chuyển dự án từ hệ thống phân loại `Spam`/`Ham` nhị phân thành một nền tảng phân tích tình báo mối đe dọa email chạy cục bộ. Hệ thống xem mỗi email như một sự kiện an toàn thông tin có cấu trúc, bao gồm nội dung văn bản, URL, QR, file đính kèm, sender/header, điểm rủi ro, campaign và feedback của người dùng.

## Kiến Trúc

```text
Email / MBOX / QR
        |
        v
EmailFeatureExtractor
        |
        +--> Đặc trưng văn bản
        +--> Đặc trưng URL/domain
        +--> Đặc trưng QR payload
        +--> Chỉ báo file đính kèm
        +--> Metadata sender/header
        +--> Điểm rule-based threat
        |
        v
Hybrid ML + Threat Taxonomy + Risk Aggregator
        |
        v
CampaignIntelligenceEngine
        |
        +--> Tóm tắt campaign
        +--> Node/edge cho threat graph
        +--> Báo cáo Markdown/JSON
        |
        v
Dashboard + Feedback + Review Queue + Retraining Export
```

## Các Thành Phần Chính

### 1. EmailFeatureExtractor

Module này tạo bản ghi đặc trưng có cấu trúc cho từng email:

- Body và subject đã chuẩn hóa.
- Sender, sender domain, reply-to, reply-to domain.
- Recipients, timestamp, direction, category.
- Danh sách URL và domain.
- QR payload nếu có.
- File đáng nghi.
- Từ khóa nhạy cảm.
- Rule scores: phishing, fake link, malware, risk score.
- Indicators dùng cho campaign detection.

### 2. Threat Taxonomy

Hệ thống không chỉ trả về `Spam` hoặc `Ham`, mà ánh xạ kết quả sang threat taxonomy:

- `Safe`
- `Spam`
- `Phishing`
- `Malware Risk`
- `Business Email Compromise`
- `Quishing`
- `Credential Theft`
- `Payment Scam`

Threat taxonomy được tính từ kết quả ML, rule-based analyzer, URL/QR signals và các lý do phát hiện được.

### 3. Risk Aggregator

Risk Aggregator kết hợp:

- ML spam score.
- Threat score từ email analyzer.
- Phishing score.
- Fake link score.
- Malware score.
- Campaign score nếu email thuộc campaign.

Kết quả cuối cùng gồm:

- `risk_score`
- `risk_level`
- `verdict`
- `threat_label`
- `reasons`
- `recommended_actions`
- `component_scores`

### 4. CampaignIntelligenceEngine

Campaign engine gom nhóm các email đáng nghi thành chiến dịch tấn công dựa trên:

- Độ giống nội dung email.
- Domain overlap.
- URL overlap.
- Sender-domain similarity.
- Brand overlap.
- QR payload overlap.
- Threat label overlap.
- Time-window proximity.

Kết quả campaign gồm:

- `campaign_id`
- `primary_threat_label`
- `risk_level`
- `risk_score`
- `email_count`
- `first_seen`
- `last_seen`
- `top_domains`
- `top_brands`
- `representative_reasons`

## Model Lab

Training pipeline ghi lại metadata thí nghiệm phong phú hơn:

- Dataset identity.
- Feature configuration.
- Threat taxonomy mapping.
- Precision, recall, F1 theo từng lớp.
- Macro F1 và weighted F1.
- Confusion matrix.
- ROC-AUC và PR-AUC nếu mô hình hỗ trợ.
- Threshold analysis.
- Calibration metadata.
- Error analysis cho false positive, false negative, low-confidence cases và model-rule conflicts.

Metadata của Model Lab được lưu tại:

```text
outputs/<timestamp>/observations/model_lab_metadata.json
outputs/<timestamp>/observations/threshold_analysis.csv
outputs/<timestamp>/observations/error_analysis.json
```

## Database Migration

Chạy `database/schema.sql` trên MySQL database mới hoặc copy phần bảng mở rộng vào schema hiện có. Các bảng mới:

- `Model_Run`
- `Prediction_Threat_Metadata`
- `Extracted_Indicator`
- `Threat_Campaign`
- `Campaign_Email`
- `Prediction_Feedback`
- `Review_Queue`

Các bảng cũ `Single_Prediction_History` và `Batch_Prediction_History` vẫn được giữ tương thích.

## Kịch Bản Demo

1. Email an toàn: nội dung công việc ngắn, không có link đáng nghi.
2. Phishing URL: email yêu cầu đăng nhập/xác minh mật khẩu với domain giả mạo.
3. Quishing/payment QR: QR payload chứa payment payload hoặc URL đáng nghi.
4. File đính kèm rủi ro: nội dung nhắc tới `invoice.pdf.exe` hoặc yêu cầu bật macro.
5. MBOX campaign: nhiều email phishing dùng chung domain hoặc subject/body tương tự.
6. Feedback review: đánh dấu dự đoán sai và xuất các item đã duyệt cho retraining.

## Kiểm Tra

Chạy:

```bash
python -m compileall src app.py
python scripts/smoke_adaptive_threat_intelligence.py
```

## Giới Hạn Hiện Tại

- Kiểm tra SPF, DKIM và DMARC mới được biểu diễn như metadata tùy chọn, chưa thực hiện xác minh DNS trực tiếp.
- Transformer-based language model chưa nằm trong phạm vi triển khai đầu tiên.
- Campaign clustering đang dùng scoring xác định và dễ giải thích, nhưng threshold có thể cần tinh chỉnh khi mailbox lớn hơn.
- Feedback được lưu để review trước khi dùng cho retraining nhằm giảm rủi ro poisoning.

## AI Threat Risk Model

Tang risk analysis moi su dung supervised ML thay vi chi dua vao diem rule co dinh.

- `src/security/ai_threat_model.py`: schema dataset, feature builders, training, evaluation, artifact loading va prediction.
- `data/ai_threat/email_threat_seed.csv`: seed dataset cho email threat labels.
- `data/ai_threat/url_threat_seed.csv`: seed dataset cho URL phishing labels.
- `scripts/train_ai_threat_models.py`: train email threat classifier va URL phishing classifier.
- `scripts/smoke_ai_threat_models.py`: smoke check train/predict/model-unavailable behavior.

Khi `ai_threat_model_path` va `ai_url_model_path` trong `src/config/config.py` tro den artifact hop le, prediction pipeline dung AI model lam nguon duy nhat cho `threat_label`, `class_scores`, `risk_score`, `risk_level` va `verdict`. Neu artifact khong ton tai, pipeline tra `model_unavailable` va khong fallback sang rule-based scoring.
