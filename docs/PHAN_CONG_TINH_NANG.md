# Phân Công Tính Năng Cho 2 Thành Viên

Tài liệu này phân chia các tính năng hiện có và các hướng nâng cấp của dự án Spam Email Classification System cho 2 thành viên phụ trách. Việc phân công dựa trên cấu trúc source code hiện tại và các module đang có trong dự án.

## Tổng Quan Phân Công

| Thành viên | Vai trò chính | Phạm vi phụ trách |
| --- | --- | --- |
| Thành viên 1 | Machine Learning và xử lý dữ liệu | Dataset, training pipeline, prediction pipeline, xử lý email/MBOX, model và vectorizer |
| Thành viên 2 | Ứng dụng, database và bảo mật | Giao diện Streamlit, đăng nhập/đăng ký, MySQL, dashboard, lịch sử, threat detection URL/QR/email |

## Thành Viên 1: Machine Learning Và Xử Lý Dữ Liệu

### Tính Năng Phụ Trách

- Nạp dữ liệu huấn luyện từ `data/dataset/dataset.csv`.
- Tiền xử lý dữ liệu email, tách feature và label.
- Mã hóa nhãn:
  - `spam` thành `0`.
  - `ham` thành `1`.
- Chia tập train/test theo tỉ lệ 70/30.
- Vector hóa nội dung email bằng TF-IDF.
- Nâng cấp hybrid feature pipeline: word TF-IDF, character n-gram TF-IDF và numeric security features.
- Huấn luyện và so sánh nhiều mô hình:
  - Logistic Regression.
  - Decision Tree.
  - SVM.
  - KNN.
  - Random Forest.
- Tìm tham số tốt nhất bằng GridSearchCV.
- Lưu model, vectorizer và các file đánh giá vào thư mục `outputs/`.
- Ghi metadata cho Model Lab: dataset identity, feature config, taxonomy, threshold analysis, error analysis.
- Nạp model đã huấn luyện để dự đoán email đơn.
- Xử lý file MBOX và phân loại hàng loạt email.
- Xuất kết quả batch thành DataFrame/CSV.

### File/Module Liên Quan

| File | Nội dung phụ trách |
| --- | --- |
| `src/components/data_ingestion.py` | Đọc dataset huấn luyện |
| `src/components/data_transformation.py` | Xử lý label, chia train/test, hybrid features |
| `src/components/model_training.py` | Huấn luyện, đánh giá và lưu model |
| `src/components/model_lab.py` | Model Lab, threshold analysis, error analysis |
| `src/pipeline/training_pipeline.py` | Điều phối toàn bộ pipeline huấn luyện |
| `src/pipeline/prediction_pipeline.py` | Dự đoán email đơn và file MBOX |
| `src/utils/email_utils.py` | Tách nội dung email, làm sạch text, lấy người nhận |
| `src/utils/state.py` | Quản lý state cho training/prediction |
| `src/config/config.py` | Cấu hình đường dẫn dataset, model và vectorizer |
| `data/dataset/dataset.csv` | Dữ liệu huấn luyện |
| `data/models/v1/` | Model và vectorizer có sẵn |

### Kết Quả Cần Đảm Bảo

- Pipeline huấn luyện chạy được bằng lệnh:

```bash
python -m src.pipeline.training_pipeline
```

- Model và vectorizer được lưu đúng cấu trúc:

```text
outputs/<timestamp>/models/
```

- Model Lab sinh các file quan sát:

```text
outputs/<timestamp>/observations/model_metadata.csv
outputs/<timestamp>/observations/model_comparison_summary.csv
outputs/<timestamp>/observations/threshold_analysis.csv
outputs/<timestamp>/observations/error_analysis.json
outputs/<timestamp>/observations/model_lab_metadata.json
```

- Đường dẫn `model_path` và `feature_path` trong `src/config/config.py` trỏ đúng file model đang sử dụng.
- Chức năng dự đoán email đơn trả về:
  - `prediction`
  - `confidence`
  - `raw_prediction`
  - `threat_label`
  - `risk_score`
  - `risk_level`
  - `verdict`
- Chức năng xử lý MBOX trả về bảng kết quả có cột `Prediction`, `Threat Label`, `Risk Score`, `Risk Level`, `Verdict`, `Campaign ID`.

## Thành Viên 2: Ứng Dụng, Database Và Bảo Mật

### Tính Năng Phụ Trách

- Xây dựng và vận hành giao diện Streamlit trong `app.py`.
- Thiết lập layout, sidebar, tabs và các luồng thao tác người dùng.
- Chế độ khách:
  - Kiểm tra email đơn.
  - Phân tích URL trực tiếp.
  - Phân tích QR image.
- Chế độ người dùng đã đăng nhập:
  - Dashboard.
  - Kiểm tra email đơn và lưu lịch sử.
  - Xử lý file MBOX và lưu thống kê.
  - Xem lịch sử phân loại.
  - Gửi feedback cho kết quả dự đoán.
- Đăng ký, đăng nhập và đăng xuất tài khoản.
- Kết nối MySQL bằng biến môi trường trong `.env`.
- Tạo database và bảng bằng script SQL.
- Lưu lịch sử dự đoán email đơn.
- Lưu lịch sử xử lý file MBOX.
- Lưu threat metadata, extracted indicators, feedback và review queue.
- Hiển thị dashboard thống kê và dashboard bảo mật.
- Phân tích đe dọa trong email:
  - Phishing.
  - Fake link.
  - Malware.
  - File đính kèm/tên file đáng nghi.
- Phân tích QR code trong ảnh và đánh giá rủi ro URL.
- Hiển thị campaign summaries, graph data và report download.

### File/Module Liên Quan

| File | Nội dung phụ trách |
| --- | --- |
| `app.py` | Giao diện Streamlit và điều phối các tab |
| `src/auth/auth.py` | Đăng ký, đăng nhập, lưu và đọc lịch sử/feedback/review queue |
| `src/database/db.py` | Kết nối MySQL và health check |
| `src/components/dashboard.py` | Dashboard thống kê người dùng và bảo mật |
| `src/security/email_threat_analyzer.py` | Phân tích rủi ro nội dung email |
| `src/security/url_risk_model.py` | Chấm điểm rủi ro URL |
| `src/security/qr_image_analyzer.py` | Đọc QR code từ ảnh và phân tích URL |
| `src/security/feature_extractor.py` | Trích xuất đặc trưng email |
| `src/security/threat_taxonomy.py` | Phân loại threat taxonomy |
| `src/security/campaign_intelligence.py` | Campaign detection, graph data, report |
| `database/schema.sql` | Script tạo database và dữ liệu mẫu |
| `.env` | Biến môi trường kết nối database |

### Kết Quả Cần Đảm Bảo

- Ứng dụng chạy được bằng lệnh:

```bash
streamlit run app.py
```

- Khi MySQL sẵn sàng, người dùng có thể:
  - Đăng ký tài khoản.
  - Đăng nhập.
  - Lưu lịch sử dự đoán.
  - Xem dashboard và lịch sử.
  - Gửi feedback cho dự đoán.
- Khi MySQL không sẵn sàng, ứng dụng vẫn cho phép khách kiểm tra email đơn, URL và QR.
- File MBOX upload được xử lý và có thể tải kết quả CSV.
- QR image upload được phân tích và hiển thị:
  - Số QR tìm thấy.
  - Điểm rủi ro.
  - Mức rủi ro.
  - URL/payload giải mã.
  - Lý do đánh giá.
- Campaign detection hiển thị campaign summary, campaign report và graph-ready data khi batch có email liên quan.

## Phân Chia Theo Màn Hình/Chức Năng Người Dùng

| Chức năng | Thành viên phụ trách chính | Thành viên phối hợp |
| --- | --- | --- |
| Kiểm tra email đơn | Thành viên 1 | Thành viên 2 |
| Hiển thị kết quả email đơn trên UI | Thành viên 2 | Thành viên 1 |
| Phân tích rủi ro trong email | Thành viên 2 | Thành viên 1 |
| Phân tích URL trực tiếp | Thành viên 2 | Thành viên 1 |
| Phân tích QR image | Thành viên 2 | Thành viên 1 |
| Xử lý file MBOX | Thành viên 1 | Thành viên 2 |
| Campaign detection trong MBOX | Thành viên 1 | Thành viên 2 |
| Upload MBOX và tải CSV/report | Thành viên 2 | Thành viên 1 |
| Huấn luyện lại model | Thành viên 1 | Thành viên 2 |
| Model Lab và báo cáo metric | Thành viên 1 | Thành viên 2 |
| Cấu hình đường dẫn model | Thành viên 1 | Thành viên 2 |
| Đăng ký/đăng nhập | Thành viên 2 | Thành viên 1 |
| Lưu lịch sử dự đoán | Thành viên 2 | Thành viên 1 |
| Feedback loop/review queue | Thành viên 2 | Thành viên 1 |
| Dashboard | Thành viên 2 | Thành viên 1 |
| README và tài liệu cài đặt/demo | Thành viên 2 | Thành viên 1 |

## Tiêu Chí Nghiệm Thu

### Phần Của Thành Viên 1

- Chạy được pipeline huấn luyện không lỗi.
- Có model/vectorizer hợp lệ để app load khi khởi động.
- Dự đoán email đơn trả về đúng format.
- Xử lý được file MBOX và sinh kết quả có nhãn `Spam`/`Ham`.
- Có threat label, risk score và verdict trong kết quả prediction.
- Có báo cáo metric sau khi huấn luyện.
- Có Model Lab output cho threshold analysis và error analysis.

### Phần Của Thành Viên 2

- App Streamlit khởi động được.
- Các tab hiển thị đúng theo trạng thái đăng nhập.
- Đăng ký/đăng nhập hoạt động khi MySQL đã cấu hình.
- Lịch sử single email và batch MBOX được lưu/đọc từ database.
- Dashboard hiển thị dữ liệu của người dùng.
- Phân tích QR và threat detection hiển thị kết quả rõ ràng.
- Feedback được lưu và case sai được đưa vào review queue.
- Campaign summaries và report download hiển thị khi batch có email liên quan.

## Ghi Chú Khi Làm Việc Nhóm

- Trước khi demo, cần thống nhất đường dẫn model trong `src/config/config.py`.
- Nếu dùng model trong repo, có thể cấu hình:

```python
model_path = "data/models/v1/model.pkl"
feature_path = "data/models/v1/feature.pkl"
```

- Nếu huấn luyện model mới, cần cập nhật lại đường dẫn tới thư mục `outputs/<timestamp>/models/`.
- Thành viên 1 nên bàn giao cho Thành viên 2 một cặp file model/vectorizer đã test thành công.
- Thành viên 2 nên báo lại lỗi load model, lỗi database hoặc lỗi format output để Thành viên 1 điều chỉnh pipeline.
- Trước khi bảo vệ, cả nhóm nên chạy:

```bash
python -m compileall src app.py scripts
python scripts\smoke_adaptive_threat_intelligence.py
```

## Phân Công Cho Hướng Cải Tiến MailGuard AI

Chi tiết roadmap nằm trong `docs/KE_HOACH_CAI_TIEN_DU_AN.md`. Tóm tắt phân công nâng cấp:

| Hạng mục cải tiến | Thành viên 1 | Thành viên 2 |
| --- | --- | --- |
| Risk score tổng hợp | Mapping confidence từ ML model sang spam score | Tổng hợp spam/phishing/URL/QR/file score và hiển thị UI |
| Explainable reasons | Lý do liên quan spam keywords, vectorizer/model output | Lý do liên quan URL, QR, phishing, malware, attachment |
| URL phishing detection | Hỗ trợ feature engineering và test case | Phụ trách rule-based URL analyzer |
| QR phishing detection | Hỗ trợ bộ mẫu QR test | Phụ trách QR analyzer và UI |
| Security dashboard | Cung cấp metric model và batch prediction | Truy vấn DB, vẽ biểu đồ, hiển thị risky domains |
| Feedback loop | Chuẩn bị cách dùng feedback cho retraining | Tạo form feedback và bảng DB |
| Model evaluation | Accuracy, precision, recall, F1, confusion matrix | Hiển thị bảng/biểu đồ trên Streamlit |
| Campaign detection | Similarity score, clustering, campaign summaries | Hiển thị campaign dashboard, report download |
| Threat graph | Cung cấp node/edge từ pipeline | Hiển thị graph-ready data trong UI |
| Admin mode | Chuẩn hóa format blacklist/whitelist cho analyzer | Role admin, CRUD rule và dashboard tổng |
| FastAPI/Docker | Đóng gói prediction logic thành service | Tích hợp app, DB và hướng dẫn deployment |

Ưu tiên cao nhất nên làm trước:

1. Risk score tổng hợp.
2. Explainable reasons.
3. URL phishing và QR phishing.
4. Security dashboard.
5. Feedback loop.
6. Campaign detection.
7. Model Lab.
