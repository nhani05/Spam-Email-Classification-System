# Spam Email Classification System

Hệ thống phân loại email spam/ham bằng Machine Learning, có giao diện Streamlit để kiểm tra email đơn, xử lý file MBOX, phân tích rủi ro URL/QR, lưu lịch sử theo tài khoản người dùng và hỗ trợ các tính năng nâng cấp theo hướng MailGuard AI.

## Tính Năng Chính

- Phân loại nội dung email thành `Spam` hoặc `Ham`.
- Hiển thị độ tin cậy của dự đoán nếu mô hình hỗ trợ `predict_proba`.
- Phân tích dấu hiệu đe dọa trong email: phishing, fake link, malware, file đáng nghi và URL đáng nghi.
- Phân tích trực tiếp một hoặc nhiều URL, chấm điểm rủi ro `0-100`, hiển thị domain đích, lý do và đặc trưng URL.
- Phân tích ảnh có QR code/quishing, giải mã QR payload và chấm điểm rủi ro URL mà không mở liên kết.
- Xử lý hàng loạt email từ file MBOX và xuất kết quả CSV.
- Đăng ký, đăng nhập và lưu lịch sử dự đoán bằng MySQL.
- Dashboard và lịch sử cho người dùng đã đăng nhập.
- Pipeline huấn luyện lại mô hình từ dataset CSV.
- Hỗ trợ hướng nâng cấp Adaptive Threat Intelligence: threat taxonomy, campaign detection, feedback loop và model lab.

## Công Nghệ Sử Dụng

- Python
- Streamlit
- Pandas
- Scikit-learn
- OpenCV
- BeautifulSoup
- MySQL Connector
- TF-IDF vectorizer và các mô hình ML như Logistic Regression, Decision Tree, SVM, KNN, Random Forest

## Cấu Trúc Thư Mục

```text
.
|-- app.py                         # Ứng dụng Streamlit
|-- requirements.txt               # Danh sách package Python
|-- pyproject.toml                 # Cấu hình dự án khi dùng uv
|-- data/                          # Dataset/model versioned nếu cần fallback
|-- database/
|   |-- schema.sql                 # Script tạo database MySQL chính
|-- docs/                          # Tài liệu dự án, demo, roadmap
|-- notebooks/                     # Notebook thử nghiệm
|-- scripts/                       # Smoke checks và tiện ích demo
|-- src/
|   |-- config/                    # Cau hinh duong dan du lieu/model
|   |-- features/                  # Code chia theo tung tinh nang demo
|   |   |-- auth/                  # Dang nhap, lich su, feedback
|   |   |-- dashboard/             # Dashboard va Model Lab
|   |   |-- email_summarizer/      # Tom tat email bang local AI
|   |   |-- rag_chatbot/           # Chatbot hoi dap noi dung email
|   |   |-- spam_classifier/       # Train/predict spam classifier
|   |   `-- threat_intelligence/   # URL, QR, phishing, campaign, risk scoring
|   |-- infrastructure/            # Adapter ha tang nhu database
|   `-- shared/                    # Logger, email utils, state
|-- outputs/                       # Model/runtime artifact local, bị ignore bởi Git
```

## Yêu Cầu Môi Trường

- Python 3.13 trở lên theo `pyproject.toml`.
- MySQL nếu muốn dùng đăng nhập, lịch sử, dashboard, feedback và các bảng adaptive learning.
- Có sẵn file model và vectorizer đúng với đường dẫn trong `src/config/config.py`.

## Cài Đặt

Tạo và kích hoạt môi trường ảo:

```bash
python -m venv venv
venv\Scripts\activate
```

Cài dependencies:

```bash
pip install -r requirements.txt
```

Nếu dùng `uv`:

```bash
uv sync
```

## Cấu Hình Database

Tạo database MySQL bằng file script:

```bash
mysql -u root -p < database/schema.sql
```

Tạo file `.env` ở thư mục gốc dự án:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=spam_detection
```

Nếu MySQL chưa sẵn sàng, ứng dụng vẫn có thể chạy chế độ khách để kiểm tra email đơn, phân tích URL và phân tích QR. Các chức năng đăng nhập, lịch sử, dashboard, feedback và review queue sẽ không hoạt động đầy đủ.

## Cấu Hình Model

Ứng dụng load model từ `src/config/config.py`. Cấu hình hiện tự tìm thư mục `outputs/` mới nhất có đủ artifact spam classifier:

```python
model_path = "outputs/2026-06-08_09-08-52/models/SVM_model.pkl"
feature_path = "outputs/2026-06-08_09-08-52/models/vectorizer.pkl"
```

Nếu thư mục `outputs/...` không tồn tại, cập nhật về model có sẵn trong repo:

```python
model_path = "data/models/v1/model.pkl"
feature_path = "data/models/v1/feature.pkl"
```

Hoặc chạy lại pipeline huấn luyện để sinh model mới trong thư mục `outputs/`.

## Chạy Ứng Dụng

```bash
streamlit run app.py
```

Sau khi chạy, mở đường dẫn Streamlit hiển thị trên terminal, thường là:

```text
http://localhost:8501
```

## Huấn Luyện Lại Model

Dataset mặc định nằm tại:

```text
data/dataset/dataset.csv
```

Chạy pipeline huấn luyện:

```bash
python -m src.features.spam_classifier.training_pipeline
```

Pipeline sẽ:

1. Đọc dữ liệu từ CSV.
2. Mã hóa nhãn `spam` thành `0`, `ham` thành `1`.
3. Chia train/test theo tỉ lệ 70/30.
4. Vector hóa nội dung email bằng hybrid feature pipeline: word TF-IDF, character n-gram TF-IDF và numeric security features.
5. Huấn luyện và tìm tham số tốt nhất cho nhiều mô hình.
6. Lưu model, vectorizer, metadata và báo cáo metric vào `outputs/<timestamp>/`.

Sau khi huấn luyện, cập nhật `model_path` và `feature_path` trong `src/config/config.py` để trỏ tới model mới.

## Sử Dụng Ứng Dụng

- Khách: kiểm tra email đơn, phân tích URL trực tiếp và phân tích QR image/quishing.
- Người dùng đã đăng nhập: có thêm dashboard, xử lý file MBOX, xem lịch sử và gửi feedback.
- File MBOX hỗ trợ upload qua tab `File MBOX`.
- Kết quả batch có thể tải xuống dưới dạng CSV.
- Mục `Phishing URL Detection` chấp nhận nhiều URL, mỗi dòng một URL. Hệ thống đánh dấu các dấu hiệu như short link, redirect lồng nhau, ký tự encode, URL quá dài, domain nhiều số/gạch nối, TLD rủi ro cao và giả mạo thương hiệu.
- Mục `Quishing Detection` nhận ảnh `png`, `jpg`, `jpeg`, `webp`, `bmp`, giải mã QR payload và dùng chung bộ chấm điểm URL.

## Adaptive Threat Intelligence Platform

Dự án đã được nâng cấp theo hướng:

```text
MailGuard AI: Adaptive Email Threat Intelligence Platform
```

Hướng này biến mỗi email thành một security event có cấu trúc:

- Hybrid threat modeling: kết hợp TF-IDF word/char n-gram, numeric security features, URL, QR, attachment và rule score.
- Threat taxonomy: Safe, Spam, Phishing, Malware Risk, Business Email Compromise, Quishing, Credential Theft, Payment Scam.
- Model Evaluation Lab: metadata cho mỗi lần train, per-class metrics, macro/weighted F1, confusion matrix, threshold analysis và error analysis.
- Campaign Threat Intelligence: gom nhóm email nguy hiểm thành phishing/scam campaign, tạo graph-ready nodes/edges và xuất report.
- Adaptive Feedback Learning: người dùng đã đăng nhập có thể gửi feedback, hệ thống đưa case khó vào review queue và xuất dữ liệu retraining đã duyệt.

## Kiểm Tra Nhanh

```bash
python -m compileall src app.py scripts
python scripts\smoke_adaptive_threat_intelligence.py
```

Kết quả mong đợi:

```text
adaptive threat intelligence smoke passed
```

## Tài Liệu Dự Án

- `docs/HUONG_DAN_DEMO_DU_AN.md`: Kịch bản demo chi tiết, input mẫu, kết quả mong đợi và cách trả lời câu hỏi.
- `docs/ADAPTIVE_THREAT_INTELLIGENCE.md`: Tài liệu kiến trúc Adaptive Threat Intelligence Platform.
- `docs/KE_HOACH_CAI_TIEN_DU_AN.md`: Roadmap nâng cấp dự án thành MailGuard AI.
- `docs/PHAN_CONG_TINH_NANG.md`: Phân công tính năng cho hai thành viên.

## Ghi Chú

- File `.env`, `outputs/`, `venv/`, log và file MBOX được bỏ qua trong `.gitignore`.
- Mật khẩu được hash trong logic ứng dụng nếu có `bcrypt`; nếu thiếu `bcrypt`, hệ thống fallback SHA-256 chỉ phù hợp cho môi trường phát triển.
- Nếu lỗi load model xảy ra khi mở app, hãy kiểm tra lại `model_path` và `feature_path`.
