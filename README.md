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
|-- data/
|   |-- dataset/dataset.csv        # Dữ liệu huấn luyện
|   `-- models/v1/                 # Model/vectorizer có sẵn
|-- database/
|   |-- schema.sql                 # Script tạo database MySQL chính
|   |-- legacy_schema.sql          # Schema MySQL phiên bản cũ
|   `-- local/                     # SQLite local/runtime
|-- docs/                          # Tài liệu dự án, demo, roadmap
|-- notebooks/                     # Notebook thử nghiệm
|-- scripts/                       # Smoke checks và tiện ích demo
|-- src/
|   |-- app/                       # Streamlit views, page handlers, formatting
|   |-- auth/                      # Compatibility exports cho auth APIs cũ
|   |-- components/                # Compatibility exports cho module cũ
|   |-- core/                      # Cấu hình, logging, artifact path helpers
|   |-- config/                    # Compatibility exports cho config cũ
|   |-- data/                      # Email parsing và data helpers
|   |-- database/                  # Kết nối MySQL
|   |-- ml/                        # Model lab, spam classifier, threat/url classifiers
|   |-- persistence/               # Users, predictions, feedback, campaigns
|   |-- pipeline/                  # Compatibility exports cho pipeline cũ
|   |-- security/                  # Phân tích URL, QR, email indicators, campaign
|   |-- workflows/                 # Prediction và training orchestration
|   `-- utils/                     # Logger, email utils, state, DB helpers
```

Chi tiết mapping refactor nằm ở `docs/PROJECT_STRUCTURE.md`. Các module cũ như
`src.components.*`, `src.pipeline.*`, `src.security.ai_threat_model`,
`src.auth.auth`, `src.config.config` và `src.utils.email_utils` vẫn được giữ làm
compatibility shim để script, demo và artifact pickle hiện tại tiếp tục chạy.

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

Ứng dụng load model từ `src/core/config.py` thông qua compatibility export `src/config/config.py`:

```python
model_path = "outputs/<latest_run>/models/SVM_model.pkl"
feature_path = "outputs/<latest_run>/models/vectorizer.pkl"
```

Nếu thư mục `outputs/...` không tồn tại, ứng dụng tự fallback về model có sẵn trong repo:

```python
model_path = "data/models/v1/model.pkl"
feature_path = "data/models/v1/feature.pkl"
```

Hoặc chạy lại pipeline huấn luyện để sinh model mới trong thư mục `outputs/`. Đường dẫn `model_path` và `feature_path` mặc định sẽ tự trỏ tới thư mục `outputs` mới nhất mà không cần sửa tay.

Artifact hiện được phân loại như sau:

- Bundled baseline artifacts: model/vectorizer có sẵn trong `data/models/v1/`.
- Current runtime artifacts: các path đang được `Config` load, ví dụ `outputs/ai-threat-current/models/`.
- Historical training runs: các lần train timestamp trong `outputs/<run-id>/`.

## Chạy Ứng Dụng

```bash
streamlit run app.py
```

Sau khi chạy, mở đường dẫn Streamlit hiển thị trên terminal, thường là:

```text
http://localhost:8501
```

## Huấn Luyện Lại Model Spam/Ham

Dataset mặc định nằm tại:

```text
data/dataset/dataset.csv
```

Chạy pipeline huấn luyện legacy compatibility cho spam/ham baseline:

```bash
python -m src.pipeline.training_pipeline  # legacy spam/ham baseline
```

Pipeline sẽ:

1. Đọc dữ liệu từ CSV.
2. Mã hóa nhãn `spam` thành `0`, `ham` thành `1`.
3. Chia train/test theo tỉ lệ 70/30.
4. Vector hóa nội dung email bằng hybrid feature pipeline: word TF-IDF, character n-gram TF-IDF và numeric security features.
5. Huấn luyện và tìm tham số tốt nhất cho nhiều mô hình.
6. Lưu model, vectorizer, metadata và báo cáo metric vào `outputs/<timestamp>/`.

Nếu muốn huấn luyện lại AI threat models mới, dùng command riêng:

```bash
python scripts\train_ai_threat_models.py --fixture-mode --force
python scripts\train_ai_threat_models.py --force --publish
```

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

- AI-only threat modeling: kết hợp TF-IDF word/char n-gram, numeric security features, URL, QR và attachment features; runtime verdict/risk không dùng rule score.
- Threat taxonomy: Safe, Spam, Phishing, Malware Risk, Business Email Compromise, Quishing, Credential Theft, Payment Scam.
- Model Evaluation Lab: metadata cho mỗi lần train, per-class metrics, macro/weighted F1, confusion matrix, threshold analysis và error analysis.
- Campaign Threat Intelligence: gom nhóm email nguy hiểm thành phishing/scam campaign, tạo graph-ready nodes/edges và xuất report.
- Adaptive Feedback Learning: người dùng đã đăng nhập có thể gửi feedback, hệ thống đưa case khó vào review queue và xuất dữ liệu retraining đã duyệt.

## Kiểm Tra Nhanh

```bash
python -m compileall src app.py scripts
python scripts\smoke_adaptive_threat_intelligence.py
python scripts\smoke_email_threat_lifecycle.py
```

Kết quả mong đợi:

```text
adaptive threat intelligence smoke passed
```

## Tài Liệu Dự Án

- `docs/DEMO.md`: Kịch bản demo chi tiết, input mẫu, kết quả mong đợi và cách trả lời câu hỏi.
- `docs/ADAPTIVE_THREAT_INTELLIGENCE.md`: Tài liệu kiến trúc Adaptive Threat Intelligence Platform.
- `docs/PROJECT_STRUCTURE.md`: Bản đồ cấu trúc thư mục và ownership module.
- `docs/KE_HOACH_CAI_TIEN_DU_AN.md`: Roadmap nâng cấp dự án thành MailGuard AI.
- `docs/PHAN_CONG_TINH_NANG.md`: Phân công tính năng cho hai thành viên.

## Ghi Chú

- File `.env`, `outputs/`, `venv/`, log và file MBOX được bỏ qua trong `.gitignore`.
- Mật khẩu được hash trong logic ứng dụng nếu có `bcrypt`; nếu thiếu `bcrypt`, hệ thống fallback SHA-256 chỉ phù hợp cho môi trường phát triển.
- Nếu lỗi load model xảy ra khi mở app, hãy kiểm tra lại `model_path` và `feature_path`.

## AI Threat Risk Model

Du an co them pipeline AI/ML rieng cho risk analysis. Quy trinh train lai chuan la:

```text
Data -> Cleaning -> Feature -> Train -> Evaluate -> Save model -> App integration -> Feedback -> Retrain
```

Du lieu production khong duoc train truc tiep tu seed CSV. Seed trong `data/ai_threat/email_threat_seed.csv` va `data/ai_threat/url_threat_seed.csv` chi dung cho smoke/fixture mode. Production retraining phai build canonical dataset tu nguon ngoai hoac feedback da duyet. Weak/generated/synthetic labels duoc ghi provenance nhung bi loai khoi primary training/evaluation mac dinh; chi include khi chay them `--include-weak-labels`.

Thu muc du lieu AI threat:

- `data/ai_threat/raw/`: file nguon local nhu PhishFuzzer JSON, Nazario mbox, SpamAssassin, Enron, PhishTank, URLhaus.
- `data/ai_threat/canonical/`: CSV canonical dung de train production.
- `data/ai_threat/manifests/`: manifest nguon, checksum, validation report, dataset version.
- `data/ai_threat/feedback/`: export feedback da review/approve.
- `data/ai_threat/fixtures/`: fixture nho cho smoke test.

Build canonical dataset tu file local:

```bash
python scripts\train_ai_threat_models.py --stage import ^
  --phishfuzzer-json data\ai_threat\raw\phishfuzzer.json ^
  --nazario-mbox data\ai_threat\raw\phishing-2025 ^
  --spamassassin-path data\ai_threat\raw\spamassassin ^
  --enron-maildir data\ai_threat\raw\enron ^
  --phishtank-path data\ai_threat\raw\phishtank.csv ^
  --urlhaus-path data\ai_threat\raw\urlhaus.csv
```

Train production tu canonical dataset:

```bash
python scripts\train_ai_threat_models.py --force
```

Publish artifact current sau khi pass publish gate:

```bash
python scripts\train_ai_threat_models.py --force --publish
```

Smoke test voi seed fixture:

```bash
python scripts\train_ai_threat_models.py --fixture-mode --force
python scripts\smoke_ai_threat_models.py
```

Pipeline nay train hai model sklearn:

- Email threat classifier: du doan `Safe`, `Spam`, `Phishing`, `Malware Risk`, `Credential Theft`, `Payment Scam`, `Quishing`, `Business Email Compromise` tu canonical dataset co provenance.
- URL phishing classifier: du doan URL benign/suspicious/phishing tu dac trung lexical/domain.

Artifact duoc luu trong `outputs/<run-id>_ai-threat/models/`. Khi publish gate pass, artifact duoc copy ve:

```python
ai_threat_model_path = "outputs/ai-threat-current/models/email_threat_model.pkl"
ai_url_model_path = "outputs/ai-threat-current/models/url_phishing_model.pkl"
```

Neu cac artifact nay chua co, ung dung tra ve trang thai `model_unavailable` cho risk analysis va khong fallback ve rule-based analyzer. Cac helper cu chi duoc dung cho parsing, feature extraction hoac evidence display, khong phai nguon quyet dinh verdict/risk runtime.

File smoke nhanh cho lifecycle moi:

```bash
python scripts\smoke_email_threat_lifecycle.py
```
