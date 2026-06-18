# Sơ Đồ Luồng Xử Lý Các Chức Năng MailGuard AI

Cập nhật: 18/06/2026

Tài liệu này mô tả luồng xử lý của các chức năng chính trong hệ thống MailGuard AI. Các sơ đồ được viết bằng Mermaid, có thể xem bằng Markdown Preview của VS Code, GitHub hoặc các công cụ hỗ trợ Mermaid.

## 1. Tổng Quan Kiến Trúc Xử Lý

```mermaid
flowchart TD
    A[Người dùng mở ứng dụng Streamlit] --> B[app.py khởi tạo session state]
    B --> C[Khởi tạo PredictionPipeline]
    C --> D{Load model và vectorizer Spam/Ham thành công?}
    D -- Không --> E[Hiển thị lỗi và dừng phần dự đoán Spam/Ham]
    D -- Có --> F[Sidebar tài khoản]
    F --> G{Người dùng đã đăng nhập?}
    G -- Chưa --> H[Chế độ khách]
    G -- Rồi --> I[Chế độ đầy đủ]
    H --> H1[Email đơn]
    H --> H2[Phishing Detector]
    H --> H3[Tóm tắt email]
    H --> H4[Chatbot RAG]
    H --> H5[File MBOX: yêu cầu đăng nhập]
    I --> I1[Dashboard]
    I --> I2[Email đơn]
    I --> I3[Phishing Detector]
    I --> I4[File MBOX]
    I --> I5[Tóm tắt email]
    I --> I6[Chatbot RAG]
    I --> I7[Lịch sử]
```

Giải thích:

- `app.py` là điểm vào của ứng dụng Streamlit.
- `PredictionPipeline` load spam classifier và vectorizer theo cấu hình trong `src/config/config.py`.
- `Config` ưu tiên artifact mới nhất trong `outputs/` nếu có đủ model/vectorizer; nếu không có thì fallback về `data/models/v1/`.
- Chế độ khách vẫn dùng được Email đơn, Phishing Detector, Tóm tắt và Chatbot.
- Sau khi đăng nhập, người dùng có thêm Dashboard, xử lý File MBOX, Lịch sử và Feedback.

## 2. Đăng Ký Tài Khoản

```mermaid
flowchart TD
    A[Người dùng chọn Đăng ký ở sidebar] --> B[Nhập username, password, confirm]
    B --> C{Submit form?}
    C -- Chưa --> Z[Chờ người dùng nhập tiếp]
    C -- Rồi --> D{Đủ thông tin?}
    D -- Không --> E[Thông báo thiếu thông tin]
    D -- Có --> F{Password trùng confirm?}
    F -- Không --> G[Thông báo mật khẩu không khớp]
    F -- Có --> H[register_user]
    H --> I[Chuẩn hóa username và validate độ dài]
    I --> J[Truy vấn User theo username]
    J --> K{Username đã tồn tại?}
    K -- Có --> L[Trả AuthError]
    K -- Không --> M[Hash password bằng bcrypt hoặc SHA-256 fallback]
    M --> N[INSERT vào bảng User]
    N --> O[Thông báo tạo tài khoản thành công]
    O --> P[Chuyển về form Đăng nhập và rerun]
```

Giải thích:

- UI đăng ký nằm trong sidebar của `app.py`.
- Logic nghiệp vụ nằm trong `src/features/auth/service.py`.
- Password được băm bằng `bcrypt` nếu thư viện khả dụng; nếu không có `bcrypt`, code fallback sang SHA-256 cho môi trường phát triển.
- Tài khoản được lưu vào bảng `User` trong MySQL.

## 3. Đăng Nhập / Đăng Xuất

```mermaid
flowchart TD
    A[Người dùng chọn Đăng nhập] --> B[Nhập username và password]
    B --> C{Submit form?}
    C -- Chưa --> Z[Chờ người dùng nhập tiếp]
    C -- Rồi --> D{Đủ thông tin?}
    D -- Không --> E[Thông báo thiếu thông tin]
    D -- Có --> F[login_user]
    F --> G[SELECT User theo username]
    G --> H{Có user và password đúng?}
    H -- Không --> I[Trả AuthError]
    H -- Có --> J[Cập nhật session_state logged_in, user_id, username]
    J --> K[st.rerun để mở chế độ đầy đủ]
    K --> L[Người dùng thấy các tab đầy đủ]
    L --> M{Bấm Đăng xuất?}
    M -- Có --> N[Reset session_state tài khoản]
    N --> O[st.rerun về chế độ khách]
```

Giải thích:

- `login_user` lấy password hash từ database và gọi `_verify_password`.
- Khi đăng nhập thành công, trạng thái được giữ trong `st.session_state`.
- Khi đăng xuất, các biến `logged_in`, `user_id`, `username`, `last_prediction_id` được reset.

## 4. Kiểm Tra Email Đơn Spam/Ham

```mermaid
flowchart TD
    A[Người dùng mở tab Email đơn] --> B[Dán nội dung email]
    B --> C{Bấm Phân tích email?}
    C -- Chưa --> Z[Chờ thao tác tiếp]
    C -- Rồi --> D{Nội dung rỗng?}
    D -- Có --> E[Thông báo yêu cầu nhập email]
    D -- Không --> F[pipeline.predict_single_email]
    F --> G[clean_text để làm sạch nội dung]
    G --> H[feature_transformer.transform]
    H --> I[model.predict]
    I --> J[Quy đổi 0 thành Spam, 1 thành Ham]
    J --> K{Model có predict_proba?}
    K -- Có --> L[Tính confidence = max probability * 100]
    K -- Không --> M[confidence = None]
    L --> N[Hiển thị kết quả và độ tin cậy]
    M --> N
    N --> O{Người dùng đã đăng nhập và DB OK?}
    O -- Không --> P[Không lưu lịch sử]
    O -- Có --> Q[save_single_prediction]
    Q --> R[INSERT Single_Prediction_History]
    R --> S[Lưu last_prediction_id để feedback]
```

Giải thích:

- Chức năng này dùng `PredictionPipeline.predict_single_email`.
- Feature pipeline được load từ `Config.feature_path`, model được load từ `Config.model_path`.
- Nếu người dùng đăng nhập và database kết nối được, kết quả được lưu vào `Single_Prediction_History`.
- Chế độ khách chỉ hiển thị kết quả, không lưu lịch sử.

## 5. Gửi Feedback Cho Kết Quả Dự Đoán

```mermaid
flowchart TD
    A[Sau khi dự đoán email đơn] --> B{Đã đăng nhập và có last_prediction_id?}
    B -- Không --> Z[Không hiển thị feedback]
    B -- Có --> C[Hiển thị expander Phản hồi kết quả]
    C --> D[Người dùng chọn Đúng hoặc Sai]
    D --> E{Kết quả Sai?}
    E -- Không --> F[feedback = correct]
    E -- Có --> G[Nhập nhãn đúng và ghi chú]
    F --> H[save_prediction_feedback]
    G --> H
    H --> I[INSERT Prediction_Feedback]
    I --> J{feedback incorrect?}
    J -- Không --> K[Hoàn tất]
    J -- Có --> L[create_review_queue_item]
    L --> M[INSERT Review_Queue với priority high]
```

Giải thích:

- Feedback chỉ xuất hiện sau khi có bản ghi dự đoán được lưu.
- Nếu người dùng đánh dấu kết quả sai, hệ thống tạo thêm item trong `Review_Queue`.
- Review Queue được dashboard hiển thị để phục vụ kiểm tra và cải thiện model.

## 6. Xử Lý File MBOX Theo Lô

```mermaid
flowchart TD
    A[Người dùng mở tab File MBOX] --> B{Đã đăng nhập?}
    B -- Không --> C[Thông báo yêu cầu đăng nhập]
    B -- Có --> D[Upload file .mbox hoặc .txt]
    D --> E{Bấm Xử lý file?}
    E -- Không --> Z[Chờ upload hoặc submit]
    E -- Có --> F[Lưu upload vào file tạm]
    F --> G[pipeline.predict_mbox_file]
    G --> H[process_mailbox]
    H --> I[mailbox.mbox đọc từng message]
    I --> J[Lấy Date, From, Reply-To, Recipients, Subject, Body]
    J --> K[Gán Category từ X-Gmail-Labels nếu có]
    K --> L[clean_text và extract_body]
    L --> M[run_prediction cho từng email]
    M --> N[Vectorize Body]
    N --> O[model.predict và tính confidence nếu có]
    O --> P[Tạo DataFrame kết quả]
    P --> Q[Xóa file tạm]
    Q --> R[Thống kê tổng email, Spam, Ham]
    R --> S[Hiển thị preview]
    S --> T[Cho tải CSV]
    T --> U{DB OK?}
    U -- Không --> V[Không lưu batch history]
    U -- Có --> W[save_batch_prediction]
    W --> X[INSERT Batch_Prediction_History]
```

Giải thích:

- Chức năng MBOX bắt buộc đăng nhập.
- File upload được ghi ra file tạm rồi đọc bằng `mailbox.mbox`.
- Mỗi email được trích metadata và body, sau đó chạy cùng model Spam/Ham.
- Kết quả đầy đủ được xuất CSV; database chỉ lưu thống kê batch.

## 7. Xem Lịch Sử Phân Tích

```mermaid
flowchart TD
    A[Người dùng mở tab Lịch sử] --> B{Đã đăng nhập?}
    B -- Không --> C[Thông báo yêu cầu đăng nhập]
    B -- Có --> D{Database OK?}
    D -- Không --> E[Thông báo lỗi kết nối DB]
    D -- Có --> F[Tạo 2 tab: Email đơn và File MBOX]
    F --> G[get_single_history]
    G --> H[SELECT Single_Prediction_History theo user_id]
    H --> I[Hiển thị bảng email đơn gần nhất]
    F --> J[get_batch_history]
    J --> K[SELECT Batch_Prediction_History theo user_id]
    K --> L[Hiển thị bảng batch MBOX gần nhất]
```

Giải thích:

- Lịch sử chỉ khả dụng khi người dùng đăng nhập và MySQL kết nối được.
- Lịch sử email đơn có preview nội dung và confidence.
- Lịch sử MBOX lưu thống kê batch, không lưu toàn bộ từng email trong file upload.

## 8. Dashboard Bảo Mật

```mermaid
flowchart TD
    A[Người dùng đã đăng nhập mở Dashboard] --> B[get_single_history]
    B --> C{Có dữ liệu?}
    C -- Không --> D[Thông báo chưa có dữ liệu]
    C -- Có --> E[Chuyển rows thành DataFrame]
    E --> F[Tính tổng email, số Spam, số Ham]
    F --> G[Hiển thị metric tổng email, tỉ lệ Spam, tỉ lệ Ham]
    G --> H[Vẽ biểu đồ tròn Spam/Ham]
    H --> I[Vẽ line chart số email theo ngày]
    I --> J[get_review_queue]
    J --> K{Có item review?}
    K -- Có --> L[Hiển thị bảng hàng đợi rà soát]
    K -- Không --> M[Bỏ qua review queue]
    L --> N[export_retraining_data]
    M --> N
    N --> O{Có mẫu đã duyệt?}
    O -- Có --> P[Hiển thị số mẫu retraining đã duyệt]
    O -- Không --> Q[Bỏ qua]
    P --> R[discover_model_runs]
    Q --> R
    R --> S{Có Model Lab run?}
    S -- Có --> T[Hiển thị bảng Model Lab]
    S -- Không --> U[Bỏ qua]
    T --> V[Hiển thị email gần đây]
    U --> V
```

Giải thích:

- Dashboard tổng hợp dữ liệu từ lịch sử dự đoán của người dùng.
- Biểu đồ tròn cho thấy tỉ lệ Spam/Ham, line chart cho thấy số email theo thời gian.
- Dashboard cũng hiển thị `Review_Queue` và các run Model Lab nếu có artifact trong `outputs/*/observations/model_lab_metadata.json`.

## 9. Phishing Detector Cho Email/Text

```mermaid
flowchart TD
    A[Người dùng mở tab Phishing Detector] --> B{transformers và torch khả dụng?}
    B -- Không --> C[Thông báo cần cài thư viện]
    B -- Có --> D[Chọn tab Email/Text]
    D --> E[Dán nội dung email hoặc link đáng nghi]
    E --> F{Bấm Kiểm tra phishing?}
    F -- Không --> Z[Chờ người dùng thao tác]
    F -- Có --> G{Nội dung rỗng?}
    G -- Có --> H[Thông báo yêu cầu nhập nội dung]
    G -- Không --> I[detect_phishing]
    I --> J[load_phishing_detector từ outputs/email_phishing_detector_vi]
    J --> K[Tokenizer mã hóa text max_length 512]
    K --> L[Model sequence classification suy luận]
    L --> M[softmax logits thành probabilities]
    M --> N[Chọn label có xác suất cao nhất]
    N --> O[Hiển thị nhãn An toàn/Phishing, confidence, điểm phishing]
```

Giải thích:

- Model phishing local được load một lần bằng `st.cache_resource`.
- Input được tokenize và cắt ở 512 token.
- Kết quả gồm label, confidence và xác suất theo từng nhãn (`benign`, `phishing`).
- Chức năng này không ghi database trong luồng hiện tại.

## 10. Phishing Detector Cho Ảnh QR

```mermaid
flowchart TD
    A[Người dùng chọn tab QR phishing] --> B[Upload ảnh PNG/JPG/WebP/BMP]
    B --> C[Hiển thị ảnh preview]
    C --> D{Bấm Kiểm tra QR phishing?}
    D -- Không --> Z[Chờ thao tác tiếp]
    D -- Có --> E[decode_qr_payloads]
    E --> F[Mở ảnh bằng PIL và tạo các biến thể xử lý ảnh]
    F --> G[OpenCV QRCodeDetector detectAndDecodeMulti]
    G --> H[OpenCV detectAndDecode đơn]
    H --> I{Có payload QR?}
    I -- Không --> J[Thông báo không phát hiện QR]
    I -- Có --> K[Chạy detect_phishing cho từng payload]
    K --> L[Tổng hợp số QR, số QR phishing, điểm cao nhất]
    L --> M[Hiển thị kết luận toàn ảnh]
    M --> N[Hiển thị chi tiết từng QR và payload]
```

Giải thích:

- Ảnh QR được tiền xử lý theo nhiều biến thể: ảnh gốc, ảnh phóng to, grayscale, tăng contrast, sharpen, crop và binary mask cho QR cách điệu.
- Mỗi payload đọc được từ QR được đưa qua cùng model phishing text.
- Nếu ít nhất một payload bị gán nhãn phishing, UI cảnh báo ảnh QR có dấu hiệu phishing.

## 11. Tóm Tắt Email Bằng Local AI

```mermaid
flowchart TD
    A[Người dùng mở tab Tóm tắt] --> B{transformers và torch khả dụng?}
    B -- Không --> C[Thông báo cần cài thư viện]
    B -- Có --> D[Chọn kiểu input]
    D --> E{Paste text hay upload MBOX?}
    E -- Paste text --> F[Lấy nội dung từ text_area]
    E -- MBOX --> G[Upload file MBOX]
    G --> H[extract_text_from_mbox_bytes]
    H --> I[Ghi file tạm và đọc bằng mailbox.mbox]
    I --> J[Trích text/plain từ từng email]
    J --> K[Ghép các email bằng dấu phân cách]
    F --> L[Chọn min_length và max_length]
    K --> L
    L --> M{Bấm Tóm tắt ngay?}
    M -- Không --> Z[Chờ thao tác tiếp]
    M -- Có --> N{Nội dung rỗng?}
    N -- Có --> O[Thông báo cần cung cấp nội dung]
    N -- Không --> P[local_ai_summarize]
    P --> Q[load_local_summarizer từ outputs/email_summarizer_vi]
    Q --> R[Chia text thành chunks 3000 ký tự]
    R --> S[Bỏ qua chunk quá ngắn]
    S --> T[Thêm prefix vietnews:]
    T --> U[Tokenizer và model.generate beam search]
    U --> V[Decode summary_ids thành text]
    V --> W[Hiển thị bản tóm tắt và nội dung gốc trong expander]
```

Giải thích:

- Chức năng tóm tắt chạy model Seq2Seq local trong `outputs/email_summarizer_vi`.
- Nếu input là MBOX, hệ thống chỉ trích các phần `text/plain`.
- Văn bản dài được chia thành nhiều chunk để phù hợp giới hạn token của model.
- Mỗi chunk được sinh tóm tắt riêng, sau đó ghép thành kết quả cuối.

## 12. Chatbot RAG Trên File MBOX

```mermaid
flowchart TD
    A[Người dùng mở tab Chatbot] --> B[Upload file MBOX]
    B --> C{File mới hoặc chưa có vector_store?}
    C -- Có --> D[build_vector_db]
    D --> E[Ghi upload vào file tạm]
    E --> F[mailbox.mbox đọc từng email]
    F --> G[Trích text/plain và subject]
    G --> H[Tạo Document với metadata source=subject]
    H --> I[RecursiveCharacterTextSplitter chunk_size 1000 overlap 150]
    I --> J[HuggingFaceEmbeddings tạo vector]
    J --> K[FAISS.from_documents tạo vector store]
    K --> L[load_local_summarizer]
    L --> M[Đưa local model vào HuggingFacePipeline]
    M --> N[Lưu vector_store, llm, prompt vào session_state]
    C -- Không --> O[Dùng lại vector_store hiện có]
    N --> P[Người dùng nhập câu hỏi]
    O --> P
    P --> Q[Retriever FAISS tìm top 3 chunks liên quan]
    Q --> R[Ghép context]
    R --> S[PromptTemplate + local LLM sinh câu trả lời]
    S --> T[Hiển thị câu trả lời]
    T --> U[Expander hiển thị các đoạn email liên quan]
```

Giải thích:

- Chatbot RAG không train model mới.
- Lập chỉ mục: email được tách thành `Document`, chia chunk, vector hóa bằng `sentence-transformers/all-MiniLM-L6-v2` và lưu vào FAISS.
- Hỏi đáp: câu hỏi được dùng để truy vấn FAISS, lấy 3 đoạn liên quan làm context, sau đó local LLM sinh câu trả lời.
- Local LLM hiện lấy từ `outputs/email_summarizer_vi` qua hàm `load_local_summarizer`.
- Vector store và lịch sử chat được giữ trong `st.session_state`.

## 13. Huấn Luyện Lại Spam Classifier

```mermaid
flowchart TD
    A[Chạy python -m src.features.spam_classifier.training_pipeline] --> B[TrainingPipeline khởi tạo TrainingState]
    B --> C[DataIngestion.load_data]
    C --> D[Đọc data/dataset/dataset.csv]
    D --> E[DataTransformation.transform_data]
    E --> F[Encode label spam=0, ham=1]
    F --> G[Chia train/test 70/30 stratify]
    G --> H[FeatureUnion]
    H --> H1[Word TF-IDF ngram 1-2]
    H --> H2[Char TF-IDF char_wb ngram 3-5]
    H --> H3[Security numeric features]
    H1 --> I[Fit/transform train và transform test]
    H2 --> I
    H3 --> I
    I --> J[ModelTraining.train_models]
    J --> K[GridSearchCV từng model]
    K --> L[Train LogisticRegression, DecisionTree, SVM, KNN, RandomForest]
    L --> M[Đánh giá accuracy, precision, recall, F1]
    M --> N[Chọn model có F1 tốt nhất]
    N --> O[Lưu vectorizer.pkl và model.pkl]
    O --> P[Lưu metadata và CSV metrics]
    P --> Q[Lưu Model Lab artifacts]
    Q --> R[outputs hoặc thư mục output theo Config]
```

Giải thích:

- Pipeline huấn luyện đọc dataset mặc định từ `data/dataset/dataset.csv`.
- Feature vector gồm word TF-IDF, char n-gram TF-IDF và các dấu hiệu số về bảo mật như độ dài, số chữ số, số URL, từ khóa khẩn cấp, credential, payment và file nguy hiểm.
- Hệ thống train nhiều model bằng `GridSearchCV`, đánh giá trên tập test và chọn model có F1-score tốt nhất.
- Artifact mới được lưu vào thư mục output của lần train; khi app chạy lại, `Config` có thể ưu tiên artifact mới nếu tìm thấy đủ model/vectorizer.

## 14. Model Lab Và Artifact Đánh Giá

```mermaid
flowchart TD
    A[Sau khi chọn best model] --> B[save_model_lab_outputs]
    B --> C[Dự đoán lại trên tập test]
    C --> D{Model có predict_proba?}
    D -- Có --> E[Lấy xác suất spam và confidence]
    D -- Không --> F[Dùng điểm thay thế từ nhãn dự đoán]
    E --> G[Quy đổi y_true/y_pred để spam là positive class]
    F --> G
    G --> H[evaluate_predictions]
    H --> I[Tính per-class precision/recall/F1, macro/weighted F1, confusion matrix]
    I --> J[threshold_report]
    J --> K[Phân tích threshold 0.35, 0.5, 0.65, 0.8]
    K --> L[error_analysis]
    L --> M[Liệt kê false positives, false negatives, low confidence]
    M --> N[Lưu threshold_analysis.csv]
    N --> O[Lưu error_analysis.json]
    O --> P[Lưu model_lab_metadata.json]
    P --> Q[Dashboard discover_model_runs đọc và hiển thị]
```

Giải thích:

- Model Lab là phần artifact phục vụ quan sát chất lượng model sau train.
- `threshold_analysis.csv` giúp so sánh trade-off giữa precision/recall ở các ngưỡng.
- `error_analysis.json` giúp xem các mẫu bị dự đoán sai hoặc độ tin cậy thấp.
- Dashboard đọc `model_lab_metadata.json` trong `outputs/*/observations/` để hiển thị các lần train.

## 15. Luồng Kết Nối Database Dùng Chung

```mermaid
flowchart TD
    A[Chức năng cần database] --> B[db.py load .env]
    B --> C[_get_db_config đọc DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME]
    C --> D[get_connection]
    D --> E{mysql-connector-python khả dụng?}
    E -- Không --> F[Raise RuntimeError]
    E -- Có --> G[mysql.connector.connect]
    G --> H[Thực thi fetchone/fetchall/execute]
    H --> I{Thành công?}
    I -- Có --> J[commit và đóng kết nối]
    I -- Lỗi --> K[rollback và raise lỗi]
```

Giải thích:

- Database adapter nằm trong `src/infrastructure/database/db.py`.
- `fetchone`, `fetchall`, `execute` là các helper dùng chung cho auth, lịch sử, dashboard, feedback và batch history.
- `ping()` được app dùng để kiểm tra database trước khi hiển thị các thao tác cần DB.

## 16. Bảng Tổng Hợp Chức Năng Và Nơi Lưu Trữ

| Chức năng | Input chính | Xử lý chính | Output | Lưu trữ |
| --- | --- | --- | --- | --- |
| Đăng ký | Username, password | Validate, hash password, insert user | Tài khoản mới | `User` |
| Đăng nhập | Username, password | Verify password hash | Session đăng nhập | `st.session_state` |
| Email đơn | Nội dung email | Clean text, vectorize, model predict | Spam/Ham, confidence | `Single_Prediction_History` nếu đăng nhập |
| Feedback | Prediction ID, đúng/sai, nhãn sửa | Insert feedback, tạo review item nếu sai | Trạng thái feedback | `Prediction_Feedback`, `Review_Queue` |
| File MBOX | File `.mbox`/`.txt` | Parse mailbox, predict từng email | Bảng kết quả, CSV | `Batch_Prediction_History` |
| Lịch sử | User ID | Query lịch sử email/batch | Bảng lịch sử | MySQL |
| Dashboard | Lịch sử user | Tổng hợp metric, chart, review queue, model runs | Báo cáo trên UI | MySQL + `outputs/` |
| Phishing email/text | Email/link/text | Tokenize, classifier phishing | An toàn/Phishing | Không lưu trong luồng hiện tại |
| Phishing QR | Ảnh QR | Decode QR, classify payload | Kết luận QR phishing | Không lưu trong luồng hiện tại |
| Tóm tắt email | Text hoặc MBOX | Trích text, chunk, local Seq2Seq generate | Bản tóm tắt | Không lưu trong luồng hiện tại |
| Chatbot RAG | MBOX và câu hỏi | Chunk, embedding, FAISS retrieval, local LLM answer | Câu trả lời và context | `st.session_state` |
| Train spam classifier | Dataset CSV | Transform, train nhiều model, chọn best | Model, vectorizer, metrics | `outputs/` hoặc output dir theo `Config` |
