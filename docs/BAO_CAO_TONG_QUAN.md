# BÁO CÁO TỔNG QUAN DỰ ÁN MAILGUARD AI

**Tên đề tài:** Nghiên cứu và Xây dựng Hệ thống Phân tích An toàn Email (Adaptive Email Threat Intelligence Platform) tích hợp Học máy, Mô hình ngôn ngữ lớn (LLM) và RAG.

---

## 1. Giới Thiệu Dự Án
**MailGuard AI** không chỉ là một hệ thống phân loại Spam/Ham thông thường, mà là một nền tảng **Phân tích Mối đe dọa Email Thích ứng (Adaptive Threat Intelligence)**. Hệ thống có khả năng tiếp nhận email văn bản hoặc file MBOX, sau đó bóc tách đặc trưng để phát hiện các rủi ro bảo mật phức tạp như: Phishing (Lừa đảo), Quishing (Lừa đảo qua mã QR), Malware (Mã độc), BEC (Giả mạo doanh nghiệp) và Tấn công phi kỹ thuật (Social Engineering).

Dự án kết hợp chặt chẽ giữa **Học máy truyền thống (Machine Learning)**, **Luật bảo mật (Rule-based Heuristics)** và **Trí tuệ nhân tạo tạo sinh (Generative AI / LLM)** để mang lại kết luận rủi ro chính xác và có tính giải thích cao.

---

## 2. Kiến Trúc Công Nghệ Áp Dụng
Hệ thống được phát triển trên kiến trúc hiện đại, xử lý toàn bộ tác vụ tính toán ngay trên thiết bị cục bộ (Local Environment):
- **Ngôn ngữ lập trình:** Python 3.13
- **Giao diện người dùng (UI):** Streamlit
- **Cơ sở dữ liệu:** MySQL (Quản lý User, Lịch sử phân tích, Phản hồi Feedback, Review Queue)
- **Học máy (Machine Learning):** Scikit-learn, Pandas, Numpy, Scipy
- **Deep Learning & NLP:** PyTorch, Transformers (Hugging Face), Datasets
- **Xử lý hình ảnh (Computer Vision):** OpenCV, Pillow, scikit-image
- **Truy vấn ngữ nghĩa (RAG):** LangChain, FAISS Vector Database, Sentence-Transformers

---

## 3. Thuật Toán và Các Mô Hình AI Chi Tiết
Hệ thống sử dụng cơ chế **Hybrid Detection** (Phát hiện lai) với 5 luồng phân tích chính:

### 3.1. Phân loại Spam Cơ sở (Machine Learning)
- **Thuật toán:** Hệ thống trích xuất đặc trưng lai (Hybrid Feature Engineering) bao gồm: `Word TF-IDF` (n-gram 1-2), `Character TF-IDF` (n-gram 3-5) và Các đặc trưng bảo mật số học (Độ dài, đếm URL, cờ khẩn cấp, file đính kèm).
- **Huấn luyện:** Sử dụng `GridSearchCV` để tối ưu siêu tham số trên nhiều thuật toán (Logistic Regression, Decision Tree, SVM, KNN, Random Forest). Mô hình tốt nhất (thường là SVM hoặc Random Forest) sẽ được lưu cục bộ dưới dạng `.pkl` để nhận diện tỷ lệ Spam/Ham và độ tin cậy (Confidence).

### 3.2. Phân tích Lừa Đảo Chuyên Sâu (Fine-tuned Transformer)
- **Công nghệ:** Sử dụng mô hình `nxtcute/xlm-r-phishing-and-social-engineering-detector-vi` (Kiến trúc XLM-RoBERTa).
- **Huấn luyện (Pipeline tự động):** Kịch bản ETL của dự án tự động tải tập dữ liệu `phish-eval-vi`, tiến hành tokenization và huấn luyện (Fine-tuning) với `Trainer` của Hugging Face để nhận diện các thủ đoạn phi kỹ thuật và lừa đảo bằng Tiếng Việt.
- **Hoạt động:** Trả về nhãn (Safe / Phishing) và điểm rủi ro. Điểm này được đối chiếu chéo với các luật (Rule-based) về từ khóa khẩn cấp, tài chính để ra quyết định cuối cùng.

### 3.3. Tóm Tắt Email Cục Bộ (Local Generative AI)
- **Công nghệ:** Sử dụng kiến trúc Text-to-Text Transfer Transformer đa ngôn ngữ (`VietAI/vit5-base`).
- **Huấn luyện:** Mã nguồn hỗ trợ tải bộ dữ liệu báo chí tiếng Việt, biến đổi chuỗi tiền tố `"vietnews: "` và sử dụng `Seq2SeqTrainer` để tự tay huấn luyện mô hình tóm tắt cục bộ chạy trên máy cá nhân mà không phụ thuộc API bên ngoài.
- **Thuật toán sinh văn bản:** Sử dụng `Beam Search` (num_beams=4) và `Length Penalty` để nội dung tóm tắt đầu ra được tự nhiên và mạch lạc.

### 3.4. Trợ Lý Ảo Truy Vấn Hộp Thư (RAG Chatbot)
Để giải quyết bài toán đọc hàng ngàn email trong file `.mbox`, dự án sử dụng kiến trúc RAG (Retrieval-Augmented Generation):
- **Vectorization:** Email được chia nhỏ bằng `RecursiveCharacterTextSplitter`. Các đoạn văn bản được nhúng thành Vector không gian bằng mô hình `sentence-transformers/all-MiniLM-L6-v2`.
- **Lưu trữ tìm kiếm:** Lưu vào CSDL Vector cục bộ cực nhanh `FAISS`.
- **Truy vấn:** Khi người dùng đặt câu hỏi, FAISS dùng thuật toán Cosine Similarity để kéo ra (Retrieve) 3 đoạn email giống nhất.
- **Sinh câu trả lời:** Đưa ngữ cảnh (Context) vừa tìm được vào prompt cho mô hình LLM `ViT5` cục bộ để tổng hợp câu trả lời chính xác, tránh hiện tượng AI "ảo giác" (Hallucination).

### 3.5. Phân Tích Mã QR và Quishing (Computer Vision & Heuristics)
- **Trích xuất ảnh:** Dùng OpenCV (`cv2.QRCodeDetector`) và Pillow kết hợp thuật toán làm nét (Sharpen), tăng tương phản và chuyển đổi không gian màu HSV/Grayscale để bắt được cả các mã QR bị làm mờ hoặc chèn logo (như VietQR).
- **Phân tích URL:** Bóc tách URL từ QR và chấm điểm rủi ro (Heuristics) dựa trên hàng loạt quy tắc: IP giả dạng, miền rút gọn (bit.ly), chuyển hướng lồng nhau, TLD độc hại (.zip, .top), và tính khoảng cách chuỗi (SequenceMatcher) để phát hiện giả mạo thương hiệu (Brand Impersonation).

---

## 4. Các Tính Năng Nghiệp Vụ Cốt Lõi Khác
- **Risk Aggregator (Bộ Hợp Nhất Rủi Ro):** Không phụ thuộc vào một kết quả duy nhất. Mọi điểm số từ AI Spam, AI Lừa đảo, AI Mã độc, và Phân tích URL được đưa vào bộ tổng hợp. Nếu có xung đột (VD: AI bảo Ham nhưng URL chứa mã độc), rủi ro vẫn bị đẩy lên mức Critical. Hệ thống tự động sinh ra các "Lý do giải thích" (Explainable Reasons) và "Hành động khuyến nghị".
- **Campaign Intelligence (Nhận Diện Chiến Dịch):** Thuật toán Clustering riêng biệt gom nhóm các email khả nghi trong một đợt gửi MBOX dựa trên hệ số Jaccard (URL, Domain, QR) và độ tương đồng văn bản để phát hiện các tổ chức tấn công có tổ chức, vẽ sơ đồ quan hệ mạng lưới (Threat Graph).
- **Adaptive Learning (Học Thích Ứng):** Người dùng có thể Đánh giá "Đúng/Sai" cho AI. Dữ liệu này được đưa vào Hàng đợi Rà soát (Review Queue), xây dựng nên vòng lặp MLOps giúp hệ thống ngày càng thông minh hơn qua các lần tái huấn luyện.

---

## 5. Thành Tựu Đạt Được
- **Xây dựng thành công hệ thống Hybrid:** Kết hợp hiệu quả giữa Machine Learning, Deep Learning và các luật bảo mật để đưa ra đánh giá toàn diện, khắc phục điểm yếu của từng phương pháp khi hoạt động riêng lẻ.
- **Triển khai AI cục bộ (Local First):** Toàn bộ các mô hình AI (Phân loại, Tóm tắt, RAG) đều có khả năng chạy offline trên máy người dùng, đảm bảo tính riêng tư, bảo mật và không phụ thuộc vào API của bên thứ ba.
- **Tự động hóa quy trình MLOps:** Xây dựng thành công các pipeline tự động cho việc Huấn luyện (Fine-tuning), Đánh giá và Tái huấn luyện mô hình, giúp hệ thống có khả năng tự học và cải thiện theo thời gian.
- **Tính giải thích cao (Explainable AI):** Thay vì chỉ đưa ra kết quả cuối cùng, hệ thống cung cấp chi tiết các "lý do" và "điểm số thành phần", giúp người dùng hiểu rõ tại sao một email được coi là nguy hiểm.
- **Khả năng mở rộng:** Kiến trúc module hóa cho phép dễ dàng tích hợp các mô hình AI mới, các bộ luật bảo mật mới hoặc kết nối với các hệ thống bên ngoài (như Gmail API) trong tương lai.

---

## 6. Hạn Chế và Hướng Cải Thiện
- **Dữ liệu huấn luyện:** Các mô hình AI hiện tại được huấn luyện trên các bộ dữ liệu công khai (báo chí, email lừa đảo mẫu). Để tăng độ chính xác trong thực tế, cần bổ sung và huấn luyện lại với các bộ dữ liệu email nội bộ, chuyên ngành hơn.
- **Phân tích Header Email:** Hệ thống chưa phân tích sâu các thông tin trong header như SPF, DKIM, DMARC. Tích hợp các kiểm tra này sẽ giúp phát hiện các cuộc tấn công giả mạo email (Spoofing) hiệu quả hơn.
- **Tối ưu hiệu năng:** Việc tải và chạy nhiều mô hình AI cục bộ có thể tiêu tốn nhiều tài nguyên (RAM/CPU). Cần nghiên cứu các kỹ thuật tối ưu hóa như Quantization (lượng tử hóa) hoặc Pruning (tỉa mô hình) để giảm dung lượng và tăng tốc độ xử lý.
- **Tích hợp thời gian thực:** Nâng cấp hệ thống để có thể đồng bộ trực tiếp với các dịch vụ email như Gmail/Outlook, tự động quét các email mới và gửi cảnh báo theo thời gian thực thay vì phải xử lý thủ công.